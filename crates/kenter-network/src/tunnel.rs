//! WebSocket tunnel client for the relay (`kenter-tunnler`).
//!
//! Implements:
//!   1. WSS connect to `wss://<host>/connect`
//!   2. Challenge-response auth via Stellar JWT
//!   3. Service binding
//!   4. Stream-multiplexed request/response dispatch

use crate::error::{NetworkError, Result};
use crate::jwt::create_stellar_jwt;
use crate::protocol::HealthResponse;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use kenter_crypto::keypair::StellarKeypair;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Type aliases for the WebSocket split halves
// ---------------------------------------------------------------------------

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    Message,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
>;

/// Outstanding outbound requests, keyed by `stream_id`, awaiting a matching
/// `tunnel_response`. The message loop is the single reader of the socket and
/// routes each response to the waiting request's channel — so concurrent
/// requests never steal each other's responses (the demultiplexer).
type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tunnel client configuration.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Relay host, with its port if any (e.g. `relay.example.org`). No
    /// default: the caller names the relay.
    pub host: String,
    /// Services to advertise during auth (e.g. `["kenter"]`).
    pub services: Vec<String>,
    /// Local port to bind (forwarded requests arrive here).
    pub local_port: u16,
    /// JWT expiration in seconds (default 3600).
    pub jwt_expires_secs: u64,
    /// Timeout for the auth handshake in seconds.
    pub auth_timeout_secs: u64,
    /// Timeout for forwarded request responses in seconds.
    ///
    /// Must cover the slowest thing a node does before it answers, and
    /// that is `/kenter/extend`: the node submits `confirm_link` and
    /// waits for it to land before replying, and its own wait for a
    /// transaction is 60 seconds (`kenter_client::tx`). A link on testnet
    /// can take 19-30 seconds, so 30 gives up on nodes that are working.
    /// 120 covers the node's 60, plus simulate and submit, with
    /// margin. The relay's own limit (`TUNNLER_REQUEST_TIMEOUT`) must be
    /// at least this, or it cuts the same request off in the middle.
    pub request_timeout_secs: u64,
    /// Use TLS (`wss://` / `https://`). Default `true` for production. Set `false`
    /// to reach a plaintext local server (`ws://` / `http://`) during development —
    /// e.g. a locally-run `kenter-tunnler` with no TLS terminator in front.
    pub secure: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            services: vec!["kenter".into()],
            local_port: 9090,
            jwt_expires_secs: 3600,
            auth_timeout_secs: 15,
            request_timeout_secs: 120,
            secure: true,
        }
    }
}

impl TunnelConfig {
    pub fn wss_url(&self) -> String {
        let scheme = if self.secure { "wss" } else { "ws" };
        format!("{scheme}://{}/connect", self.host)
    }

    pub fn endpoint_base(&self) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        format!("{scheme}://{}", self.host)
    }
}

// ---------------------------------------------------------------------------
// Tunnel events (internal)
// ---------------------------------------------------------------------------

/// Internal command sent from public API → message loop.
enum LoopCommand {
    /// Shut down the message loop.
    Shutdown,
}

/// Incoming tunnel request delivered to the handler callback.
#[derive(Debug, Clone)]
pub struct IncomingRequest {
    pub stream_id: u64,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

// ---------------------------------------------------------------------------
// Auth info returned after successful handshake
// ---------------------------------------------------------------------------

/// Information returned after successful tunnel authentication.
#[derive(Debug, Clone)]
pub struct TunnelEndpoint {
    /// The public endpoint URL assigned by the server (e.g.
    /// `https://GADDR.relay.example.org`).
    pub endpoint_url: String,
    /// The server's Stellar address.
    pub server_address: String,
    /// Services confirmed by the server.
    pub services: Vec<String>,
    /// Whether E2E encryption is available.
    pub encryption_available: bool,
}

// ---------------------------------------------------------------------------
// Request handler trait
// ---------------------------------------------------------------------------

/// Trait for handling incoming tunnel requests.
///
/// Implement this to dispatch Kenter protocol messages
/// (`/kenter/health`, `/kenter/extend`, and `/kenter/shard` where served).
pub trait RequestHandler: Send + Sync + 'static {
    fn handle_request(
        &self,
        req: IncomingRequest,
    ) -> Pin<Box<dyn Future<Output = Value> + Send + '_>>;
}

/// Records a freshly-built chain link on the mint.
///
/// A port, not a dependency: this crate stays chain-free so the protocol can be
/// reasoned about as transport plus crypto, and `kenter-node` supplies the
/// Soroban implementation. Same shape as `ChainRead` / `Store` / `DerivingVault`
/// elsewhere in the workspace.
///
/// The mint accepts `confirm_link` only from a member of the assigned pair, so
/// this is the node's own call to make — the depositor cannot make it on the
/// node's behalf.
pub trait LinkConfirmer: Send + Sync + 'static {
    /// Is this request for a print this node is really part of?
    ///
    /// Asked **before** extending, against the slot on-chain: the chain's
    /// event id must be the slot's, its links must be exactly the links
    /// confirmed so far, and this node must be the pair assigned to the
    /// next one -- and each earlier link signed by the pair the slot names
    /// for it. `/kenter/extend` is reachable by anyone through the relay,
    /// and the chain it carries is checked only for internal consistency,
    /// so without this a stranger could hand a node a chain built from
    /// throwaway keys with a real slot's id and have the node confirm a
    /// link into that print, killing it. The signer check
    /// matters as much as the key check: event id and partial keys are
    /// public once confirmed, and nothing binds a partial key to the keys
    /// that signed its link, so a look-alike chain could copy both.
    /// No default: an implementation that forgot this would admit
    /// everything.
    ///
    /// `prior_links` is `(partial_public_key, node_a_public, node_b_public)`
    /// for every link the chain already has, in order.
    fn admits(
        &self,
        slot_id: u32,
        event_id: [u8; 32],
        prior_links: Vec<([u8; 32], [u8; 32], [u8; 32])>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), String>> + Send + '_>>;

    fn confirm_link(
        &self,
        slot_id: u32,
        link_index: u32,
        partial_public_key: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), String>> + Send + '_>>;
}

/// Wrap a protocol payload in the HTTP envelope the relay's proxy expects.
///
/// The proxy reads `status_code` and takes `body` **as a string**, so a handler
/// that returns its payload at the top level yields HTTP 200 with an *empty*
/// body — the response vanishes between the node and the caller. That is not
/// hypothetical: every Kenter endpoint did exactly this until the multi-node
/// test drove one over the real proxy path
/// (`kenter-tunnler/src/multi_node_test.rs`). Direct-handler tests cannot catch
/// it, because the envelope only exists on the transport.
fn http_envelope(status_code: u16, payload: Value) -> Value {
    serde_json::json!({
        "status_code": status_code,
        "headers": { "content-type": "application/json" },
        "body": payload.to_string(),
    })
}

/// Full Kenter protocol handler that dispatches to the extend and health
/// endpoints, and to the shard endpoint only when asked to
/// ([`KenterHandler::with_shard_service`]).
///
/// Responses are wrapped by [`http_envelope`]. Protocol-level failures (a bad
/// shard request, a node not in a print relay) are still **HTTP 200** with the
/// error in the protocol payload, because they are answers rather than
/// transport faults — `parse_shard_response` and friends read `status` from the
/// payload, not from the HTTP code.
pub struct KenterHandler {
    /// Pair node context for shard requests (redemption).
    pub pair_ctx: Arc<crate::handlers::PairNodeContext>,
    /// Extend context for chain extension (printing).
    /// `None` if this node is not currently participating in a print relay.
    pub extend_ctx: Arc<Mutex<Option<crate::handlers::ExtendNodeContext>>>,
    /// Records each extension on-chain. `None` keeps the node chain-free, which
    /// is fine for transport tests but means prints it takes part in can never
    /// be registered — the mint counts confirmed links before accepting a token.
    pub confirmer: Option<Arc<dyn LinkConfirmer>>,
    /// Extensions this node built and confirmed, keyed by a hash of the exact
    /// request that asked for each.
    ///
    /// A reply lost on the way back leaves the depositor with a link
    /// confirmed on-chain and no chain to continue, and the slot no longer
    /// admits the request (its link is done). So a byte-identical request
    /// gets the same reply again, without a second confirmation. Only the
    /// party that sent the original request has its bytes, and the reply
    /// is what that party was already owed. Bounded: the newest
    /// [`SERVED_KEEP`].
    pub served: Arc<Mutex<std::collections::VecDeque<([u8; 32], Value)>>>,
    /// Whether `/kenter/shard` is answered. **Off by default.**
    ///
    /// Shards serve only redemption by key (`redeem_by_key`), which no
    /// Kenter client uses: notes are redeemed by chain, which needs no node.
    /// The handler gives a shard to anyone who presents a note's public
    /// inputs, so serving it would let anyone compose a note's ephemeral
    /// secret through the network. That cannot reach a payout (the mint
    /// also wants the claim key or owner proof), but it is a public
    /// endpoint doing nothing useful. Only the in-process shard test turns
    /// it on ([`Self::with_shard_service`]).
    pub serve_shards: bool,
}

/// How many served extensions a node remembers.
pub const SERVED_KEEP: usize = 64;

impl KenterHandler {
    /// A handler that serves `/kenter/health` and `/kenter/extend`, and
    /// refuses `/kenter/shard`.
    pub fn new(
        pair_ctx: Arc<crate::handlers::PairNodeContext>,
        extend_ctx: Arc<Mutex<Option<crate::handlers::ExtendNodeContext>>>,
        confirmer: Option<Arc<dyn LinkConfirmer>>,
    ) -> Self {
        Self {
            pair_ctx,
            extend_ctx,
            confirmer,
            served: Default::default(),
            serve_shards: false,
        }
    }

    /// Also answer `/kenter/shard`. For testing the shard scheme only.
    pub fn with_shard_service(mut self) -> Self {
        self.serve_shards = true;
        self
    }
}

/// What `/kenter/shard` answers on a node that does not serve shards.
pub const SHARDS_NOT_SERVED: &str = "this node does not serve shards: Kenter notes are redeemed by chain";

impl RequestHandler for KenterHandler {
    fn handle_request(
        &self,
        req: IncomingRequest,
    ) -> Pin<Box<dyn Future<Output = Value> + Send + '_>> {
        let pair_ctx = Arc::clone(&self.pair_ctx);
        let extend_ctx = Arc::clone(&self.extend_ctx);
        let confirmer = self.confirmer.clone();
        let served = Arc::clone(&self.served);
        let serve_shards = self.serve_shards;

        Box::pin(async move {
            match req.path.as_str() {
                "/kenter/health" => {
                    // Report the pair so a print driver can name both members
                    // in request_print. Public keys only; nothing secret here.
                    let partner_address = extend_ctx
                        .lock()
                        .await
                        .as_ref()
                        .map(|c| c.partner_keypair.stellar_address());
                    let resp = HealthResponse {
                        status: "ok".into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        node_address: Some(pair_ctx.own_keypair.stellar_address()),
                        partner_address,
                    };
                    http_envelope(200, serde_json::to_value(resp).unwrap_or_default())
                }

                "/kenter/shard" => {
                    // Refused before the body is read, so a node that does
                    // not serve shards does no work for the request.
                    if !serve_shards {
                        return http_envelope(
                            404,
                            serde_json::json!({"status": "error", "error": SHARDS_NOT_SERVED}),
                        );
                    }
                    let body = match req.body.as_deref() {
                        Some(b) => b,
                        None => {
                            return http_envelope(
                                200,
                                serde_json::json!({"status": "error", "error": "missing request body"}),
                            )
                        }
                    };
                    let shard_req: crate::protocol::ShardRequest = match serde_json::from_str(body) {
                        Ok(r) => r,
                        Err(e) => {
                            return http_envelope(
                                200,
                                serde_json::json!({"status": "error", "error": format!("invalid shard request: {e}")}),
                            )
                        }
                    };
                    let resp = crate::handlers::handle_shard_request(&pair_ctx, &shard_req);
                    http_envelope(200, serde_json::to_value(resp).unwrap_or_default())
                }

                "/kenter/extend" => {
                    let body = match req.body.as_deref() {
                        Some(b) => b,
                        None => {
                            return http_envelope(
                                200,
                                serde_json::json!({"status": "error", "error": "missing request body"}),
                            )
                        }
                    };
                    let extend_req: crate::protocol::ExtendRequest = match serde_json::from_str(body) {
                        Ok(r) => r,
                        Err(e) => {
                            return http_envelope(
                                200,
                                serde_json::json!({"status": "error", "error": format!("invalid extend request: {e}")}),
                            )
                        }
                    };
                    let slot_id = extend_req.slot_id;
                    // The same request again: the reply was lost.
                    let request_hash: [u8; 32] = {
                        use sha2::Digest;
                        sha2::Sha256::digest(body.as_bytes()).into()
                    };
                    if let Some((_, reply)) =
                        served.lock().await.iter().find(|(h, _)| *h == request_hash)
                    {
                        return http_envelope(200, reply.clone());
                    }
                    // Check the request against the slot before doing any
                    // work for it. See `LinkConfirmer::admits`. A node with
                    // no confirmer (`--no-confirm`, transport testing) does
                    // not touch the ledger, so it has nothing to protect.
                    if let Some(confirmer) = confirmer.as_ref() {
                        let partial = base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            &extend_req.partial_token,
                        )
                        .map_err(|e| format!("invalid partial_token base64: {e}"))
                        .and_then(|b| {
                            kenter_crypto::container::deserialize_partial_token(&b)
                                .map_err(|e| format!("invalid partial token: {e}"))
                        });
                        let refused = match partial {
                            Err(e) => Some(e),
                            Ok(p) => confirmer
                                .admits(
                                    slot_id,
                                    p.header.event_id,
                                    p.chain
                                        .links
                                        .iter()
                                        .map(|l| {
                                            (l.partial_public_key, l.node_a_public, l.node_b_public)
                                        })
                                        .collect(),
                                )
                                .await
                                .err(),
                        };
                        if let Some(e) = refused {
                            return http_envelope(
                                200,
                                serde_json::json!({
                                    "type": "extend_response",
                                    "status": "error",
                                    "error": format!("not extending: {e}"),
                                }),
                            );
                        }
                    }
                    let resp = {
                        let ctx_guard = extend_ctx.lock().await;
                        match ctx_guard.as_ref() {
                            Some(ctx) => {
                                Some(crate::handlers::handle_extend_request(ctx, &extend_req))
                            }
                            None => None,
                        }
                    };
                    let Some(resp) = resp else {
                        return http_envelope(
                            200,
                            serde_json::json!({"status": "error", "error": "node not participating in print relay"}),
                        );
                    };

                    // Record the link we just created. Done after extending, and
                    // reported as a failure if it does not land: an unconfirmed
                    // link cannot be registered, so silently returning the
                    // extended token would hand the requestor a chain that dies
                    // at `register_token` with no clue why.
                    if resp.status == "ok" {
                        if let Some(confirmer) = confirmer.as_ref() {
                            match crate::handlers::last_link_of(&resp) {
                                Ok((link_index, partial_public_key)) => {
                                    if let Err(e) = confirmer
                                        .confirm_link(slot_id, link_index, partial_public_key)
                                        .await
                                    {
                                        return http_envelope(
                                            200,
                                            serde_json::json!({
                                                "type": "extend_response",
                                                "status": "error",
                                                "error": format!("extended, but confirm_link failed: {e}"),
                                            }),
                                        );
                                    }
                                }
                                Err(e) => {
                                    return http_envelope(
                                        200,
                                        serde_json::json!({
                                            "type": "extend_response",
                                            "status": "error",
                                            "error": format!("cannot read the new link: {e}"),
                                        }),
                                    )
                                }
                            }
                        }
                    }
                    let reply = serde_json::to_value(resp).unwrap_or_default();
                    if confirmer.is_some() && reply["status"] == "ok" {
                        let mut s = served.lock().await;
                        s.push_back((request_hash, reply.clone()));
                        while s.len() > SERVED_KEEP {
                            s.pop_front();
                        }
                    }
                    http_envelope(200, reply)
                }

                // A genuinely unknown path IS a transport-level 404, unlike the
                // protocol errors above.
                _ => http_envelope(
                    404,
                    serde_json::json!({
                        "status": "error",
                        "error": format!("unknown endpoint: {}", req.path),
                    }),
                ),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// TunnelClient
// ---------------------------------------------------------------------------

/// A WebSocket tunnel client that connects to the relay,
/// authenticates via Stellar JWT, and dispatches incoming requests.
pub struct TunnelClient {
    keypair: StellarKeypair,
    config: TunnelConfig,
}

impl TunnelClient {
    pub fn new(keypair: StellarKeypair, config: TunnelConfig) -> Self {
        Self { keypair, config }
    }

    /// Connect, authenticate, bind, and run the message loop.
    ///
    /// Spawns the message loop as a tokio task. Returns the endpoint
    /// info and a session handle. The loop runs until shutdown or
    /// disconnect.
    pub async fn run(
        self,
        handler: Arc<dyn RequestHandler>,
    ) -> Result<(TunnelEndpoint, SessionHandle)> {
        // 1. WebSocket connect
        let (ws_stream, _response) =
            tokio_tungstenite::connect_async(&self.config.wss_url())
                .await
                .map_err(NetworkError::WebSocket)?;

        info!(url = %self.config.wss_url(), "WebSocket connected");

        let (ws_write, mut ws_read) = ws_stream.split();
        let ws_write = Arc::new(Mutex::new(ws_write));

        // 2. Auth handshake (challenge → JWT response → auth_ok)
        let endpoint =
            self.authenticate(&ws_write, &mut ws_read).await?;

        info!(endpoint = %endpoint.endpoint_url, "Authenticated");

        // 3. Bind service
        self.bind_service(&ws_write).await?;

        info!(service = %self.config.services.first().unwrap_or(&String::new()),
              port = self.config.local_port, "Service bound");

        // 4. Spawn message loop
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<LoopCommand>();
        let request_timeout = self.config.request_timeout_secs;
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let stream_counter = Arc::new(AtomicU64::new(0));

        let loop_handle = tokio::spawn(message_loop(
            Arc::clone(&ws_write),
            ws_read,
            cmd_rx,
            handler,
            request_timeout,
            Arc::clone(&pending),
        ));

        Ok((
            endpoint,
            SessionHandle {
                cmd_tx,
                loop_handle,
                ws_write,
                pending,
                stream_counter,
                request_timeout,
            },
        ))
    }

    /// Perform challenge-response authentication.
    async fn authenticate(
        &self,
        ws_write: &Arc<Mutex<WsSink>>,
        ws_read: &mut WsStream,
    ) -> Result<TunnelEndpoint> {
        let timeout = std::time::Duration::from_secs(self.config.auth_timeout_secs);

        // --- Receive auth_challenge ---
        let challenge_msg = tokio::time::timeout(timeout, ws_read.next())
            .await
            .map_err(|_| NetworkError::Timeout("auth challenge".into()))?
            .ok_or(NetworkError::ConnectionClosed)?
            .map_err(NetworkError::WebSocket)?;

        let challenge: Value = match challenge_msg {
            Message::Text(t) => serde_json::from_str(&t)?,
            _ => return Err(NetworkError::Protocol("expected text message for challenge".into())),
        };

        if challenge.get("type").and_then(|v| v.as_str()) != Some("auth_challenge") {
            return Err(NetworkError::Protocol(format!(
                "expected auth_challenge, got: {}",
                challenge.get("type").unwrap_or(&Value::Null)
            )));
        }

        let challenge_id = challenge["challenge_id"]
            .as_str()
            .ok_or_else(|| NetworkError::Protocol("missing challenge_id".into()))?;
        let challenge_value = challenge["challenge"]
            .as_str()
            .ok_or_else(|| NetworkError::Protocol("missing challenge value".into()))?;
        let server_address = challenge["server_address"]
            .as_str()
            .ok_or_else(|| NetworkError::Protocol("missing server_address".into()))?;

        debug!(challenge_id, "Received auth challenge");

        // --- Build JWT with challenge claim ---
        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "challenge".to_string(),
            serde_json::json!(challenge_value),
        );

        let jwt = create_stellar_jwt(
            &self.keypair,
            server_address,
            &self.config.services,
            Some(self.config.jwt_expires_secs),
            &custom_claims,
        );

        // --- Send auth_response ---
        let auth_resp = serde_json::json!({
            "type": "auth_response",
            "jwt": jwt,
            "challenge_id": challenge_id,
        });

        {
            let mut w = ws_write.lock().await;
            w.send(Message::Text(auth_resp.to_string()))
                .await
                .map_err(NetworkError::WebSocket)?;
        }

        debug!("Sent auth_response");

        // --- Receive auth_ok or auth_failed ---
        let auth_result = tokio::time::timeout(timeout, ws_read.next())
            .await
            .map_err(|_| NetworkError::Timeout("auth result".into()))?
            .ok_or(NetworkError::ConnectionClosed)?
            .map_err(NetworkError::WebSocket)?;

        let result: Value = match auth_result {
            Message::Text(t) => serde_json::from_str(&t)?,
            _ => return Err(NetworkError::Protocol("expected text for auth result".into())),
        };

        match result.get("type").and_then(|v| v.as_str()) {
            Some("auth_ok") => {
                let endpoint_url = result["endpoint"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let svr_addr = result["server_address"]
                    .as_str()
                    .unwrap_or(server_address)
                    .to_string();
                let services: Vec<String> = result["services"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let encryption_available = result["encryption_available"]
                    .as_bool()
                    .unwrap_or(false);

                Ok(TunnelEndpoint {
                    endpoint_url,
                    server_address: svr_addr,
                    services,
                    encryption_available,
                })
            }
            Some("auth_failed") => {
                let err = result["error"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();
                Err(NetworkError::AuthFailed(err))
            }
            other => Err(NetworkError::Protocol(format!(
                "unexpected auth response type: {other:?}"
            ))),
        }
    }

    /// Send a `bind` message to register our service.
    async fn bind_service(
        &self,
        ws_write: &Arc<Mutex<WsSink>>,
    ) -> Result<()> {
        let bind_msg = serde_json::json!({
            "type": "bind",
            "service": self.config.services.first().unwrap_or(&"kenter".to_string()),
            "local_port": self.config.local_port,
        });

        let mut w = ws_write.lock().await;
        w.send(Message::Text(bind_msg.to_string()))
            .await
            .map_err(NetworkError::WebSocket)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Session handle
// ---------------------------------------------------------------------------

/// Handle to a running tunnel session.
///
/// Use this to shut down the tunnel, wait for it to finish, or make outbound
/// requests to remote peers (e.g. a combiner sending shard requests to pair
/// nodes) via [`SessionHandle::request`].
pub struct SessionHandle {
    cmd_tx: mpsc::UnboundedSender<LoopCommand>,
    loop_handle: tokio::task::JoinHandle<()>,
    ws_write: Arc<Mutex<WsSink>>,
    pending: PendingMap,
    stream_counter: Arc<AtomicU64>,
    request_timeout: u64,
}

impl SessionHandle {
    /// Request graceful shutdown of the tunnel.
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(LoopCommand::Shutdown);
    }

    /// A detachable shutdown trigger.
    ///
    /// [`Self::join`] consumes the handle, so a caller that wants to wait on the
    /// loop *and* still be able to stop it (a daemon awaiting both the session
    /// and a signal) cannot hold both. Take one of these first.
    pub fn shutdown_trigger(&self) -> impl Fn() + Send + Sync + 'static {
        let tx = self.cmd_tx.clone();
        move || {
            let _ = tx.send(LoopCommand::Shutdown);
        }
    }

    /// Wait for the message loop to finish.
    pub async fn join(self) -> std::result::Result<(), tokio::task::JoinError> {
        self.loop_handle.await
    }

    /// Send a request and return the **payload**, unwrapping the HTTP envelope.
    ///
    /// [`Self::request`] hands back exactly what the peer's handler returned,
    /// which for any Kenter node is the `{status_code, headers, body}` envelope
    /// the relay's proxy expects — `body` being a JSON *string*. A caller
    /// reaching a node over HTTP gets that unwrapped by the proxy, so the two
    /// routes to the same endpoint otherwise disagree about the shape of the
    /// answer. This is the one to use for protocol calls; `request` stays raw
    /// for callers that need the status code or headers.
    pub async fn request_json(
        &self,
        target_address: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let raw = self.request(target_address, method, path, body).await?;

        // A handler that did not use the envelope: pass it through rather than
        // failing, so a non-Kenter peer is still usable.
        let Some(inner) = raw.get("body") else {
            return Ok(raw);
        };
        if let Some(code) = raw.get("status_code").and_then(|v| v.as_u64()) {
            if !(200..300).contains(&code) {
                return Err(NetworkError::Protocol(format!(
                    "{target_address} {path} returned HTTP {code}: {inner}"
                )));
            }
        }
        match inner {
            Value::String(text) => serde_json::from_str(text).map_err(|e| {
                NetworkError::Protocol(format!("{target_address} {path}: body is not JSON: {e}"))
            }),
            other => Ok(other.clone()),
        }
    }

    /// Send an HTTP-style request through the tunnel to a remote peer and await
    /// its response.
    ///
    /// Correlated by a unique `stream_id`: the request registers a one-shot
    /// receiver in the pending map, and the single message-loop reader routes the
    /// matching `tunnel_response` back to it. Concurrent requests therefore never
    /// steal or drop each other's responses (unlike the earlier read-and-skip
    /// implementation). Uses the session's configured request timeout.
    pub async fn request(
        &self,
        target_address: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let stream_id = self.stream_counter.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(stream_id, tx);

        let request = serde_json::json!({
            "type": "tunnel_request",
            "stream_id": stream_id,
            "target": target_address,
            // Serialised, not embedded: `IncomingRequest::body` is an
            // `Option<String>` and the relay's HTTP proxy sends it as a string
            // too. Passing the Value through made the peer see no body at all
            // and answer "missing request body" — the two routes to a node have
            // to agree on the encoding.
            "request": { "method": method, "path": path, "body": body.map(|v| v.to_string()) },
        });

        // Send; on failure, unregister so we don't leak the pending entry.
        if let Err(e) = {
            let mut w = self.ws_write.lock().await;
            w.send(Message::Text(request.to_string())).await
        } {
            self.pending.lock().await.remove(&stream_id);
            return Err(NetworkError::WebSocket(e));
        }

        let timeout = std::time::Duration::from_secs(self.request_timeout);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            // Sender dropped (message loop ended) → connection is gone.
            Ok(Err(_)) => Err(NetworkError::ConnectionClosed),
            Err(_) => {
                self.pending.lock().await.remove(&stream_id);
                Err(NetworkError::Timeout(format!(
                    "tunnel request to {target_address}{path}"
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Message loop
// ---------------------------------------------------------------------------

async fn message_loop(
    ws_write: Arc<Mutex<WsSink>>,
    mut ws_read: WsStream,
    mut cmd_rx: mpsc::UnboundedReceiver<LoopCommand>,
    handler: Arc<dyn RequestHandler>,
    _request_timeout: u64,
    pending: PendingMap,
) {
    let next_ping = tokio::time::interval(std::time::Duration::from_secs(30));
    tokio::pin!(next_ping);

    loop {
        tokio::select! {
            // --- Incoming WebSocket message ---
            msg = ws_read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let data: Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("Invalid JSON from tunnel: {e}");
                                continue;
                            }
                        };
                        handle_server_message(
                            &data,
                            &ws_write,
                            Arc::clone(&handler),
                            &pending,
                        ).await;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let mut w = ws_write.lock().await;
                        let _ = w.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!("Tunnel connection closed");
                        break;
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {e}");
                        break;
                    }
                    _ => {} // Binary, Pong, Frame — ignore
                }
            }

            // --- Internal commands ---
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(LoopCommand::Shutdown) | None => {
                        info!("Tunnel shutting down");
                        let mut w = ws_write.lock().await;
                        let _ = w.send(Message::Close(None)).await;
                        break;
                    }
                }
            }

            // --- Keepalive ping ---
            _ = next_ping.tick() => {
                let ping = serde_json::json!({"type": "ping"});
                let mut w = ws_write.lock().await;
                if let Err(e) = w.send(Message::Text(ping.to_string())).await {
                    error!("Ping failed: {e}");
                    break;
                }
            }
        }
    }

    // The socket is gone: drop every pending sender so in-flight
    // `SessionHandle::request` calls resolve to ConnectionClosed instead of
    // hanging until their timeout.
    pending.lock().await.clear();
}

/// Dispatch a single message from the tunnel server.
async fn handle_server_message(
    data: &Value,
    ws_write: &Arc<Mutex<WsSink>>,
    handler: Arc<dyn RequestHandler>,
    pending: &PendingMap,
) {
    let msg_type = data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    match msg_type {
        // Response to one of OUR outbound requests — route it to the waiter.
        "tunnel_response" => {
            if let Some(stream_id) = data.get("stream_id").and_then(|v| v.as_u64()) {
                if let Some(tx) = pending.lock().await.remove(&stream_id) {
                    let _ = tx.send(data.get("response").cloned().unwrap_or(Value::Null));
                } else {
                    debug!("tunnel_response for unknown stream {stream_id} (late/duplicate)");
                }
            }
        }

        "ping" => {
            // Server-level ping (JSON, not WebSocket ping frame).
            let pong = serde_json::json!({"type": "pong"});
            let mut w = ws_write.lock().await;
            let _ = w.send(Message::Text(pong.to_string())).await;
        }

        "bind_ok" => {
            debug!("bind_ok received");
        }

        "tunnel_request" => {
            let stream_id = data
                .get("stream_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let request = data.get("request").cloned().unwrap_or(Value::Null);

            let incoming = IncomingRequest {
                stream_id,
                method: request
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_string(),
                path: request
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string(),
                headers: request
                    .get("headers")
                    .and_then(|v| v.as_object())
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default(),
                body: request
                    .get("body")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            };

            // Dispatch to handler (spawned so we don't block the loop).
            let ws_w = Arc::clone(ws_write);
            tokio::spawn(async move {
                let response = handler.handle_request(incoming).await;
                let msg = serde_json::json!({
                    "type": "tunnel_response",
                    "stream_id": stream_id,
                    "response": response,
                });
                let mut w = ws_w.lock().await;
                if let Err(e) = w.send(Message::Text(msg.to_string())).await {
                    error!("Failed to send tunnel_response for stream {stream_id}: {e}");
                }
            });
        }

        "encryption_enabled" => {
            info!("E2E encryption enabled (XSalsa20-Poly1305)");
        }

        other => {
            debug!("Unhandled message type: {other}");
        }
    }
}

// Outbound requests to remote tunnel peers are made via [`SessionHandle::request`],
// which correlates responses through the message loop's stream-id demultiplexer.
// Nothing else may read the socket: a reader that dropped frames that were not
// its own response could not coexist with the message loop.
