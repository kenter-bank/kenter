//! A real multi-node Kenter network, in process.
//!
//! `kenter-network`'s `full_lifecycle.rs` proves the protocol by calling the
//! handlers directly — the transport is imagined. This proves the same thing
//! with the transport real: a relay, several independent pair nodes each with
//! its own keys and its own `TunnelClient`, and a combiner that reaches them
//! only over HTTP → proxy → WebSocket → handler.
//!
//! The assertion that matters: shards collected from separate nodes over the
//! wire compose into a key whose signature verifies under the token's ephemeral
//! public key. That is the threshold property working across a network rather
//! than inside a single test process.
//!
//! It also makes the trust boundary concrete. One node process serves one
//! *pair* and holds both of that pair's secrets, because `PartialToken::extend`
//! dual-signs the link. So `PAIRS` independent parties — not `2 * PAIRS` —
//! stand between this network and a reconstructable key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Mutex;

use kenter_crypto::compose::verify_chain_public_key_from_links;
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::redemption::{RedemptionRequest, RedemptionSession};
use kenter_crypto::token::{assemble_bearer_token, PartialToken};
use kenter_network::handlers::{
    build_shard_request, parse_shard_response, ExtendNodeContext, PairNodeContext,
    ShardRateLimiter,
};
use kenter_network::protocol::ShardResponse;
use kenter_network::protocol::ExtendRequest;
use kenter_network::tunnel::{
    KenterHandler, LinkConfirmer, SessionHandle, TunnelClient, TunnelConfig,
};

use crate::config::AppConfig;
use crate::server::build_router;
use crate::state::AppState;

/// Pairs in the test token. Each is one node process — one trust domain.
const PAIRS: u16 = 3;
/// Token header time; arbitrary, not window-checked.
const TEST_TIME: i64 = 1_741_800_000;

/// Redemption requests carry a timestamp the nodes check against a tight
/// window (-60s..+300s), so this one must be real wall-clock, not a fixture.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn test_config(server_secret: String) -> AppConfig {
    AppConfig {
        host: "127.0.0.1".into(),
        port: 0,
        domain: "local.test".into(),
        server_secret,
        jwt_clock_skew: 60,
        session_timeout: 86_400,
        challenge_ttl: 30,
        rate_limit_window: 60,
        rate_limit_max_attempts: 10_000,
        rate_limit_block_duration: 300,
        request_timeout: 30,
        log_level: "warn".into(),
        roster_contract_id: None, // gating off: no Soroban call in a unit test
        soroban_rpc_url: "http://unused.invalid".into(),
        soroban_network_passphrase: "Test SDF Network ; September 2015".into(),
        roster_cache_ttl: 300,
        // The tests connect over loopback with no proxy in front, so
        // nothing needs to be believed about who the client is.
        trusted_proxies: Vec::new(),
        // The relay's own list, plus the shard endpoint: the nodes here
        // are built with shard service on to keep that code tested
        // (`start_node`), and these tests reach it through the relay.
        proxy_paths: crate::config::PROXY_PATHS
            .iter()
            .chain(&["/kenter/shard"])
            .map(|p| p.to_string())
            .collect(),
    }
}

/// One node in the network: its own keys, its own tunnel session.
struct Node {
    address: String,
    own: StellarKeypair,
    partner: StellarKeypair,
    _session: SessionHandle,
}

/// POST JSON through the relay's proxy to `address`, retrying while the node
/// finishes registering (the server inserts the connection just after auth, so
/// a first attempt can race).
async fn proxy_post(
    http: &reqwest::Client,
    port: u16,
    address: &str,
    path: &str,
    body: &Value,
) -> Value {
    let url = format!("http://127.0.0.1:{port}/proxy/{address}{path}");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let resp = http
            .post(&url)
            .json(body)
            .send()
            .await
            .expect("proxy request send");
        if resp.status().as_u16() == 200 {
            let text = resp.text().await.expect("proxy body");
            return serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("body not JSON ({e}); raw={text:?}"));
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node {address} never became reachable (last status {})",
            resp.status()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn boot_relay() -> u16 {
    let server_kp = StellarKeypair::random();
    let config = test_config(server_kp.stellar_secret().to_string());
    let state = Arc::new(AppState::new(config, server_kp, None));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let router = build_router(state);
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("server serve");
    });
    port
}

/// Start one pair node against the relay — the same wiring `kenter-node` does.
async fn start_node(port: u16) -> Node {
    let own = StellarKeypair::random();
    let partner = StellarKeypair::random();
    let address = own.stellar_address();

    let handler = Arc::new(KenterHandler {
        pair_ctx: Arc::new(PairNodeContext {
            own_keypair: own.clone(),
            rate_limiter: ShardRateLimiter::new(),
        }),
        extend_ctx: Arc::new(Mutex::new(Some(ExtendNodeContext {
            own_keypair: own.clone(),
            partner_keypair: partner.clone(),
        }))),
        confirmer: None,
        served: Default::default(),
        // This test drives the shard scheme over the real proxy path.
        serve_shards: true,
    });

    let cfg = TunnelConfig {
        host: format!("127.0.0.1:{port}"),
        services: vec!["kenter".into()],
        secure: false,
        ..Default::default()
    };
    let (_endpoint, session) = TunnelClient::new(own.clone(), cfg)
        .run(handler)
        .await
        .expect("node connect → auth → bind");

    Node { address, own, partner, _session: session }
}

/// The network reconstructs a token's ephemeral key from shards fetched over
/// the wire — and the resulting signature verifies under that key.
#[tokio::test]
async fn multi_node_network_serves_shards_that_rebuild_the_token_key() {
    let port = boot_relay().await;

    let mut nodes = Vec::new();
    for _ in 0..PAIRS {
        nodes.push(start_node(port).await);
    }

    // Build a token whose chain is contributed by exactly these nodes, so the
    // shards fetched later are genuinely theirs.
    let event_id: [u8; 32] = [0x5c; 32];
    let (mut partial, _first_shard) = PartialToken::initiate(
        event_id,
        TEST_TIME,
        Some(1_000),
        PAIRS,
        &nodes[0].own,
        &nodes[0].partner,
        vec![],
    )
    .expect("initiate");
    // The requestor's own pair is the FINAL link, added by assembly - so extend
    // with the middle nodes only and let the last node assemble. Every link then
    // belongs to a node we can reach over the relay.
    for node in &nodes[1..nodes.len() - 1] {
        partial.extend(&node.own, &node.partner).expect("extend");
    }
    let last = nodes.last().expect("at least one node");
    let token = assemble_bearer_token(&partial, &last.own, &last.partner, 7, None)
        .expect("assemble");
    assert_eq!(token.chain.links.len(), PAIRS as usize);
    verify_chain_public_key_from_links(&token.chain.links, &token.ephemeral_public_key)
        .expect("chain composes to the token's ephemeral key");

    // A combiner asks each pair for its shard, reaching them only over the relay.
    let combiner = StellarKeypair::random();
    let combiner_public = combiner.raw_public();
    let holder = StellarKeypair::random();
    let token_hash: [u8; 32] = [0xAB; 32];
    let ephemeral_key = token.ephemeral_public_key;
    let chain_links = token.chain.links.clone();

    let request =
        RedemptionRequest::new(token, token_hash, &holder, combiner_public, now_secs());

    let http = reqwest::Client::new();
    let mut encrypted_shards = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let shard_req = build_shard_request(
            &chain_links[i],
            &event_id,
            &combiner_public,
            &request.holder_address,
            &token_hash,
            &request.nonce,
            &request.holder_signature,
            request.timestamp,
        );
        let body = serde_json::to_value(&shard_req).expect("request to json");
        let raw = proxy_post(&http, port, &node.address, "/kenter/shard", &body).await;

        let response: ShardResponse = serde_json::from_value(raw.clone())
            .unwrap_or_else(|e| panic!("node {} returned {raw}: {e}", node.address));
        assert_eq!(response.status, "ok", "node {} refused: {raw}", node.address);
        encrypted_shards.push(parse_shard_response(&response).expect("parse shard"));
    }

    // Compose and sign — the real redemption path, fed entirely by the network.
    let mut session = RedemptionSession::new(request, combiner).expect("session");
    assert_eq!(session.total_count(), PAIRS as usize);
    for (i, enc) in encrypted_shards.iter().enumerate() {
        session
            .receive_shard(enc, &nodes[i].own.verifying_key())
            .expect("accept shard");
    }
    assert!(session.is_complete(), "all pairs contributed");

    let msg = b"stellar:redeem:multi-node";
    let (signature, public_bytes) = session.compose_and_sign(msg).expect("compose and sign");
    assert_eq!(
        public_bytes, ephemeral_key,
        "the composed key must be the token's ephemeral key"
    );
    ed25519_dalek::VerifyingKey::from_bytes(&public_bytes)
        .expect("valid key")
        .verify_strict(msg, &signature)
        .expect("a signature built from networked shards must verify");
}

/// A shard request replayed against the same node for the same link is refused.
/// Each node rate-limits per (event_id, link_index), which is what stops a
/// combiner — or anyone who can reach the relay — harvesting a pair's shard
/// twice.
#[tokio::test]
async fn a_replayed_shard_request_is_refused() {
    let port = boot_relay().await;
    let node = start_node(port).await;

    let event_id: [u8; 32] = [0x77; 32];
    // Two pairs: this node's, plus the requestor's own closing pair.
    let (partial, _s) = PartialToken::initiate(
        event_id,
        TEST_TIME,
        Some(1_000),
        2,
        &node.own,
        &node.partner,
        vec![],
    )
    .expect("initiate");

    let combiner = StellarKeypair::random();
    let holder = StellarKeypair::random();
    let token_hash: [u8; 32] = [0x12; 32];
    let requestor = StellarKeypair::random();
    let assembly_partner = StellarKeypair::random();
    let token = assemble_bearer_token(&partial, &requestor, &assembly_partner, 7, None)
        .expect("assemble");
    let link = token.chain.links[0].clone();
    let request =
        RedemptionRequest::new(token, token_hash, &holder, combiner.raw_public(), now_secs());

    let shard_req = build_shard_request(
        &link,
        &event_id,
        &combiner.raw_public(),
        &request.holder_address,
        &token_hash,
        &request.nonce,
        &request.holder_signature,
        request.timestamp,
    );
    let body = serde_json::to_value(&shard_req).expect("json");
    let http = reqwest::Client::new();

    let first = proxy_post(&http, port, &node.address, "/kenter/shard", &body).await;
    assert_eq!(first["status"], "ok", "first request should be served: {first}");

    let second = proxy_post(&http, port, &node.address, "/kenter/shard", &body).await;
    assert_eq!(
        second["status"], "refused",
        "a repeat for the same link must be refused: {second}"
    );
    // Distinct from a malformed request, so a combiner can tell "you already
    // had this" from "your request was bad" and not retry pointlessly.
    let malformed = proxy_post(
        &http,
        port,
        &node.address,
        "/kenter/shard",
        &serde_json::json!({"type": "shard_request"}),
    )
    .await;
    assert_eq!(malformed["status"], "error", "malformed request: {malformed}");
}

/// Every node answers health over the relay, on a distinct address — the
/// liveness check an operator would run against a deployed network.
#[tokio::test]
async fn every_node_answers_health_through_the_relay() {
    let port = boot_relay().await;
    let mut nodes = Vec::new();
    for _ in 0..PAIRS {
        nodes.push(start_node(port).await);
    }

    let http = reqwest::Client::new();
    for node in &nodes {
        let body = proxy_post(
            &http,
            port,
            &node.address,
            "/kenter/health",
            &serde_json::json!({}),
        )
        .await;
        assert_eq!(body["status"], "ok", "node {} unhealthy: {body}", node.address);
    }

    // The relay routes by address, so colliding identities would silently send
    // every request to one node and a "network" would be one machine.
    let mut addresses: Vec<&str> = nodes.iter().map(|n| n.address.as_str()).collect();
    addresses.sort_unstable();
    addresses.dedup();
    assert_eq!(addresses.len(), PAIRS as usize, "node addresses must be distinct");
}

// ── confirm_link: a node records its own link (OWNER of the call is the node) ──

/// A confirmer that records what it was asked to confirm, or fails on command.
struct RecordingConfirmer {
    seen: std::sync::Mutex<Vec<(u32, u32, [u8; 32])>>,
    fail: bool,
}

impl LinkConfirmer for RecordingConfirmer {
    /// Admits everything: these tests are about transport and recording,
    /// and have no ledger to check a slot against.
    fn admits(
        &self,
        _slot_id: u32,
        _event_id: [u8; 32],
        _prior_links: Vec<([u8; 32], [u8; 32], [u8; 32])>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }

    fn confirm_link(
        &self,
        slot_id: u32,
        link_index: u32,
        partial_public_key: [u8; 32],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>,
    > {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push((slot_id, link_index, partial_public_key));
            if self.fail {
                Err("submission rejected".into())
            } else {
                Ok(())
            }
        })
    }
}

async fn start_node_with_confirmer(
    port: u16,
    confirmer: Arc<RecordingConfirmer>,
) -> Node {
    let own = StellarKeypair::random();
    let partner = StellarKeypair::random();
    let address = own.stellar_address();

    let handler = Arc::new(KenterHandler {
        pair_ctx: Arc::new(PairNodeContext {
            own_keypair: own.clone(),
            rate_limiter: ShardRateLimiter::new(),
        }),
        extend_ctx: Arc::new(Mutex::new(Some(ExtendNodeContext {
            own_keypair: own.clone(),
            partner_keypair: partner.clone(),
        }))),
        confirmer: Some(confirmer),
        served: Default::default(),
        serve_shards: false,
    });

    let cfg = TunnelConfig {
        host: format!("127.0.0.1:{port}"),
        services: vec!["kenter".into()],
        secure: false,
        ..Default::default()
    };
    let (_endpoint, session) = TunnelClient::new(own.clone(), cfg)
        .run(handler)
        .await
        .expect("node connect");
    Node { address, own, partner, _session: session }
}

/// Build a 3-pair partial whose first link belongs to `opener`, ready to extend.
fn partial_for(opener: &Node, event_id: [u8; 32]) -> PartialToken {
    let (partial, _s) = PartialToken::initiate(
        event_id,
        TEST_TIME,
        Some(1_000),
        3,
        &opener.own,
        &opener.partner,
        vec![],
    )
    .expect("initiate");
    partial
}

/// The node confirms the link it just created, for the slot the request named.
/// This is the step that lets a network issue a token without the depositor
/// playing every node role.
#[tokio::test]
async fn extending_node_confirms_its_own_link_on_chain() {
    let port = boot_relay().await;
    let opener = start_node(port).await;
    let confirmer = Arc::new(RecordingConfirmer {
        seen: std::sync::Mutex::new(Vec::new()),
        fail: false,
    });
    let extender = start_node_with_confirmer(port, Arc::clone(&confirmer)).await;

    let event_id = [0x21u8; 32];
    let partial = partial_for(&opener, event_id);
    let slot_id = 4242u32;

    let req = kenter_network::handlers::build_extend_request(&partial, slot_id)
        .expect("build extend request");
    let raw = proxy_post(
        &http_client(),
        port,
        &extender.address,
        "/kenter/extend",
        &serde_json::to_value(&req).unwrap(),
    )
    .await;
    assert_eq!(raw["status"], "ok", "extend failed: {raw}");

    let seen = confirmer.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "exactly one confirmation");
    let (got_slot, got_index, got_key) = seen[0];
    assert_eq!(got_slot, slot_id, "the slot from the request must be used");
    assert_eq!(got_index, 1, "the extender added link 1, after the opener's link 0");

    // And the key confirmed must be the one actually in the extended chain —
    // confirming someone else's partial key would register a chain that cannot
    // redeem.
    let resp: kenter_network::protocol::ExtendResponse =
        serde_json::from_value(raw).expect("response");
    let extended =
        kenter_network::handlers::parse_extend_response(&resp).expect("parse");
    assert_eq!(extended.chain.links.len(), 2);
    assert_eq!(got_key, extended.chain.links[1].partial_public_key);
}

/// A reply lost after the link was confirmed is not the end of the
/// print: the same request again gets the same reply, and the node does not
/// confirm a second time. A different request is not served from the cache.
#[tokio::test]
async fn the_same_request_again_gets_the_same_reply_without_a_second_confirmation() {
    let port = boot_relay().await;
    let opener = start_node(port).await;
    let confirmer = Arc::new(RecordingConfirmer {
        seen: std::sync::Mutex::new(Vec::new()),
        fail: false,
    });
    let extender = start_node_with_confirmer(port, Arc::clone(&confirmer)).await;

    let partial = partial_for(&opener, [0x24u8; 32]);
    let req = serde_json::to_value(
        &kenter_network::handlers::build_extend_request(&partial, 77).unwrap(),
    )
    .unwrap();
    let first = proxy_post(&http_client(), port, &extender.address, "/kenter/extend", &req).await;
    let again = proxy_post(&http_client(), port, &extender.address, "/kenter/extend", &req).await;
    assert_eq!(first["status"], "ok", "{first}");
    assert_eq!(first, again, "the lost reply is served again, unchanged");
    assert_eq!(confirmer.seen.lock().unwrap().len(), 1, "confirmed once only");

    // Another slot is another request: built and confirmed afresh.
    let other = serde_json::to_value(
        &kenter_network::handlers::build_extend_request(&partial, 78).unwrap(),
    )
    .unwrap();
    let third = proxy_post(&http_client(), port, &extender.address, "/kenter/extend", &other).await;
    assert_eq!(third["status"], "ok", "{third}");
    assert_eq!(confirmer.seen.lock().unwrap().len(), 2);
}

/// A failed confirmation is reported, not swallowed. An unconfirmed link cannot
/// be registered, so returning the extended token as if nothing happened would
/// hand the requestor a chain that dies at register_token with no explanation.
#[tokio::test]
async fn a_failed_confirmation_fails_the_extend() {
    let port = boot_relay().await;
    let opener = start_node(port).await;
    let confirmer = Arc::new(RecordingConfirmer {
        seen: std::sync::Mutex::new(Vec::new()),
        fail: true,
    });
    let extender = start_node_with_confirmer(port, Arc::clone(&confirmer)).await;

    let partial = partial_for(&opener, [0x22u8; 32]);
    let req = kenter_network::handlers::build_extend_request(&partial, 7)
        .expect("build extend request");
    let raw = proxy_post(
        &http_client(),
        port,
        &extender.address,
        "/kenter/extend",
        &serde_json::to_value(&req).unwrap(),
    )
    .await;

    assert_eq!(raw["status"], "error", "must surface the failure: {raw}");
    assert!(
        raw["error"].as_str().unwrap_or_default().contains("confirm_link"),
        "the error should name the failing step: {raw}"
    );
}

/// Without a confirmer the node still extends — transport testing stays
/// possible — but nothing is recorded, which is why such a print cannot be
/// registered.
#[tokio::test]
async fn a_node_without_a_confirmer_extends_but_records_nothing() {
    let port = boot_relay().await;
    let opener = start_node(port).await;
    let extender = start_node(port).await; // confirmer: None

    let partial = partial_for(&opener, [0x23u8; 32]);
    let req = kenter_network::handlers::build_extend_request(&partial, 9)
        .expect("build extend request");
    let raw = proxy_post(
        &http_client(),
        port,
        &extender.address,
        "/kenter/extend",
        &serde_json::to_value(&req).unwrap(),
    )
    .await;
    assert_eq!(raw["status"], "ok", "extend still works: {raw}");
}

fn http_client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Keeps the import used even if the helpers above change shape.
#[allow(dead_code)]
fn _extend_request_type_check(r: &ExtendRequest) -> u32 {
    r.slot_id
}
