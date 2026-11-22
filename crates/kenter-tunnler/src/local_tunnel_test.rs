//! End-to-end local tunnel test.
//!
//! Boots the tunnler server in-process (roster gating off), connects a real
//! `kenter_network` `TunnelClient` over **plaintext `ws://`** (the dev-mode
//! `TunnelConfig { secure: false }`), and drives a request through the full path:
//! external HTTP → proxy → `tunnel_request` → client handler → `tunnel_response`
//! → proxy → HTTP response.
//!
//! Guards two behaviours of the relay path:
//!   - the proxy forwards the **real HTTP method** (not a hard-coded `GET`), and
//!   - the client's outbound response correlation (stream-id demultiplexer).
//!
//! Everything runs in-process, so this needs no deployed relay.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use kenter_crypto::keypair::StellarKeypair;
use kenter_network::tunnel::{IncomingRequest, RequestHandler, TunnelClient, TunnelConfig};

use crate::config::AppConfig;
use crate::server::build_router;
use crate::state::AppState;

/// A node-side handler that echoes the request method + path back in the body,
/// so the test can assert the method survived the proxy hop.
struct EchoHandler;

impl RequestHandler for EchoHandler {
    fn handle_request(
        &self,
        req: IncomingRequest,
    ) -> Pin<Box<dyn Future<Output = Value> + Send + '_>> {
        Box::pin(async move {
            let body = serde_json::json!({ "method": req.method, "path": req.path }).to_string();
            serde_json::json!({
                "status_code": 200,
                "headers": { "content-type": "application/json" },
                "body": body,
            })
        })
    }
}

fn test_config(server_secret: String) -> AppConfig {
    AppConfig {
        host: "127.0.0.1".into(),
        port: 0, // unused: we bind the listener ourselves
        domain: "local.test".into(),
        server_secret,
        jwt_clock_skew: 60,
        session_timeout: 86_400,
        challenge_ttl: 30,
        rate_limit_window: 60,
        rate_limit_max_attempts: 10_000, // don't rate-limit the test
        rate_limit_block_duration: 300,
        request_timeout: 30,
        log_level: "warn".into(),
        roster_contract_id: None, // gating OFF → any key may connect, no Soroban call
        soroban_rpc_url: "http://unused.invalid".into(),
        soroban_network_passphrase: "Test SDF Network ; September 2015".into(),
        roster_cache_ttl: 300,
        // The tests connect over loopback with no proxy in front, so
        // nothing needs to be believed about who the client is.
        trusted_proxies: Vec::new(),
    }
}

/// Proxy the given method until the tunnel client is registered (the server
/// inserts the connection just after `auth_ok`, so the first attempt can race).
/// Returns the parsed JSON body once a 200 comes back.
async fn proxy_json(
    http: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let resp = http
            .request(method.clone(), url)
            .send()
            .await
            .expect("proxy request send");
        if resp.status().as_u16() == 200 {
            let text = resp.text().await.expect("proxy body");
            return serde_json::from_str(&text).expect("body is JSON");
        }
        // 502 while the client isn't registered yet — retry briefly.
        assert!(
            std::time::Instant::now() < deadline,
            "tunnel client never became reachable via the proxy (last status {})",
            resp.status()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn local_tunnel_roundtrip_and_method_passthrough() {
    // --- Boot the server in-process ---
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

    // --- Connect a real client over plaintext ws:// (the dev fix) ---
    let client_kp = StellarKeypair::random();
    let client_addr = client_kp.stellar_address();
    let client_cfg = TunnelConfig {
        host: format!("127.0.0.1:{port}"),
        services: vec!["kenter".into()],
        local_port: 9090,
        jwt_expires_secs: 3600,
        auth_timeout_secs: 15,
        request_timeout_secs: 30,
        secure: false, // ← ws:// / http://, not wss://
    };

    let (endpoint, _session) = TunnelClient::new(client_kp, client_cfg)
        .run(Arc::new(EchoHandler))
        .await
        .expect("client connect → auth → bind");
    assert!(
        endpoint.endpoint_url.contains(&client_addr),
        "endpoint {} should name the client address",
        endpoint.endpoint_url
    );

    // --- Drive requests through the tunnel ---
    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/proxy/{client_addr}/kenter/ping");

    // GET round-trips end to end.
    let get_body = proxy_json(&http, reqwest::Method::GET, &url).await;
    assert_eq!(get_body["method"], "GET");
    assert_eq!(get_body["path"], "/kenter/ping");

    // POST must arrive as POST at the node — the proxy-method fix. (Before it,
    // every verb was relayed as GET.)
    let post_body = proxy_json(&http, reqwest::Method::POST, &url).await;
    assert_eq!(
        post_body["method"], "POST",
        "proxy must forward the real HTTP method, not hard-coded GET"
    );

    // DELETE too, for good measure.
    let del_body = proxy_json(&http, reqwest::Method::DELETE, &url).await;
    assert_eq!(del_body["method"], "DELETE");
}
