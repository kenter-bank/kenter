//! A node does not serve `/kenter/shard` unless it is built to.
//!
//! Notes are redeemed by chain, which needs no node; shards serve only
//! redemption by key, which no Kenter client uses. The handler the node
//! daemon builds (`KenterHandler::new`) must refuse the endpoint, and
//! refuse it before doing any work for the request.

use std::collections::HashMap;
use std::sync::Arc;

use kenter_crypto::keypair::StellarKeypair;
use kenter_network::handlers::{ExtendNodeContext, PairNodeContext, ShardRateLimiter};
use kenter_network::tunnel::{IncomingRequest, KenterHandler, RequestHandler, SHARDS_NOT_SERVED};
use tokio::sync::Mutex;

fn handler() -> KenterHandler {
    let own = StellarKeypair::random();
    let partner = StellarKeypair::random();
    KenterHandler::new(
        Arc::new(PairNodeContext { own_keypair: own.clone(), rate_limiter: ShardRateLimiter::new() }),
        Arc::new(Mutex::new(Some(ExtendNodeContext { own_keypair: own, partner_keypair: partner }))),
        None,
    )
}

fn request(path: &str, body: Option<&str>) -> IncomingRequest {
    IncomingRequest {
        stream_id: 1,
        method: "POST".into(),
        path: path.into(),
        headers: HashMap::new(),
        body: body.map(str::to_string),
    }
}

/// The payload inside the relay's HTTP envelope.
fn payload(env: &serde_json::Value) -> serde_json::Value {
    serde_json::from_str(env["body"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn a_default_node_refuses_shard_requests() {
    let h = handler();
    assert!(!h.serve_shards, "shard service must be off by default");
    // Any body, valid or not, gets the same refusal: nothing is parsed.
    for body in [None, Some("{}"), Some("not json")] {
        let env = h.handle_request(request("/kenter/shard", body)).await;
        assert_eq!(env["status_code"], 404);
        let p = payload(&env);
        assert_eq!(p["status"], "error");
        assert_eq!(p["error"], SHARDS_NOT_SERVED);
    }
}

#[tokio::test]
async fn a_default_node_still_answers_health() {
    let env = handler().handle_request(request("/kenter/health", None)).await;
    assert_eq!(env["status_code"], 200);
    assert_eq!(payload(&env)["status"], "ok");
}

#[tokio::test]
async fn shard_service_can_be_turned_on_for_testing() {
    let h = handler().with_shard_service();
    // Reaches the shard handler, which then wants a body.
    let env = h.handle_request(request("/kenter/shard", None)).await;
    assert_eq!(env["status_code"], 200);
    assert_eq!(payload(&env)["error"], "missing request body");
}
