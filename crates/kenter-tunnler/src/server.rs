use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::proxy::proxy_handler;
use crate::state::AppState;
use crate::ws::handle_connection;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/connect", get(ws_upgrade_handler))
        .route("/health", get(health_handler))
        .route(
            // axum 0.7 path syntax: `:name` for a param, `*name` for catch-all.
            "/proxy/:stellar_address/*path",
            get(proxy_handler)
                .post(proxy_handler)
                .put(proxy_handler)
                .delete(proxy_handler),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let ip = client_ip(addr, &headers, &state.config.trusted_proxies);
    ws.on_upgrade(move |socket| handle_connection(socket, ip, state))
}

/// Who is actually connecting.
///
/// The TCP peer is the reverse proxy whenever there is one, and the
/// shipped nginx is one (`config/nginx-kenter-tunnler.conf`). Keying
/// anything per-client on the peer would put every client in one
/// bucket: the auth rate limiter would block that bucket after ten
/// connections from anyone at all, taking every printing node off the
/// relay for the block duration, and the challenge store's IP binding
/// would mean nothing because every challenge was bound to the same
/// address.
///
/// `X-Real-IP` is read **only** from a peer in `trusted_proxies`. A
/// client can set any header it likes, so believing it unconditionally
/// would let anyone claim any address -- evading their own block, or
/// planting one on somebody else. That is a worse failure than the
/// shared bucket, so the untrusted case falls back to the peer, which
/// is at least something the client cannot forge.
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
    if !trusted.contains(&peer.ip()) {
        return peer.ip();
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| peer.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(s: &str) -> SocketAddr {
        format!("{s}:443").parse().unwrap()
    }

    fn with_real_ip(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", v.parse().unwrap());
        h
    }

    /// **N1 regression.** Behind the proxy, the client is the client.
    #[test]
    fn a_trusted_proxy_speaks_for_the_client() {
        let trusted = [IpAddr::from([127, 0, 0, 1])];
        let got = client_ip(peer("127.0.0.1"), &with_real_ip("198.51.100.7"), &trusted);
        assert_eq!(got, IpAddr::from([198, 51, 100, 7]));
    }

    /// **N1 regression, the other half.** An untrusted peer does not get
    /// to name itself. Believing the header from anyone would turn a
    /// shared-bucket denial of service into a per-victim one.
    #[test]
    fn an_untrusted_peer_cannot_claim_an_address() {
        let trusted = [IpAddr::from([127, 0, 0, 1])];
        let got = client_ip(peer("203.0.113.9"), &with_real_ip("198.51.100.7"), &trusted);
        assert_eq!(got, IpAddr::from([203, 0, 113, 9]), "the header must be ignored");
    }

    /// A trusted proxy that sends nothing, or nonsense, falls back to
    /// the peer rather than to a default everyone shares.
    #[test]
    fn a_missing_or_unparseable_header_falls_back_to_the_peer() {
        let trusted = [IpAddr::from([127, 0, 0, 1])];
        let p = peer("127.0.0.1");
        assert_eq!(client_ip(p, &HeaderMap::new(), &trusted), p.ip());
        assert_eq!(client_ip(p, &with_real_ip("nonsense"), &trusted), p.ip());
    }

    /// With nothing trusted -- the tunnler exposed directly -- the peer
    /// is the only thing worth believing.
    #[test]
    fn trusting_nobody_always_uses_the_peer() {
        let got = client_ip(peer("203.0.113.9"), &with_real_ip("127.0.0.1"), &[]);
        assert_eq!(got, IpAddr::from([203, 0, 113, 9]));
    }
}

async fn health_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let connections = state.connections.count();
    serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "connections": connections,
        "roster_gating": state.roster.is_some(),
    })
    .to_string()
}
