use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::extract::ws::Message;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use tokio::sync::mpsc;

use crate::state::AppState;

/// HTTP proxy handler: forward requests to connected tunnel clients.
///
/// Route: `POST /proxy/{stellar_address}/{path}`, for a `path` in the
/// config's `proxy_paths` only (`config::PROXY_PATHS`). Anyone on the
/// internet can call this route, so what it forwards is the short list a
/// wallet needs, and everything else is refused here, before a tunnel
/// stream is spent on it.
///
/// This is called by nginx when an external request arrives at
/// `{address}.relay.example.org/{path}`. Nginx extracts the address
/// from the subdomain and proxies to this endpoint.
///
/// Alternative: the address can also come from X-Stellar-Address header
/// (for cases where nginx sets it directly).
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path((stellar_address, path)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: String,
) -> Response {
    let path = format!("/{path}");
    if !state.config.proxy_paths.iter().any(|p| *p == path) {
        return (StatusCode::NOT_FOUND, "not a node endpoint").into_response();
    }

    // Validate Stellar address format
    if !is_valid_stellar_address(&stellar_address) {
        return (StatusCode::BAD_REQUEST, "invalid Stellar address format").into_response();
    }

    // Look up connection
    let conn = match state.connections.find_by_address(&stellar_address) {
        Some(c) => c,
        None => {
            return (StatusCode::BAD_GATEWAY, "no active tunnel for this address").into_response();
        }
    };

    // Create stream for this request
    let Some((mut stream, response_rx)) = conn.streams.create_stream() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "tunnel is at its in-flight request limit",
        )
            .into_response();
    };
    let sender = conn.sender.clone();
    // `stream` returns the id on drop unless the request is answered,
    // so every early return below cleans up without saying so.
    let stream_id = stream.id();
    drop(conn);

    // Build request headers as JSON object
    let mut header_map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(name.to_string(), serde_json::json!(v));
        }
    }

    // Send tunnel_request to the connected client
    let tunnel_req = serde_json::json!({
        "type": "tunnel_request",
        "stream_id": stream_id,
        "request": {
            "method": method.as_str(),
            "path": path,
            "headers": header_map,
            "body": if body.is_empty() { None } else { Some(&body) },
        }
    });

    // `try_send`, not an unbounded push: a node that has stopped
    // reading its socket must shed requests rather than accumulate them.
    match sender.try_send(Message::Text(tunnel_req.to_string())) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "tunnel is not keeping up",
            )
                .into_response();
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            return (StatusCode::BAD_GATEWAY, "tunnel send failed").into_response();
        }
    }

    // Wait for response
    let timeout = Duration::from_secs(state.config.request_timeout);
    let response = match tokio::time::timeout(timeout, response_rx).await {
        Ok(Ok(resp)) => {
            // Answered: `resolve` already took the entry out.
            stream.answered();
            resp
        }
        Ok(Err(_)) => {
            return (StatusCode::BAD_GATEWAY, "tunnel client disconnected").into_response();
        }
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "tunnel request timeout").into_response();
        }
    };

    // Parse tunnel response
    let status_code = response
        .get("status_code")
        .or_else(|| response.get("status"))
        .and_then(|v| v.as_u64())
        .unwrap_or(200) as u16;

    let resp_body = response
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);

    // Build response with filtered headers
    let mut builder = Response::builder().status(status);

    if let Some(headers) = response.get("headers").and_then(|v| v.as_object()) {
        for (name, value) in headers {
            if is_safe_response_header(name) {
                if let Some(v) = value.as_str() {
                    builder = builder.header(name, v);
                }
            }
        }
    }

    builder.body(Body::from(resp_body)).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "response build failed").into_response()
    })
}

fn is_valid_stellar_address(addr: &str) -> bool {
    addr.len() == 56 && addr.starts_with('G') && addr.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Whitelist of safe response headers to pass through the proxy.
fn is_safe_response_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "content-type"
            | "content-length"
            | "cache-control"
            | "etag"
            | "last-modified"
            | "expires"
            | "access-control-allow-origin"
            | "access-control-allow-methods"
            | "access-control-allow-headers"
            | "location"
            | "x-request-id"
    )
}
