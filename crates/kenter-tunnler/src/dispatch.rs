use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::state::{AppState, StreamManager};

/// Dispatch an incoming JSON message from a connected client.
///
/// Message types:
/// - `pong`: keepalive response (ignored)
/// - `bind`: service binding request
/// - `tunnel_response`: response to a forwarded request (resolves pending stream)
/// - `tunnel_request` (with `target`): relay to another connected node
pub async fn dispatch_client_message(
    text: &str,
    stellar_address: &str,
    _connection_key: &str,
    streams: &Arc<StreamManager>,
    state: &Arc<AppState>,
) {
    let data: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            warn!(%stellar_address, "invalid JSON from client: {e}");
            return;
        }
    };

    let msg_type = data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    match msg_type {
        "pong" => {
            debug!(%stellar_address, "pong received");
        }

        "bind" => {
            debug!(%stellar_address, service = ?data["service"], "bind request (acknowledged)");
            // Binding is already handled during connection registration.
            // Send bind_ok for protocol compatibility.
            if let Some(conn) = state.connections.find_by_address(stellar_address) {
                let bind_ok = serde_json::json!({
                    "type": "bind_ok",
                    "service": data["service"],
                    "local_port": data["local_port"],
                });
                let _ = conn.sender.try_send(Message::Text(bind_ok.to_string()));
            }
        }

        "tunnel_response" => {
            // Client is responding to a forwarded request (from proxy or relay).
            // Route the response to the pending stream.
            let stream_id = data
                .get("stream_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let response = data.get("response").cloned().unwrap_or_default();

            if !streams.resolve(stream_id, response) {
                debug!(%stellar_address, %stream_id, "no pending stream for response (timeout or duplicate)");
            }
        }

        "tunnel_request" => {
            // Node-to-node relay: client wants to send a request to another node.
            let source_stream_id = data
                .get("stream_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let target_address = match data.get("target").and_then(|v| v.as_str()) {
                Some(t) => t.to_string(),
                None => {
                    warn!(%stellar_address, "tunnel_request missing target");
                    return;
                }
            };
            let request_body = data.get("request").cloned().unwrap_or_default();

            let state = Arc::clone(state);
            let source_address = stellar_address.to_string();

            // Spawn relay task so we don't block the message loop
            tokio::spawn(async move {
                relay_request(
                    &state,
                    &source_address,
                    source_stream_id,
                    &target_address,
                    request_body,
                )
                .await;
            });
        }

        other => {
            debug!(%stellar_address, "unhandled message type: {other}");
        }
    }
}

/// Relay a tunnel_request from source node to target node and return the response.
async fn relay_request(
    state: &AppState,
    source_address: &str,
    source_stream_id: u64,
    target_address: &str,
    request_body: serde_json::Value,
) {
    // Look up target connection
    let target_conn = match state.connections.find_by_address(target_address) {
        Some(conn) => conn,
        None => {
            // Send error response back to source
            send_relay_error(state, source_address, source_stream_id, "target not connected").await;
            return;
        }
    };

    // Create a stream on the target connection for the response.
    // `target_stream` gives the id back on drop unless the relay is
    // answered, so the failure paths below clean up on their own rather
    // than leaving an entry until the target's tunnel drops.
    let Some((mut target_stream, response_rx)) = target_conn.streams.create_stream() else {
        drop(target_conn);
        send_relay_error(state, source_address, source_stream_id, "target is busy").await;
        return;
    };
    let target_stream_id = target_stream.id();
    let target_sender = target_conn.sender.clone();
    drop(target_conn); // release DashMap ref before awaiting

    // Forward the request to the target
    let forward_msg = serde_json::json!({
        "type": "tunnel_request",
        "stream_id": target_stream_id,
        "request": request_body,
    });

    // `try_send`: a target that has stopped reading sheds the request
    // rather than growing its queue without limit.
    if let Err(e) = target_sender.try_send(Message::Text(forward_msg.to_string())) {
        let detail = match e {
            mpsc::error::TrySendError::Full(_) => "target is not keeping up",
            mpsc::error::TrySendError::Closed(_) => "target send failed",
        };
        send_relay_error(state, source_address, source_stream_id, detail).await;
        return;
    }

    // Wait for response with timeout
    let timeout = Duration::from_secs(state.config.request_timeout);
    let response = match tokio::time::timeout(timeout, response_rx).await {
        Ok(Ok(resp)) => {
            target_stream.answered();
            resp
        }
        Ok(Err(_)) => {
            // oneshot dropped — target disconnected
            send_relay_error(state, source_address, source_stream_id, "target disconnected")
                .await;
            return;
        }
        Err(_) => {
            send_relay_error(state, source_address, source_stream_id, "relay timeout").await;
            return;
        }
    };

    // Send response back to source
    if let Some(source_conn) = state.connections.find_by_address(source_address) {
        let response_msg = serde_json::json!({
            "type": "tunnel_response",
            "stream_id": source_stream_id,
            "response": response,
        });
        let _ = source_conn.sender.try_send(Message::Text(response_msg.to_string()));
    }
}

async fn send_relay_error(
    state: &AppState,
    source_address: &str,
    source_stream_id: u64,
    error: &str,
) {
    if let Some(source_conn) = state.connections.find_by_address(source_address) {
        let error_msg = serde_json::json!({
            "type": "tunnel_response",
            "stream_id": source_stream_id,
            "response": {
                "status": 502,
                "error": error,
            },
        });
        let _ = source_conn.sender.try_send(Message::Text(error_msg.to_string()));
    }
}
