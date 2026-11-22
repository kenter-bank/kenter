use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::auth::jwt::verify_client_jwt;
use crate::dispatch::dispatch_client_message;
use crate::state::AppState;

/// Records a failed authentication unless it is disarmed.
///
/// The handshake has a dozen early returns and will grow more. Counting
/// attempts at each one is a rule somebody eventually forgets, and the
/// cost of forgetting is a free attempt -- so "did not authenticate" is
/// the default here, and only reaching the end disarms it.
///
/// A connection opened and dropped before the handshake finishes counts
/// too. That is deliberate: it is an attempt that did not authenticate,
/// and leaving it free is the hole an attacker walks through.
struct AuthAttempt<'a> {
    limiter: &'a crate::auth::rate_limit::RateLimiter,
    ip: IpAddr,
    authenticated: bool,
}

impl AuthAttempt<'_> {
    fn succeeded(&mut self) {
        self.authenticated = true;
    }
}

impl Drop for AuthAttempt<'_> {
    fn drop(&mut self) {
        if !self.authenticated {
            self.limiter.record_failure(self.ip);
        }
    }
}

/// Handle a new WebSocket connection through the full lifecycle:
/// auth handshake → message loop → cleanup.
///
/// `client_ip` is the *client's* address, resolved by
/// `server::client_ip` — not the TCP peer, which behind a reverse proxy
/// is the proxy for everyone.
pub async fn handle_connection(socket: WebSocket, client_ip: IpAddr, state: Arc<AppState>) {
    // A read: an attempt is recorded by the guard below, on the way out,
    // and only if authentication did not happen.
    if let Err(e) = state.rate_limiter.check(client_ip) {
        warn!(%client_ip, "rate limited: {e}");
        let _ = send_and_close(socket, serde_json::json!({
            "type": "auth_failed",
            "error": e,
        }))
        .await;
        return;
    }

    let mut attempt = AuthAttempt {
        limiter: &state.rate_limiter,
        ip: client_ip,
        authenticated: false,
    };

    let (mut sender, mut receiver) = socket.split();

    // --- Step 1: Send auth_challenge ---
    let (challenge_id, challenge_value) = state.challenges.generate(client_ip);
    let server_address = state.server_keypair.stellar_address();

    let challenge_msg = serde_json::json!({
        "type": "auth_challenge",
        "challenge_id": challenge_id,
        "challenge": challenge_value,
        "server_address": server_address,
    });

    if sender
        .send(Message::Text(challenge_msg.to_string()))
        .await
        .is_err()
    {
        return;
    }

    debug!(%client_ip, %challenge_id, "sent auth_challenge");

    // --- Step 2: Wait for auth_response ---
    let auth_timeout = Duration::from_secs(15);
    let auth_msg = match tokio::time::timeout(auth_timeout, receiver.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) => return,
        Ok(Some(Err(e))) => {
            debug!(%client_ip, "ws error during auth: {e}");
            return;
        }
        Ok(Some(Ok(_))) => {
            debug!(%client_ip, "unexpected non-text message during auth");
            return;
        }
        Err(_) => {
            debug!(%client_ip, "auth timeout");
            let _ = sender
                .send(Message::Text(
                    serde_json::json!({
                        "type": "auth_failed",
                        "error": "auth timeout"
                    })
                    .to_string(),
                ))
                .await;
            return;
        }
    };

    let auth_data: serde_json::Value = match serde_json::from_str(&auth_msg) {
        Ok(v) => v,
        Err(e) => {
            send_auth_failed(&mut sender, &format!("invalid JSON: {e}")).await;
            return;
        }
    };

    if auth_data.get("type").and_then(|v| v.as_str()) != Some("auth_response") {
        send_auth_failed(&mut sender, "expected auth_response").await;
        return;
    }

    let jwt = match auth_data["jwt"].as_str() {
        Some(j) => j,
        None => {
            send_auth_failed(&mut sender, "missing jwt").await;
            return;
        }
    };

    let resp_challenge_id = match auth_data["challenge_id"].as_str() {
        Some(c) => c,
        None => {
            send_auth_failed(&mut sender, "missing challenge_id").await;
            return;
        }
    };

    // --- Step 3: Verify challenge binding ---
    // Look up the challenge value for this challenge_id
    // (verify_client_jwt will check the challenge claim matches)
    if resp_challenge_id != challenge_id {
        send_auth_failed(&mut sender, "challenge_id mismatch").await;
        return;
    }

    // --- Step 4: Verify JWT ---
    let claims = match verify_client_jwt(
        jwt,
        &server_address,
        &challenge_value,
        state.config.jwt_clock_skew,
    ) {
        Ok(c) => c,
        Err(e) => {
            send_auth_failed(&mut sender, &e).await;
            // Mark challenge as consumed even on failure
            let _ = state
                .challenges
                .verify(&challenge_id, &challenge_value, client_ip);
            return;
        }
    };

    // Consume the challenge (single-use)
    if let Err(e) = state
        .challenges
        .verify(&challenge_id, &challenge_value, client_ip)
    {
        send_auth_failed(&mut sender, &e).await;
        return;
    }

    // --- Step 4b: Roster membership check ---
    if let Some(ref roster) = state.roster {
        match roster.is_member(&claims.stellar_address).await {
            Ok(true) => {
                debug!(address = %claims.stellar_address, "roster check passed");
            }
            Ok(false) => {
                send_auth_failed(&mut sender, "not on roster").await;
                return;
            }
            Err(e) => {
                warn!(address = %claims.stellar_address, "roster check failed: {e}");
                send_auth_failed(&mut sender, "roster check unavailable").await;
                return;
            }
        }
    }

    // Authenticated: disarm the guard, then forget the address entirely
    // so earlier fumbles do not count against a node that got there.
    attempt.succeeded();
    drop(attempt);
    state.rate_limiter.reset(client_ip);

    let stellar_address = claims.stellar_address.clone();
    let services = claims.services.clone();
    let primary_service = services.first().cloned().unwrap_or_else(|| "kenter".into());

    info!(%stellar_address, ?services, %client_ip, "authenticated");

    // --- Step 5: Send auth_ok ---
    let endpoint = state.endpoint_url(&stellar_address);
    let auth_ok = serde_json::json!({
        "type": "auth_ok",
        "endpoint": endpoint,
        "server_address": server_address,
        "services": services,
        "encryption_available": false,
    });

    if sender.send(Message::Text(auth_ok.to_string())).await.is_err() {
        return;
    }

    // --- Step 6: Register connection ---
    // Bounded: an unbounded queue would let a node that stopped reading
    // its socket accumulate messages without limit. Senders use
    // `try_send` and shed when it is full, which is the honest answer --
    // a node that is not keeping up is not going to serve the request.
    let (msg_tx, mut msg_rx) =
        mpsc::channel::<Message>(crate::state::OUTBOUND_QUEUE);
    let (connection_key, generation, streams) =
        state
            .connections
            .insert(&stellar_address, &primary_service, msg_tx, services.clone());

    info!(%stellar_address, %connection_key, "connection registered");

    // --- Step 7: Message loop ---
    let ping_interval = Duration::from_secs(30);
    let mut ping_timer = tokio::time::interval(ping_interval);
    ping_timer.tick().await; // consume first immediate tick

    // Session timeout: absolute deadline for this connection
    let session_deadline = tokio::time::Instant::now()
        + Duration::from_secs(state.config.session_timeout);

    loop {
        tokio::select! {
            // Incoming WebSocket messages from client
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        dispatch_client_message(
                            &text,
                            &stellar_address,
                            &connection_key,
                            &streams,
                            &state,
                        ).await;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = sender.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!(%stellar_address, "client disconnected");
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(%stellar_address, "ws error: {e}");
                        break;
                    }
                    _ => {}
                }
            }

            // Outbound messages (from proxy or relay)
            msg = msg_rx.recv() => {
                match msg {
                    Some(out_msg) => {
                        if sender.send(out_msg).await.is_err() {
                            warn!(%stellar_address, "failed to send outbound message");
                            break;
                        }
                    }
                    None => break,
                }
            }

            // Keepalive ping
            _ = ping_timer.tick() => {
                let ping = serde_json::json!({"type": "ping"});
                if sender.send(Message::Text(ping.to_string())).await.is_err() {
                    warn!(%stellar_address, "keepalive ping failed");
                    break;
                }
            }

            // Session timeout
            _ = tokio::time::sleep_until(session_deadline) => {
                info!(%stellar_address, "session timeout reached");
                let msg = serde_json::json!({
                    "type": "session_expired",
                    "error": "session timeout",
                });
                let _ = sender.send(Message::Text(msg.to_string())).await;
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
        }
    }

    // --- Cleanup ---
    // Cancel any pending streams (proxy/relay requests awaiting responses)
    let cancelled = streams.cancel_all();
    if cancelled > 0 {
        debug!(%stellar_address, cancelled, "cancelled pending streams");
    }
    // Only if this is still our registration. A reconnect under the same
    // key replaces the entry, and removing it here would take the live
    // connection off the map -- unreachable until it reconnects again,
    // which it has no reason to do.
    if state.connections.remove_generation(&connection_key, generation) {
        info!(%stellar_address, "connection cleaned up");
    } else {
        info!(%stellar_address, %connection_key, "superseded by a reconnect; leaving it registered");
    }
}

async fn send_auth_failed(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    error: &str,
) {
    let msg = serde_json::json!({
        "type": "auth_failed",
        "error": error,
    });
    let _ = sender.send(Message::Text(msg.to_string())).await;
}

async fn send_and_close(socket: WebSocket, msg: serde_json::Value) -> Result<(), ()> {
    let (mut sender, _) = socket.split();
    let _ = sender
        .send(Message::Text(msg.to_string()))
        .await;
    let _ = sender.send(Message::Close(None)).await;
    Ok(())
}
