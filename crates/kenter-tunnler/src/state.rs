use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::Message;
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};

use crate::auth::challenge::ChallengeStore;
use crate::auth::rate_limit::RateLimiter;
use crate::config::AppConfig;
use crate::roster::RosterCache;
use kenter_crypto::keypair::StellarKeypair;

pub struct AppState {
    pub config: AppConfig,
    pub server_keypair: StellarKeypair,
    pub connections: ConnectionMap,
    pub challenges: ChallengeStore,
    pub rate_limiter: RateLimiter,
    /// If Some, roster membership is enforced during auth.
    pub roster: Option<RosterCache>,
}

impl AppState {
    pub fn new(config: AppConfig, server_keypair: StellarKeypair, roster: Option<RosterCache>) -> Self {
        let challenges = ChallengeStore::new(config.challenge_ttl);
        let rate_limiter = RateLimiter::new(
            config.rate_limit_window,
            config.rate_limit_max_attempts,
            config.rate_limit_block_duration,
        );

        Self {
            config,
            server_keypair,
            connections: ConnectionMap::new(),
            challenges,
            rate_limiter,
            roster,
        }
    }

    /// Construct the public endpoint URL for a given Stellar address.
    pub fn endpoint_url(&self, stellar_address: &str) -> String {
        format!("https://{}.{}", stellar_address, self.config.domain)
    }
}

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

pub struct ConnectionMap {
    inner: DashMap<String, TunnelConnection>,
    /// Hands out a distinct generation per registration, so a handler
    /// can tell its own entry from the one that replaced it.
    next_generation: AtomicU64,
}

pub struct TunnelConnection {
    pub sender: mpsc::Sender<Message>,
    pub stellar_address: String,
    pub services: Vec<String>,
    pub connected_at: Instant,
    pub streams: Arc<StreamManager>,
    /// Which registration this is, for the same key.
    ///
    /// A node reconnecting registers under the same
    /// `{address}:{service}` key and overwrites the old entry. The old
    /// handler then runs its cleanup; removing the key unconditionally
    /// would delete the *new* connection, which is still live, and leave
    /// it unreachable until it reconnects again. Cleanup compares this
    /// first.
    pub generation: u64,
}

impl ConnectionMap {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            next_generation: AtomicU64::new(1),
        }
    }

    /// Register a connection.
    ///
    /// Returns the key, this registration's generation, and its stream
    /// manager. The stream manager comes back from here rather than
    /// from a follow-up `get` because between an insert and that get, a
    /// reconnect can replace the entry -- and the handler would then
    /// hold, and later cancel, somebody else's streams.
    pub fn insert(
        &self,
        stellar_address: &str,
        service: &str,
        sender: mpsc::Sender<Message>,
        services: Vec<String>,
    ) -> (String, u64, Arc<StreamManager>) {
        let key = format!("{stellar_address}:{service}");
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let streams = Arc::new(StreamManager::new());
        self.inner.insert(
            key.clone(),
            TunnelConnection {
                sender,
                stellar_address: stellar_address.to_string(),
                services,
                connected_at: Instant::now(),
                streams: Arc::clone(&streams),
                generation,
            },
        );
        (key, generation, streams)
    }

    /// Remove a connection, but only if it is still the one that
    /// `generation` registered.
    ///
    /// Returns whether anything was removed. A handler whose entry has
    /// already been replaced by a reconnect gets `false` and must leave
    /// the live connection alone.
    pub fn remove_generation(&self, key: &str, generation: u64) -> bool {
        self.inner
            .remove_if(key, |_, c| c.generation == generation)
            .is_some()
    }

    /// Look up a connection by exact key.
    pub fn get(&self, key: &str) -> Option<dashmap::mapref::one::Ref<'_, String, TunnelConnection>> {
        self.inner.get(key)
    }

    /// Find a connection by Stellar address (prefix match on composite key).
    pub fn find_by_address(
        &self,
        stellar_address: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, TunnelConnection>> {
        let prefix = format!("{stellar_address}:");
        for entry in self.inner.iter() {
            if entry.key().starts_with(&prefix) {
                let key = entry.key().clone();
                drop(entry);
                return self.inner.get(&key);
            }
        }
        None
    }

    /// Number of active connections.
    pub fn count(&self) -> usize {
        self.inner.len()
    }

    /// List all connected Stellar addresses (deduped).
    pub fn connected_addresses(&self) -> Vec<String> {
        self.inner
            .iter()
            .map(|e| e.value().stellar_address.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Stream multiplexing (per-connection)
// ---------------------------------------------------------------------------

/// How many requests may be in flight on one tunnel at once.
///
/// `/proxy` is unauthenticated, and before the N4 fix each request
/// allocated a pending entry that only `cancel_all` ever removed -- so
/// a timed-out request leaked one, and pointing a loop at a node that
/// does not answer grew the map until the connection dropped. A cap
/// turns that into a 503 for the caller instead of memory for the
/// operator.
pub const MAX_IN_FLIGHT: usize = 256;

/// Depth of a tunnel's outbound queue.
///
/// Was unbounded, which let a node that stopped reading its socket
/// accumulate messages without limit. Bounded, the queue fills and
/// requests are shed, which is the honest answer: a node that is not
/// keeping up is not going to serve them.
pub const OUTBOUND_QUEUE: usize = 256;

pub struct StreamManager {
    next_id: AtomicU64,
    pub pending: DashMap<u64, oneshot::Sender<serde_json::Value>>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            pending: DashMap::new(),
        }
    }

    /// Open a stream, or `None` if this tunnel already has
    /// [`MAX_IN_FLIGHT`] requests outstanding.
    ///
    /// Hands back a [`StreamGuard`] rather than a bare id, so the entry
    /// cannot outlive the request that opened it. Both callers -- the
    /// HTTP proxy and the node-to-node relay -- had several early
    /// returns that left one behind.
    pub fn create_stream(
        self: &Arc<Self>,
    ) -> Option<(StreamGuard, oneshot::Receiver<serde_json::Value>)> {
        if self.pending.len() >= MAX_IN_FLIGHT {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id, tx);
        let guard = StreamGuard {
            streams: Arc::clone(self),
            stream_id: id,
            resolved: false,
        };
        Some((guard, rx))
    }

    /// How many requests are outstanding on this tunnel.
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Resolve a pending stream with a response.
    pub fn resolve(&self, stream_id: u64, response: serde_json::Value) -> bool {
        if let Some((_, tx)) = self.pending.remove(&stream_id) {
            let _ = tx.send(response);
            true
        } else {
            false
        }
    }

    /// Cancel all pending streams (e.g., on disconnect).
    /// Dropping the oneshot senders causes receivers to get `RecvError`.
    pub fn cancel_all(&self) -> usize {
        let count = self.pending.len();
        self.pending.clear();
        count
    }
}

/// Owns a pending stream for as long as a request is in flight.
///
/// Dropping it returns the id unless the request was answered. `/proxy`
/// is unauthenticated: without this each timeout or send failure would
/// leave an entry that only a tunnel teardown removes, so a loop aimed
/// at a node that does not answer would grow the map until then.
pub struct StreamGuard {
    streams: Arc<StreamManager>,
    stream_id: u64,
    resolved: bool,
}

impl StreamGuard {
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    /// The request was answered, so `resolve` has already taken the
    /// entry out and there is nothing to give back.
    pub fn answered(&mut self) {
        self.resolved = true;
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if !self.resolved {
            self.streams.pending.remove(&self.stream_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Session expiration
// ---------------------------------------------------------------------------

impl ConnectionMap {
    /// Remove connections that have exceeded the session timeout.
    /// Returns the number of expired connections removed.
    pub fn expire_sessions(&self, timeout: Duration) -> usize {
        let mut expired = Vec::new();
        for entry in self.inner.iter() {
            if entry.value().connected_at.elapsed() > timeout {
                expired.push(entry.key().clone());
            }
        }
        let count = expired.len();
        for key in expired {
            if let Some((_, conn)) = self.inner.remove(&key) {
                conn.streams.cancel_all();
                tracing::info!(
                    stellar_address = %conn.stellar_address,
                    "session expired, connection removed"
                );
            }
        }
        count
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn register(map: &ConnectionMap, addr: &str) -> (String, u64, Arc<StreamManager>) {
        let (tx, _rx) = mpsc::channel(OUTBOUND_QUEUE);
        map.insert(addr, "kenter", tx, vec!["kenter".into()])
    }

    /// **N2 regression.** A reconnect must not be de-registered by the
    /// handler it replaced.
    ///
    /// Both register under the same `{address}:{service}` key, so the
    /// second overwrites the first. The first handler then runs its
    /// cleanup, and removing the key unconditionally would take the live
    /// connection off the map: the node would look connected to itself
    /// and be unreachable to everyone else, until it happened to
    /// reconnect again. A flaky network is enough.
    #[test]
    fn a_reconnect_survives_the_old_handlers_cleanup() {
        let map = ConnectionMap::new();

        let (key_old, gen_old, _s1) = register(&map, "GABC");
        let (key_new, gen_new, _s2) = register(&map, "GABC");
        assert_eq!(key_old, key_new, "the same node reuses the key");
        assert_ne!(gen_old, gen_new);

        // The old handler finally notices its socket is gone.
        let removed = map.remove_generation(&key_old, gen_old);

        assert!(!removed, "the old handler must not remove the new entry");
        assert!(
            map.get(&key_new).is_some(),
            "the reconnected node must still be registered"
        );
        assert_eq!(map.count(), 1);
    }

    /// The ordinary case still cleans up, or every disconnect leaks.
    #[test]
    fn a_handler_removes_its_own_registration() {
        let map = ConnectionMap::new();
        let (key, generation, _s) = register(&map, "GABC");

        assert!(map.remove_generation(&key, generation));
        assert!(map.get(&key).is_none());
        assert_eq!(map.count(), 0);
    }

    /// **N4 regression.** A request that is never answered gives its
    /// stream back.
    ///
    /// `/proxy` is unauthenticated and nothing removed the pending
    /// entry on a timeout or a send failure -- only a tunnel teardown
    /// did. Pointing a loop at a node that does not answer therefore
    /// grew the map for as long as the node stayed connected.
    #[test]
    fn an_unanswered_request_does_not_leak_its_stream() {
        let streams = Arc::new(StreamManager::new());

        for _ in 0..1000 {
            let (_guard, _rx) = streams.create_stream().expect("under the cap");
            // guard drops here, as it would on every early return
        }

        assert_eq!(streams.in_flight(), 0, "pending entries outlived their requests");
    }

    /// An answered request leaves nothing behind either: `resolve` took
    /// the entry, and the guard must not then remove a later one that
    /// happens to reuse the id.
    #[test]
    fn an_answered_request_leaves_nothing_behind() {
        let streams = Arc::new(StreamManager::new());
        let (mut guard, rx) = streams.create_stream().unwrap();

        assert!(streams.resolve(guard.id(), serde_json::json!({"status": 200})));
        guard.answered();
        drop(guard);

        assert_eq!(streams.in_flight(), 0);
        assert!(rx.blocking_recv().is_ok(), "the response must still arrive");
    }

    /// **N4 regression.** One tunnel cannot be given unlimited
    /// concurrent work.
    #[test]
    fn a_tunnel_has_an_in_flight_ceiling() {
        let streams = Arc::new(StreamManager::new());

        let mut held = Vec::new();
        for _ in 0..MAX_IN_FLIGHT {
            held.push(streams.create_stream().expect("up to the cap"));
        }
        assert!(
            streams.create_stream().is_none(),
            "past the cap the caller must be refused, not queued"
        );

        // And the ceiling lifts as requests finish.
        held.pop();
        assert!(streams.create_stream().is_some());
    }

    /// Each registration gets its own stream manager, handed back at
    /// insert rather than fetched afterwards -- between an insert and a
    /// follow-up `get`, a reconnect can replace the entry, and the
    /// handler would cancel streams belonging to the connection that
    /// replaced it.
    #[test]
    fn each_registration_owns_its_streams() {
        let map = ConnectionMap::new();
        let (_k1, _g1, s1) = register(&map, "GABC");
        let (_k2, _g2, s2) = register(&map, "GABC");
        assert!(
            !Arc::ptr_eq(&s1, &s2),
            "a reconnect must not share the previous connection's streams"
        );
    }
}
