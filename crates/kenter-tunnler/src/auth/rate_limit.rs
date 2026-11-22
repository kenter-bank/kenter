use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Soft cap on tracked addresses before a sweep is forced.
///
/// The map is keyed by client IP, which before the N1 fix was always the
/// reverse proxy -- one key, no growth, and no reason to think about
/// this. Keying on the real client means an attacker chooses the keys,
/// so the map now has to be told when to forget.
const SWEEP_AT: usize = 10_000;

struct RateLimitEntry {
    attempts: Vec<Instant>,
    blocked_until: Option<Instant>,
}

impl RateLimitEntry {
    /// Is this entry still saying anything? An entry with no live
    /// attempts and no running block is just memory.
    fn live(&self, now: Instant, window: Duration) -> bool {
        if let Some(until) = self.blocked_until {
            if now < until {
                return true;
            }
        }
        self.attempts
            .iter()
            .any(|t| now.duration_since(*t) < window)
    }
}

/// Per-client-IP limiter for the authentication handshake.
///
/// Two things about it are deliberate:
///
/// - **It counts failures, not connections.** `check` is a read. An
///   attempt is recorded by [`RateLimiter::record_failure`], which the
///   handshake calls when it ends without authenticating. Counting
///   every `check` would make a node's ordinary, successful connections
///   eat the same budget as an attacker's, so the limiter would throttle
///   the people it exists to protect.
/// - **The IP must be the client's.** See `client_ip` in `server.rs`.
///   Keyed on the TCP peer behind a reverse proxy, every client would
///   share one bucket: ten connections from anyone would block every
///   printing node on the relay for `block_duration`, repeatable
///   indefinitely.
pub struct RateLimiter {
    entries: DashMap<IpAddr, RateLimitEntry>,
    window: Duration,
    max_attempts: u32,
    block_duration: Duration,
    /// When the map was last swept. A `Mutex` rather than an atomic
    /// because it holds an `Instant`; it is touched once per sweep
    /// interval, so it is never contended.
    last_sweep: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(window_secs: u64, max_attempts: u32, block_duration_secs: u64) -> Self {
        Self {
            entries: DashMap::new(),
            window: Duration::from_secs(window_secs),
            max_attempts,
            block_duration: Duration::from_secs(block_duration_secs),
            last_sweep: Mutex::new(Instant::now()),
        }
    }

    /// May this address attempt to authenticate?
    ///
    /// A read. It records nothing, so a client that connects and
    /// authenticates costs it nothing.
    pub fn check(&self, ip: IpAddr) -> Result<(), String> {
        let now = Instant::now();
        let Some(entry) = self.entries.get(&ip) else {
            return Ok(());
        };

        if let Some(until) = entry.blocked_until {
            if now < until {
                return Err("IP temporarily blocked due to excessive auth attempts".into());
            }
        }

        let recent = entry
            .attempts
            .iter()
            .filter(|t| now.duration_since(**t) < self.window)
            .count();
        if recent >= self.max_attempts as usize {
            return Err("rate limit exceeded".into());
        }
        Ok(())
    }

    /// Record a handshake that ended without authenticating, and block
    /// the address if it has now had too many.
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        {
            let mut entry = self.entries.entry(ip).or_insert_with(|| RateLimitEntry {
                attempts: Vec::new(),
                blocked_until: None,
            });

            // A block that has run out resets the slate, so an address is
            // not blocked forever by attempts nobody can age out.
            if let Some(until) = entry.blocked_until {
                if now >= until {
                    entry.blocked_until = None;
                    entry.attempts.clear();
                }
            }

            entry.attempts.retain(|t| now.duration_since(*t) < self.window);
            entry.attempts.push(now);

            if entry.attempts.len() >= self.max_attempts as usize {
                entry.blocked_until = Some(now + self.block_duration);
            }
        }

        self.maybe_sweep(now);
    }

    /// Forget an address entirely. Called on successful authentication,
    /// so a node that mistypes and then gets it right starts clean.
    pub fn reset(&self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    /// Drop entries that have nothing left to say.
    ///
    /// Bounded by "addresses seen within the window, plus addresses
    /// currently blocked", which is the most the limiter needs to
    /// remember. Runs at most once per window, or immediately once the
    /// map is larger than [`SWEEP_AT`].
    fn maybe_sweep(&self, now: Instant) {
        let due = {
            let Ok(mut last) = self.last_sweep.lock() else {
                return; // poisoned: skip the sweep rather than panic in a handshake
            };
            let due = now.duration_since(*last) >= self.window
                || self.entries.len() > SWEEP_AT;
            if due {
                *last = now;
            }
            due
        };
        if due {
            let window = self.window;
            self.entries.retain(|_, e| e.live(now, window));
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    /// A client that authenticates costs the limiter nothing.
    ///
    /// If `check` recorded on every call, a node reconnecting normally
    /// would spend the same budget as an attacker failing, and the
    /// limiter would throttle the traffic it exists to protect.
    #[test]
    fn a_successful_handshake_spends_no_budget() {
        let rl = RateLimiter::new(60, 3, 300);
        for _ in 0..100 {
            rl.check(ip(1)).expect("a read must not accumulate");
        }
    }

    /// Failures do accumulate, and the block follows.
    #[test]
    fn failures_accumulate_and_block() {
        let rl = RateLimiter::new(60, 3, 300);
        rl.record_failure(ip(1));
        rl.record_failure(ip(1));
        assert!(rl.check(ip(1)).is_ok(), "two of three is still allowed");
        rl.record_failure(ip(1));
        assert!(rl.check(ip(1)).is_err(), "the third trips it");
    }

    /// **N1 regression.** One address cannot block another.
    ///
    /// This is the whole finding: behind a reverse proxy every client
    /// shared one key, so blocking that key took the relay down for
    /// everyone. The separation is only real if the key is the client's.
    #[test]
    fn blocking_one_address_leaves_others_alone() {
        let rl = RateLimiter::new(60, 3, 300);
        for _ in 0..5 {
            rl.record_failure(ip(1));
        }
        assert!(rl.check(ip(1)).is_err());
        assert!(rl.check(ip(2)).is_ok(), "a neighbour must be unaffected");
    }

    /// A successful authentication clears the slate.
    #[test]
    fn reset_forgets_an_address() {
        let rl = RateLimiter::new(60, 3, 300);
        rl.record_failure(ip(1));
        rl.record_failure(ip(1));
        rl.reset(ip(1));
        assert!(rl.check(ip(1)).is_ok());
        assert_eq!(rl.tracked(), 0);
    }

    /// The map forgets addresses that have gone quiet, so an attacker
    /// cycling source addresses cannot grow it without bound.
    #[test]
    fn the_map_sweeps_entries_that_have_aged_out() {
        // Zero-length window: every attempt is already outside it.
        let rl = RateLimiter::new(0, 3, 0);
        for n in 0..50u8 {
            rl.record_failure(ip(n));
        }
        assert!(
            rl.tracked() <= 1,
            "expired entries should not survive a sweep, found {}",
            rl.tracked()
        );
    }
}
