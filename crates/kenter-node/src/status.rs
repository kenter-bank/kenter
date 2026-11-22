//! What the running daemon reports, and the lock that says one is running.

use std::fs::{File, OpenOptions};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::home::{Home, write_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Stopped,
    Starting,
    /// One or both addresses need XLM before the pair can join.
    AwaitingFunds,
    /// Joining, converting, or reactivating on the roster.
    Joining,
    Online,
    /// The relay connection dropped, or no relay answered; retrying.
    Reconnecting,
    Stopping,
    /// Cannot run without the operator (see `detail`).
    Failed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStatus {
    pub state: State,
    pub pid: u32,
    /// The relay currently bound, or being tried.
    pub relay: Option<String>,
    /// The public endpoint the relay assigned.
    pub endpoint: Option<String>,
    /// Unix seconds the current binding started.
    pub online_since: Option<u64>,
    /// Links this process has confirmed on-chain, i.e. prints served.
    pub links_confirmed: u64,
    /// Positions this process has claimed.
    #[serde(default)]
    pub claims_made: u64,
    /// Of those, the ones the pair was selected for.
    #[serde(default)]
    pub claims_won: u64,
    /// Whether the pair is registered with the mint, which is what makes it
    /// eligible to be drawn. Separate
    /// from roster membership: a pair can be staked and online and still
    /// never be selected until this is true.
    #[serde(default)]
    pub pair_registered: bool,
    /// Why the state is what it is, for amber and red states.
    pub detail: Option<String>,
    /// Unix seconds of the last write.
    pub updated: u64,
}

impl DaemonStatus {
    pub fn read(home: &Home) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(home.status()).ok()?).ok()
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The daemon's status, shared in memory (the tray reads it there) and
/// mirrored to `status.json` on every change (the CLI reads it there).
#[derive(Clone)]
pub struct Reporter {
    home: Home,
    inner: Arc<Mutex<DaemonStatus>>,
}

impl Reporter {
    pub fn new(home: Home) -> Self {
        let status = DaemonStatus { pid: std::process::id(), ..Default::default() };
        Self { home, inner: Arc::new(Mutex::new(status)) }
    }

    pub fn set(&self, f: impl FnOnce(&mut DaemonStatus)) {
        let snapshot = {
            let mut s = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut s);
            s.updated = now();
            s.clone()
        };
        match serde_json::to_vec_pretty(&snapshot) {
            Ok(json) => {
                if let Err(e) = write_atomic(&self.home.status(), &json, false) {
                    tracing::warn!("status file: {e}");
                }
            }
            Err(e) => tracing::warn!("status file: {e}"),
        }
    }

    /// Change state and detail together, the common case.
    pub fn state(&self, state: State, detail: Option<String>) {
        self.set(|s| {
            s.state = state;
            s.detail = detail;
        });
    }

    pub fn snapshot(&self) -> DaemonStatus {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Held by the daemon for its whole life. An OS file lock, so it is
/// released when the process dies however it dies, and a stale lock file
/// on disk means nothing.
#[derive(Debug)]
pub struct DaemonLock {
    _file: File,
}

impl DaemonLock {
    pub fn acquire(home: &Home) -> Result<Self, String> {
        home.ensure()?;
        let path = home.lock();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| format!("opening {}: {e}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(format!(
                "a node is already running from {}",
                home.root().display()
            )),
            Err(std::fs::TryLockError::Error(e)) => {
                Err(format!("locking {}: {e}", path.display()))
            }
        }
    }
}

/// Is a daemon running from this home? Takes the lock for an instant.
pub fn daemon_running(home: &Home) -> bool {
    matches!(DaemonLock::acquire(home), Err(e) if e.contains("already running"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_excludes_a_second_holder_until_dropped() {
        let home = Home::at(crate::testing::tempdir("lock"));
        let held = DaemonLock::acquire(&home).unwrap();
        assert!(DaemonLock::acquire(&home).unwrap_err().contains("already running"));
        assert!(daemon_running(&home));
        drop(held);
        assert!(!daemon_running(&home));
        DaemonLock::acquire(&home).unwrap();
    }

    #[test]
    fn the_reporter_mirrors_to_disk() {
        let home = Home::at(crate::testing::tempdir("status"));
        home.ensure().unwrap();
        let r = Reporter::new(home.clone());
        r.state(State::Online, None);
        r.set(|s| s.links_confirmed += 3);
        let disk = DaemonStatus::read(&home).unwrap();
        assert_eq!(disk.state, State::Online);
        assert_eq!(disk.links_confirmed, 3);
        assert_eq!(disk, r.snapshot());
    }
}
