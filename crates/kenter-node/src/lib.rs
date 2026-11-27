//! `kenter_node`: a Kenter pair node as a library, so the CLI, the
//! headless service and the tray all run the same code.
//!
//! - [`home`]: where an install keeps its files.
//! - [`config`]: `node.json` (name, relays, terms; no secrets).
//! - [`keys`]: the pair's two keys, from one node-only recovery phrase.
//! - [`chain`]: the node's own on-chain calls and reads.
//! - [`daemon`]: prepare, serve with relay fallback, deregister on stop.
//! - [`status`]: what the daemon reports, and the lock that says it runs.
//!
//! **One install is one pair** (`crates/kenter-node/ARCHITECTURE.md`): the
//! pair, not the node, is the unit of trust, and a daemon hosting several
//! would look like several parties while being one.

pub mod chain;
pub mod config;
pub mod daemon;
pub mod home;
pub mod keys;
pub mod select;
pub mod slot_cache;
pub mod status;
/// The desktop tray and settings window. Windows and
/// macOS; a Linux desktop tray needs a GTK loop and is not built yet.
#[cfg(all(feature = "tray", any(windows, target_os = "macos")))]
pub mod tray;

#[cfg(test)]
pub(crate) mod testing {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh, empty directory under the target dir's temp area.
    pub fn tempdir(tag: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kenter-node-test-{}-{}-{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
