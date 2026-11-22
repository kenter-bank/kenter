//! Where an installed node keeps its files.
//!
//! One directory per network, so a testnet node and a mainnet node on the
//! same machine cannot share keys or config by accident:
//!
//! | OS | Default |
//! |---|---|
//! | Windows | `%LOCALAPPDATA%\kenter-node\<network>` (local, never roamed) |
//! | elsewhere | `$XDG_DATA_HOME/kenter-node/<network>`, else `~/.local/share/kenter-node/<network>` |
//!
//! `KENTER_NODE_HOME` replaces the whole path (used as given, no network
//! suffix), for tests and for operators who keep several installs.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Home {
    root: PathBuf,
}

impl Home {
    /// `KENTER_NODE_HOME`, else the platform default for this build's
    /// network.
    pub fn locate() -> Result<Self, String> {
        if let Some(v) = std::env::var_os("KENTER_NODE_HOME").filter(|v| !v.is_empty()) {
            return Ok(Self::at(PathBuf::from(v)));
        }
        let network = kenter_client::network::built().name;
        Ok(Self::at(default_base()?.join("kenter-node").join(network)))
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `node.json`: name, relays, terms, endpoints. No secrets.
    pub fn config(&self) -> PathBuf {
        self.root.join("node.json")
    }

    /// `pair.phrase`: the recovery phrase both node keys derive from.
    pub fn phrase(&self) -> PathBuf {
        self.root.join("pair.phrase")
    }

    /// `status.json`: what the running daemon last reported.
    pub fn status(&self) -> PathBuf {
        self.root.join("status.json")
    }

    /// `stop.request`: `kenter-node stop` creates it; the running daemon
    /// polls for it, removes it and stops cleanly. The home is owner-only,
    /// so only the operator can ask.
    pub fn stop_request(&self) -> PathBuf {
        self.root.join("stop.request")
    }

    /// `reload.request`: the settings window creates it after saving; the
    /// tray restarts its node so the new settings take effect.
    pub fn reload_request(&self) -> PathBuf {
        self.root.join("reload.request")
    }

    /// `register.request`: Settings' "Register now" creates it; the running
    /// daemon's selection task removes it and retries registering the pair
    /// at once instead of at its next scheduled attempt.
    pub fn register_request(&self) -> PathBuf {
        self.root.join("register.request")
    }

    /// `daemon.lock`: held by the running daemon for its whole life.
    pub fn lock(&self) -> PathBuf {
        self.root.join("daemon.lock")
    }

    /// Create the directory, owner-only on unix.
    pub fn ensure(&self) -> Result<(), String> {
        fs::create_dir_all(&self.root)
            .map_err(|e| format!("creating {}: {e}", self.root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("restricting {}: {e}", self.root.display()))?;
        }
        Ok(())
    }
}

fn default_base() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        // LOCALAPPDATA, not APPDATA: APPDATA roams with the profile on
        // managed machines, and a phrase file must not travel.
        std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALAPPDATA is not set; set KENTER_NODE_HOME".to_string())
    }
    #[cfg(not(windows))]
    {
        if let Some(x) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(x));
        }
        std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(|h| PathBuf::from(h).join(".local").join("share"))
            .ok_or_else(|| "HOME is not set; set KENTER_NODE_HOME".to_string())
    }
}

/// Write `bytes` to `path` through a temporary file and a rename, so a
/// reader never sees half a file. `private` makes the file owner-only on
/// unix; on Windows the per-user profile directory already is.
///
/// The temporary file is always created fresh (`create_new`, after
/// removing any stale one), because a mode given at open applies only on
/// creation: reusing a looser leftover would put a secret on disk readable
/// by others before the rename.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing stale {}: {e}", tmp.display())),
    }
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut f: File = opts
            .open(&tmp)
            .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("replacing {}: {e}", path.display()))
}
