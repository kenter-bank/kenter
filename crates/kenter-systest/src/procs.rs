//! The relay and the node daemons, as child processes.
//!
//! Secrets reach the children through the environment, never argv — a process
//! list is not a secret store, and `kenter-node` refuses argv secrets for the
//! same reason. Each child's output is captured to a file so the results log
//! can carry it even when the child is what failed.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use zeroize::Zeroizing;

/// An environment variable for a child. `Zeroizing` because some of these are
/// node secrets, and a plain `String` would leave copies behind in the
/// harness after the child has them.
pub type EnvVar = (&'static str, Zeroizing<String>);

pub struct Daemon {
    pub name: String,
    child: Child,
    log_path: PathBuf,
}

impl Daemon {
    /// Spawn `bin` with `args`, with `env` added to the inherited environment.
    ///
    /// `bin` is resolved next to this harness rather than through PATH or
    /// `cargo run`: the binary being tested should be the one that was just
    /// built, and `cargo run` would hold a build lock for the life of the
    /// daemon.
    pub fn spawn(
        name: &str,
        bin: &str,
        args: &[String],
        env: &[EnvVar],
        log_dir: &Path,
    ) -> Result<Daemon, String> {
        let exe = sibling_binary(bin)?;
        std::fs::create_dir_all(log_dir).map_err(|e| format!("{}: {e}", log_dir.display()))?;
        let log_path = log_dir.join(format!("{name}.log"));
        let out = std::fs::File::create(&log_path)
            .map_err(|e| format!("{}: {e}", log_path.display()))?;
        let err = out
            .try_clone()
            .map_err(|e| format!("{}: {e}", log_path.display()))?;

        let mut cmd = Command::new(&exe);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        for (k, v) in env {
            cmd.env(k, v.as_str());
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("spawning {}: {e}", exe.display()))?;
        Ok(Daemon {
            name: name.to_string(),
            child,
            log_path,
        })
    }

    /// Everything the child has written so far.
    pub fn log(&self) -> String {
        let mut s = String::new();
        if let Ok(mut f) = std::fs::File::open(&self.log_path) {
            let _ = f.read_to_string(&mut s);
        }
        s
    }

    /// Has the child already given up? `Some(code)` if it has exited.
    pub fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.to_string()),
            Ok(None) => None,
            Err(e) => Some(format!("unknown ({e})")),
        }
    }

    /// Wait for a line to appear in the child's output, or time out.
    ///
    /// Polling a log file rather than piping: the child writes to a file so
    /// the log survives the harness, and reading it twice is cheaper than
    /// keeping a reader thread per daemon.
    pub fn wait_for(&mut self, needle: &str, seconds: u64) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        loop {
            let log = self.log();
            if log.contains(needle) {
                return Ok(());
            }
            if let Some(status) = self.exited() {
                return Err(format!(
                    "{} exited ({status}) before saying {needle:?}:\n{log}",
                    self.name
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "{} did not say {needle:?} within {seconds}s:\n{log}",
                    self.name
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    /// A harness that panics must not leave daemons holding a relay port and
    /// a roster identity.
    fn drop(&mut self) {
        self.stop();
    }
}

/// Find a binary in the same build output as the running harness.
///
/// Two directories, because a test binary lives in `target/<profile>/deps`
/// while the daemons it is looking for are one level up in
/// `target/<profile>`. Resolved from `current_exe` rather than PATH so the
/// binary under test is the one that was just built.
fn sibling_binary(name: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "the harness has no parent directory".to_string())?;
    let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);

    let mut looked = Vec::new();
    for candidate_dir in [Some(dir), dir.parent()].into_iter().flatten() {
        let candidate = candidate_dir.join(&filename);
        if candidate.exists() {
            return Ok(candidate);
        }
        looked.push(candidate_dir.display().to_string());
    }
    Err(format!(
        "{name} is not built — run `cargo build -p {name}` (looked in {})",
        looked.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error has to name the build command, because "not found" on its own
    /// sends people looking at PATH, which is not where this looks.
    #[test]
    fn a_missing_binary_says_how_to_build_it() {
        let err = sibling_binary("kenter-definitely-not-a-binary").unwrap_err();
        assert!(err.contains("cargo build -p"), "{err}");
    }

    /// The harness itself is always in the build output — and under
    /// `cargo test` that is one directory up from this test binary, which is
    /// exactly the case the two-directory search exists for.
    #[test]
    fn a_present_binary_resolves() {
        let found = sibling_binary("kenter-systest").expect("the harness is built");
        assert!(found.exists(), "{}", found.display());
    }
}
