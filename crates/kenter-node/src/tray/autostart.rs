//! Start the tray at login (set from Settings).
//!
//! Windows: a value under `HKCU\...\CurrentVersion\Run`, which runs the
//! tray for this user only, with no elevation. Written through `reg.exe`,
//! so no registry crate is needed. Other platforms: not yet (section D,
//! with the installers), and the setting says so rather than pretending.
//!
//! The entry starts the default home. An install with `KENTER_NODE_HOME`
//! set is a developer's and starts by hand.

#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const VALUE: &str = "KenterNode";

pub fn supported() -> bool {
    cfg!(windows)
}

/// The command line the login entry runs: this executable, which is
/// `kenter-node-tray` (no arguments starts the tray).
#[cfg(windows)]
fn command() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locating kenter-node-tray: {e}"))?;
    Ok(format!("\"{}\"", exe.display()))
}

/// `reg.exe` by full path. A bare `reg` is resolved starting from the
/// application's own directory, so a `reg.exe` planted beside the tray
/// would run inside the process that holds the pair's keys.
#[cfg(windows)]
fn reg() -> std::process::Command {
    let root = std::env::var_os("SystemRoot")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    std::process::Command::new(root.join("System32").join("reg.exe"))
}

#[cfg(windows)]
pub fn enabled() -> bool {
    reg()
        .args(["query", RUN_KEY, "/v", VALUE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
pub fn set(on: bool) -> Result<(), String> {
    let mut cmd = reg();
    if on {
        cmd.args(["add", RUN_KEY, "/v", VALUE, "/t", "REG_SZ", "/d", &command()?, "/f"]);
    } else {
        if !enabled() {
            return Ok(());
        }
        cmd.args(["delete", RUN_KEY, "/v", VALUE, "/f"]);
    }
    let out = cmd.output().map_err(|e| format!("running reg.exe: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "reg.exe refused: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(not(windows))]
pub fn enabled() -> bool {
    false
}

#[cfg(not(windows))]
pub fn set(_on: bool) -> Result<(), String> {
    Err("starting at login is not supported on this platform yet".into())
}
