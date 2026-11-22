//! `kenter-node-tray`: the desktop node.
//!
//! - no arguments: the tray, running the node in-process;
//! - `settings`: the settings window (the tray launches this).
//!
//! A separate binary from the `kenter-node` CLI because a GUI started at
//! login must not open a console window, which on Windows is a property of
//! the executable (`windows_subsystem`). Logs go to `node.log` in the
//! node's home.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

/// No desktop tray on this platform yet (a Linux tray needs a GTK loop):
/// say so, rather than fail to build.
#[cfg(not(any(windows, target_os = "macos")))]
fn main() -> ExitCode {
    eprintln!("kenter-node-tray: no desktop tray on this platform yet; run `kenter-node run` instead");
    ExitCode::FAILURE
}

#[cfg(any(windows, target_os = "macos"))]
fn main() -> ExitCode {
    let home = match kenter_node::home::Home::locate() {
        Ok(h) => h,
        Err(e) => return fail(&e),
    };
    if let Err(e) = home.ensure() {
        return fail(&e);
    }
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.root().join("node.log"))
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "kenter_node=info,kenter_network=info".into()),
            )
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
    }

    let arg = std::env::args().nth(1);
    let result = match arg.as_deref() {
        None => kenter_node::tray::run(home),
        Some("settings") => kenter_node::tray::settings::run(home),
        Some(other) => Err(format!("unknown argument {other:?}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn fail(e: &str) -> ExitCode {
    tracing::error!("{e}");
    eprintln!("error: {e}");
    ExitCode::FAILURE
}
