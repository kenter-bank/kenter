//! Bakes each network's relay list into the build.
//!
//! The relays a wallet may reach a node through are part of the network,
//! like the contracts: a node names its relay, and an operator who could name
//! any host would learn every depositor's IP. So the list is fixed when the
//! binary is built, from `KENTER_TESTNET_RELAYS` and `KENTER_MAINNET_RELAYS`
//! (comma-separated hosts, optionally with a port, no scheme). Unset means no
//! relays, which fails closed: such a wallet reaches no node.

use std::fmt::Write as _;

fn hosts(var: &str) -> Vec<String> {
    println!("cargo:rerun-if-env-changed={var}");
    let raw = std::env::var(var).unwrap_or_default();
    raw.split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .inspect(|h| {
            let ok = h
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':');
            assert!(ok && !h.contains("//"), "{var}: {h:?} is not a bare host[:port]");
        })
        .collect()
}

fn main() {
    let mut out = String::new();
    for (name, var) in [("TESTNET_RELAYS", "KENTER_TESTNET_RELAYS"), ("MAINNET_RELAYS", "KENTER_MAINNET_RELAYS")] {
        let list = hosts(var);
        write!(out, "/// From `{var}` at build time.\npub const {name}: &[&str] = &[").unwrap();
        for h in &list {
            write!(out, "{h:?}, ").unwrap();
        }
        out.push_str("];\n");
    }
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("relays.rs");
    std::fs::write(dest, out).unwrap();
}
