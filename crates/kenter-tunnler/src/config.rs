use std::env;
use std::net::{IpAddr, SocketAddr};

#[cfg(not(feature = "mainnet"))]
const PASSPHRASE: &str = "Test SDF Network ; September 2015";
#[cfg(not(feature = "mainnet"))]
const DEFAULT_RPC: &str = "https://soroban-testnet.stellar.org";
#[cfg(feature = "mainnet")]
const PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
#[cfg(feature = "mainnet")]
const DEFAULT_RPC: &str = "https://rpc.ankr.com/stellar_soroban";

use crate::error::{Result, TunnlerError};

/// The node paths a wallet may reach through `/proxy`: the health check a
/// depositor makes before a print, and the extend request during one.
/// Anything else is refused at the relay and never reaches a tunnel.
/// `/kenter/shard` is not here: nodes no longer serve it.
pub const PROXY_PATHS: &[&str] = &["/kenter/health", "/kenter/extend"];

/// Largest request body `/proxy` accepts. An extend request carries the
/// partial token of a chain of at most 12 pairs, a few KB; a health check
/// has no body.
pub const MAX_PROXY_BODY: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub domain: String,
    pub server_secret: String,
    pub jwt_clock_skew: u64,
    pub session_timeout: u64,
    pub challenge_ttl: u64,
    pub rate_limit_window: u64,
    pub rate_limit_max_attempts: u32,
    pub rate_limit_block_duration: u64,
    pub request_timeout: u64,
    pub log_level: String,
    /// Roster contract ID (if empty, roster check is disabled — open access)
    pub roster_contract_id: Option<String>,
    pub soroban_rpc_url: String,
    pub soroban_network_passphrase: String,
    /// How long to cache roster membership checks (seconds)
    pub roster_cache_ttl: u64,
    /// Peers whose `X-Real-IP` is believed.
    ///
    /// Everything per-client -- the auth rate limiter, the challenge
    /// binding -- keys on the client's address, and behind a reverse
    /// proxy the TCP peer is the proxy. Reading `X-Real-IP` fixes that
    /// only if the header cannot be set by the client, so it is read
    /// from these peers and nobody else: a header believed
    /// unconditionally lets anyone claim any address, which is worse
    /// than the shared bucket it replaces.
    ///
    /// Defaults to loopback, which is where the shipped nginx proxies
    /// from (`config/nginx-kenter-tunnler.conf`: `server 127.0.0.1:8000`).
    pub trusted_proxies: Vec<IpAddr>,
    /// The paths `/proxy` forwards, each with its leading `/`. Always
    /// [`PROXY_PATHS`] in a running relay; tests that drive other node
    /// endpoints through a relay add theirs.
    pub proxy_paths: Vec<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let server_secret = env::var("TUNNLER_SERVER_SECRET")
            .map_err(|_| TunnlerError::Config("TUNNLER_SERVER_SECRET is required".into()))?;

        Ok(Self {
            host: env::var("TUNNLER_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("TUNNLER_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8000),
            // No default: a relay that guessed its domain would hand nodes
            // endpoints no wallet will accept.
            domain: env::var("TUNNLER_DOMAIN")
                .map_err(|_| TunnlerError::Config("TUNNLER_DOMAIN is required".into()))?,
            server_secret,
            jwt_clock_skew: parse_env_u64("TUNNLER_JWT_CLOCK_SKEW", 60),
            session_timeout: parse_env_u64("TUNNLER_SESSION_TIMEOUT", 86400),
            challenge_ttl: parse_env_u64("TUNNLER_CHALLENGE_TTL", 30),
            rate_limit_window: parse_env_u64("TUNNLER_RATE_LIMIT_WINDOW", 60),
            rate_limit_max_attempts: env::var("TUNNLER_RATE_LIMIT_MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            rate_limit_block_duration: parse_env_u64("TUNNLER_RATE_LIMIT_BLOCK_DURATION", 300),
            // At least the client's `request_timeout_secs` (120): a node
            // answering `/kenter/extend` waits for its `confirm_link` to
            // land first, which can take most of a minute.
            request_timeout: parse_env_u64("TUNNLER_REQUEST_TIMEOUT", 120),
            log_level: env::var("TUNNLER_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            roster_contract_id: env::var("ROSTER_CONTRACT_ID").ok().filter(|s| !s.is_empty()),
            // The network is fixed per build, as in `kenter_client::network`:
            // these are defaults for where it is reached, and a mainnet
            // build's are mainnet's. The env can still name an endpoint.
            soroban_rpc_url: env::var("SOROBAN_RPC_URL")
                .unwrap_or_else(|_| DEFAULT_RPC.into()),
            soroban_network_passphrase: env::var("SOROBAN_NETWORK_PASSPHRASE")
                .unwrap_or_else(|_| PASSPHRASE.into()),
            roster_cache_ttl: parse_env_u64("TUNNLER_ROSTER_CACHE_TTL", 300),
            trusted_proxies: parse_trusted_proxies(
                env::var("TUNNLER_TRUSTED_PROXIES").ok().as_deref(),
            ),
            // Not from the environment: a relay that forwards more than
            // the wallet's two calls is one nobody meant to run.
            proxy_paths: PROXY_PATHS.iter().map(|p| p.to_string()).collect(),
        })
    }

    pub fn bind_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("invalid bind address")
    }
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse `TUNNLER_TRUSTED_PROXIES`: a comma-separated list of addresses.
///
/// Unset means loopback, which is where the shipped nginx proxies from.
/// An explicit empty string means trust nobody -- useful when the
/// tunnler is exposed directly and every `X-Real-IP` is a client's
/// invention. Unparseable entries are dropped rather than defaulted
/// over: silently widening trust because someone typed an address wrong
/// is the wrong direction to fail.
fn parse_trusted_proxies(raw: Option<&str>) -> Vec<IpAddr> {
    match raw {
        None => vec![
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        ],
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_trusts_loopback_because_that_is_where_nginx_sits() {
        let t = parse_trusted_proxies(None);
        assert!(t.contains(&IpAddr::from([127, 0, 0, 1])));
        assert!(t.contains(&IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
    }

    /// An operator who sets it empty is saying "trust nobody", and must
    /// get that rather than the default.
    #[test]
    fn an_empty_setting_trusts_nobody() {
        assert!(parse_trusted_proxies(Some("")).is_empty());
        assert!(parse_trusted_proxies(Some("  ,  ")).is_empty());
    }

    #[test]
    fn a_list_is_parsed_and_junk_is_dropped() {
        let t = parse_trusted_proxies(Some("10.0.0.1, not-an-ip ,::1"));
        assert_eq!(t.len(), 2, "the junk entry must not widen trust");
        assert!(t.contains(&IpAddr::from([10, 0, 0, 1])));
    }
}
