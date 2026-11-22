use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, info};

use super::client::SorobanClient;

struct CachedEntry {
    is_member: bool,
    checked_at: Instant,
}

/// In-memory roster membership cache backed by Soroban RPC.
///
/// On cache miss or expiry, queries the roster contract via `getLedgerEntries`.
/// If no contract ID is configured, all addresses are allowed (open access).
pub struct RosterCache {
    client: SorobanClient,
    cache: DashMap<String, CachedEntry>,
    ttl: Duration,
}

impl RosterCache {
    pub fn new(rpc_url: &str, contract_id: &str, cache_ttl_secs: u64) -> Result<Self, String> {
        let client = SorobanClient::new(rpc_url, contract_id)?;
        info!(%contract_id, "roster gating enabled");

        Ok(Self {
            client,
            cache: DashMap::new(),
            ttl: Duration::from_secs(cache_ttl_secs),
        })
    }

    /// Check if a Stellar address is a registered node on the roster.
    ///
    /// Returns cached result if fresh, otherwise queries the contract.
    pub async fn is_member(&self, stellar_address: &str) -> Result<bool, String> {
        // Check cache
        if let Some(entry) = self.cache.get(stellar_address) {
            if entry.checked_at.elapsed() < self.ttl {
                debug!(%stellar_address, cached = entry.is_member, "roster cache hit");
                return Ok(entry.is_member);
            }
        }

        // Cache miss or expired — query the contract
        let is_member = self.client.is_node(stellar_address).await?;

        self.cache.insert(
            stellar_address.to_string(),
            CachedEntry {
                is_member,
                checked_at: Instant::now(),
            },
        );

        debug!(%stellar_address, %is_member, "roster check (from chain)");
        Ok(is_member)
    }

    /// Evict expired entries from the cache.
    pub fn cleanup(&self) {
        let before = self.cache.len();
        self.cache.retain(|_, entry| entry.checked_at.elapsed() < self.ttl);
        let evicted = before - self.cache.len();
        if evicted > 0 {
            debug!(evicted, "roster cache cleanup");
        }
    }

    /// Invalidate a specific address (e.g., on disconnect).
    pub fn invalidate(&self, stellar_address: &str) {
        self.cache.remove(stellar_address);
    }
}
