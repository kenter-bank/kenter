//! The installed node's life: get the pair onto the roster, stay bound to
//! a relay, and take the pair out of selection when it stops.
//!
//! 1. **Prepare.** Wait for both addresses to be funded, then join (or
//!    volunteer), convert to volunteer if the config asks, and mark both
//!    records active.
//! 2. **Serve.** Bind to the first relay in the list that answers. When the
//!    binding drops, go back to the top of the list, with backoff while
//!    nothing answers. The assigned endpoint is recorded on both roster
//!    records: at once on the first binding or on the primary relay, and
//!    on a fallback only once the binding has held for
//!    [`FALLBACK_SETTLE`], so a relay blip costs no transactions.
//! 3. **Select.** Alongside serving, [`crate::select`] registers the pair,
//!    seeds slots whose beacon round is out, and claims positions the pair
//!    could win (`docs/architecture/node-selection.md`). Nothing assigns a
//!    node to a print: a node is in a print only if it claimed it.
//! 4. **Stop.** On a stop request, close the tunnel and set both records
//!    inactive. A crash or power cut skips this; a selected node that has
//!    gone silent is skipped by the depositor (`skip_position`).
//!
//! **One account, one submitter at a time.** The own key signs
//! `confirm_link` for prints *and* this module's roster calls. Two
//! transactions from one account in flight race for the sequence number and
//! one fails, which for `confirm_link` loses a print. [`OwnKeyLock`]
//! serialises every own-key submission, and the confirmer re-reads the
//! sequence before each one, because other submitters advance it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use std::future::Future;
use std::pin::Pin;

use kenter_client::{MintClient, NetworkConfig, TxBuilder};
use kenter_crypto::keypair::StellarKeypair;
use kenter_network::handlers::{ExtendNodeContext, PairNodeContext, ShardRateLimiter};
use kenter_network::tunnel::{KenterHandler, LinkConfirmer, TunnelClient, TunnelConfig};
use tokio::sync::{Mutex, watch};

use crate::chain::{Chain, FEE_FLOAT, LOW_BALANCE, XLM, funding_target, spendable, xlm};
use crate::config::{NodeConfig, Relay};
use crate::home::Home;
use crate::keys::PairKeys;
use crate::slot_cache::SlotCache;
use crate::status::{DaemonLock, Reporter, State, now};

/// How long a fallback binding must hold before the roster is told.
pub const FALLBACK_SETTLE: Duration = Duration::from_secs(10 * 60);
/// At most one endpoint record per this long, whatever the relays say: a
/// relay that hands out a new endpoint on every bind and then drops the
/// connection would otherwise spend two transactions a cycle from the fee
/// float.
pub const ENDPOINT_RECORD_EVERY: Duration = Duration::from_secs(10 * 60);
/// Longest endpoint accepted from a relay.
const MAX_ENDPOINT: usize = 200;

/// Check the endpoint a relay assigned before anything is written to the
/// roster with it.
///
/// The relay's `auth_ok` string is taken as-is by the transport, so a
/// hostile relay, or anyone on the path to a `ws://` one, could otherwise
/// make the node publish any string as its address. Accepted:
/// `https://<own address>.<domain>` (`http://` only for an insecure dev
/// relay), where `<domain>` is the configured relay's own host whenever
/// that host is a name. A relay configured by IP (local development) may
/// name any domain.
pub fn valid_endpoint(endpoint: &str, relay: &Relay, own_address: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("relay {} gave endpoint {endpoint:?}: {why}", relay.host));
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT {
        return bad("empty or too long");
    }
    // A secure relay must hand out https. A development relay (plain
    // ws://) still advertises its public https address, since TLS sits in
    // a proxy in front of it, so either scheme is accepted there.
    let rest = match (endpoint.strip_prefix("https://"), endpoint.strip_prefix("http://")) {
        (Some(r), _) => r,
        (None, Some(r)) if !relay.secure => r,
        _ => return bad(if relay.secure { "not https://" } else { "not https:// or http://" }),
    };
    let host = rest.strip_suffix('/').unwrap_or(rest);
    if host.is_empty()
        || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return bad("host has characters a host name cannot");
    }
    let Some((label, domain)) = host.split_once('.') else {
        return bad("no domain");
    };
    if !label.eq_ignore_ascii_case(own_address) {
        return bad("not this node's address");
    }
    let relay_name = relay.host.rsplit_once(':').map_or(relay.host.as_str(), |(h, _)| h);
    let by_ip = relay_name.parse::<std::net::IpAddr>().is_ok() || relay_name == "localhost";
    if domain.is_empty() || (!by_ip && !domain.eq_ignore_ascii_case(relay_name)) {
        return bad("not under the relay's own host");
    }
    Ok(())
}
/// How often both records are heartbeated, keeping them off the archive
/// queue.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const BACKOFF_MIN: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const FUNDS_POLL: Duration = Duration::from_secs(60);
const RETRY: Duration = Duration::from_secs(30);
const STOP_TX_TIMEOUT: Duration = Duration::from_secs(45);

/// Serialises every transaction the own key signs (module docs).
pub type OwnKeyLock = Arc<Mutex<()>>;

/// Slots this node confirmed a link on and that have not been settled yet.
///
/// If such a print is abandoned, the node is paid when the slot is settled
/// -- but only while the slot's draw is still there, which is about a day
/// past the slot's expiry (`docs/architecture/node-selection.md`). Past that its
/// fee is burned. So the selection loop clears these itself once they
/// expire ([`crate::select::run`]). Kept in memory: a node restarted
/// across an abandoned print relies on someone else clearing it.
pub type Owed = Arc<std::sync::Mutex<std::collections::BTreeSet<u32>>>;

/// Submits `confirm_link` for links this node builds.
///
/// The mint accepts the call only from a member of the assigned pair, which
/// is why the node, not the depositor, makes it.
pub struct MintLinkConfirmer {
    mint: Mutex<MintClient>,
    /// This node's own address: the slot must name it for the next link.
    address: String,
    own_lock: OwnKeyLock,
    confirmed: Arc<AtomicU64>,
    owed: Owed,
    /// The slots extend requests have named lately, so the check before
    /// an extend costs the RPC a few reads per burst, not two per request.
    slots: SlotCache,
}

impl MintLinkConfirmer {
    pub fn new(net: &NetworkConfig, own: &StellarKeypair, own_lock: OwnKeyLock) -> Self {
        Self {
            mint: Mutex::new(MintClient::new(
                TxBuilder::new(net.rpc_client(), own.clone()),
                &net.mint,
            )),
            address: own.stellar_address(),
            own_lock,
            confirmed: Arc::new(AtomicU64::new(0)),
            owed: Owed::default(),
            slots: SlotCache::default(),
        }
    }

    /// Links confirmed so far by this confirmer.
    pub fn counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.confirmed)
    }

    /// The slots this confirmer has confirmed on, for the selection loop
    /// to clear if they are abandoned ([`Owed`]).
    pub fn owed(&self) -> Owed {
        Arc::clone(&self.owed)
    }
}

impl LinkConfirmer for MintLinkConfirmer {
    fn admits(
        &self,
        slot_id: u32,
        event_id: [u8; 32],
        prior_links: Vec<([u8; 32], [u8; 32], [u8; 32])>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            // Position 1 is asked before selection formally closes; the
            // slot's claims are its positions once they can no longer
            // change, which needs the current ledger to tell. Both reads
            // go through the cache (`crate::slot_cache`), which never lets
            // an old snapshot refuse a request a fresh one would admit.
            let read = || async move {
                let mint = self.mint.lock().await;
                let slot = mint
                    .get_slot(slot_id)
                    .await
                    .map_err(|e| format!("reading slot {slot_id}: {e}"))?;
                let ledger = mint
                    .tx()
                    .rpc()
                    .get_latest_ledger()
                    .await
                    .map_err(|e| format!("reading the latest ledger: {e}"))?;
                Ok((ledger, slot))
            };
            self.slots
                .admits(slot_id, &self.address, event_id, &prior_links, read)
                .await
        })
    }

    fn confirm_link(
        &self,
        slot_id: u32,
        link_index: u32,
        partial_public_key: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let _one_at_a_time = self.own_lock.lock().await;
            let mut mint = self.mint.lock().await;
            // Other submitters on this account move the sequence on.
            mint.tx_mut()
                .refresh_sequence()
                .await
                .map_err(|e| format!("reading account sequence: {e}"))?;
            match mint.confirm_link(slot_id, link_index, partial_public_key).await {
                Ok(completed) => {
                    self.confirmed.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut owed) = self.owed.lock() {
                        owed.insert(slot_id);
                    }
                    tracing::info!(slot_id, link_index, completed, "link confirmed on-chain");
                    Ok(())
                }
                Err(e) => Err(format!("confirm_link(slot {slot_id}, link {link_index}): {e}")),
            }
        })
    }
}

/// The request handler for one pair: shard and extend contexts plus,
/// optionally, the on-chain confirmer.
pub fn pair_handler(keys: &PairKeys, confirmer: Option<Arc<dyn LinkConfirmer>>) -> Arc<KenterHandler> {
    Arc::new(KenterHandler::new(
        Arc::new(PairNodeContext {
            own_keypair: keys.own.clone(),
            rate_limiter: ShardRateLimiter::new(),
        }),
        Arc::new(Mutex::new(Some(ExtendNodeContext {
            own_keypair: keys.own.clone(),
            partner_keypair: keys.partner.clone(),
        }))),
        confirmer,
    ))
}

pub fn tunnel_config(relay: &Relay) -> TunnelConfig {
    TunnelConfig {
        host: relay.host.clone(),
        secure: relay.secure,
        services: vec!["kenter".into()],
        ..Default::default()
    }
}

/// Resolves when a stop has been asked for, or the stop sender is gone.
async fn stopped(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Sleep, or return `true` early if a stop is asked for.
async fn sleep_or_stop(rx: &mut watch::Receiver<bool>, d: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = stopped(rx) => true,
    }
}

enum Prep {
    AwaitFunds(String),
    Retry(String),
    Fatal(String),
}

/// Run the installed node until `stop` turns true (or its sender drops).
///
/// Holds the home's [`DaemonLock`] throughout, so a second daemon, or a
/// CLI command that submits transactions, refuses while this runs.
pub async fn run(
    home: Home,
    cfg: NodeConfig,
    keys: PairKeys,
    reporter: Reporter,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    let _lock = DaemonLock::acquire(&home)?;
    let net = cfg.network()?;
    let chain = Arc::new(Chain::new(net.clone()));
    let own_lock: OwnKeyLock = Arc::new(Mutex::new(()));
    let keys = Arc::new(keys);

    reporter.state(State::Starting, None);
    let [own_address, partner_address] = keys.addresses();
    tracing::info!(node = %own_address, partner = %partner_address, network = net.profile.name, "pair node starting");

    // 1. Prepare.
    loop {
        match prepare(&chain, &cfg, &keys, &own_lock, &reporter).await {
            Ok(()) => break,
            Err(Prep::AwaitFunds(msg)) => {
                reporter.state(State::AwaitingFunds, Some(msg));
                if sleep_or_stop(&mut stop, FUNDS_POLL).await {
                    reporter.state(State::Stopped, None);
                    return Ok(());
                }
            }
            Err(Prep::Retry(msg)) => {
                tracing::warn!("{msg}");
                reporter.state(State::Starting, Some(msg));
                if sleep_or_stop(&mut stop, RETRY).await {
                    reporter.state(State::Stopped, None);
                    return Ok(());
                }
            }
            Err(Prep::Fatal(msg)) => {
                reporter.state(State::Failed, Some(msg.clone()));
                return Err(msg);
            }
        }
    }

    // 2. Serve.
    let confirmer = Arc::new(MintLinkConfirmer::new(&net, &keys.own, Arc::clone(&own_lock)));
    let counter = confirmer.counter();
    let owed = confirmer.owed();
    let handler = pair_handler(&keys, Some(confirmer as Arc<dyn LinkConfirmer>));

    let heartbeat = tokio::spawn(heartbeats(Arc::clone(&chain), Arc::clone(&keys), Arc::clone(&own_lock)));
    // Register the pair, seed and claim prints.
    let selecting = tokio::spawn(crate::select::run(
        Arc::clone(&chain),
        Arc::clone(&keys),
        Arc::clone(&own_lock),
        Some(reporter.clone()),
        Some(home.register_request()),
        Some(owed),
    ));
    let counting = {
        let reporter = reporter.clone();
        let counter = Arc::clone(&counter);
        tokio::spawn(async move {
            let mut last = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let n = counter.load(Ordering::Relaxed);
                if n != last {
                    last = n;
                    reporter.set(|s| s.links_confirmed = n);
                }
            }
        })
    };

    let mut backoff = BACKOFF_MIN;
    let mut first_bind = true;
    let mut deactivated = false;
    // When an endpoint was last written to the roster (SA-1 rate limit).
    let recorded_at: Arc<Mutex<Option<std::time::Instant>>> = Arc::new(Mutex::new(None));
    let mut last_record: Option<std::time::Instant> = None;
    'serve: loop {
        if *stop.borrow() {
            break;
        }
        let mut bound = None;
        let mut last_error = String::new();
        for (index, relay) in cfg.relays.iter().enumerate() {
            reporter.set(|s| {
                s.state = if first_bind { State::Starting } else { State::Reconnecting };
                s.relay = Some(relay.host.clone());
            });
            let attempt = TunnelClient::new(keys.own.clone(), tunnel_config(relay)).run(handler.clone());
            let result = tokio::select! {
                r = attempt => r,
                _ = stopped(&mut stop) => break 'serve,
            };
            match result {
                Ok((endpoint, session)) => {
                    bound = Some((index, relay, endpoint, session));
                    break;
                }
                Err(e) => {
                    tracing::warn!(relay = %relay.host, "relay unavailable: {e}");
                    last_error = format!("{}: {e}", relay.host);
                }
            }
        }

        let Some((index, relay, endpoint, session)) = bound else {
            reporter.set(|s| {
                s.state = State::Reconnecting;
                s.endpoint = None;
                s.online_since = None;
                s.detail = Some(format!("no relay answered (last: {last_error})"));
            });
            if sleep_or_stop(&mut stop, backoff).await {
                break;
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
            continue;
        };
        backoff = BACKOFF_MIN;

        tracing::info!(relay = %relay.host, endpoint = %endpoint.endpoint_url, "node is serving");
        reporter.set(|s| {
            s.state = State::Online;
            s.relay = Some(relay.host.clone());
            s.endpoint = Some(endpoint.endpoint_url.clone());
            s.online_since = Some(now());
            s.detail = None;
        });

        let settle = if first_bind || index == 0 { Duration::ZERO } else { FALLBACK_SETTLE };
        first_bind = false;
        let recorder = match valid_endpoint(&endpoint.endpoint_url, relay, &own_address) {
            Ok(()) => {
                // Rate limit, whatever the relay says.
                let since_last = last_record.map(|t| t.elapsed()).unwrap_or(ENDPOINT_RECORD_EVERY);
                let wait = settle.max(ENDPOINT_RECORD_EVERY.saturating_sub(since_last));
                Some(tokio::spawn(record_endpoint(
                    Arc::clone(&chain),
                    Arc::clone(&keys),
                    Arc::clone(&own_lock),
                    endpoint.endpoint_url.clone(),
                    wait,
                    Arc::clone(&recorded_at),
                )))
            }
            Err(e) => {
                tracing::warn!("{e}; not recording it");
                reporter.set(|s| s.detail = Some(format!("{e}; not recorded on the roster")));
                None
            }
        };

        let trigger = session.shutdown_trigger();
        let join = session.join();
        tokio::pin!(join);
        let stopping = tokio::select! {
            _ = &mut join => false,
            _ = stopped(&mut stop) => true,
        };
        if let Some(r) = recorder {
            r.abort();
        }
        last_record = *recorded_at.lock().await;
        if stopping {
            // Leave selection while still reachable, then close the
            // tunnel, so no print picks the node in the gap (SA-3).
            deactivate(&chain, &keys, &own_lock, &reporter, &counter).await;
            deactivated = true;
            trigger();
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut join).await;
            break;
        }
        tracing::warn!(relay = %relay.host, "relay connection lost; reconnecting");
        reporter.set(|s| {
            s.state = State::Reconnecting;
            s.online_since = None;
            s.detail = Some(format!("lost the connection to {}", relay.host));
        });
        if sleep_or_stop(&mut stop, BACKOFF_MIN).await {
            break;
        }
    }

    // 3. Stop. (Already out of selection if the stop came while bound.)
    heartbeat.abort();
    selecting.abort();
    counting.abort();
    if !deactivated {
        deactivate(&chain, &keys, &own_lock, &reporter, &counter).await;
    }
    reporter.set(|s| {
        s.state = State::Stopped;
        s.relay = None;
        s.endpoint = None;
        s.online_since = None;
        s.detail = None;
    });
    Ok(())
}

/// Set both records inactive, best effort, so prints stop choosing a node
/// that is going away.
async fn deactivate(
    chain: &Chain,
    keys: &PairKeys,
    own_lock: &OwnKeyLock,
    reporter: &Reporter,
    counter: &AtomicU64,
) {
    reporter.set(|s| {
        s.state = State::Stopping;
        s.links_confirmed = counter.load(Ordering::Relaxed);
        s.detail = Some("leaving selection".into());
    });
    for kp in [&keys.own, &keys.partner] {
        let _guard = own_lock.lock().await;
        match tokio::time::timeout(STOP_TX_TIMEOUT, chain.set_active(kp, false)).await {
            Ok(Ok(())) => tracing::info!(address = %kp.stellar_address(), "out of selection"),
            Ok(Err(e)) => tracing::warn!("{e}"),
            Err(_) => tracing::warn!(address = %kp.stellar_address(), "timed out leaving selection"),
        }
    }
}

/// Fund the partner from the node's own address when it needs it: its
/// joining amount while it is not on the roster yet (creating the account
/// if need be), or a fee float once it is a member and runs low. Returns
/// whether anything was sent. Waits, rather than fails, when the own
/// address cannot spare it yet.
async fn fund_partner(
    chain: &Chain,
    keys: &PairKeys,
    views: &[crate::chain::AccountView],
    target: i128,
    own_lock: &OwnKeyLock,
    reporter: &Reporter,
) -> Result<bool, Prep> {
    let (own, partner) = (&views[0], &views[1]);
    let own_native = own.native.unwrap_or(0);
    // What the own address must keep for itself.
    let own_keeps = if own.node.is_none() { target } else { 2 * XLM + LOW_BALANCE };
    let need = match (&partner.node, partner.native) {
        (None, None) => target,
        (None, Some(n)) if n < target => target - n,
        (Some(_), Some(n)) if spendable(n, partner.subentries) < LOW_BALANCE => FEE_FLOAT,
        _ => return Ok(false),
    };
    if own_native < own_keeps + need + XLM / 10 {
        return Ok(false);
    }
    reporter.state(State::Joining, Some(format!("funding the partner {}", partner.address)));
    let _guard = own_lock.lock().await;
    chain
        .send_xlm(&keys.own, &partner.address, need, partner.native.is_none())
        .await
        .map_err(Prep::Retry)?;
    tracing::info!(partner = %partner.address, amount = %xlm(need), "funded the partner");
    Ok(true)
}

/// Get both addresses onto the roster, on the configured terms, active.
///
/// **Active before any relay binding, deliberately.**
/// A gated relay admits only members the roster counts (`is_node`:
/// active and not unbonding), so an inactive pair could never bind to
/// activate afterwards. The cost: with every relay down, the pair is
/// selectable and unreachable until a relay answers or the operator stops
/// it, which is the case the depositor skipping a silent node
/// (`skip_position`) covers.
async fn prepare(
    chain: &Chain,
    cfg: &NodeConfig,
    keys: &PairKeys,
    own_lock: &OwnKeyLock,
    reporter: &Reporter,
) -> Result<(), Prep> {
    let own_address = keys.own.stellar_address();
    let min_stake = chain.min_stake(&own_address).await.map_err(Prep::Retry)?;
    let target = funding_target(min_stake, cfg.volunteer);

    let pair = [(&keys.own, cfg.name.clone()), (&keys.partner, cfg.partner_name())];
    let mut views = Vec::with_capacity(2);
    for (kp, _) in &pair {
        views.push(chain.view(kp).await.map_err(Prep::Retry)?);
    }

    // One address to fund. The operator sends the
    // whole pair's amount to the node's own address; the node creates and
    // funds its partner from it. Funding is a precondition for joining
    // only: a member that has run low is a warning, not a reason not to
    // serve.
    if fund_partner(chain, keys, &views, target, own_lock, reporter).await? {
        views[1] = chain.view(&keys.partner).await.map_err(Prep::Retry)?;
        views[0] = chain.view(&keys.own).await.map_err(Prep::Retry)?;
    }
    let own_short = views[0].node.is_none() && views[0].native.unwrap_or(0) < target;
    let partner_short = views[1].node.is_none() && views[1].native.unwrap_or(0) < target;
    if own_short || partner_short {
        let have = views[0].native.unwrap_or(0);
        let want = if views[1].node.is_none() {
            target + (target - views[1].native.unwrap_or(0)).max(0) + XLM / 10
        } else {
            target
        };
        return Err(Prep::AwaitFunds(format!(
            "send {} XLM to {} (has {})",
            xlm((want - have).max(0)),
            views[0].address,
            xlm(have)
        )));
    }

    for ((kp, name), view) in pair.iter().zip(&views) {
        let _guard = own_lock.lock().await;
        match &view.node {
            None => {
                reporter.state(State::Joining, Some(format!("joining as {}", view.address)));
                chain.join(kp, name, cfg.volunteer).await.map_err(Prep::Retry)?;
            }
            Some(n) if n.unbonding_at.is_some() => {
                return Err(Prep::Fatal(format!(
                    "{} has left the roster and is unbonding; withdraw the stake \
                     (`kenter-node withdraw`) before this pair can serve again",
                    view.address
                )));
            }
            Some(n) => {
                if cfg.volunteer && !n.volunteer {
                    reporter.state(State::Joining, Some(format!("converting {} to volunteer", view.address)));
                    chain.join(kp, name, true).await.map_err(Prep::Retry)?;
                } else if !cfg.volunteer && n.volunteer {
                    tracing::warn!(address = %view.address, "this address volunteers; that is permanent, so it stays a volunteer");
                }
                if !n.active {
                    reporter.state(State::Joining, Some(format!("re-entering selection as {}", view.address)));
                    chain.set_active(kp, true).await.map_err(Prep::Retry)?;
                }
            }
        }
    }
    Ok(())
}

/// After `settle`, make both roster records name `endpoint`, if they do not
/// already. Aborted by the caller when the binding drops.
async fn record_endpoint(
    chain: Arc<Chain>,
    keys: Arc<PairKeys>,
    own_lock: OwnKeyLock,
    endpoint: String,
    settle: Duration,
    recorded_at: Arc<Mutex<Option<std::time::Instant>>>,
) {
    tokio::time::sleep(settle).await;
    for kp in [&keys.own, &keys.partner] {
        let current = match chain.view(kp).await {
            Ok(v) => v.node.map(|n| n.tunnel_endpoint),
            Err(e) => {
                tracing::warn!("{e}");
                continue;
            }
        };
        if current.as_deref() == Some(endpoint.as_str()) {
            continue;
        }
        let _guard = own_lock.lock().await;
        // Counted as a record whether or not it lands: the limit is on
        // attempts, which is what spends the float.
        *recorded_at.lock().await = Some(std::time::Instant::now());
        match chain.set_endpoint(kp, &endpoint).await {
            Ok(()) => tracing::info!(address = %kp.stellar_address(), %endpoint, "endpoint recorded"),
            Err(e) => tracing::warn!("{e}"),
        }
    }
}

async fn heartbeats(chain: Arc<Chain>, keys: Arc<PairKeys>, own_lock: OwnKeyLock) {
    loop {
        tokio::time::sleep(HEARTBEAT_EVERY).await;
        for kp in [&keys.own, &keys.partner] {
            let _guard = own_lock.lock().await;
            if let Err(e) = chain.heartbeat(kp).await {
                tracing::warn!("{e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh address per run: no real account in the source.
    fn fresh_address() -> String {
        kenter_crypto::keypair::StellarKeypair::random().stellar_address()
    }

    fn named() -> Relay {
        Relay::new("relay.example.org")
    }

    #[test]
    fn the_relays_own_endpoint_for_this_node_is_accepted() {
        let me = fresh_address();
        #[allow(non_snake_case)]
        let ME = me.as_str();
        let ep = format!("https://{ME}.relay.example.org");
        valid_endpoint(&ep, &named(), ME).unwrap();
        // Hosts are case-insensitive; relays lowercase them.
        valid_endpoint(&ep.to_lowercase(), &named(), ME).unwrap();
        valid_endpoint(&format!("{ep}/"), &named(), ME).unwrap();
    }

    /// SA-1: a relay cannot make the node publish just anything.
    #[test]
    fn anything_else_is_refused() {
        let me = fresh_address();
        #[allow(non_snake_case)]
        let ME = me.as_str();
        let other = fresh_address();
        for ep in [
            String::new(),
            format!("http://{ME}.relay.example.org"),
            format!("https://{other}.relay.example.org"),
            format!("https://{ME}.evil.example"),
            format!("https://{ME}.relay.example.org.evil.example"),
            format!("https://{ME}.relay.example.org/path"),
            format!("https://{ME}"),
            format!("https://{ME}.relay.example.org\"><script>"),
            format!("https://{ME}.{}", "a".repeat(300)),
        ] {
            assert!(valid_endpoint(&ep, &named(), ME).is_err(), "accepted {ep:?}");
        }
    }

    /// A relay configured by IP (local development) may name any domain,
    /// over plain http only when configured insecure.
    #[test]
    fn a_dev_relay_by_ip_may_name_its_domain() {
        let me = fresh_address();
        #[allow(non_snake_case)]
        let ME = me.as_str();
        let dev = Relay { host: "127.0.0.1:8089".into(), secure: false };
        valid_endpoint(&format!("http://{ME}.relay.example.net"), &dev, ME).unwrap();
        // What a real dev relay sends: its public https address.
        valid_endpoint(&format!("https://{ME}.relay.example.net"), &dev, ME).unwrap();
        assert!(valid_endpoint(&format!("ftp://{ME}.relay.example.net"), &dev, ME).is_err());
    }
}
