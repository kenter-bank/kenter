//! The pair's part in choosing prints (`docs/architecture/node-selection.md`):
//! register the pair once, watch the mint for slots, seed any whose beacon
//! round is out and that this pair would claim, and claim positions the pair
//! might win.
//!
//! **What it can be made to spend.** Every slot anyone opens is visible
//! here, so a stranger can make the node *consider* as many as they like.
//! What it *spends* is bounded:
//!
//! - **An allowance per day, in XLM**, not a count per hour. It is
//!   [`DAILY_SHARE`] of whatever the address can spend above
//!   [`LOW_BALANCE`], so a node with a small float spends little, and a
//!   node at the floor spends nothing. Transactions are charged at
//!   generous estimates ([`CLAIM_COST`], [`SEED_COST`]). A sent transaction
//!   is charged whether it lands or not. A failed simulation sends nothing
//!   and costs nothing.
//! - **The threshold tightens as the allowance runs down.** The sortition
//!   probability (`threshold`) is scaled by the share of the allowance
//!   left. A stranger flooding the mint with slots drains the allowance
//!   into the node's best scores rather than its first ones, so the claims
//!   it has left go where it is most likely to win.
//! - **A reserve for short lists** ([`SHORT_LIST_RESERVE`]): claims on a
//!   slot whose window has passed with positions unfilled draw on their own
//!   part of the allowance, so an honest print short of nodes is not left
//!   waiting by a flood that has spent the rest.
//! - **Seeds only for slots this pair would claim**. The seed can be
//!   computed from the beacon round before it is on chain
//!   (`selection_seed`), so a node scores itself first. Among the nodes that
//!   would claim, the lower the score, the sooner a node seeds. The slot is
//!   re-read just before sending, so usually exactly one node pays.
//!   If the beacon cannot be fetched, the same order applies under the
//!   mint's fallback seed (`fallback_seed`) once it opens, so issuance
//!   continues while drand is down.
//!
//! The real price of a flood is the mint's forfeit, which the person
//! opening the slots pays. This allowance only makes sure a flood cannot
//! empty the node.
//!
//! **Abandoned prints it worked on are cleared here.** A node that
//! confirmed a link on a print the depositor then abandoned is paid when
//! the slot is settled, but only within about a day of its expiry, while
//! the slot's draw still names the node.
//! So once such a slot expires, this clears it ([`crate::daemon::Owed`]).
//!
//! **Pairing is never undone here.** The pair registers once
//! (`register_pair`). If the mint has either address paired with someone
//! else, the node reports it and claims nothing. Dissolving a registration
//! is the operator's decision, not the daemon's.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kenter_client::{
    Beacon, MintClient, RosterClient, SelectionInfo, SlotInfo, TxBuilder, fallback_seed,
    selection_score, selection_seed,
};

use crate::chain::{Chain, LOW_BALANCE, spendable};
use crate::daemon::OwnKeyLock;
use crate::keys::PairKeys;
use crate::status::Reporter;

/// How often the mint is read.
const TICK: Duration = Duration::from_secs(5);
/// Slots before the current one looked at on start, in case one opened
/// just before the daemon did.
const LOOKBACK: u32 = 32;
/// What one claim is charged against the allowance, in stroops. A claim
/// measured about 0.001 XLM on testnet (fee charged 9,520); with the
/// contention margin declared it can be several times that, and most of it
/// is refunded.
pub const CLAIM_COST: i128 = 60_000;
/// The most the selection submitter will sign as a resource fee, in
/// stroops (0.02 XLM): a few times what a claim really costs, so what is
/// signed and what is budgeted stay close. The
/// client's default cap is 5 XLM.
pub const SELECTION_FEE_CAP: u64 = 200_000;
/// What one seed is charged, in stroops (about 0.0015 XLM measured).
pub const SEED_COST: i128 = 30_000;
/// Share of the spendable XLM above [`LOW_BALANCE`] that selection may use
/// in a day.
pub const DAILY_SHARE: f64 = 0.2;
/// Part of the day's allowance kept for filling short lists after the
/// window.
pub const SHORT_LIST_RESERVE: f64 = 0.25;
/// How long after a round is published the depositor gets to seed it
/// before any node does.
pub const SEED_GRACE: Duration = Duration::from_secs(8);
/// Over how long after the grace the nodes that would claim spread their
/// seeding, lowest score first.
pub const SEED_SPREAD: Duration = Duration::from_secs(20);
/// Beacon fetches per slot before a node gives up seeding it.
const SEED_FETCHES: u32 = 10;
/// Sortition safety factor `C`: expected claims per print are
/// `C · (k + b)`.
const SORTITION_C: f64 = 3.0;
/// How often the roster's size and the selection parameters are re-read.
const SLOW: Duration = Duration::from_secs(10 * 60);
/// How often slots this node confirmed on are checked for abandonment.
const OWED_CHECK: Duration = Duration::from_secs(60);
/// Attempts to clear one abandoned slot before leaving it to others.
const CLEAR_TRIES: u32 = 5;
/// What one clear is charged against the allowance, in stroops. It can
/// create the node's balance entry, which on mainnet prepays 120 days of
/// rent (~0.02 XLM); unmeasured, so generous.
pub const CLEAR_COST: i128 = 400_000;
/// The most a clear will sign as a resource fee, in stroops (0.05 XLM).
pub const CLEAR_FEE_CAP: u64 = 500_000;
/// How often an unfinished registration is retried.
const REGISTER_RETRY: Duration = Duration::from_secs(30);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// How long one slot's evidence counts toward the live-pair estimate.
const LIVE_WINDOW: Duration = DAY;
/// At most this many slots of evidence are kept.
const LIVE_SLOTS: usize = 50;
/// Slots of evidence below which the roster count is used instead.
const LIVE_MIN_SLOTS: usize = 3;

/// How many pairs are live, estimated from the claims seen on recent slots
/// (`docs/architecture/node-selection.md`, the live-pair estimate).
///
/// The roster counts every pair that joined and has not left, which
/// includes machines that are off and nodes whose keys are gone. With `P`
/// live pairs, a slot's `k`-th lowest claim score is about `k / (P + 1)`,
/// and every live pair claims its very lowest scores whatever its
/// allowance, so the estimate depends on no one's threshold, and a
/// throttled network does not move it.
#[derive(Default)]
struct LivePairs {
    /// `(when, j, the j-th lowest score as a fraction)`.
    obs: VecDeque<(Instant, f64, f64)>,
}

impl LivePairs {
    fn record(&mut self, seen: Option<(u32, f64)>) {
        let Some((j, s)) = seen else { return };
        if j == 0 || s <= 0.0 {
            return;
        }
        self.obs.push_back((Instant::now(), j as f64, s));
        while self.obs.len() > LIVE_SLOTS {
            self.obs.pop_front();
        }
    }

    /// The estimate, never above the roster's count and never below one.
    /// The roster's count until there is enough evidence.
    fn estimate(&mut self, roster_pairs: u32) -> u32 {
        while self.obs.front().is_some_and(|(t, _, _)| t.elapsed() > LIVE_WINDOW) {
            self.obs.pop_front();
        }
        let roster_pairs = roster_pairs.max(1);
        if self.obs.len() < LIVE_MIN_SLOTS {
            return roster_pairs;
        }
        let (j, s) = self.obs.iter().fold((0.0, 0.0), |(j, s), (_, ji, si)| (j + ji, s + si));
        ((j / s - 1.0).round().max(1.0) as u32).clamp(1, roster_pairs)
    }
}

/// One slot's evidence for [`LivePairs`]: `(j, s_j)`, the `j`-th lowest of
/// its claim scores as a fraction, with `j = k` or fewer if fewer claimed.
/// `None` for a slot with no claims.
pub fn evidence(scores: &[[u8; 32]], k: usize) -> Option<(u32, f64)> {
    let mut f: Vec<f64> = scores.iter().map(score_fraction).collect();
    f.sort_by(f64::total_cmp);
    let j = k.min(f.len());
    (j > 0).then(|| (j as u32, f[j - 1]))
}

/// A day's spending, in stroops, as a sliding window.
#[derive(Default)]
struct Spent {
    log: VecDeque<(Instant, i128)>,
}

impl Spent {
    fn today(&mut self) -> i128 {
        while self.log.front().is_some_and(|(t, _)| t.elapsed() > DAY) {
            self.log.pop_front();
        }
        self.log.iter().map(|(_, x)| x).sum()
    }

    fn spend(&mut self, stroops: i128) {
        self.log.push_back((Instant::now(), stroops));
    }
}

/// What is left of today's allowance, as a share of it: 1 untouched, 0 spent.
fn left(allowance: i128, spent: i128) -> f64 {
    if allowance <= 0 {
        return 0.0;
    }
    ((allowance - spent).max(0) as f64 / allowance as f64).clamp(0.0, 1.0)
}

/// Whether a pair with `score` should claim on `slot`: the mint would take
/// it, and either the sortition threshold says it might win, or the window
/// has passed short of positions.
///
/// `share` is the part of the regular allowance left. The threshold is
/// scaled by it, so a draining allowance goes to the best scores.
/// The short-list case has its own reserve and ignores it.
pub fn worth_claiming(slot: &SlotInfo, score: &[u8; 32], ledger: u32, pairs_on_roster: u32, share: f64) -> bool {
    let k = slot.positions();
    let cap = 2 * k as usize;
    if slot.claims.len() >= cap && slot.claims.last().is_some_and(|c| c.score <= *score) {
        return false; // the mint would answer ClaimNotCompetitive
    }
    if slot.seed.is_some() && ledger > slot.claim_deadline {
        return (slot.claims.len() as u32) < k;
    }
    let p = threshold(slot, pairs_on_roster, share);
    if p >= 1.0 {
        return true; // a small roster, and allowance to spare: every pair claims
    }
    score_fraction(score) < p
}

/// The sortition probability for `slot`, scaled by `share` (see
/// [`worth_claiming`]).
fn threshold(slot: &SlotInfo, pairs_on_roster: u32, share: f64) -> f64 {
    SORTITION_C * (2 * slot.positions()) as f64 / pairs_on_roster.max(1) as f64 * share
}

/// Where a pair falls among those that would act, 0 first and 1 last: its
/// score fraction over the threshold. Spreading turns over this rather than
/// the raw fraction keeps them apart when only low scores qualify.
fn turn(score: &[u8; 32], p: f64) -> f64 {
    if p >= 1.0 {
        return score_fraction(score);
    }
    (score_fraction(score) / p.max(f64::MIN_POSITIVE)).clamp(0.0, 1.0)
}

/// The longest a pair waits for its turn to fill a short list, in ledgers.
/// Inside the print's own patience for a short draw (`kenter-print`'s
/// `CLAIM_GRACE_LEDGERS`, 24), so the last turns still land before the
/// depositor gives up.
pub const SHORT_LIST_MAX_WAIT: u32 = 20;

/// The ledger after the window at which a pair with `score` claims on a
/// short list.
///
/// By expected rank, not a fixed spread: with `pairs` eligible and
/// `missing` positions open, about `missing` pairs fall in each ledger
/// whatever the roster's size, best scores first.
pub fn short_list_turn(score: &[u8; 32], pairs: u32, missing: u32) -> u32 {
    let rank = score_fraction(score) * pairs.max(1) as f64;
    ((rank / missing.max(1) as f64) as u32).min(SHORT_LIST_MAX_WAIT)
}

/// A score as a fraction of the largest possible: its first 8 bytes.
fn score_fraction(score: &[u8; 32]) -> f64 {
    u64::from_be_bytes(score[..8].try_into().unwrap()) as f64 / u64::MAX as f64
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run until aborted.
pub async fn run(
    chain: Arc<Chain>,
    keys: Arc<PairKeys>,
    own_lock: OwnKeyLock,
    reporter: Option<Reporter>,
    register_request: Option<std::path::PathBuf>,
    owed: Option<crate::daemon::Owed>,
) {
    // The development form (`legacy.rs`) has no status file to write.
    let report = |f: &dyn Fn(&mut crate::status::DaemonStatus)| {
        if let Some(r) = &reporter {
            r.set(f);
        }
    };
    let own = keys.own.stellar_address();
    let partner = keys.partner.stellar_address();
    let net = chain.net.clone();
    let reader = MintClient::new(TxBuilder::read_only(net.rpc_client(), &own), &net.mint);
    let mut submitter = MintClient::new(
        TxBuilder::new(net.rpc_client(), keys.own.clone()).with_max_resource_fee(SELECTION_FEE_CAP),
        &net.mint,
    );
    // Registration is once per pair and prepays its records' rent, which
    // is far above what a claim costs, so it signs under the client's
    // ordinary limit, not SELECTION_FEE_CAP. Under the cap it would be
    // refused every time, and a new pair could never be drawn.
    let mut registrar = MintClient::new(TxBuilder::new(net.rpc_client(), keys.own.clone()), &net.mint);
    // Clearing an abandoned print has its own cap, sized for the call
    // not the registrar's 5 XLM, and not the claim cap either,
    // since it can create a balance entry.
    let mut clearer = MintClient::new(
        TxBuilder::new(net.rpc_client(), keys.own.clone()).with_max_resource_fee(CLEAR_FEE_CAP),
        &net.mint,
    );
    let mut last_register: Option<Instant> = None;
    let beacon = match Beacon::quicknet() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("no beacon client, so no seeding: {e}");
            return;
        }
    };

    let mut registered_at: Option<u32> = None;
    let mut last_slow: Option<Instant> = None;
    let mut pairs_on_roster: u32 = 1;
    let mut live = LivePairs::default();
    let mut last_estimate: Option<u32> = None;
    let mut sel: Option<SelectionInfo> = None;
    let mut next_seen: Option<u32> = None;
    // Slots being watched, and what this node has settled about each.
    // Everything keyed by slot is dropped when the slot leaves `open`,
    // so nothing grows without bound.
    let mut open: BTreeSet<u32> = BTreeSet::new();
    let mut decided: HashSet<u32> = HashSet::new();
    let mut claimed: HashSet<u32> = HashSet::new();
    let mut seeded_by_us: HashSet<u32> = HashSet::new();
    let mut fetches: HashMap<u32, u32> = HashMap::new();
    let mut signatures: HashMap<u32, [u8; 96]> = HashMap::new();
    let mut regular = Spent::default();
    let mut short_list = Spent::default();
    let mut window: Option<u32> = None;
    let mut last_owed: Option<Instant> = None;
    let mut clear_tries: HashMap<u32, u32> = HashMap::new();

    loop {
        tokio::time::sleep(TICK).await;

        // Slow work: the roster's size, the selection parameters, and the
        // pair's registration until it is done.
        if last_slow.is_none_or(|t| t.elapsed() > SLOW) {
            last_slow = Some(Instant::now());
            let mut roster = RosterClient::new(TxBuilder::read_only(net.rpc_client(), &own), &net.roster);
            if let Ok(n) = roster.get_node_count().await {
                pairs_on_roster = (n / 2).max(1);
            }
            if sel.is_none() {
                sel = submitter.selection().await.ok();
            }
        }
        // Until the pair is registered it can be drawn for nothing, so this
        // is retried every REGISTER_RETRY rather than on the slow tick.
        // The operator can ask for an attempt now (Settings, "Register now").
        let asked = register_request.as_ref().is_some_and(|p| p.exists() && std::fs::remove_file(p).is_ok());
        if registered_at.is_none() && (asked || last_register.is_none_or(|t| t.elapsed() > REGISTER_RETRY)) {
            last_register = Some(Instant::now());
            registered_at = register(&mut registrar, &keys, &own_lock, reporter.as_ref(), &own, &partner).await;
            if registered_at.is_some() {
                report(&|s| {
                    s.pair_registered = true;
                    if s.detail.as_deref().is_some_and(|d| d.starts_with("not yet registered")) {
                        s.detail = None;
                    }
                });
            }
        }
        let (Some(sel), Some(registered)) = (sel.as_ref(), registered_at) else {
            continue;
        };

        let Ok(ledger) = net.rpc_client().get_latest_ledger().await else { continue };

        // Abandoned prints this node confirmed on: clear them once expired,
        // while the draw still names the node, so it is paid.
        if let Some(owed) = owed.as_ref()
            && last_owed.is_none_or(|t| t.elapsed() > OWED_CHECK)
        {
            last_owed = Some(Instant::now());
            if window.is_none() {
                window = reader.max_print_ledgers().await.ok();
            }
            let ids: Vec<u32> = owed.lock().map(|o| o.iter().copied().collect()).unwrap_or_default();
            // Inside the same limits as selection: above the floor,
            // and charged to the day's allowance.
            let float = match net.rpc_client().get_holdings(&own).await {
                Ok(Some(h)) => (spendable(h.native, h.subentries) - LOW_BALANCE).max(0),
                _ => 0,
            };
            let allowance = (float as f64 * DAILY_SHARE * (1.0 - SHORT_LIST_RESERVE)) as i128;
            if let (Some(window), false) = (window, ids.is_empty())
                && let Ok(slots) = reader.get_slots(&ids).await
            {
                for id in ids {
                    let settled = match slots.get(&id) {
                        None => true, // registered, cancelled or cleared
                        // A volunteer's fee is burned whoever settles, so
                        // clearing would spend XLM for nothing.
                        Some(s) if paid_nothing(s, &own) => true,
                        Some(s) if ledger > s.created_at.saturating_add(window) => {
                            if regular.today() + CLEAR_COST > allowance {
                                false // try again when the allowance allows
                            } else {
                                let _one = own_lock.lock().await;
                                let _ = clearer.tx_mut().refresh_sequence().await;
                                let result = clearer.clear_expired_slot(id).await;
                                if result.is_ok()
                                    || matches!(result, Err(kenter_client::ClientError::TransactionFailed { .. }))
                                {
                                    regular.spend(CLEAR_COST);
                                }
                                match result {
                                    Ok(refund) => {
                                        tracing::info!(slot = id, refund, "cleared an abandoned print this node worked on");
                                        true
                                    }
                                    Err(e) => {
                                        let n = clear_tries.entry(id).or_insert(0);
                                        *n += 1;
                                        tracing::info!(slot = id, tries = *n, "abandoned print not cleared: {e}");
                                        *n >= CLEAR_TRIES
                                    }
                                }
                            }
                        }
                        Some(_) => false, // still inside its window
                    };
                    if settled {
                        clear_tries.remove(&id);
                        if let Ok(mut o) = owed.lock() {
                            o.remove(&id);
                        }
                    }
                }
            }
        }

        // The pairs actually competing, not the roster's count ([`LivePairs`]).
        // Worked out before the slots are read, so a new estimate is
        // logged when it changes, not only once another print opens.
        let roster_pairs = pairs_on_roster;
        let pairs_on_roster = live.estimate(roster_pairs);
        if last_estimate != Some(pairs_on_roster) {
            last_estimate = Some(pairs_on_roster);
            tracing::info!(live = pairs_on_roster, roster = roster_pairs, "live pairs estimated");
        }

        let Ok(next) = reader.next_slot_id().await else { continue };
        let from = next_seen.unwrap_or(next.saturating_sub(LOOKBACK));
        open.extend(from..next);
        next_seen = Some(next);
        if open.is_empty() {
            continue;
        }
        let ids: Vec<u32> = open.iter().copied().collect();
        let Ok(slots) = reader.get_slots(&ids).await else { continue };

        // Today's allowance, from what the address can spend now.
        let float = match net.rpc_client().get_holdings(&own).await {
            Ok(Some(h)) => (spendable(h.native, h.subentries) - LOW_BALANCE).max(0),
            _ => 0,
        };
        let daily = (float as f64 * DAILY_SHARE) as i128;
        let regular_allowance = (daily as f64 * (1.0 - SHORT_LIST_RESERVE)) as i128;
        let short_allowance = daily - regular_allowance;
        let share = left(regular_allowance, regular.today());

        // Stop watching a slot, and forget what was kept about it.
        macro_rules! done {
            ($id:expr) => {{
                let id = $id;
                open.remove(&id);
                decided.remove(&id);
                seeded_by_us.remove(&id);
                fetches.remove(&id);
                signatures.remove(&id);
            }};
        }

        for id in ids {
            let Some(slot) = slots.get(&id) else {
                claimed.remove(&id);
                done!(id); // registered, cancelled or expired
                continue;
            };
            // Its draw is gone: nothing can be seeded or claimed.
            if slot.lapsed {
                claimed.remove(&id);
                done!(id);
                continue;
            }
            if slot.positions_fixed(ledger) {
                // Evidence for the live-pair estimate: every claim the
                // slot kept, the selected pairs included once it closed.
                if let Some(seed) = slot.seed {
                    let mut scores: Vec<[u8; 32]> = slot.claims.iter().map(|c| c.score).collect();
                    if slot.closed && slot.pairs.len() >= 2 {
                        for (a, b) in &slot.pairs[1..slot.pairs.len() - 1] {
                            if let Ok(s) = selection_score(seed, a, b) {
                                scores.push(s);
                            }
                        }
                    }
                    live.record(evidence(&scores, slot.positions() as usize));
                }
                if claimed.remove(&id) {
                    let won = slot
                        .chain(ledger)
                        .is_some_and(|c| c.iter().any(|(a, b)| *a == own || *b == own));
                    if won {
                        report(&|s| s.claims_won += 1);
                        tracing::info!(slot = id, "selected for a print");
                    }
                }
                done!(id);
                continue;
            }
            // Only a pair registered before the request may claim,
            // so only such a slot is worth seeding either.
            if registered >= slot.created_at {
                done!(id);
                continue;
            }

            // ── Seed: only a slot this pair would claim, after the grace,
            // lowest scores first. ──
            let Some(seed) = slot.seed else {
                if seeded_by_us.contains(&id) || share <= 0.0 {
                    continue;
                }
                let due = sel.round_time(slot.beacon_round) + SEED_GRACE.as_secs();
                if unix_now() < due {
                    continue;
                }
                // The round's signature, if a mirror has it. A failed fetch
                // is retried next tick, up to `SEED_FETCHES`.
                let sig = match signatures.get(&id) {
                    Some(s) => Some(*s),
                    None => {
                        let n = fetches.entry(id).or_insert(0);
                        if *n >= SEED_FETCHES {
                            None
                        } else {
                            *n += 1;
                            match beacon.signature(slot.beacon_round).await {
                                Ok(s) => {
                                    signatures.insert(id, s);
                                    Some(s)
                                }
                                Err(e) => {
                                    tracing::debug!(slot = id, "beacon: {e}");
                                    None
                                }
                            }
                        }
                    }
                };
                // Without the round, only the mint's fallback can seed, and
                // only once it opens: the beacon is down, or unreachable from
                // here and nobody else has posted it in that time.
                let fallback_due = sel.fallback_time(slot.beacon_round) + SEED_GRACE.as_secs();
                let (would_be, start) = match &sig {
                    Some(sig) => (selection_seed(&net.mint, id, sig), due),
                    None if unix_now() >= fallback_due => {
                        (fallback_seed(&net.mint, id, slot.beacon_round), fallback_due)
                    }
                    None => continue,
                };
                let Ok(would_be) = would_be else { continue };
                let Ok(score) = selection_score(would_be, &own, &partner) else { continue };
                if !worth_claiming(slot, &score, ledger, pairs_on_roster, share) {
                    continue;
                }
                let p = threshold(slot, pairs_on_roster, share);
                let my_turn = start + (turn(&score, p) * SEED_SPREAD.as_secs_f64()) as u64;
                if unix_now() < my_turn {
                    continue;
                }
                // Somebody may have just seeded it.
                if reader.get_slot(id).await.ok().flatten().is_none_or(|s| s.seed.is_some()) {
                    continue;
                }
                seeded_by_us.insert(id);
                let _one = own_lock.lock().await;
                let _ = submitter.tx_mut().refresh_sequence().await;
                let sent = match sig {
                    Some(sig) => submitter.seed_print(id, sig).await,
                    None => submitter.seed_fallback(id).await,
                };
                match sent {
                    Ok(_) => {
                        regular.spend(SEED_COST);
                        tracing::info!(slot = id, fallback = sig.is_none(), "seeded");
                    }
                    Err(e) => {
                        // Sent and failed still cost the fee.
                        if matches!(e, kenter_client::ClientError::TransactionFailed { .. }) {
                            regular.spend(SEED_COST);
                        }
                        tracing::debug!(slot = id, "not seeded: {e}");
                    }
                }
                continue;
            };

            // ── Claim. ──
            if decided.contains(&id) {
                continue;
            }
            if slot.claims.iter().any(|c| c.pair.0 == own || c.pair.1 == own) {
                decided.insert(id);
                continue;
            }
            let Ok(score) = selection_score(seed, &own, &partner) else {
                decided.insert(id);
                continue;
            };
            let short = ledger > slot.claim_deadline;
            if !worth_claiming(slot, &score, ledger, pairs_on_roster, share) {
                // Not now. After the window a short list can change that,
                // so only a slot still inside it is settled for good.
                if !short {
                    decided.insert(id);
                }
                continue;
            }
            if short {
                // Every pair qualifies once the window passes short, and
                // the mint takes only k: best scores go first, a ledger or
                // so apart, and each re-reads the slot first.
                let missing = slot.positions().saturating_sub(slot.claims.len() as u32);
                let my_ledger = slot.claim_deadline + 1 + short_list_turn(&score, pairs_on_roster, missing);
                if ledger < my_ledger {
                    continue;
                }
                let fresh = reader.get_slot(id).await.ok().flatten();
                if fresh.is_none_or(|f| f.claims.len() as u32 >= f.positions()) {
                    continue;
                }
            }
            let (spent, allowance) = if short {
                (short_list.today(), short_allowance)
            } else {
                (regular.today(), regular_allowance)
            };
            if spent + CLAIM_COST > allowance {
                let why = if float == 0 {
                    "too little XLM to claim prints"
                } else {
                    "today's claim allowance is spent"
                };
                report(&|s| s.detail = Some(why.into()));
                continue;
            }
            decided.insert(id);
            let _one = own_lock.lock().await;
            let _ = submitter.tx_mut().refresh_sequence().await;
            // Claims that could land first: the list's room left.
            let may_land_first = (2 * slot.positions()).saturating_sub(slot.claims.len() as u32);
            let result = submitter.claim_position(id, &keys.partner, may_land_first).await;
            let sent = match &result {
                Ok(_) => true,
                Err(e) => matches!(e, kenter_client::ClientError::TransactionFailed { .. }),
            };
            if sent {
                if short {
                    short_list.spend(CLAIM_COST);
                } else {
                    regular.spend(CLAIM_COST);
                }
            }
            match result {
                Ok(rank) => {
                    claimed.insert(id);
                    report(&|s| s.claims_made += 1);
                    tracing::info!(slot = id, rank, "claimed a position");
                }
                Err(e) => tracing::info!(slot = id, "claim not made: {e}"),
            }
        }
    }
}

/// Whether settling `slot` would pay `own` nothing: its fee there is a
/// volunteer's, burned whoever settles, or it confirmed no link the slot
/// still records.
fn paid_nothing(slot: &SlotInfo, own: &str) -> bool {
    let Some(i) = slot.pairs.iter().position(|(a, b)| a == own || b == own) else {
        return true;
    };
    let bit = if slot.pairs[i].0 == own { 2 * i } else { 2 * i + 1 };
    i as u32 >= slot.completed_links || bit >= 32 || slot.volunteers & (1 << bit) != 0
}

/// Register the pair with the mint if it is not yet. Returns the
/// registration ledger once registered.
///
/// Never unpairs: if either address is paired with someone else, that is
/// reported and the node claims nothing until the operator resolves it.
async fn register(
    mint: &mut MintClient,
    keys: &PairKeys,
    own_lock: &OwnKeyLock,
    reporter: Option<&Reporter>,
    own: &str,
    partner: &str,
) -> Option<u32> {
    let mine = mint.pair_of(own).await.ok()?;
    let theirs = mint.pair_of(partner).await.ok()?;
    match (mine, theirs) {
        (Some((p, at)), Some((q, _))) if p == partner && q == own => return Some(at),
        (None, None) => {}
        _ => {
            let msg = "the mint has this pair's addresses registered with other partners; \
                       it claims no prints until that pairing is undone on the mint (unpair)";
            tracing::warn!("{msg}");
            if let Some(r) = reporter {
                r.set(|s| s.detail = Some(msg.into()));
            }
            return None;
        }
    }
    let _one = own_lock.lock().await;
    let _ = mint.tx_mut().refresh_sequence().await;
    match mint.register_pair(&keys.partner).await {
        Ok(at) => {
            tracing::info!(ledger = at, "pair registered for selection");
            Some(at)
        }
        Err(e) => {
            // NodeTooNew among others: retried every REGISTER_RETRY. Said
            // in the status too, since a pair that cannot register is never
            // drawn and nothing else would show it.
            tracing::warn!("pair not registered yet: {e}");
            if let Some(r) = reporter {
                r.set(|s| s.detail = Some(format!("not yet registered for prints: {e}")));
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_client::{ClaimInfo, TokenState};

    fn slot(total: u32, claims: Vec<[u8; 32]>, deadline: u32) -> SlotInfo {
        SlotInfo {
            slot_id: 1,
            depositor: String::new(),
            amount: 0,
            total_pairs: total,
            pairs: vec![],
            completed_links: 0,
            state: TokenState::Printing,
            event_id: [0; 32],
            partial_keys: vec![],
            beacon_round: 1,
            seed: Some([1; 32]),
            claim_deadline: deadline,
            claims: claims
                .into_iter()
                .map(|score| ClaimInfo {
                    score,
                    pair: (String::new(), String::new()),
                    volunteer_a: false,
                    volunteer_b: false,
                })
                .collect(),
            closed: false,
            last_progress: 0,
            created_at: 0,
            filled: false,
            volunteers: 0,
            lapsed: false,
        }
    }

    #[test]
    fn a_small_roster_claims_everything_in_the_window() {
        // 3 pairs, k = 1: p = min(1, 3·2/3) = 1.
        assert!(worth_claiming(&slot(3, vec![], 100), &[0xff; 32], 50, 3, 1.0));
    }

    #[test]
    fn a_large_roster_claims_only_low_scores() {
        // 1000 pairs, k = 1: p = 6/1000.
        assert!(worth_claiming(&slot(3, vec![], 100), &[0; 32], 50, 1000, 1.0));
        assert!(!worth_claiming(&slot(3, vec![], 100), &[0x80; 32], 50, 1000, 1.0));
    }

    #[test]
    fn a_claim_the_mint_would_refuse_is_never_sent() {
        let full = slot(3, vec![[0x10; 32], [0x20; 32]], 100);
        assert!(!worth_claiming(&full, &[0x30; 32], 50, 3, 1.0));
        assert!(worth_claiming(&full, &[0x01; 32], 50, 3, 1.0));
    }

    #[test]
    fn after_the_window_only_a_short_list_is_worth_it() {
        assert!(worth_claiming(&slot(4, vec![[0x10; 32]], 100), &[0xff; 32], 101, 1000, 1.0));
        assert!(!worth_claiming(&slot(3, vec![[0x10; 32]], 100), &[0x01; 32], 101, 3, 1.0));
    }

    /// As the allowance drains, only better scores claim.
    #[test]
    fn a_draining_allowance_goes_to_the_best_scores() {
        let s = slot(3, vec![], 100);
        // 100 pairs, k = 1: p = 0.06 at a full allowance.
        let mid = {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&((0.04 * u64::MAX as f64) as u64).to_be_bytes());
            x
        };
        assert!(worth_claiming(&s, &mid, 50, 100, 1.0));
        assert!(!worth_claiming(&s, &mid, 50, 100, 0.5), "p = 0.03 < 0.04");
        assert!(!worth_claiming(&s, &[0; 32], 50, 100, 0.0), "nothing left, nothing claimed");
        // The short-list case does not depend on it.
        assert!(worth_claiming(&slot(4, vec![[0x10; 32]], 100), &mid, 101, 100, 0.0));
    }

    /// Turns spread over the whole window even when only low scores
    /// qualify.
    #[test]
    fn turns_spread_over_those_that_qualify() {
        let at = |f: f64| {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&((f * u64::MAX as f64) as u64).to_be_bytes());
            x
        };
        let p = 0.18;
        assert!(turn(&at(0.01), p) < 0.1);
        assert!(turn(&at(0.17), p) > 0.9, "the last qualifier goes near the end, not at 3.6 s");
        assert_eq!(turn(&at(0.5), 2.0), score_fraction(&at(0.5)));
    }

    /// About `missing` pairs per ledger, whatever the roster's size,
    /// and never past the print's patience.
    #[test]
    fn short_list_turns_go_by_expected_rank() {
        let at = |f: f64| {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&((f * u64::MAX as f64) as u64).to_be_bytes());
            x
        };
        // 100 pairs, 2 missing: the best two share ledger 0, the next two 1.
        assert_eq!(short_list_turn(&at(0.005), 100, 2), 0);
        assert_eq!(short_list_turn(&at(0.025), 100, 2), 1);
        // Out of the queue entirely at most SHORT_LIST_MAX_WAIT ledgers on.
        assert_eq!(short_list_turn(&at(0.99), 100, 1), SHORT_LIST_MAX_WAIT);
        // Three pairs, one missing: one a ledger.
        assert_eq!(short_list_turn(&at(0.5), 3, 1), 1);
    }

    #[test]
    fn the_allowance_is_a_day_wide() {
        let mut spent = Spent::default();
        spent.spend(CLAIM_COST);
        spent.spend(SEED_COST);
        assert_eq!(spent.today(), CLAIM_COST + SEED_COST);
        assert_eq!(left(100, 25), 0.75);
        assert_eq!(left(100, 200), 0.0);
        assert_eq!(left(0, 0), 0.0, "no float, no allowance");
    }

    fn at(f: f64) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&((f * u64::MAX as f64) as u64).to_be_bytes());
        x
    }

    /// The k-th lowest score of P live pairs is about k / (P + 1).
    #[test]
    fn the_live_estimate_comes_from_the_lowest_scores() {
        let mut live = LivePairs::default();
        assert_eq!(live.estimate(15), 15, "no evidence yet: the roster's count");
        // Four live pairs, one position: the lowest of four scores
        // averages 1/5.
        for scores in [vec![at(0.1), at(0.3)], vec![at(0.25)], vec![at(0.2), at(0.6)], vec![at(0.25), at(0.5)]] {
            live.record(evidence(&scores, 1));
        }
        assert_eq!(live.estimate(15), 4, "4 / (0.1 + 0.25 + 0.2 + 0.25) - 1 = 4");
        // Never above the roster, never below one.
        assert_eq!(live.estimate(3), 3);
    }

    /// A throttled network claims fewer high scores, and the
    /// estimate does not move, because it never looks at them.
    #[test]
    fn throttling_does_not_move_the_estimate() {
        // Three positions, forty live pairs: the third lowest is ~3/41.
        let full = [at(0.02), at(0.05), at(0.073), at(0.1), at(0.12), at(0.14)];
        let throttled = [at(0.02), at(0.05), at(0.073)];
        assert_eq!(evidence(&full, 3), evidence(&throttled, 3));
        let mut live = LivePairs::default();
        for _ in 0..3 {
            live.record(evidence(&throttled, 3));
        }
        assert_eq!(live.estimate(100), 40, "3 / 0.073 - 1, not capped at 2k = 6");
        assert_eq!(evidence(&[], 3), None);
        assert_eq!(evidence(&[at(0.3)], 3), Some((1, 0.3)), "fewer claims than positions");
    }

    /// A clear is sent only where settling would pay this node.
    #[test]
    fn a_clear_is_only_worth_it_where_the_node_is_paid() {
        let own = "ME".to_string();
        let mut s = slot(3, vec![], 100);
        s.pairs = vec![
            ("D".into(), "D".into()),
            (own.clone(), "PARTNER".into()),
            ("D".into(), "D".into()),
        ];
        s.completed_links = 2;
        assert!(!paid_nothing(&s, &own), "own link confirmed, not a volunteer");
        s.volunteers = 1 << 2; // pair 1's node_a
        assert!(paid_nothing(&s, &own), "a volunteer's fee is burned either way");
        s.volunteers = 1 << 3; // the partner volunteers, not this node
        assert!(!paid_nothing(&s, &own));
        s.completed_links = 1;
        assert!(paid_nothing(&s, &own), "its link was never confirmed");
        s.pairs = vec![("D".into(), "D".into()), ("D".into(), "D".into())];
        assert!(paid_nothing(&s, &own), "a lapsed slot no longer names it");
    }
}
