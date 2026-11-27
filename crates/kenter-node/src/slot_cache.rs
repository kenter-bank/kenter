//! A short-lived cache of the slots extend requests name, so a burst of
//! requests costs the node's RPC a few reads instead of two per request.
//!
//! The extend endpoint is reachable by anyone through the relay. Before it
//! does any work for a request, a node checks it against the slot on chain
//! ([`SlotInfo::admits_next`]), which takes two RPC reads: the slot and the
//! latest ledger. Without a cache, junk naming a real slot costs the sender
//! one request and the node two reads, and on a free RPC with a quota
//! that's a way to cut a node off from the ledger it needs to confirm
//! links in honest prints.
//!
//! **A stale snapshot must never refuse an honest request.** A refused
//! extend makes the depositor wait out the serve time and skip the pair,
//! so a cache that refused on old data would let anyone who keeps a
//! node's snapshot of a slot warm get that node skipped. So:
//!
//! - **An admission from a snapshot stands.** Admitting on old data costs
//!   at most one wasted extend: the mint takes `confirm_link` only in
//!   order, from the assigned pair.
//! - **A final refusal stands.** "Final" means no later ledger can change
//!   it: the slot has left `Printing`, the chain is for another event, or
//!   the slot has already confirmed more links than the request carries.
//!   Each of those is permanent.
//! - **Any other refusal is checked again** against a snapshot read no
//!   earlier than the request arrived (the slot may since have been created,
//!   had its positions fixed, confirmed the link the request carries, or
//!   had a position skipped to this node). Re-reads of one slot are at
//!   least [`SlotCache::recheck_after`] apart, so even that path costs a
//!   bounded number of reads however many requests arrive.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kenter_client::{SlotInfo, TokenState};

/// How long a snapshot answers requests that it admits or finally refuses:
/// about one ledger.
pub const FRESH_FOR: Duration = Duration::from_secs(5);
/// Least time between two re-reads of one slot for a refusal that a later
/// ledger could overturn.
pub const RECHECK_AFTER: Duration = Duration::from_secs(1);
/// Snapshots older than this are dropped when a new one is stored, so the
/// map holds only slots requested recently.
const FORGET_AFTER: Duration = Duration::from_secs(60);

/// `(partial_public_key, node_a_public, node_b_public)` per link, as in
/// [`SlotInfo::admits_next`].
pub type Link = ([u8; 32], [u8; 32], [u8; 32]);

/// A slot as read at one moment: `None` if it did not exist.
#[derive(Debug)]
pub struct Snapshot {
    pub ledger: u32,
    pub slot: Option<SlotInfo>,
    pub at: Instant,
}

pub struct SlotCache {
    entries: Mutex<HashMap<u32, Arc<Snapshot>>>,
    /// Held while reading the chain, so concurrent requests for a slot
    /// wait for one read instead of each making their own.
    reading: tokio::sync::Mutex<()>,
    fresh_for: Duration,
    recheck_after: Duration,
}

impl Default for SlotCache {
    fn default() -> Self {
        Self::new(FRESH_FOR, RECHECK_AFTER)
    }
}

impl SlotCache {
    pub fn new(fresh_for: Duration, recheck_after: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            reading: tokio::sync::Mutex::new(()),
            fresh_for,
            recheck_after,
        }
    }

    /// Whether `me` should extend `slot_id` next, as
    /// [`SlotInfo::admits_next`] decides, from a snapshot where that is
    /// safe. `read` reads `(latest ledger, slot)` from the chain.
    pub async fn admits<F, Fut>(
        &self,
        slot_id: u32,
        me: &str,
        event_id: [u8; 32],
        prior_links: &[Link],
        read: F,
    ) -> Result<(), String>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<(u32, Option<SlotInfo>), String>>,
    {
        let arrived = Instant::now();
        let snap = self
            .snapshot(slot_id, |s| s.at.elapsed() < self.fresh_for, &read)
            .await?;
        let verdict = judge(&snap, slot_id, me, event_id, prior_links);
        if verdict.is_ok() || is_final(&snap, event_id, prior_links.len()) {
            return verdict;
        }
        // A later ledger could overturn this: look again, at a snapshot
        // read since the request arrived, and no sooner than
        // `recheck_after` after the last read of this slot.
        let not_before = arrived.max(snap.at + self.recheck_after);
        tokio::time::sleep(not_before.saturating_duration_since(Instant::now())).await;
        let fresh = self.snapshot(slot_id, |s| s.at >= not_before, &read).await?;
        judge(&fresh, slot_id, me, event_id, prior_links)
    }

    /// The stored snapshot of `slot_id` if `good` accepts it, else a new one.
    async fn snapshot<F, Fut>(
        &self,
        slot_id: u32,
        good: impl Fn(&Snapshot) -> bool,
        read: &F,
    ) -> Result<Arc<Snapshot>, String>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<(u32, Option<SlotInfo>), String>>,
    {
        if let Some(s) = self.stored(slot_id).filter(|s| good(s)) {
            return Ok(s);
        }
        let _one_read = self.reading.lock().await;
        // Someone else may have read it while we waited.
        if let Some(s) = self.stored(slot_id).filter(|s| good(s)) {
            return Ok(s);
        }
        let at = Instant::now();
        let (ledger, slot) = read().await?;
        let snap = Arc::new(Snapshot { ledger, slot, at });
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.retain(|_, s| s.at.elapsed() < FORGET_AFTER);
        entries.insert(slot_id, Arc::clone(&snap));
        Ok(snap)
    }

    fn stored(&self, slot_id: u32) -> Option<Arc<Snapshot>> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&slot_id)
            .cloned()
    }

    /// How many slots are held. For tests.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn judge(snap: &Snapshot, slot_id: u32, me: &str, event_id: [u8; 32], prior_links: &[Link]) -> Result<(), String> {
    match &snap.slot {
        None => Err(format!("slot {slot_id} does not exist")),
        Some(slot) => slot.admits_next(me, event_id, prior_links, snap.ledger),
    }
}

/// Whether no later ledger can turn this snapshot's refusal into an
/// admission. See the module docs.
fn is_final(snap: &Snapshot, event_id: [u8; 32], links: usize) -> bool {
    match &snap.slot {
        None => false,
        Some(slot) => {
            slot.state != TokenState::Printing
                || slot.event_id != event_id
                || slot.partial_keys.len() > links
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use kenter_crypto::keypair::StellarKeypair;

    const EVENT: [u8; 32] = [7; 32];

    struct Pairs {
        a: StellarKeypair,
        b: StellarKeypair,
        c: StellarKeypair,
        d: StellarKeypair,
    }

    fn pairs() -> Pairs {
        Pairs {
            a: StellarKeypair::random(),
            b: StellarKeypair::random(),
            c: StellarKeypair::random(),
            d: StellarKeypair::random(),
        }
    }

    /// A closed two-pair slot: link 0 by (a, b), link 1 by (c, d), with
    /// `confirmed` links done.
    fn slot(p: &Pairs, confirmed: usize) -> SlotInfo {
        let addr = |k: &StellarKeypair| k.stellar_address();
        SlotInfo {
            slot_id: 3,
            depositor: addr(&p.a),
            amount: 10_000_000,
            total_pairs: 2,
            pairs: vec![(addr(&p.a), addr(&p.b)), (addr(&p.c), addr(&p.d))],
            completed_links: confirmed as u32,
            state: TokenState::Printing,
            event_id: EVENT,
            partial_keys: (0..confirmed).map(|i| [i as u8 + 1; 32]).collect(),
            beacon_round: 1,
            seed: Some([0; 32]),
            claim_deadline: 10,
            claims: Vec::new(),
            closed: true,
            last_progress: 0,
            created_at: 1,
            filled: true,
            volunteers: 0,
            lapsed: false,
        }
    }

    /// The one prior link a request for link 1 carries: link 0, by (a, b).
    fn link0(p: &Pairs) -> Vec<Link> {
        vec![([1; 32], p.a.raw_public(), p.b.raw_public())]
    }

    /// A chain whose slot is `state()` at the time of each read, counting reads.
    struct Chain {
        reads: AtomicUsize,
        state: Mutex<Option<SlotInfo>>,
    }

    impl Chain {
        fn new(s: Option<SlotInfo>) -> Arc<Self> {
            Arc::new(Self { reads: AtomicUsize::new(0), state: Mutex::new(s) })
        }
        fn set(&self, s: Option<SlotInfo>) {
            *self.state.lock().unwrap() = s;
        }
        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
        fn reader(self: &Arc<Self>) -> impl Fn() -> std::future::Ready<Result<(u32, Option<SlotInfo>), String>> {
            let me = Arc::clone(self);
            move || {
                me.reads.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok((100, me.state.lock().unwrap().clone())))
            }
        }
    }

    fn cache() -> SlotCache {
        SlotCache::new(Duration::from_secs(5), Duration::from_millis(200))
    }

    #[tokio::test]
    async fn a_burst_of_admitted_requests_costs_one_read() {
        let p = pairs();
        let chain = Chain::new(Some(slot(&p, 1)));
        let c = cache();
        let me = p.c.stellar_address();
        for _ in 0..20 {
            c.admits(3, &me, EVENT, &link0(&p), chain.reader()).await.unwrap();
        }
        assert_eq!(chain.reads(), 1);
    }

    #[tokio::test]
    async fn junk_for_a_finished_slot_costs_one_read() {
        let p = pairs();
        let mut done = slot(&p, 2);
        done.state = TokenState::Active;
        let chain = Chain::new(Some(done));
        let c = cache();
        let me = p.c.stellar_address();
        for _ in 0..20 {
            assert!(c.admits(3, &me, EVENT, &link0(&p), chain.reader()).await.is_err());
        }
        assert_eq!(chain.reads(), 1, "a final refusal must come from the snapshot");
    }

    #[tokio::test]
    async fn a_snapshot_from_before_the_confirm_does_not_refuse_the_honest_request() {
        // Someone asks about the slot before link 0 is confirmed, so the
        // node holds a snapshot with no links. Link 0 then lands, and the
        // depositor's real request for link 1 arrives.
        let p = pairs();
        let chain = Chain::new(Some(slot(&p, 0)));
        let c = cache();
        let me = p.c.stellar_address();
        assert!(c.admits(3, &me, EVENT, &link0(&p), chain.reader()).await.is_err());
        chain.set(Some(slot(&p, 1)));
        c.admits(3, &me, EVENT, &link0(&p), chain.reader())
            .await
            .expect("the honest request must be admitted on a fresh read");
    }

    #[tokio::test]
    async fn a_slot_unknown_when_first_asked_is_read_again() {
        let p = pairs();
        let chain = Chain::new(None);
        let c = cache();
        let me = p.c.stellar_address();
        assert!(c.admits(3, &me, EVENT, &link0(&p), chain.reader()).await.is_err());
        chain.set(Some(slot(&p, 1)));
        c.admits(3, &me, EVENT, &link0(&p), chain.reader()).await.unwrap();
    }

    #[tokio::test]
    async fn a_skip_to_this_node_is_seen() {
        // Position 1 is (c, d) in the snapshot; a skip gives it to a
        // runner-up, who then gets the depositor's request.
        let p = pairs();
        let chain = Chain::new(Some(slot(&p, 1)));
        let c = cache();
        let runner_up = StellarKeypair::random();
        let me = runner_up.stellar_address();
        assert!(c.admits(3, &me, EVENT, &link0(&p), chain.reader()).await.is_err());
        let mut skipped = slot(&p, 1);
        skipped.pairs[1] = (me.clone(), StellarKeypair::random().stellar_address());
        chain.set(Some(skipped));
        c.admits(3, &me, EVENT, &link0(&p), chain.reader()).await.unwrap();
    }

    #[tokio::test]
    async fn re_reads_for_refusals_a_later_ledger_could_change_are_spaced() {
        // A stranger claiming to be position 1 on a live slot: refused,
        // and not final, so it is checked again, but no oftener than
        // `recheck_after` however fast the requests come.
        let p = pairs();
        let chain = Chain::new(Some(slot(&p, 1)));
        let c = cache();
        let stranger = StellarKeypair::random().stellar_address();
        let start = Instant::now();
        for _ in 0..10 {
            assert!(c.admits(3, &stranger, EVENT, &link0(&p), chain.reader()).await.is_err());
        }
        let elapsed = start.elapsed();
        let max_reads = 2 + (elapsed.as_millis() / 200) as usize;
        assert!(
            chain.reads() <= max_reads,
            "{} reads in {elapsed:?}; at most {max_reads} allowed",
            chain.reads()
        );
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_read() {
        let p = pairs();
        let chain = Chain::new(Some(slot(&p, 1)));
        let c = Arc::new(cache());
        let me = p.c.stellar_address();
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let (c, chain, me, links) = (Arc::clone(&c), Arc::clone(&chain), me.clone(), link0(&p));
            tasks.push(tokio::spawn(async move {
                c.admits(3, &me, EVENT, &links, chain.reader()).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        assert_eq!(chain.reads(), 1);
    }

    #[tokio::test]
    async fn a_read_error_is_a_refusal_and_is_not_stored() {
        let p = pairs();
        let c = cache();
        let me = p.c.stellar_address();
        let failing = || std::future::ready(Err::<(u32, Option<SlotInfo>), _>("rpc down".to_string()));
        assert_eq!(c.admits(3, &me, EVENT, &link0(&p), failing).await, Err("rpc down".into()));
        assert!(c.is_empty());
    }
}
