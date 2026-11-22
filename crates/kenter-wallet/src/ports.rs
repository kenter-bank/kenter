//! The ports the wallet core depends on. **Shells implement these with native or
//! wasm engines** — this crate never depends on a concrete transport or storage,
//! which is what keeps it wasm-safe.
//!
//! Both ports are `async`: on wasm the natural backends (browser `fetch`,
//! IndexedDB) are async, and native backends wrap trivially. Methods are used
//! through generic bounds, so `async fn` in traits needs no boxing.

use crate::error::Result;
use crate::models::{BackupRecord, HeldToken, OnChainToken, PendingReceive};

/// Read-only view of the chain the wallet needs for reconciliation.
///
/// Desktop implements this over `kenter-client` (Soroban RPC); the PWA over the
/// browser `fetch` API. MVP-1 needs only token status.
#[allow(async_fn_in_trait)]
pub trait ChainRead {
    /// Look up a note's on-chain status by its print slot.
    ///
    /// The slot, not the ephemeral key: the mint keys records by slot,
    /// because a caller-named key is one anyone can claim first. Two records may name the same key and they are not
    /// the same note.
    async fn token_status(&self, slot_id: u32) -> Result<OnChainToken>;

    /// The XDR of the mint contract's address, as the mint itself hashes it.
    ///
    /// Every owner digest covers it, so a signature cannot be lifted off one
    /// deployment and replayed against another holding the same escrow. It
    /// belongs to the reader rather than to a caller because the reader is
    /// what knows which mint these answers came from; asking a caller to
    /// supply it alongside would let the two disagree, and the disagreement
    /// would only surface as a rejected transaction on a live ledger.
    fn mint_contract_xdr(&self) -> Vec<u8>;

    /// Which mint these answers are about, as a contract id.
    ///
    /// Records are addressed by slot, and slot ids restart at zero on
    /// each deployment, so a wallet has to know whose slot zero it is
    /// looking at before an answer means anything.
    fn mint_id(&self) -> String;

    /// Where these answers come from, in a form fit to show a holder.
    ///
    /// The receive gates are self-certifying only against an honest
    /// source: the reads behind G1-G3 are one endpoint's word, and nothing
    /// in the protocol proves that word against the ledger. The payee is
    /// therefore trusting something, and a trust they cannot see is one
    /// they cannot judge -- so the screen that asks them to treat a payment
    /// as settled names what it asked.
    ///
    /// Must not carry a credential. Some endpoints put an API key in the
    /// path, and this string is rendered.
    fn ledger_source(&self) -> String;
}

/// Holds a [`Store`]'s write lock until dropped.
///
/// Opaque, and empty unless the implementation needs somewhere to keep a
/// handle. The filesystem store keeps the open file whose lock the OS is
/// holding; dropping this closes it, and so does the process dying, which
/// is why there is no staleness to recover from.
#[derive(Debug, Default)]
pub struct StoreGuard {
    /// The locked handle, for implementations that have one.
    #[cfg(feature = "fs")]
    pub(crate) file: Option<std::fs::File>,
}

/// Local persistence of held tokens.
///
/// Desktop implements this over the filesystem; the PWA over IndexedDB. Keyed by
/// [`HeldToken::id`] (the ephemeral address).
#[allow(async_fn_in_trait)]
pub trait Store {
    /// Take the store's write lock for the duration of a
    /// read-modify-write, waiting if another holder has it.
    ///
    /// Several wallet operations read then write — `reconcile`'s bind,
    /// `sync`'s snapshot write-back, `bind_owner`, `verify_ownership`,
    /// `forget`, the mark-spent paths. Nothing serialized them, and the
    /// desktop GUI opens eleven stores across its job threads while the
    /// CLI shares the same directory by design.
    ///
    /// Defaults to a guard that holds nothing, which is right for a store
    /// with a single owner: the in-memory one used by tests, and the
    /// browser's IndexedDB, where there is one tab and no second handle.
    /// [`crate::FileStore`] overrides it.
    ///
    /// # Not re-entrant
    ///
    /// Taking it twice on one thread **deadlocks**, because the
    /// filesystem implementation locks per open handle and opens a fresh
    /// one each call — the same property that makes it exclude two
    /// threads of one process. So exactly one method per call path may
    /// take it. `TokenWallet::balance` deliberately does not: it
    /// delegates to `reconcile`, which does.
    fn lock(&self) -> Result<StoreGuard> {
        Ok(StoreGuard::default())
    }

    /// Insert a token. Implementations should error on collision only if the
    /// caller relies on it; the wallet checks for duplicates before calling.
    async fn put(&mut self, token: HeldToken) -> Result<()>;

    /// Fetch one token by id.
    async fn get(&self, id: &str) -> Result<Option<HeldToken>>;

    /// All held tokens.
    async fn all(&self) -> Result<Vec<HeldToken>>;

    /// Remove a token by id (no-op if absent).
    async fn remove(&mut self, id: &str) -> Result<()>;

    // ── Owner-key bookkeeping ──

    /// Reserve the next fresh owner-derivation index and persist the advance.
    ///
    /// Monotonic and never reused: an abandoned receive simply burns an index,
    /// which costs nothing, whereas reuse would link two payments to one
    /// commitment. Must never return [`STATIC_RECEIVE_INDEX`], which is reserved.
    async fn allocate_owner_index(&mut self) -> Result<u32>;

    /// Raise the counter to at least `to`, and report where it ended up.
    /// **Never moves it backwards**, so `to = 0` is a read.
    ///
    /// Deliberately the same contract as the card's `ADVANCE INDEX`
    /// (`stellar-keycard`), which is also a forward-only setter doubling as
    /// the reader, so the two allocators cannot drift apart in behaviour.
    ///
    /// Restore is what needs the setter. A backup carries the counter as it
    /// stood when the file was written, which may be *behind* where the wallet
    /// has since reached; moving it back would hand out an index already in
    /// use, which is two payments at one commitment.
    /// Forward-only makes that unrepresentable rather than merely avoided.
    async fn advance_owner_index(&mut self, to: u32) -> Result<u32>;

    /// Record a reserved-but-unconsummated receive.
    async fn put_pending(&mut self, pending: PendingReceive) -> Result<()>;

    /// All outstanding pending receives.
    async fn pending(&self) -> Result<Vec<PendingReceive>>;

    /// Drop a pending receive by index (no-op if absent).
    async fn remove_pending(&mut self, index: u32) -> Result<()>;

    // ── Backup bookkeeping ──

    /// What the wallet remembers about the last backup it wrote.
    async fn last_backup(&self) -> Result<Option<BackupRecord>>;

    /// Remember a backup that has been written **and landed**. Called after
    /// the bytes are safely somewhere, never before: recording a backup that
    /// then failed to write would tell a holder they are covered when they
    /// are not, which is worse than telling them nothing.
    async fn record_backup(&mut self, record: BackupRecord) -> Result<()>;
}
