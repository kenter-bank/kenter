//! The wallet core: orchestrates the [`Store`], [`ChainRead`] and
//! [`DerivingVault`] ports over the held-token model.
//!
//! The vault is threaded through the core on purpose. The receive gates
//! (G1–G4) and the owner-authorization digest rule
//! (`docs/architecture/spend-mode.md`) are **protocol**, not shell
//! convenience: a client that skips a gate or signs the wrong bytes is unsafe, not merely inconvenient.
//! Implementing them once here means the PWA inherits them instead of
//! reimplementing — which is exactly where that kind of drift would appear.

use kenter_crypto::container::deserialize_bearer_token;
use kenter_crypto::spend::{RedeemOwnerProof, SpendAuthorization};
use kenter_vault::DerivingVault;

use crate::owner;

use crate::error::{Gate, Result, WalletError};
use crate::models::{
    Balance, ExportKind, HeldToken, KnownOwner, OnChainToken, PendingReceive, ReconciledToken,
    SyncReport,
    TokenStatus, STATIC_RECEIVE_INDEX,
};
use crate::ports::{ChainRead, Store};

/// Stand-in for "no custody backend wired". Deliberately does **not** implement
/// [`DerivingVault`], so the owner-key operations simply do not exist on a wallet
/// built with [`TokenWallet::new`] — a compile error rather than a runtime one.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoVault;

/// A token wallet composed from a chain reader, a store, and (optionally) a
/// custody backend.
///
/// Generic over the ports so `async fn` in traits needs no boxing and each shell
/// supplies its own native/wasm engines.
pub struct TokenWallet<C: ChainRead, S: Store, V = NoVault> {
    chain: C,
    store: S,
    vault: V,
}

impl<C: ChainRead, S: Store> TokenWallet<C, S, NoVault> {
    /// A wallet with no custody backend: import, reconcile and balance work;
    /// receiving and owner authorizations are not available.
    pub fn new(chain: C, store: S) -> Self {
        TokenWallet { chain, store, vault: NoVault }
    }
}

impl<C: ChainRead, S: Store, V> TokenWallet<C, S, V> {
    /// A wallet that can also derive and sign with owner keys.
    pub fn with_vault(chain: C, store: S, vault: V) -> Self {
        TokenWallet { chain, store, vault }
    }

    /// Borrow the underlying store / chain / vault (shells may need direct access).
    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn chain(&self) -> &C {
        &self.chain
    }
    pub fn vault(&self) -> &V {
        &self.vault
    }

    /// Import a received token from its container bytes.
    ///
    /// Verifies the token offline (chain integrity + key consistency) before it is
    /// stored, and persists the bytes verbatim. `imported_at` is host-supplied —
    /// the core has no clock (wasm target). Errors if the token is already held.
    pub async fn import(&mut self, container_bytes: Vec<u8>, imported_at: i64) -> Result<HeldToken> {
        // The wallet lock is taken only around the write, never across the
        // ledger read a collision needs: holding it across a slow RPC would
        // stall every other writer, in every thread and process, until it
        // answered.
        let token = deserialize_bearer_token(&container_bytes)
            .map_err(|e| WalletError::Codec(e.to_string()))?;
        token
            .verify_chain_integrity()
            .map_err(|e| WalletError::InvalidToken(e.to_string()))?;

        let held = HeldToken::from_bearer(&token, container_bytes, imported_at);
        let existing = {
            let _guard = self.store.lock()?;
            match self.store.get(&held.id).await? {
                None => {
                    self.store.put(held.clone()).await?;
                    return Ok(held);
                }
                Some(existing) => existing,
            }
        };
        self.resolve_collision(existing, held).await
    }

    /// Write `updated` if the stored record still equals `snapshot`.
    ///
    /// The way every read-modify-write that needs the ledger or the card now
    /// works: read without the lock, do the slow part, then take the lock
    /// for a re-read and a write. If anything changed the record meanwhile
    /// -- a hand-over marked, a note forgotten, another process's sync --
    /// this writes nothing and returns `false`; the decision was made about
    /// a record that no longer exists, and the next run sees the new one.
    /// Holding the lock across the round trip instead would stall every
    /// other writer behind a slow RPC or an NFC tap.
    async fn commit_if_unchanged(
        &mut self,
        snapshot: &HeldToken,
        updated: &HeldToken,
    ) -> Result<bool> {
        let _guard = self.store.lock()?;
        match self.store.get(&snapshot.id).await? {
            Some(now) if &now == snapshot => {
                self.store.put(updated.clone()).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Two containers want the same id. Decide which one the wallet keeps.
    ///
    /// "First wins" is not a safe rule. It would let anyone who knew a
    /// note's ephemeral key -- which is public, being the sum of the
    /// partial keys `confirm_link` publishes -- post a worthless container
    /// first and lock the real payment out of its owner's own wallet.
    /// Nothing would be stolen; the note simply could not be taken
    /// delivery of.
    ///
    /// Byte-identical bytes are the ordinary case -- the same file
    /// imported twice -- and still a `Duplicate`, because there is
    /// nothing to choose between them and the caller should hear that
    /// they already have it.
    ///
    /// Otherwise the ledger decides. It is the only party that knows
    /// which chain was registered, and `import` is offline precisely so
    /// a note can be taken now and checked later -- so this is the one
    /// place it reaches for a chain read, on a collision that should
    /// never happen honestly.
    async fn resolve_collision(
        &mut self,
        existing: HeldToken,
        incoming: HeldToken,
    ) -> Result<HeldToken> {
        if existing.blob == incoming.blob {
            return Err(WalletError::Duplicate(existing.id));
        }

        // Bound to another deployment: this ledger cannot judge it. Its slot
        // of the same number is a different note, so `existing` reads as
        // "not described" and the incoming twin -- registered here by
        // whoever chose to -- would win, replacing the only copy of a note
        // that is live on its own mint. Never evicted on this ledger's
        // word.
        if matches!(&existing.mint, Some(m) if m != &self.chain.mint_id()) {
            return Err(WalletError::Duplicate(existing.id));
        }

        // Ask about each one's own slot: two containers sharing an
        // ephemeral key may well have been registered under different
        // slots, which are two independent records.
        let existing_ok = match self.chain.token_status(existing.slot_id).await {
            Ok(on) => Self::describes(&on, &existing),
            // Cannot reach the ledger. Change nothing -- replacing a
            // note on a failed read is how a transient outage becomes a
            // lost note.
            Err(e) => return Err(e),
        };
        let incoming_ok = match self.chain.token_status(incoming.slot_id).await {
            Ok(on) => Self::describes(&on, &incoming),
            Err(e) => return Err(e),
        };

        match (existing_ok, incoming_ok) {
            // The one already held is not the note; this one is. Replaced
            // only if it is still the record that was judged.
            (Some(false), Some(true)) => {
                if self.commit_if_unchanged(&existing, &incoming).await? {
                    Ok(incoming)
                } else {
                    Err(WalletError::Duplicate(existing.id))
                }
            }
            // Keep what we have: it is the real one, or neither is, or
            // the ledger cannot say. "Cannot tell" must not evict --
            // that would hand the eviction back to whoever gets to
            // choose when the ledger is unreadable.
            _ => Err(WalletError::Duplicate(existing.id)),
        }
    }

    /// All held tokens (local only, no chain read).
    pub async fn held(&self) -> Result<Vec<HeldToken>> {
        self.store.all().await
    }

    /// Drop a token from the store by id.
    pub async fn forget(&mut self, id: &str) -> Result<()> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        self.store.remove(id).await
    }

    /// Read each held token's on-chain status. One chain read per token; a failed
    /// read surfaces as an error (callers may choose to treat it as `Unknown`).
    pub async fn reconcile(&mut self) -> Result<Vec<ReconciledToken>> {
        // No lock across the reads: one RPC per note, and a slow ledger
        // would hold every other writer until it answered. The one write,
        // binding a note to this mint, takes it briefly below.
        let held = self.store.all().await?;
        let configured = self.chain.mint_id();
        // Every commitment this wallet can open, so a note owned by any
        // other commitment reads as `NotOurs`.
        let known = self.known_owners().await?;
        let mut out = Vec::with_capacity(held.len());
        for mut t in held {
            // Bound to another mint: do not read this ledger at all.
            // Slot ids restart at zero per deployment, so its slot 0 is
            // a different note and any answer about it is noise.
            if matches!(&t.mint, Some(m) if m != &configured) {
                out.push(ReconciledToken {
                    held: t,
                    status: TokenStatus::OtherMint,
                    on_chain_amount: None,
                });
                continue;
            }

            let on = self.chain.token_status(t.slot_id).await?;
            let describes = Self::describes(&on, &t);
            let bound = t.mint.is_some();

            let status = match on.status {
                TokenStatus::Active if describes == Some(false) => TokenStatus::Counterfeit,
                // The one answer that is about *this note's content*,
                // and therefore the only one that may bind it.
                TokenStatus::Active if describes == Some(true) => {
                    if !bound {
                        // Re-read before writing. `t` is a snapshot taken
                        // before the RPC above, and writing it back whole
                        // would undo anything that landed in that window
                        // -- the desktop app and the CLI share a wallet
                        // directory by design, and the lock is not held
                        // across the RPC.
                        //
                        // What that costs is not abstract. `marked_spent`
                        // is the only record that a pure-bearer note was
                        // handed over, because the ledger cannot see a
                        // handover; losing it puts a note the holder
                        // already gave away back into spendable, and the
                        // second payee passes G2 because the note is
                        // still Active. Whoever redeems first is paid.
                        //
                        // A note deleted in the window stays deleted, and
                        // one bound by someone else is left alone.
                        let _guard = self.store.lock()?;
                        let Some(mut fresh) = self.store.get(&t.id).await? else {
                            // Deleted in the window. Leaving it out of
                            // this run's output matters as much as not
                            // resurrecting it: reporting a note the
                            // holder just forgot as Active counts it as
                            // spendable one last time.
                            continue;
                        };
                        if fresh.mint.is_none() {
                            fresh.mint = Some(configured.clone());
                            self.store.put(fresh.clone()).await?;
                        }
                        t = fresh;
                    }
                    // Live and genuine, but whose? A spend-mode record
                    // names its owner, and if that is no commitment this
                    // wallet can open, the note is someone else's money
                    // and not spendable. Pure bearer has no owner to compare.
                    match on.owner_commitment {
                        Some(live)
                            if t.owner_commitment != Some(live)
                                && !known.iter().any(|k| k.commitment == live) =>
                        {
                            TokenStatus::NotOurs
                        }
                        _ => TokenStatus::Active,
                    }
                }
                // Everything else is content-free. A `Redeemed` marker
                // holds a ledger number and says nothing about which
                // note was paid; an absent record says nothing at all.
                // On an unbound note neither is evidence, and reporting
                // `Redeemed` is what invites a holder to delete a live
                // note.
                other if !bound => {
                    let _ = other;
                    TokenStatus::Unbound
                }
                other => other,
            };
            out.push(ReconciledToken { held: t, status, on_chain_amount: on.amount });
        }
        Ok(out)
    }

    /// Does the ledger's record describe *these bytes*?
    ///
    /// `import` verifies a container offline and stores it, which is
    /// deliberate — a note can be taken now and checked later. The
    /// consequence is that without this check a counterfeit sitting in
    /// the billfold would display as Active at the ledger's amount: the
    /// receive gates catch one, but the CLI's `import` does not go
    /// through them.
    /// Reconciliation is the thing that is supposed to tell a holder
    /// what they actually have, so the comparison belongs here.
    ///
    /// Two fields have to agree. The **chain commitment**, because
    /// everything else about a note can be rebuilt from public ledger
    /// data — the partial keys are published and they sum to the
    /// ephemeral key — so without it a container assembled by someone
    /// holding no note at all looks real. And the **claim key**,
    /// because a pure-bearer container is self-signed by whoever
    /// assembled it: a payer can hand over the real chain with a claim
    /// secret that is not the registered one, and the payee then
    /// cannot redeem by chain while the payer still can.
    /// `None` means *cannot tell*, which is not the same answer as
    /// `Some(false)` and must not be treated as one. A record this
    /// build cannot parse, or a ledger entry carrying no commitment, is
    /// a gap in what we know — marking it counterfeit would let a parse
    /// bug quietly condemn an honest wallet.
    fn describes(on: &OnChainToken, held: &HeldToken) -> Option<bool> {
        let token = deserialize_bearer_token(&held.blob).ok()?;
        let expected = kenter_crypto::chain_data::token_chain_hash(&token).ok()?;
        if on.chain_hash? != expected {
            return Some(false);
        }
        // The key the record names has to be the note's own. The lookup
        // is by slot, so nothing checks this implicitly -- and a record
        // carrying someone else's key is one Path A cannot redeem.
        if on.ephemeral_key? != token.ephemeral_public_key {
            return Some(false);
        }
        // What `verify_chain` also requires: the record's event id, and a
        // participant count of exactly two per link. A chain can fail
        // either and still hash to the committed value, so without these a
        // note Path B will refuse forever would reconcile as Active. One
        // predicate serves both G2 and reconcile, so the two cannot
        // disagree. An odd count matches no chain.
        if on.event_id? != token.header.event_id {
            return Some(false);
        }
        let n = on.participants_len?;
        if n % 2 != 0 || (n / 2) as usize != token.chain.links.len() {
            return Some(false);
        }
        // Only meaningful for pure bearer: a spend-mode note proves
        // possession with the owner key, and `claim_pubkey` is not in
        // its redemption path.
        if on.owner_commitment.is_none() {
            if on.claim_pubkey? != token.claim_public_key() {
                return Some(false);
            }
        }
        Some(true)
    }

    // ── Owner-key association ──

    /// Reserve the next owner index and record the pending receive it belongs to.
    ///
    /// `commitment` is derived by the shell from its vault (the core holds no
    /// keys). Recording before the payer is told the commitment is deliberate:
    /// a crash after showing it must not lose which index was promised.
    pub async fn begin_receive(
        &mut self,
        commitment: [u8; 32],
        now: i64,
    ) -> Result<PendingReceive> {
        let index = self.store.allocate_owner_index().await?;
        let pending = PendingReceive { index, commitment, created_at: now };
        self.store.put_pending(pending.clone()).await?;
        Ok(pending)
    }

    /// Reserve an index without recording it — for the caller that needs the
    /// index first in order to derive the commitment. Pair it with
    /// [`Self::record_pending`].
    pub async fn reserve_owner_index(&mut self) -> Result<u32> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        self.store.allocate_owner_index().await
    }

    /// Record a pending receive for an index already reserved.
    pub async fn record_pending(&mut self, pending: PendingReceive) -> Result<()> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        self.store.put_pending(pending).await
    }

    /// Outstanding pending receives, lowest index first.
    pub async fn pending(&self) -> Result<Vec<PendingReceive>> {
        self.store.pending().await
    }

    /// Stop watching one index, without pretending anything was cancelled.
    ///
    /// Retiring the standing tag, chiefly. The contract will still accept a
    /// payment to that commitment forever; what ends is this wallet looking
    /// for one. Reversible, because the commitment derives from the seed.
    pub async fn forget_pending(&mut self, index: u32) -> Result<()> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        self.store.remove_pending(index).await
    }

    /// Every owner commitment this wallet can open, with the index it comes
    /// from.
    ///
    /// Two sources, both already on disk, so this needs no vault and derives
    /// nothing: the outstanding pending receives, and the `owner_commitment`
    /// recorded on each token already bound. The second source is what keeps
    /// a payment to a pay tag that has *already* been used recognisable
    /// Handing one tag to two payers is the ordinary
    /// case: the first payment consumes the pending record, and the tag is
    /// still in the second payer's hands.
    pub async fn known_owners(&self) -> Result<Vec<KnownOwner>> {
        let mut out: Vec<KnownOwner> = self
            .store
            .pending()
            .await?
            .into_iter()
            .map(|p| KnownOwner { index: p.index, commitment: p.commitment })
            .collect();
        for held in self.store.all().await? {
            let (Some(index), Some(commitment)) = (held.owner_index, held.owner_commitment)
            else {
                continue; // pure bearer, or never bound
            };
            if !out.iter().any(|k| k.commitment == commitment) {
                out.push(KnownOwner { index, commitment });
            }
        }
        Ok(out)
    }

    /// Tie a held token to the owner index that owns it, consuming the matching
    /// pending record. This is the association the whole model rests on: without
    /// it the token's owner key cannot be re-derived, and in spend mode the token
    /// cannot be spent or redeemed.
    /// Record the owner commitment for a token already bound to an index.
    ///
    /// For a note this holder minted: `bind_owner` can only carry a
    /// commitment across from a pending *receive*, and a self-minted note
    /// never had one. Without this the note ends up with an owner index and
    /// no commitment, which neither Pay nor Redeem can prove ownership
    /// with — real escrow, held, and unreachable.
    pub async fn record_owner_commitment(
        &mut self,
        id: &str,
        commitment: [u8; 32],
    ) -> Result<()> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        let mut held = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| WalletError::NotHeld(id.to_string()))?;
        held.owner_commitment = Some(commitment);
        self.store.put(held).await?;
        Ok(())
    }

    /// Bind an owner index to a token, recording the commitment too when
    /// one can be found.
    ///
    /// The commitment comes from the matching *pending receive* — which a
    /// token minted by this holder never has, because nobody was waiting
    /// for it. That left self-minted spend-mode notes with an index and no
    /// commitment, and `sync` cannot repair it: its bound branch only
    /// notices a commitment *changing*, never a missing one appearing. The
    /// callers derive it instead; see `bind_owner_with`.
    pub async fn bind_owner(&mut self, id: &str, owner_index: u32) -> Result<HeldToken> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        let mut held = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| WalletError::NotHeld(id.to_string()))?;
        // Carry the commitment across from the pending record so later
        // reconciliation can spot the pointer moving away without the vault.
        let commitment = self
            .store
            .pending()
            .await?
            .into_iter()
            .find(|p| p.index == owner_index)
            .map(|p| p.commitment);
        held.owner_index = Some(owner_index);
        if commitment.is_some() {
            held.owner_commitment = commitment;
        }
        self.store.put(held.clone()).await?;
        self.consume_pending(owner_index).await?;
        Ok(held)
    }

    /// Note that a copy of this token left, and why.
    ///
    /// Local only. It must never reach the exported container, or it becomes
    /// a fingerprint linking copies of the same note to each other.
    pub async fn record_export(&mut self, id: &str, kind: ExportKind) -> Result<HeldToken> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        let mut held = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| WalletError::NotHeld(id.to_string()))?;
        held.exports.record(kind);
        self.store.put(held.clone()).await?;
        Ok(held)
    }

    /// Record the holder's own view that a note is gone, or take it back.
    ///
    /// Reversible, and it keeps the bytes. A bearer handover that silently
    /// failed leaves value that is still recoverable, and a bookkeeping
    /// gesture must never be the thing that destroys it — that is what
    /// [`Self::forget`] is for, and why it is a different call.
    pub async fn mark_spent(&mut self, id: &str, spent: bool) -> Result<HeldToken> {
        // Serialize this read-modify-write against every other one,
        // in this process and in any other sharing the same wallet
        // directory. Held until return.
        let _guard = self.store.lock()?;
        let mut held = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| WalletError::NotHeld(id.to_string()))?;
        held.marked_spent = spent;
        self.store.put(held.clone()).await?;
        Ok(held)
    }

    /// Reconcile and reduce to a partitioned [`Balance`].
    pub async fn balance(&mut self) -> Result<Balance> {
        Ok(Balance::from_reconciled(&self.reconcile().await?))
    }

    /// Reconcile ownership against the ledger, repairing what it can.
    ///
    /// Two jobs, both of which keep the wallet's picture of what it owns honest:
    ///
    /// - **Auto-bind.** A receive that crashed between showing a commitment and
    ///   storing the token leaves a pending record and an unbound token. If the
    ///   ledger says a held token is owned by a commitment we have pending, the
    ///   index is bound and the pending record consumed.
    /// - **Spent-away.** A token we paid away stays `Active` on the ledger, so
    ///   without this it keeps counting as spendable in our own balance. When
    ///   the live commitment no longer matches the one we recorded, flag it.
    ///
    /// Needs no vault: the commitment is stored on the token at bind time.
    pub async fn sync(&mut self) -> Result<SyncReport> {
        // Reads without the lock; each write goes through
        // `commit_if_unchanged`.
        let mut report = SyncReport::default();
        // Every index we can open, not only the ones still pending: an unbound
        // token may belong to a tag a different note already consumed.
        let known = self.known_owners().await?;
        let configured = self.chain.mint_id();

        for mut held in self.store.all().await? {
            let snapshot = held.clone();
            // Bound to another deployment: this ledger's slot of the same
            // number is a different note, and its owner says nothing about
            // ours. Reading it would mark a note paid away on another
            // note's answer, so `sync` skips these as `reconcile` does.
            if matches!(&held.mint, Some(m) if m != &configured) {
                continue;
            }
            let on_chain = self.chain.token_status(held.slot_id).await?;
            let Some(live) = on_chain.owner_commitment else {
                continue; // pure bearer, or no record — nothing to own
            };
            // Only an answer about *these bytes* may change what we record
            // about them. A record for some other note under this slot, or
            // one this build cannot compare, binds nothing and pays nothing
            // away.
            if on_chain.status != TokenStatus::Active
                || Self::describes(&on_chain, &held) != Some(true)
            {
                continue;
            }

            match held.owner_index {
                // Unbound: is it owned by an index we can open?
                None => {
                    if let Some(k) = known.iter().find(|k| k.commitment == live) {
                        held.owner_index = Some(k.index);
                        held.owner_commitment = Some(k.commitment);
                        if self.commit_if_unchanged(&snapshot, &held).await? {
                            self.consume_pending(k.index).await?;
                            report.bound.push((held.id, k.index));
                        }
                    }
                }
                // Bound: has the pointer moved away from us -- or back?
                Some(_) => {
                    let ours = held.owner_commitment;
                    if ours.is_some() && ours != Some(live) && !held.spent_away {
                        held.spent_away = true;
                        if self.commit_if_unchanged(&snapshot, &held).await? {
                            report.spent_away.push(held.id);
                        }
                    } else if ours == Some(live) && held.spent_away {
                        // The ledger says it is ours again. If `spent_away`
                        // could only ever be set, one wrong answer -- a
                        // lying or mistaken RPC, or a moment pointed at the
                        // wrong mint -- would leave a live note marked gone
                        // for good, and "gone" invites `forget`. The ledger
                        // is the authority both ways.
                        held.spent_away = false;
                        if self.commit_if_unchanged(&snapshot, &held).await? {
                            report.returned.push(held.id);
                        }
                    }
                }
            }
        }
        Ok(report)
    }

    /// Finish a receive: run gates **G1–G3**, then store the token bound to
    /// whichever owner index the ledger says owns it (G4).
    ///
    /// The caller owns the polling loop — timing and UI are shell concerns — but
    /// not the gates. Every one of them must pass before this returns a token,
    /// because until G3 the payee is not paid (`docs/architecture/spend-mode.md`,
    /// "The receive gates").
    ///
    /// It is not told which receive to complete. The ledger already says who
    /// owns the note, so nominating a pending record could only disagree with
    /// it — as it would whenever a tag had been handed to more than one payer.
    pub async fn complete_receive(
        &mut self,
        container_bytes: Vec<u8>,
        now: i64,
    ) -> Result<HeldToken> {
        // G1-G3 are reads, two of them over RPC, and the caller polls this
        // for as long as a payment takes to land. The lock is taken at G4,
        // for the write alone.
        // G1 — offline structural verification. Proves valid construction; says
        // nothing about whether it is unredeemed or ours.
        // Malformed bytes never become well-formed: never retryable.
        let token = deserialize_bearer_token(&container_bytes).map_err(|e| {
            WalletError::ReceiveGate {
                gate: Gate::Structure,
                detail: format!("container: {e}"),
                retryable: false,
            }
        })?;
        token.verify_chain_integrity().map_err(|e| WalletError::ReceiveGate {
            gate: Gate::Structure,
            detail: format!("chain integrity: {e}"),
            retryable: false,
        })?;

        let held = HeldToken::from_bearer(&token, container_bytes, now);

        // Everything below is this ledger confirming this note's
        // content, so passing it is what binds the note to this mint.
        // Recorded at the end, once all four gates have agreed; never
        // taken from the container or the sender.
        let configured_mint = self.chain.mint_id();

        // G2 — the ledger must agree the token exists, is Active, and is worth
        // what the bytes claim.
        let on_chain = self.chain.token_status(held.slot_id).await?;
        match on_chain.status {
            TokenStatus::Active => {}
            // Already redeemed is final. NotFound/Unknown may simply mean the
            // payer's transaction has not landed yet, so waiting can help.
            TokenStatus::Redeemed => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "token is already redeemed".into(),
                    retryable: false,
                })
            }
            other => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: format!("on-ledger state is {other:?}, not Active"),
                    retryable: true,
                })
            }
        }
        if let Some(amount) = on_chain.amount {
            if amount != held.amount as i128 {
                // The escrow will not change to match the bytes.
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: format!("amount mismatch: ledger {amount}, token {}", held.amount),
                    retryable: false,
                });
            }
        }

        // The ledger must describe *this* chain, not merely a token with
        // this key and this amount.
        //
        // Everything else checked so far can be reconstructed from public
        // ledger data. `confirm_link` publishes each partial public key,
        // and those sum to the ephemeral key, so an attacker with no note
        // can assemble a container that passes structural verification and
        // names a real, live, correctly-valued escrow. The chain commitment
        // is the one thing they cannot forge: the full links are never
        // published, only their 32-byte public parts, and the mint recorded
        // the digest of the real ones at registration.
        //
        // A mismatch is never retryable. The ledger will not change its mind
        // about which chain it recorded.
        let expected = kenter_crypto::chain_data::token_chain_hash(&token).map_err(|e| {
            WalletError::ReceiveGate {
                gate: Gate::Structure,
                detail: format!("chain hash: {e}"),
                retryable: false,
            }
        })?;
        match on_chain.chain_hash {
            Some(recorded) if recorded == expected => {}
            Some(_) => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the ledger records a different chain for this token -                              these bytes are not the note the mint registered"
                        .into(),
                    retryable: false,
                })
            }
            // A record with no commitment is a record this build cannot
            // check. Refusing is the conservative read: accepting would
            // restore exactly the hole this gate exists to close.
            None => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the ledger record carries no chain commitment to check".into(),
                    retryable: false,
                })
            }
        }

        // Still G2: the record must also name *this* note's key.
        //
        // The chain hash above proves the ledger recorded this chain. It
        // does not prove the record points at this note: records are
        // keyed by slot, so `ephemeral_key` is a field the
        // depositor chose rather than the thing that was looked up. A
        // payer can register the real chain and claim key beside a
        // different ephemeral key, and every gate up to here passes.
        //
        // Nothing is stolen -- the payee can still redeem by chain --
        // but Path A is silently gone for them, and Path A is the route
        // that does not need the node network. Losing it quietly at
        // receive time is worse than refusing the note now.
        match on_chain.ephemeral_key {
            Some(recorded) if recorded == token.ephemeral_public_key => {}
            Some(_) => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the ledger record names a different ephemeral key - \
                             this note could not be redeemed by key"
                        .into(),
                    retryable: false,
                })
            }
            None => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the ledger record carries no ephemeral key to check".into(),
                    retryable: false,
                })
            }
        }

        // Still G2: the chain must be one the contract will accept.
        //
        // `chain_hash` proves the ledger recorded *this* chain. It does
        // not prove the contract can verify it. `verify_chain` also
        // requires the chain's event id to equal the record's, and its
        // link count to equal `participants / 2` -- and a chain can fail
        // either while remaining internally valid and hashing to exactly
        // the committed value.
        //
        // So a payer can register a chain signed by their own sybil keys
        // carrying the wrong event id or N±1 links, hand the note over,
        // and watch every gate pass. Path B then fails forever, and Path
        // A needs the ephemeral secret only the payer can compose. The
        // payer burns the full face value to do it, so this is sabotage
        // rather than theft -- but the payee has taken a note that pays
        // nothing, in exchange for something.
        match on_chain.event_id {
            Some(recorded) if recorded == token.header.event_id => {}
            Some(_) => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the ledger record names a different event id -                              the contract would refuse this chain"
                        .into(),
                    retryable: false,
                })
            }
            None => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the ledger record carries no event id to check".into(),
                    retryable: false,
                })
            }
        }

        match on_chain.participants_len {
            // The contract divides by two, so an odd count can never
            // match any chain and is refused here rather than at
            // redemption.
            Some(n) if n % 2 == 0 && (n / 2) as usize == token.chain.links.len() => {}
            Some(n) => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: format!(
                        "the record names {n} participants, so the contract                          expects {} links, but this note carries {} -                          the contract would refuse this chain",
                        n / 2,
                        token.chain.links.len()
                    ),
                    retryable: false,
                })
            }
            None => {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the ledger record carries no participant count to check".into(),
                    retryable: false,
                })
            }
        }

        // G3 — ownership actually moved to us. Self-certifying: the contract only
        // moved the pointer if the previous owner opened their commitment.
        //
        // "Us" is any commitment this wallet can open, not one nominated
        // record. The question the holder is asking is whether they were paid,
        // not which of their codes was used.
        let Some(live) = on_chain.owner_commitment else {
            // Mode is fixed at registration, so a pure-bearer token will never
            // acquire an owner.
            //
            // Pure bearer is redeemed by whoever holds the claim secret, so
            // the record's claim key must be this note's own before anything
            // else is said about it. Otherwise the note in hand can never be
            // redeemed by its holder -- only by the payer, who kept the
            // matching secret -- and the GUI, which imports on the error
            // below, would show it as held. A pure-bearer receipt is never
            // final (first to redeem wins), but a certain dud is refused
            // rather than accepted.
            if on_chain.claim_pubkey != Some(token.claim_public_key()) {
                return Err(WalletError::ReceiveGate {
                    gate: Gate::Ledger,
                    detail: "the mint's record names a different claim key, so this note \
                             can only be redeemed by whoever printed it"
                        .into(),
                    retryable: false,
                });
            }
            return Err(WalletError::ReceiveGate {
                gate: Gate::Ownership,
                detail: "token is not in spend mode, so ownership cannot be proven".into(),
                retryable: false,
            });
        };
        // Looked up after G2 so the store read only happens for a note the
        // ledger has already vouched for — it is cheap next to the RPC call
        // that just returned, and free for every file that was never going to
        // pass.
        let Some(owner) = self.known_owners().await?.into_iter().find(|k| k.commitment == live)
        else {
            // The pointer may not have moved yet; this is the gate worth waiting on.
            return Err(WalletError::ReceiveGate {
                gate: Gate::Ownership,
                detail: "the live owner commitment is not ours — not paid".into(),
                retryable: true,
            });
        };

        // G4 — bind and persist. The owner key needs no separate backup: it is
        // re-derivable from the seed given this index.
        let mut held = held;
        held.owner_index = Some(owner.index);
        held.owner_commitment = Some(owner.commitment);
        // Already here and still ours: say so rather than silently
        // rewriting the record.
        //
        // Unless we had paid it away. A note can come back
        // legitimately -- change, a refund, or being paid by the person
        // you paid -- and the gates above have just proved the ledger
        // says it is ours again, at an index this wallet owns.
        // Refusing that on the strength of our own stale bookkeeping
        // strands the value, because `sync` will not re-bind a note it
        // believes was given away. The record is replaced
        // rather than merged: every field on it now describes the new
        // ownership.
        let _guard = self.store.lock()?;
        if let Some(prior) = self.store.get(&held.id).await? {
            if !prior.spent_away {
                return Err(WalletError::Duplicate(held.id));
            }
        }
        // All four gates passed, so this mint has vouched for these
        // bytes. Bound here and nowhere earlier: importing is not
        // confirmation, and a sender does not get to nominate the
        // ledger that answers for a note.
        held.mint = Some(configured_mint);
        self.store.put(held.clone()).await?;
        self.consume_pending(owner.index).await?;
        Ok(held)
    }

    /// Retire a one-shot pay tag, leaving the standing one alone.
    ///
    /// The standing tag (the reusable receive address, index 0) is a
    /// fixture, not a pending: it is published ahead of the payer and meant to be used more
    /// than once, so consuming its record would stop the wallet watching its
    /// own advertised address the first time anybody paid it.
    async fn consume_pending(&mut self, index: u32) -> Result<()> {
        if index == STATIC_RECEIVE_INDEX {
            return Ok(());
        }
        self.store.remove_pending(index).await
    }
}

/// What [`TokenWallet::verify_ownership`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipReport {
    /// Spend notes whose claim the vault reproduced. Nothing to do.
    pub confirmed: usize,
    /// Notes whose stored commitment was wrong but whose **index** was
    /// right — the ledger agreed with the derived key, so the record was
    /// corrected rather than doubted, as `(id, index)`.
    pub corrected: Vec<(String, u32)>,
    /// Notes the vault does not own at the index they claim. The claim is
    /// stripped; the note itself is kept. `(id, why)`.
    pub disowned: Vec<(String, String)>,
    /// Notes that could not be checked — the vault or the ledger would not
    /// answer. Left exactly as they were.
    pub unchecked: usize,
}

impl OwnershipReport {
    /// Nothing needed changing.
    pub fn is_clean(&self) -> bool {
        self.corrected.is_empty() && self.disowned.is_empty()
    }
}

impl<C: ChainRead, S: Store, V: DerivingVault> TokenWallet<C, S, V> {
    /// Check that this wallet really owns the spend notes that say it does.
    ///
    /// A spend note carries `owner_index` and `owner_commitment`, and both
    /// are **local claims**: they arrive with the note, live in the store,
    /// and travel in backups. Everything else a restored record says is
    /// checked against something — the container against itself, the amount
    /// against the ledger — and this is the check for the owner claim, so no
    /// part of a restored record is believed on its own word.
    ///
    /// The damage from believing it is bounded, which is why this is not in
    /// the receive gates: `owner::authorize_redeem` derives the key and
    /// refuses if it does not open the live commitment, so a bogus claim
    /// cannot move value. It just cannot be *found out* until the holder
    /// tries to spend, which is the worst moment to learn it.
    ///
    /// Three answers per note, from the derived key, the stored claim and
    /// the live commitment:
    ///
    /// | derived vs stored | derived vs live | meaning |
    /// |---|---|---|
    /// | same | — | the claim holds |
    /// | differs | same | the stored commitment rotted; the index is right |
    /// | differs | differs | not ours at that index |
    ///
    /// The third case **strips the claim and keeps the note**. Deleting it
    /// would be the client deciding a holder's bytes are worthless on the
    /// strength of one derivation; the bytes may still be a perfectly good
    /// bearer note. What it must not do is keep telling them it is theirs
    /// to spend.
    ///
    /// Not cheap, and deliberately not run on every refresh: each note is a
    /// key derivation, which on a card is an NFC round trip. Run it where
    /// untrusted records enter — after a restore.
    pub async fn verify_ownership(&mut self, credential: &[u8]) -> Result<OwnershipReport> {
        // A key derivation per note -- an NFC round trip on a card -- and a
        // ledger read, so no lock across them. Each write
        // goes through `commit_if_unchanged`; a record that changed while
        // its card answered is counted unchecked and left alone.
        let mut report = OwnershipReport::default();

        for mut held in self.store.all().await? {
            let snapshot = held.clone();
            let (Some(index), Some(stored)) = (held.owner_index, held.owner_commitment) else {
                continue; // pure bearer: nothing claims ownership
            };

            // A failure to ask is not an answer. A card out of the field or
            // an unreachable ledger must leave the record exactly as it is,
            // or an unplugged reader would quietly disown a wallet.
            let Ok(derived) = owner::commitment_for(&mut self.vault, index, credential) else {
                report.unchecked += 1;
                continue;
            };
            if derived == stored {
                report.confirmed += 1;
                continue;
            }
            let Ok(on_chain) = self.chain.token_status(held.slot_id).await else {
                report.unchecked += 1;
                continue;
            };

            match on_chain.owner_commitment {
                // The index is right and the record was wrong. The ledger
                // is the authority on who owns a note, so this is a repair,
                // not a doubt.
                Some(live) if live == derived => {
                    held.owner_commitment = Some(derived);
                    if self.commit_if_unchanged(&snapshot, &held).await? {
                        report.corrected.push((held.id, index));
                    } else {
                        report.unchecked += 1;
                    }
                }
                other => {
                    held.owner_index = None;
                    held.owner_commitment = None;
                    if !self.commit_if_unchanged(&snapshot, &held).await? {
                        report.unchecked += 1;
                        continue;
                    }
                    report.disowned.push((
                        held.id,
                        match other {
                            None => format!(
                                "the ledger has no owner for it, and this wallet\u{2019}s key at \
                                 index {index} does not match what the record claims"
                            ),
                            Some(_) => format!(
                                "it is owned by a commitment this wallet cannot open at \
                                 index {index}"
                            ),
                        },
                    ));
                }
            }
        }
        Ok(report)
    }

    /// The owner commitment for a derivation index — what a payer spends to.
    pub fn owner_commitment_for(&mut self, index: u32, credential: &[u8]) -> Result<[u8; 32]> {
        owner::commitment_for(&mut self.vault, index, credential)
    }

    /// Begin a receive: reserve the next fresh index, derive its commitment, and
    /// record the pending receive **before** the commitment is shown to anyone.
    ///
    /// Ordering matters. If the record were written after the payer was given the
    /// commitment, a crash in between would leave a payment inbound to an index
    /// the wallet no longer knows it promised.
    pub async fn start_receive(
        &mut self,
        credential: &[u8],
        now: i64,
    ) -> Result<PendingReceive> {
        let index = self.store.allocate_owner_index().await?;
        let commitment = self.owner_commitment_for(index, credential)?;
        let pending = PendingReceive { index, commitment, created_at: now };
        self.store.put_pending(pending.clone()).await?;
        Ok(pending)
    }

    /// The spend nonce the mint currently holds for this note.
    ///
    /// Read immediately before signing and never cached: the digest covers
    /// it, so a stale value yields a signature the mint rejects — and
    /// accepting a caller-supplied one would reopen the replay this nonce
    /// exists to close.
    async fn live_spend_nonce(&self, slot_id: u32) -> Result<u32> {
        self.chain
            .token_status(slot_id)
            .await?
            .spend_nonce
            .ok_or_else(|| {
                WalletError::Chain("the mint has no record of this note".into())
            })
    }

    /// Owner proof for redeeming a spend-mode token. See [`owner::authorize_redeem`].
    pub async fn authorize_redeem(
        &mut self,
        index: u32,
        slot_id: u32,
        ephemeral_key: &[u8; 32],
        live_owner_commitment: &[u8; 32],
        recipient_xdr: &[u8],
        credential: &[u8],
    ) -> Result<RedeemOwnerProof> {
        let spend_nonce = self.live_spend_nonce(slot_id).await?;
        let contract_xdr = self.chain.mint_contract_xdr();
        owner::authorize_redeem(
            &mut self.vault,
            index,
            &contract_xdr,
            slot_id,
            ephemeral_key,
            live_owner_commitment,
            spend_nonce,
            recipient_xdr,
            credential,
        )
    }

    /// Authorization to transfer a spend-mode token. See [`owner::authorize_spend`].
    pub async fn authorize_spend(
        &mut self,
        index: u32,
        slot_id: u32,
        ephemeral_key: &[u8; 32],
        live_owner_commitment: &[u8; 32],
        new_owner_commitment: &[u8; 32],
        credential: &[u8],
    ) -> Result<SpendAuthorization> {
        let spend_nonce = self.live_spend_nonce(slot_id).await?;
        let contract_xdr = self.chain.mint_contract_xdr();
        owner::authorize_spend(
            &mut self.vault,
            index,
            &contract_xdr,
            slot_id,
            ephemeral_key,
            live_owner_commitment,
            new_owner_commitment,
            spend_nonce,
            credential,
        )
    }
}
