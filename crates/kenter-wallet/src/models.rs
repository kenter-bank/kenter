//! Wallet-core data model: locally-held tokens and their on-chain reconciliation.
//!
//! Kenter has **no account-balance query**. A holder's balance is the sum of the
//! bearer tokens they physically hold, each reconciled against its on-chain status
//! (`is_redeemed` / `TokenRecord.state`). So the wallet persists tokens locally
//! ([`HeldToken`]) and reads the chain only to learn each one's [`TokenStatus`].

use serde::{Deserialize, Serialize};

use kenter_crypto::container::deserialize_bearer_token;
use kenter_crypto::token::BearerToken;

use crate::error::{Result, WalletError};

/// A bearer token the wallet holds locally.
///
/// `blob` is the exact container bytes as received (file/QR/handoff) — persisted
/// verbatim so the stored signature is preserved. The other fields are metadata
/// extracted at import for display without re-parsing the blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeldToken {
    /// Stable id: [`note_id`] of the ephemeral address and the slot.
    ///
    /// The ephemeral address alone is not unique per token. The mint keys
    /// records by slot, so two slots naming the same key are two
    /// independent records, and the key itself is public as soon as a
    /// print completes. Keyed by address alone, anyone could register a
    /// dust note under their own slot naming a payer's key, send it first,
    /// and the genuine note would arrive as `Duplicate`. With the slot in
    /// the id the two are two rows.
    pub id: String,
    /// The print slot this note was registered under.
    ///
    /// What the mint keys its records by, so what a redemption, a spend
    /// or a status read names. The ephemeral key cannot serve that
    /// purpose: it is a public value, so whoever named it first would own
    /// the record.
    pub slot_id: u32,
    /// Combined ephemeral public key. Still the note's identity to a
    /// person -- it is what `id` is derived from -- and still what the
    /// signatures are made under; just not what addresses the record.
    pub ephemeral_public_key: [u8; 32],
    /// SHA-256 of the print-request event this token belongs to.
    pub event_id: [u8; 32],
    /// Face amount in stroops (from the token header denomination; 0 if unset).
    pub amount: u64,
    /// Canonical container bytes as received.
    pub blob: Vec<u8>,
    /// Host-supplied import time (Unix seconds). The core has no clock (wasm).
    pub imported_at: i64,
    /// The mint whose ledger has confirmed these bytes, if one has.
    ///
    /// A record is addressed by `slot_id`, and slot ids restart at zero
    /// on every deployment, so without this a note is reconciled against
    /// whichever mint the wallet happens to be pointed at. Four notes
    /// from four mints all carrying `slot_id = 0` read the current
    /// mint's slot 0, and every answer is about a different note.
    ///
    /// **Set only from the wallet's own configured mint, and only when
    /// that ledger has confirmed *this note's content*** -- a receive
    /// gate passing, or reconciliation seeing `Active` with
    /// [`TokenWallet::describes`] agreeing. Never from the container and
    /// never from a sender: a value a payer supplies is a value a payer
    /// chooses, and the point of binding is to stop one ledger answering
    /// for another.
    ///
    /// `None` means nothing has confirmed it yet, which is not the same
    /// as belonging here. Unbound notes are not grandfathered onto the
    /// configured mint; that assumption is what produces the wrong
    /// answers above.
    #[serde(default)]
    pub mint: Option<String>,
    /// Optional user label.
    pub label: Option<String>,
    /// Derivation index of the **owner key** that owns this token, if we own it
    /// (`docs/architecture/custody.md`). `None` = a pure-bearer token, or one
    /// owned by someone else.
    ///
    /// The key itself is never stored — it is re-derived from the wallet seed at
    /// `m/44'/148'/index'`. That is what makes the backup "one seed, once"
    /// instead of a new secret on every receipt.
    pub owner_index: Option<u32>,
    /// The owner commitment this token was bound to, recorded at bind time.
    ///
    /// Stored rather than re-derived so reconciliation can detect a token that
    /// has been paid away **without** the vault or a passphrase prompt: if the
    /// ledger's live commitment no longer equals this one, the token is no
    /// longer ours.
    pub owner_commitment: Option<[u8; 32]>,
    /// Set once reconciliation sees the live owner pointer move away from us.
    ///
    /// A spent-away token is still `Active` on the ledger — the value simply
    /// belongs to someone else now — so without this flag it would keep counting
    /// as spendable in the holder's own balance.
    #[serde(default)]
    pub spent_away: bool,

    /// Copies of this note that have left the client, by kind.
    #[serde(default)]
    pub exports: ExportLog,

    /// The holder's own assertion that this note is gone.
    ///
    /// Not a ledger fact and not reversible by the ledger: a bearer handover
    /// leaves no trace, so the client cannot know, and this is the holder
    /// saying so. Kept apart from `spent_away`, which the ledger *did* tell
    /// us, because one is an opinion and one is not.
    #[serde(default)]
    pub marked_spent: bool,
}

/// Why a copy of a note left, and how many times.
///
/// Kinds, not a single count. A flat count of exports called an exposure
/// figure would overstate it: a backup is a
/// copy the holder keeps and a handover is one they gave away, and only the
/// second means the note is probably gone. A holder with three backups and
/// no handovers has given nothing away.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportLog {
    /// A copy the holder keeps. Raises custody surface, not exposure.
    pub backup: u32,
    /// Delegated to a card. Unresolved until the card is reconciled: still
    /// theirs until it is tapped, and the desktop never learns that it was.
    pub to_card: u32,
    /// Given to someone else. This is the one that means *probably spent*.
    pub handover: u32,
}

/// Which kind of export happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    Backup,
    ToCard,
    Handover,
}

impl ExportLog {
    pub fn record(&mut self, kind: ExportKind) {
        let n = match kind {
            ExportKind::Backup => &mut self.backup,
            ExportKind::ToCard => &mut self.to_card,
            ExportKind::Handover => &mut self.handover,
        };
        *n = n.saturating_add(1);
    }

    /// How many other parties may hold a redeemable copy.
    ///
    /// Handovers certainly; card exports pessimistically, because the desktop
    /// cannot tell a card that still holds the note from one that has tapped
    /// it away. Backups are not counted — they are the holder's own.
    pub fn exposure(&self) -> u32 {
        self.handover.saturating_add(self.to_card)
    }

    pub fn is_empty(&self) -> bool {
        *self == ExportLog::default()
    }
}

/// The reusable "static receive address". Opt-in: every
/// payment sent to it is linkable to every other, traded for async reach.
pub const STATIC_RECEIVE_INDEX: u32 = 0;

/// Fresh per-receipt indices start here, leaving [`STATIC_RECEIVE_INDEX`] free.
pub const FIRST_FRESH_INDEX: u32 = 1;

/// What the wallet remembers about the last backup it wrote.
///
/// Kept in wallet state rather than read back off a file, because a backup
/// that lives on this disk is not a backup. The real one is on a stick in a
/// drawer, and the wallet still has to be able to say "you have received four
/// notes since you last made one" without it being plugged in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecord {
    /// When it was written (Unix seconds). Host-supplied; the core has no
    /// clock.
    pub at: i64,
    /// The ids that went into it, sorted.
    ///
    /// The set, not a hash of it, because the billfold asks two different
    /// questions and a digest only answers one. "Is this wallet covered?" is
    /// a comparison; "is *this note* in a backup?" — which every note card
    /// claims an answer to — needs membership.
    ///
    /// Sealed with the rest of the wallet state, since a list of ids is a
    /// statement about what is held and every id is a public ledger lookup.
    pub ids: Vec<String>,
    /// Where it was written, if the holder chose somewhere. Shown back to
    /// them so "make another one" has an obvious answer; never relied on,
    /// since the stick it names is usually not here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whence: Option<String>,
}

impl BackupRecord {
    /// How many notes it holds.
    pub fn notes(&self) -> usize {
        self.ids.len()
    }

    /// Whether a particular note is in it.
    pub fn covers(&self, id: &str) -> bool {
        self.ids.binary_search_by(|probe| probe.as_str().cmp(id)).is_ok()
    }
}

/// An owner index allocated for an incoming payment, before the token exists.
///
/// A payee must show a commitment *before* the payer sends the bytes
/// (`docs/architecture/spend-mode.md`, "Transfer"), so there is a window
/// where an index is spoken for and no token is held. Recording it here is what satisfies gate **G4** — and with
/// derivation there is nothing else to persist, because the seed already exists.
/// The record is consumed when the matching token is bound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingReceive {
    /// Derivation index reserved for this receive.
    pub index: u32,
    /// `SHA-256(SPEND_OWNER_COMMIT || owner_pubkey)` — what the payer spends to,
    /// and what identifies the token as ours once it lands.
    pub commitment: [u8; 32],
    /// Host-supplied creation time (Unix seconds); the core has no clock.
    pub created_at: i64,
}

/// An owner commitment this wallet can open, and the index it derives from.
///
/// The unit of the rule the receive gates rest on: a note is ours if it is
/// owned by a commitment we know, rather than by one record we happened to be
/// holding at the time. One tag handed to two payers is two notes at one
/// commitment, and both are ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownOwner {
    pub index: u32,
    pub commitment: [u8; 32],
}

/// The wallet's id for a note: its ephemeral address and the slot it was
/// registered under, `G…-<slot>`.
///
/// The slot is what the mint keys a record by; the address is what a
/// person recognises. Either alone collides. Every id the
/// wallet stores, backs up, or checks a container against is built here.
pub fn note_id(ephemeral_address: &str, slot_id: u32) -> String {
    format!("{ephemeral_address}-{slot_id}")
}

/// A note id for display: `GD7MDB…CLHR-3`. The slot is never elided,
/// since it is what tells two notes on one key apart.
pub fn short_note_id(id: &str) -> String {
    let (addr, slot) = match id.rsplit_once('-') {
        Some((a, s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => (a, Some(s)),
        _ => (id, None),
    };
    let addr = if addr.len() > 12 {
        format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    };
    match slot {
        Some(s) => format!("{addr}-{s}"),
        None => addr,
    }
}

impl HeldToken {
    /// Build metadata from a parsed token plus the bytes it was parsed from.
    pub(crate) fn from_bearer(token: &BearerToken, blob: Vec<u8>, imported_at: i64) -> Self {
        HeldToken {
            id: note_id(&token.ephemeral_address(), token.slot_id),
            slot_id: token.slot_id,
            ephemeral_public_key: token.ephemeral_public_key,
            event_id: token.header.event_id,
            amount: token.header.denomination.unwrap_or(0),
            // Unbound. Importing bytes is not a ledger confirming them,
            // and the sender does not get to say which mint answers for
            // a note.
            mint: None,
            blob,
            imported_at,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        }
    }

    /// Re-parse the stored blob back into a [`BearerToken`] (e.g. to re-verify or
    /// to build a redemption).
    pub fn to_bearer(&self) -> Result<BearerToken> {
        deserialize_bearer_token(&self.blob).map_err(|e| WalletError::Codec(e.to_string()))
    }
}

/// On-chain status of a held token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenStatus {
    /// Registered and not yet redeemed — spendable.
    Active,
    /// Already redeemed — spent.
    Redeemed,
    /// No on-chain record found for this key (e.g. never registered).
    NotFound,
    /// Status could not be determined (read failed / not yet checked).
    Unknown,
    /// Bound to a different mint than the one configured. Not read
    /// against this ledger at all, because an answer from the wrong
    /// mint is worse than no answer.
    OtherMint,
    /// Not bound to any mint, and this ledger's answer carried nothing
    /// that could bind it.
    ///
    /// A `Redeemed` marker is content-free -- it holds a ledger number
    /// and nothing about which note was paid -- and so is an absent
    /// record. Reporting either as `Redeemed` on an unbound note is
    /// what invites a holder to `forget` a live one.
    Unbound,
    /// The ledger has a live record, and it does not describe this
    /// container.
    ///
    /// Distinct from `NotFound`, which says the mint has never heard of
    /// the note, and from `Active`, which says it is good. This says
    /// the bytes held locally are not the note the mint registered —
    /// either the chain commitment or the claim key disagrees. A
    /// counterfeit reaches the store through `import`, which verifies
    /// offline by design, so this is where it has to be caught.
    Counterfeit,
    /// The ledger's record is this note, live, and owned by a commitment
    /// this wallet cannot open.
    ///
    /// A spend-mode note handed over without being spent to us, taken in by
    /// `import`; or one `verify_ownership` disowned, after which it is
    /// unbound and `sync` has no claim to compare. Neither is spendable.
    /// Counted with paid-away value: the ledger
    /// says whose it is, and it is not ours.
    NotOurs,
}

/// What a [`ChainRead`](crate::ports::ChainRead) returns for a token key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnChainToken {
    pub status: TokenStatus,
    /// On-chain recorded amount in stroops, if the record exists.
    pub amount: Option<i128>,
    /// The chain commitment the mint recorded for this token, if there is a
    /// record.
    ///
    /// The payee's **G2** gate compares it against the chain in the container
    /// they were handed. Everything else about a note can be reconstructed
    /// from public ledger data -- the partial public keys are published, and
    /// they sum to the ephemeral key -- so without this comparison a payer
    /// with no note at all can hand out convincing "payments" against any
    /// live escrow.
    pub chain_hash: Option<[u8; 32]>,
    /// The event id on the record, and the number of addresses it names.
    /// `None` when there is no record.
    ///
    /// `verify_chain` requires the chain's event id to equal the first
    /// and its link count to equal the second divided by two. A chain
    /// that fails either is still internally valid and still hashes to
    /// the committed `chain_hash`, so **G2 passes and Path B never
    /// will** -- a payee can be handed a note that pays nothing.
    pub event_id: Option<[u8; 32]>,
    pub participants_len: Option<u32>,
    /// The live owner commitment for a spend-mode token. `None` for pure bearer
    /// or when there is no record. This is what the payee's **G3** gate compares
    /// against their own commitment, and what lets reconciliation re-bind an
    /// owner index after a crash mid-receive.
    pub owner_commitment: Option<[u8; 32]>,
    /// How many times this note has been spent on, `None` when there is no
    /// record. Both owner digests cover it, so a signature authorises exactly
    /// one transfer and cannot be replayed when a note returns to a
    /// commitment it held before.
    pub spend_nonce: Option<u32>,
    /// The claim key the mint registered, `None` when there is no
    /// record. A pure-bearer note whose container carries a different
    /// one cannot be redeemed by its holder.
    pub claim_pubkey: Option<[u8; 32]>,
    /// The ephemeral key the record names, `None` when there is no
    /// record.
    ///
    /// Records are keyed by slot, so this is not the thing that was
    /// looked up -- it is a field the depositor chose, and it can
    /// disagree with the container while everything else agrees. A note
    /// whose registered key is not its own is redeemable through Path B
    /// and not through Path A, which is value the holder keeps and an
    /// escape route they lose.
    pub ephemeral_key: Option<[u8; 32]>,
}

/// A held token paired with its freshly-read on-chain status.
#[derive(Debug, Clone)]
pub struct ReconciledToken {
    pub held: HeldToken,
    pub status: TokenStatus,
    pub on_chain_amount: Option<i128>,
}

impl ReconciledToken {
    /// What this note is worth, as far as anything outside this machine can
    /// tell.
    ///
    /// **The ledger wins.** `held.amount` is a local claim: it arrives with
    /// the note, survives in the store, and travels in backups — so it is
    /// exactly the field someone handing over a loaded wallet would edit.
    /// The escrow behind a note is whatever the mint recorded, and no local
    /// record can change that, so showing the local figure was showing the
    /// one number an attacker controls.
    ///
    /// Falls back to the claim only when there is no on-chain record to
    /// check against, where it is all anyone has — and that case is already
    /// counted as `unverified` and labelled on the card.
    ///
    /// **Except a counterfeit, which is worth nothing.** The ledger has a
    /// live record for that slot and it is *another* note's, so its amount
    /// is that note's escrow, not this one's. Taking it would value a forgery
    /// at whatever the genuine note held. The local claim is
    /// no better -- it is the number a forger writes -- so zero is the only
    /// figure anything outside this machine supports.
    pub fn trusted_amount(&self) -> u64 {
        if self.status == TokenStatus::Counterfeit {
            return 0;
        }
        match self.on_chain_amount {
            // Negative or beyond u64 is not a quantity of anything; treat it
            // as unreadable rather than wrapping it into a plausible number.
            Some(a) => u64::try_from(a).unwrap_or(0),
            None => self.held.amount,
        }
    }

    /// The record claims one amount and the ledger says another.
    ///
    /// Corruption or forgery — the client cannot tell which, and does not
    /// need to: either way the record is not to be believed, and the holder
    /// should be told before they act on it.
    ///
    /// Only meaningful where the ledger has a record. A note the mint has
    /// never heard of is a different problem with its own label.
    pub fn claim_disputed(&self) -> bool {
        self.on_chain_amount
            .is_some_and(|_| self.trusted_amount() != self.held.amount)
    }
}

/// What a [`sync`](crate::TokenWallet::sync) changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Tokens newly tied to the owner index that owns them, as `(id, index)` —
    /// a receive whose binding never completed.
    pub bound: Vec<(String, u32)>,
    /// Tokens newly found to have been paid away.
    pub spent_away: Vec<String>,
    /// Tokens marked paid away that the ledger now says are ours again.
    pub returned: Vec<String>,
}

impl SyncReport {
    pub fn is_empty(&self) -> bool {
        self.bound.is_empty() && self.spent_away.is_empty() && self.returned.is_empty()
    }
}

/// Aggregate wallet balance, in stroops, partitioned by status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Σ face amounts of `Active` tokens — the spendable balance.
    pub spendable: u64,
    /// Σ face amounts of `Redeemed` tokens.
    pub redeemed: u64,
    /// Σ face amounts of tokens whose status is `NotFound` or `Unknown`.
    pub unverified: u64,
    /// Σ face amounts of tokens paid away — still `Active` on the ledger, but
    /// owned by someone else now.
    pub spent_away: u64,
    /// Σ face amounts of **every record in the store**, including notes that
    /// have been redeemed or paid away.
    ///
    /// **Not a balance, and not safe as a headline.** A redeemed note has no
    /// face value — it is gone — so this figure keeps counting money the
    /// holder no longer has. It is a diagnostic: the total this store has
    /// ever been responsible for. Use [`Balance::still_held`] for anything a
    /// person reads.
    pub total_held: u64,
    /// How many records claim an amount the ledger contradicts.
    ///
    /// A count, not a sum: the interesting quantity is "something here is
    /// lying to you", and summing the lie would put a fictional number on
    /// screen to describe fiction.
    pub disputed: u32,
}

impl Balance {
    /// Face value the holder still has a claim on.
    ///
    /// This is the figure a person should be shown. `spendable` is what the
    /// ledger confirms is live; `unverified` is included deliberately,
    /// because a note the client could not check is more likely to be the
    /// holder's than not, and a balance that drops during a network problem
    /// reads as money disappearing. The subtitle says when any of it is
    /// unverified, so the caveat travels with the number.
    ///
    /// Excludes `redeemed` and `spent_away`: both are gone, and counting
    /// them would leave the headline unchanged when a note is redeemed, so
    /// the one surface whose job is to say what you have would say
    /// something false.
    pub fn still_held(&self) -> u64 {
        self.spendable.saturating_add(self.unverified)
    }

    /// Face value that has left the billfold: redeemed, paid away, or
    /// redeemed by whoever was handed it.
    pub fn gone(&self) -> u64 {
        self.redeemed.saturating_add(self.spent_away)
    }

    /// Reduce a reconciliation into a partitioned balance (pure; no I/O).
    pub fn from_reconciled(tokens: &[ReconciledToken]) -> Balance {
        let mut b = Balance::default();
        for t in tokens {
            // The ledger's figure, not the record's. See
            // `ReconciledToken::trusted_amount`.
            let amt = t.trusted_amount();
            b.total_held = b.total_held.saturating_add(amt);
            // Checked before the chain status: a token we paid away is still
            // Active on-ledger, and counting it as spendable would overstate the
            // holder's balance by exactly the amount they just gave away.
            // The holder's own assertion counts here too. They may be wrong -
            // a handover can fail silently - but a client that keeps counting
            // a note they have given away as spendable is wrong in the
            // direction that loses people money.
            if t.held.spent_away || t.held.marked_spent {
                b.spent_away = b.spent_away.saturating_add(amt);
                continue;
            }
            match t.status {
                TokenStatus::Active => b.spendable = b.spendable.saturating_add(amt),
                TokenStatus::Redeemed => b.redeemed = b.redeemed.saturating_add(amt),
                // Somebody else's, on the ledger's word. Not ours to spend
                // and not unverified: the answer is in.
                TokenStatus::NotOurs => b.spent_away = b.spent_away.saturating_add(amt),
                // A counterfeit is not spendable: the ledger has a live
                // record and it is not this note, and its trusted amount
                // is zero. The rest are not spendable and not confirmed
                // gone either. The
                // distinction matters: `redeemed` is what tells a holder
                // a note is safe to delete, and `forget` on a bearer
                // note destroys the only copy.
                TokenStatus::Counterfeit
                | TokenStatus::NotFound
                | TokenStatus::Unknown
                | TokenStatus::OtherMint
                | TokenStatus::Unbound => {
                    b.unverified = b.unverified.saturating_add(amt)
                }
            }
            if t.claim_disputed() {
                b.disputed = b.disputed.saturating_add(1);
            }
        }
        b
    }
}

/// What a note's value is shown in when the mint's asset is not yet known.
///
/// **Not "KEN".** There is no Kenter token: a note is a claim on whatever the
/// mint escrows, which is fixed in its immutable constructor config as
/// `pay_token`. Labelling amounts with a ticker invented for the project
/// claims an asset exists that does not, which is the kind of thing people
/// make decisions on.
///
/// `$` because the intended deployment escrows USDC, where a dollar sign is
/// accurate rather than a placeholder. A mint escrowing something else should
/// be read and shown as what it is.
///
/// The established glyph for *an unspecified currency* is `¤` (U+00A4), which
/// is what this would be if the asset were genuinely unknown. There is no
/// standard symbol for a bearer instrument as such.
pub const DEFAULT_SYMBOL: &str = "$";

/// Format an amount in stroops: `$1.2500000`, seven decimal places, always.
///
/// Canonical here rather than per-shell: a divergence in how an amount is rendered is a divergence in what an
/// authorization prompt claims is being signed.
pub fn fmt_stroops(stroops: u64) -> String {
    fmt_amount(stroops, DEFAULT_SYMBOL)
}

/// [`fmt_stroops`] in a named asset's symbol.
pub fn fmt_amount(stroops: u64, symbol: &str) -> String {
    format!("{symbol}{}.{:07}", stroops / 10_000_000, stroops % 10_000_000)
}

#[cfg(test)]
mod export_tests {

    /// The attack this exists to stop: a genuine, Active note whose stored
    /// amount has been edited upward.
    ///
    /// Nothing about it looks wrong — the container verifies, the ledger
    /// has a record, the status is `Active`. Only the number is a lie, and
    /// the number must not be taken on trust.
    #[test]
    fn the_ledger_outranks_the_record_on_value() {
        let mut held = note("G1", 0);
        held.amount = 500_000_000; // the claim
        let r = ReconciledToken {
            held,
            status: TokenStatus::Active,
            on_chain_amount: Some(1_000_000), // the escrow
        };

        assert!(r.claim_disputed());
        assert_eq!(r.trusted_amount(), 1_000_000);

        let b = Balance::from_reconciled(std::slice::from_ref(&r));
        assert_eq!(b.spendable, 1_000_000, "the balance believed the record");
        assert_eq!(b.still_held(), 1_000_000);
        assert_eq!(b.disputed, 1);
    }

    /// A counterfeit's slot holds another note's record. Neither that
    /// note's escrow nor the forger's claim is this note's value.
    #[test]
    fn a_counterfeit_is_worth_nothing_not_the_genuine_notes_escrow() {
        let mut held = note("G1", 0);
        held.amount = 500_000_000; // what the forger wrote
        let r = ReconciledToken {
            held,
            status: TokenStatus::Counterfeit,
            on_chain_amount: Some(1_000_000), // the genuine note's escrow
        };
        assert_eq!(r.trusted_amount(), 0);
        let b = Balance::from_reconciled(std::slice::from_ref(&r));
        assert_eq!(b.unverified, 0);
        assert_eq!(b.still_held(), 0);
        assert_eq!(b.spendable, 0);
    }

    /// An honest note is not disputed and is counted at its face value.
    #[test]
    fn an_honest_note_is_not_flagged() {
        let mut held = note("G1", 0);
        held.amount = 1_000_000;
        let r = ReconciledToken {
            held,
            status: TokenStatus::Active,
            on_chain_amount: Some(1_000_000),
        };
        assert!(!r.claim_disputed());
        assert_eq!(r.trusted_amount(), 1_000_000);
        assert_eq!(Balance::from_reconciled(std::slice::from_ref(&r)).disputed, 0);
    }

    /// No on-chain record is a different problem with its own label. The
    /// claim is all anyone has, and it is already counted as unverified.
    #[test]
    fn an_unregistered_note_is_unverified_not_disputed() {
        let mut held = note("G1", 0);
        held.amount = 777;
        let r = ReconciledToken {
            held,
            status: TokenStatus::NotFound,
            on_chain_amount: None,
        };
        assert!(!r.claim_disputed());
        assert_eq!(r.trusted_amount(), 777);
        let b = Balance::from_reconciled(std::slice::from_ref(&r));
        assert_eq!(b.unverified, 777);
        assert_eq!(b.disputed, 0);
    }

    /// A ledger amount that is not a quantity of anything reads as zero,
    /// not as whatever it wraps to. Showing a holder a plausible number
    /// derived from nonsense is the failure mode worth avoiding.
    #[test]
    fn an_impossible_ledger_amount_reads_as_zero() {
        for bad in [-1i128, i128::MIN, i128::MAX] {
            let mut held = note("G1", 0);
            held.amount = 5;
            let r = ReconciledToken {
                held,
                status: TokenStatus::Active,
                on_chain_amount: Some(bad),
            };
            assert_eq!(r.trusted_amount(), 0, "{bad}");
            assert!(r.claim_disputed(), "{bad}");
        }
    }

    use super::*;

    /// Why exports are counted by kind: a flat count
    /// treats a backup like a handover and tells a holder their money is
    /// probably gone when they have given nothing away.
    #[test]
    fn backups_do_not_count_as_exposure() {
        let mut log = ExportLog::default();
        log.record(ExportKind::Backup);
        log.record(ExportKind::Backup);
        assert_eq!(log.exposure(), 0);
        assert_eq!(log.backup, 2);
    }

    #[test]
    fn handovers_and_card_exports_do() {
        let mut log = ExportLog::default();
        log.record(ExportKind::Handover);
        log.record(ExportKind::ToCard);
        // The card is counted pessimistically: the desktop cannot tell a
        // card that still holds the note from one that has tapped it away.
        assert_eq!(log.exposure(), 2);
    }

    #[test]
    fn an_untouched_note_has_an_empty_log() {
        assert!(ExportLog::default().is_empty());
        let mut log = ExportLog::default();
        log.record(ExportKind::Backup);
        assert!(!log.is_empty());
    }

    /// A note the holder says is gone must stop counting as spendable, even
    /// though the ledger still says Active - being wrong the other way is
    /// what loses people money.
    #[test]
    fn a_note_marked_spent_is_not_spendable() {
        let mut held = HeldToken {
            slot_id: 1,
            id: "G1".into(),
            ephemeral_public_key: [1; 32],
            event_id: [0; 32],
            amount: 500,
            blob: vec![],
            imported_at: 0,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        };
        let active = |h: &HeldToken| ReconciledToken {
            held: h.clone(),
            status: TokenStatus::Active,
            on_chain_amount: Some(500),
        };
        assert_eq!(Balance::from_reconciled(&[active(&held)]).spendable, 500);

        held.marked_spent = true;
        let b = Balance::from_reconciled(&[active(&held)]);
        assert_eq!(b.spendable, 0);
        assert_eq!(b.spent_away, 500);
        // Still a record: marking it spent is bookkeeping, not deletion.
        assert_eq!(b.total_held, 500);
        // But it is no longer the holder's, so the headline must not count it.
        assert_eq!(b.still_held(), 0);
    }

    fn note(id: &str, amount: u64) -> HeldToken {
        HeldToken {
            slot_id: 1,
            id: id.into(),
            ephemeral_public_key: [1; 32],
            event_id: [0; 32],
            amount,
            blob: vec![],
            imported_at: 0,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        }
    }

    fn at(held: &HeldToken, status: TokenStatus) -> ReconciledToken {
        ReconciledToken { held: held.clone(), status, on_chain_amount: None }
    }

    /// A note the ledger says was redeemed leaves the headline
    /// total, however the wallet came to know it.
    ///
    /// Redemption removes the token record and writes a marker, so a
    /// client reading only `Token(slot)` sees the same absence for a note
    /// that was paid out and a slot that never existed. Absence is
    /// `NotFound`, `NotFound` is `unverified`, and `still_held()` counts
    /// `unverified` -- so a redeemed note would stay in the total, which is
    /// the one direction a bearer wallet must not be wrong in. The read
    /// side is `MintClient::token_or_marker`; this pins what the balance
    /// must do once it is told.
    #[test]
    fn a_note_redeemed_through_the_marker_is_gone_not_held() {
        let n = note("G1", 500);
        let b = Balance::from_reconciled(&[at(&n, TokenStatus::Redeemed)]);

        assert_eq!(b.redeemed, 500);
        assert_eq!(b.still_held(), 0, "a redeemed note is still in the total");
        assert_eq!(b.gone(), 500);
        assert_eq!(b.unverified, 0);
    }

    /// The other half. Absence the contract itself confirms is nothing,
    /// and stays `unverified` rather than being counted as redeemed on a
    /// guess -- the client only reports `Redeemed` when it has seen the
    /// marker or the contract has said so.
    #[test]
    fn an_absent_record_is_not_assumed_redeemed() {
        let n = note("G1", 500);
        let b = Balance::from_reconciled(&[at(&n, TokenStatus::NotFound)]);

        assert_eq!(b.redeemed, 0);
        assert_eq!(b.unverified, 500);
        assert_eq!(b.still_held(), 500);
    }

    /// What `still_held` exists for: a headline showing `total_held` —
    /// every record the store has ever had — stays unchanged when a note is
    /// redeemed. The one surface whose job is to say what you have would be
    /// saying something false.
    #[test]
    fn redeeming_a_note_moves_the_headline() {
        let keep = note("G1", 300);
        let mut redeemed = note("G2", 700);

        let before = Balance::from_reconciled(&[
            at(&keep, TokenStatus::Active),
            at(&redeemed, TokenStatus::Active),
        ]);
        assert_eq!(before.still_held(), 1000);
        assert_eq!(before.gone(), 0);

        // Redeeming sets `marked_spent`, and the ledger reports it redeemed.
        redeemed.marked_spent = true;
        let after = Balance::from_reconciled(&[
            at(&keep, TokenStatus::Active),
            at(&redeemed, TokenStatus::Redeemed),
        ]);
        assert_eq!(after.still_held(), 300, "the headline has to drop");
        assert_eq!(after.gone(), 700, "and the amount has to be accounted for");
        // `total_held` is unchanged, which is exactly why it is the wrong
        // figure to show.
        assert_eq!(after.total_held, 1000);
    }

    /// A note someone else redeemed is gone too — the holder's copy is just
    /// paper at that point.
    #[test]
    fn a_note_redeemed_by_its_recipient_is_gone() {
        let handed_over = note("G1", 250);
        let b = Balance::from_reconciled(&[at(&handed_over, TokenStatus::Redeemed)]);
        assert_eq!(b.redeemed, 250);
        assert_eq!(b.still_held(), 0);
        assert_eq!(b.gone(), 250);
    }

    /// Unverified notes stay in the headline on purpose. A balance that
    /// drops because the ledger could not be reached reads as money
    /// vanishing, which is the worse way to be wrong; the subtitle carries
    /// the caveat instead.
    #[test]
    fn an_unverified_note_still_counts() {
        let n = note("G1", 400);
        for status in [TokenStatus::Unknown, TokenStatus::NotFound] {
            let b = Balance::from_reconciled(&[at(&n, status)]);
            assert_eq!(b.still_held(), 400, "{status:?}");
            assert_eq!(b.gone(), 0, "{status:?}");
        }
    }

    /// Every bucket is either held or gone, and nothing is counted twice.
    #[test]
    fn held_and_gone_partition_the_records() {
        let live = note("G1", 100);
        let unverified = note("G2", 200);
        let mut paid = note("G3", 300);
        paid.spent_away = true;
        let redeemed = note("G4", 400);

        let b = Balance::from_reconciled(&[
            at(&live, TokenStatus::Active),
            at(&unverified, TokenStatus::Unknown),
            at(&paid, TokenStatus::Active),
            at(&redeemed, TokenStatus::Redeemed),
        ]);
        assert_eq!(b.still_held(), 300);
        assert_eq!(b.gone(), 700);
        assert_eq!(b.still_held() + b.gone(), b.total_held);
    }
}

#[cfg(test)]
mod fmt_tests {
    use super::fmt_stroops;

    #[test]
    fn seven_places_always() {
        assert_eq!(fmt_stroops(0), "$0.0000000");
        assert_eq!(fmt_stroops(1), "$0.0000001");
        assert_eq!(fmt_stroops(10_000_000), "$1.0000000");
        assert_eq!(fmt_stroops(25_000_000), "$2.5000000");
        assert_eq!(fmt_stroops(2_999_400), "$0.2999400");
    }

    /// There is no Kenter token. A ticker invented for the project would
    /// claim an asset exists that does not.
    #[test]
    fn nothing_is_labelled_with_a_made_up_ticker() {
        for n in [0, 1, 25_000_000] {
            assert!(!fmt_stroops(n).contains("KEN"));
        }
    }

    #[test]
    fn a_named_asset_shows_its_own_symbol() {
        assert_eq!(super::fmt_amount(25_000_000, "XLM "), "XLM 2.5000000");
        assert_eq!(super::fmt_amount(25_000_000, "\u{a4}"), "\u{a4}2.5000000");
    }
}
