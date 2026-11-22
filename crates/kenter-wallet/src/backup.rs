//! Encrypted export and restore of held tokens — the other half of recovery.
//!
//! A recovery phrase restores **authorization**, not value. Tokens cannot be
//! enumerated from the ledger (it is keyed by the ephemeral key, and there is no
//! commitment→token index), so without the bytes there is nothing to redeem.
//! A complete backup is therefore **phrase + blobs**, and the two have opposite
//! cadences: the phrase once, the blobs on every single receipt
//! (`docs/architecture/spend-mode.md`, "The seed recovers authority, not
//! value"). This module is the blob half; [`crate::paper`] puts the same
//! content on paper, one sealed item per note.
//!
//! # Sealed under the seed, not the passphrase
//!
//! The AEAD key comes from the HD seed (`SoftVault::backup_credentials`), so a
//! restore needs the **phrase and the file** and nothing else. Sealing under the
//! vault passphrase would make the vault file a third thing you must not
//! lose — exactly the thing a backup is supposed to survive.
//!
//! This keeps the two-factor shape rather than weakening it: an attacker
//! needs seed *and* blobs without a backup, and seed *and* file with one.
//!
//! # v2: when "the phrase" stops meaning "the vault seed"
//!
//! That promise holds only while the phrase *is* the seed. With a card root
//! and a BIP85 child (`docs/architecture/custody.md`, "The four BIP-85
//! children") the phrase is the **root**, the vault seed is the **child**, and
//! this file is sealed under the child — so a holder can keep both halves of
//! the promised pair and still not open their own backup. The index is the
//! missing third thing.
//!
//! v2 records it **in the cleartext header**, for a reason that settles where:
//! the payload is sealed under the very key the index is needed to derive, so
//! an index inside the ciphertext is one you can only read once you no longer
//! need it. The file format is in `docs/architecture/data-formats.md`.
//!
//! # What travels
//!
//! Not just the bytes. `owner_index` is what lets a spend-mode token be spent or
//! redeemed at all, and the index counter has to come across too — restoring
//! without it would hand out an index twice and link two payments to one
//! commitment. Pending receives come too, since losing one loses an inbound
//! payment that may already have been promised to a payer.

use crypto_secretbox::{
    aead::{Aead, KeyInit},
    Key, Nonce, XSalsa20Poly1305,
};
use serde::{Deserialize, Serialize};

use crate::error::{Result, WalletError};
use crate::models::{BackupRecord, HeldToken, PendingReceive, FIRST_FRESH_INDEX};
use crate::ports::Store;

const BACKUP_KIND: &str = "kenter-wallet-backup";
/// Written by this build. `inspect` also reads v1 — see [`BackupFile::origin`].
const BACKUP_VERSION: u8 = 2;
/// Domain tag for [`content_digest`], so the value cannot be confused with any
/// other hash in the system.
const DIGEST_DOMAIN: &[u8] = b"kenter_v1:backup:contents";
const NONCE_LEN: usize = 24;

/// Where the seed this backup is sealed under came from.
///
/// Recorded because it decides **what a restorer has to be asked for**: a
/// phrase, a card, or a root plus an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeedOrigin {
    /// The phrase is the vault seed. Every v1 file.
    Software,
    /// The card holds the seed; the phrase, if written down, is that seed.
    Card,
    /// The vault seed is a BIP85 child of a root held elsewhere.
    Bip85Child,
}

/// Which BIP85 child the vault seed is (`docs/architecture/custody.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip85Derivation {
    /// `m/83696968'/39'/0'/{words}'/{index}'`.
    pub index: u32,
    /// 12 or 24. **Part of the path**, not decoration: children of the same
    /// index at different word counts are different seeds.
    pub words: u8,
    /// BIP32 master fingerprint of the root, as every hardware wallet reports
    /// it. Answers "which card opens this?" for a holder with more than one.
    ///
    /// Optional, because it costs a linkage: two files carrying the same value
    /// are visibly from one root, which weakens the per-device compartment
    /// BIP85 exists for. Worth it for the common case, declinable for the
    /// paranoid one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_fingerprint: Option<String>,
}

/// The cleartext wrapper. Everything identifying is here; everything valuable is
/// in `ciphertext`.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupFile {
    pub kind: String,
    pub version: u8,
    /// Which wallet this belongs to (`BackupCredentials::fingerprint`). Always
    /// the **vault** seed's fingerprint, including for a BIP85 child.
    pub seed_fingerprint: String,
    pub created_at: i64,
    /// Readable without the key, so `inspect` can say how much is in here.
    pub token_count: usize,
    /// Absent in v1. Read it through [`BackupFile::origin`], which resolves
    /// that absence deliberately rather than defaulting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_origin: Option<SeedOrigin>,
    /// Present iff the origin is [`SeedOrigin::Bip85Child`]; `inspect` enforces
    /// the iff in both directions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bip85: Option<Bip85Derivation>,
    /// [`content_digest`] of the sealed tokens. Lets a wallet answer "is my
    /// current set covered by this file?" without the key. Absent in v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    nonce: String,
    ciphertext: String,
}

impl BackupFile {
    /// What seed this file is sealed under, with v1's silence resolved.
    ///
    /// A v1 file is `Software` and that is **not a guess**: the v1 format has
    /// no card or BIP85 origin, so every v1 file is sealed under a seed that
    /// *is* the phrase. Stated here rather than left to a
    /// `#[serde(default)]`, because a default would make the same claim
    /// invisibly, including for any later format where it is not true.
    pub fn origin(&self) -> SeedOrigin {
        match self.seed_origin {
            Some(o) => o,
            None => SeedOrigin::Software,
        }
    }
}

/// What a restorer must be given to derive the key for this file.
///
/// Passed to [`encode`] so the header can say it. The fingerprint is the
/// vault seed's either way — `origin` and `bip85` describe how to *get* to
/// that seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSource {
    pub fingerprint: String,
    pub origin: SeedOrigin,
    pub bip85: Option<Bip85Derivation>,
}

impl SeedSource {
    /// A software wallet: the phrase is the vault seed.
    pub fn software(fingerprint: impl Into<String>) -> Self {
        SeedSource {
            fingerprint: fingerprint.into(),
            origin: SeedOrigin::Software,
            bip85: None,
        }
    }
}

/// A stable digest of exactly which notes a backup holds.
///
/// Sorted ids under a domain tag, so it is independent of store ordering and
/// cannot collide with another hash in the system. The wallet computes this
/// over what it holds now and compares it to a file's header: equal means
/// covered, different means something has arrived or left since.
///
/// Ids, not blobs — a note's container never changes after receipt
/// (`NoteCard::backed_up` relies on the same fact), so the id set is the whole
/// question, and hashing ids keeps this cheap enough to run on every billfold
/// paint.
pub fn content_digest(tokens: &[HeldToken]) -> String {
    digest_of_ids(tokens.iter().map(|t| t.id.as_str()))
}

/// [`content_digest`] over ids already in hand — a [`BackupRecord`]'s, say.
///
/// Sorts internally, so a caller cannot produce a different digest for the
/// same set by handing them over in a different order.
pub fn digest_of_ids<'a>(ids: impl IntoIterator<Item = &'a str>) -> String {
    use sha2::{Digest, Sha256};
    let mut ids: Vec<&str> = ids.into_iter().collect();
    ids.sort_unstable();
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    for id in ids {
        h.update(id.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

/// What a backup restores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupContents {
    pub tokens: Vec<HeldToken>,
    pub pending: Vec<PendingReceive>,
    /// The wallet's owner-index counter at export time.
    pub next_owner_index: Option<u32>,
    pub created_at: i64,
}

/// On-disk shape of a token inside the payload. Byte fields are hex for the
/// same reason the store uses hex: `Vec<u8>` through `serde_json` becomes an
/// array of integers, several times larger and unreadable.
#[derive(Debug, Serialize, Deserialize)]
struct BackupToken {
    id: String,
    slot_id: u32,
    ephemeral_public_key: String,
    event_id: String,
    amount: u64,
    imported_at: i64,
    /// The mint whose ledger confirmed these bytes. Absent on records
    /// written before binding existed, which read as unbound rather
    /// than as belonging to whatever mint is configured now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    spent_away: bool,
    /// Carried through the backup: it is the holder's own record of their own
    /// handovers, in a file only they can open. It must never reach an
    /// *exported note*, which is a different artefact entirely.
    #[serde(default, skip_serializing_if = "crate::models::ExportLog::is_empty")]
    exports: crate::models::ExportLog,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    marked_spent: bool,
    blob: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    tokens: Vec<BackupToken>,
    pending: Vec<PendingReceive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_owner_index: Option<u32>,
}

fn bad(what: &str) -> WalletError {
    WalletError::Backup(format!("corrupt backup: bad {what}"))
}

impl BackupToken {
    fn from_held(t: &HeldToken) -> Self {
        BackupToken {
            id: t.id.clone(),
            slot_id: t.slot_id,
            ephemeral_public_key: hex::encode(t.ephemeral_public_key),
            event_id: hex::encode(t.event_id),
            amount: t.amount,
            imported_at: t.imported_at,
            mint: t.mint.clone(),
            label: t.label.clone(),
            owner_index: t.owner_index,
            owner_commitment: t.owner_commitment.map(hex::encode),
            spent_away: t.spent_away,
            exports: t.exports,
            marked_spent: t.marked_spent,
            blob: hex::encode(&t.blob),
        }
    }

    fn into_held(self) -> Result<HeldToken> {
        let ephemeral_public_key: [u8; 32] = hex::decode(&self.ephemeral_public_key)
            .map_err(|_| bad("ephemeral_public_key"))?
            .try_into()
            .map_err(|_| bad("ephemeral_public_key length"))?;
        let event_id: [u8; 32] = hex::decode(&self.event_id)
            .map_err(|_| bad("event_id"))?
            .try_into()
            .map_err(|_| bad("event_id length"))?;
        let owner_commitment = match self.owner_commitment {
            None => None,
            Some(h) => Some(
                hex::decode(&h)
                    .map_err(|_| bad("owner_commitment"))?
                    .try_into()
                    .map_err(|_| bad("owner_commitment length"))?,
            ),
        };
        let blob = hex::decode(&self.blob).map_err(|_| bad("blob"))?;
        Ok(HeldToken {
            id: self.id,
            slot_id: self.slot_id,
            ephemeral_public_key,
            event_id,
            amount: self.amount,
            blob,
            imported_at: self.imported_at,
            mint: self.mint.clone(),
            label: self.label,
            owner_index: self.owner_index,
            owner_commitment,
            spent_away: self.spent_away,
            exports: self.exports,
            marked_spent: self.marked_spent,
        })
    }
}

/// Seal a wallet's tokens into a portable backup.
///
/// `seed` is what a restorer will have to be given — see [`SeedSource`]. It
/// is not optional for a card-rooted wallet: without it the file records no
/// way back to its own key.
pub fn encode(
    key: &[u8; 32],
    seed: &SeedSource,
    tokens: &[HeldToken],
    pending: &[PendingReceive],
    next_owner_index: Option<u32>,
    now: i64,
) -> Result<Vec<u8>> {
    if (seed.origin == SeedOrigin::Bip85Child) != seed.bip85.is_some() {
        return Err(WalletError::Backup(
            "a BIP85-child backup must carry its derivation, and only it may"
                .into(),
        ));
    }
    let payload = Payload {
        tokens: tokens.iter().map(BackupToken::from_held).collect(),
        pending: pending.to_vec(),
        next_owner_index,
    };
    let plain = serde_json::to_vec(&payload)
        .map_err(|e| WalletError::Backup(format!("encoding payload: {e}")))?;

    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plain.as_slice())
        .map_err(|_| WalletError::Backup("sealing the backup failed".into()))?;

    let file = BackupFile {
        kind: BACKUP_KIND.to_string(),
        version: BACKUP_VERSION,
        seed_fingerprint: seed.fingerprint.clone(),
        created_at: now,
        token_count: tokens.len(),
        seed_origin: Some(seed.origin),
        bip85: seed.bip85.clone(),
        content_digest: Some(content_digest(tokens)),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(&ciphertext),
    };
    serde_json::to_vec_pretty(&file)
        .map_err(|e| WalletError::Backup(format!("encoding backup: {e}")))
}

/// Seal one item for a paper backup.
///
/// Paper seals each note separately rather than the whole file once, so a
/// damaged symbol costs one note instead of everything
/// (`crate::paper`). Same key as the file, same construction, fresh nonce
/// per item — which is required, not merely tidy: XSalsa20-Poly1305 with a
/// repeated nonce under one key leaks the XOR of the plaintexts, and here
/// the plaintexts would be notes.
pub fn seal_item(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let nonce: [u8; NONCE_LEN] = rand::random();
    let mut out = Vec::with_capacity(NONCE_LEN + plain.len() + 16);
    out.extend_from_slice(&nonce);
    out.extend(
        cipher
            .encrypt(Nonce::from_slice(&nonce), plain)
            .map_err(|_| WalletError::Backup("sealing a paper item failed".into()))?,
    );
    Ok(out)
}

/// Open what [`seal_item`] sealed.
///
/// A failure here is reported per item and does not stop the others, so a
/// holder scanning a sheet with one bad symbol still gets the rest.
pub fn open_item(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() <= NONCE_LEN {
        return Err(WalletError::Backup("the item is too short to be sealed".into()));
    }
    let (nonce, body) = sealed.split_at(NONCE_LEN);
    XSalsa20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| {
            WalletError::Backup(
                "this item will not open with that wallet's key - either it belongs to \
                 another wallet, or the symbols were misread"
                    .into(),
            )
        })
}

/// Read a backup's header without the key — which wallet, when, how much.
pub fn inspect(bytes: &[u8]) -> Result<BackupFile> {
    let file: BackupFile = serde_json::from_slice(bytes)
        .map_err(|e| WalletError::Backup(format!("not a backup file: {e}")))?;
    if file.kind != BACKUP_KIND {
        return Err(WalletError::Backup(format!(
            "not a Kenter wallet backup (kind {:?})",
            file.kind
        )));
    }
    if file.version == 0 || file.version > BACKUP_VERSION {
        return Err(WalletError::Backup(format!(
            "backup version {} is not supported (this build reads 1 and {BACKUP_VERSION})",
            file.version
        )));
    }

    // A v1 file carrying v2 fields is lying about one of the two, and the
    // cheap thing to do is say so now rather than derive a key from a header
    // half of which is being ignored.
    if file.version == 1
        && (file.seed_origin.is_some() || file.bip85.is_some() || file.content_digest.is_some())
    {
        return Err(WalletError::Backup(
            "this file says version 1 but carries version 2 fields".into(),
        ));
    }

    // The derivation is present exactly when the origin needs one. Checked in
    // both directions: a BIP85 child without it cannot be opened at all, and a
    // software backup carrying one is describing a seed it was not sealed
    // under.
    if (file.origin() == SeedOrigin::Bip85Child) != file.bip85.is_some() {
        return Err(WalletError::Backup(format!(
            "backup header is inconsistent: origin {:?} with{} a BIP85 derivation",
            file.origin(),
            if file.bip85.is_some() { "" } else { "out" }
        )));
    }
    if let Some(d) = file.bip85.as_ref().filter(|d| d.words != 12 && d.words != 24) {
        return Err(WalletError::Backup(format!(
            "BIP85 word count {} is neither 12 nor 24, so the path is unusable",
            d.words
        )));
    }
    Ok(file)
}

/// Open a backup.
///
/// The fingerprint is checked before decryption so restoring another wallet's
/// file says so, instead of surfacing as an indistinguishable AEAD failure that
/// looks like a wrong passphrase.
pub fn decode(key: &[u8; 32], fingerprint: &str, bytes: &[u8]) -> Result<BackupContents> {
    let file = inspect(bytes)?;
    if file.seed_fingerprint != fingerprint {
        return Err(WalletError::Backup(format!(
            "this backup belongs to a different wallet (file {}, yours {fingerprint})",
            file.seed_fingerprint
        )));
    }

    let nonce = hex::decode(&file.nonce).map_err(|_| bad("nonce"))?;
    // `Nonce::from_slice` panics on the wrong length, and this one came
    // out of a file. A damaged or crafted backup should fail to open,
    // not take the process down.
    if nonce.len() != NONCE_LEN {
        return Err(bad("nonce"));
    }
    let ciphertext = hex::decode(&file.ciphertext).map_err(|_| bad("ciphertext"))?;
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| {
            WalletError::Backup(
                "could not open the backup — the fingerprint matched, so the file is damaged"
                    .into(),
            )
        })?;

    let payload: Payload = serde_json::from_slice(&plain)
        .map_err(|e| WalletError::Backup(format!("corrupt backup payload: {e}")))?;
    let tokens = payload
        .tokens
        .into_iter()
        .map(BackupToken::into_held)
        .collect::<Result<Vec<_>>>()?;

    Ok(BackupContents {
        tokens,
        pending: payload.pending,
        next_owner_index: payload.next_owner_index,
        created_at: file.created_at,
    })
}

// ---------------------------------------------------------------------------
// Store-aware export and restore
//
// `encode` and `decode` are the format; these two are the promise. Everything
// above this line can be exercised with a hand-built `Vec<HeldToken>`, which is
// why it was all correct and all useless: nothing read the store, and nothing
// wrote one back.
// ---------------------------------------------------------------------------

/// Seal everything a wallet currently holds.
///
/// Takes `&mut` only for the counter: reading it is `advance_owner_index(0)`,
/// which is forward-only and so cannot disturb what it reports.
///
/// The counter travels because `owner_index` is what makes a spend-mode note
/// spendable, and a restored wallet that starts allocating from 1 again would
/// reissue indices its own restored notes already stand on.
pub async fn export<S: Store>(
    store: &mut S,
    key: &[u8; 32],
    seed: &SeedSource,
    now: i64,
) -> Result<Vec<u8>> {
    let tokens = store.all().await?;
    let pending = store.pending().await?;
    let next_owner_index = store.advance_owner_index(0).await?;
    encode(key, seed, &tokens, &pending, Some(next_owner_index), now)
}

/// What a [`restore`] did.
///
/// Reported rather than returned as a bare count because "restored 4 notes"
/// and "restored 4 notes, kept 11 you already had" are different sentences to
/// a holder who is about to decide whether the file was the right one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreReport {
    /// Notes in the file that the wallet did not have.
    pub tokens_added: usize,
    /// Notes in the file the wallet already held, left exactly as they were.
    pub tokens_kept: usize,
    pub pending_added: usize,
    pub pending_kept: usize,
    pub owner_index_before: u32,
    pub owner_index_after: u32,
    /// Notes in the file that do not verify, and were **not** stored, as
    /// `(id, why)`.
    ///
    /// See [`check`] for what is checked and why refusing beats importing.
    pub rejected: Vec<(String, String)>,
}

impl RestoreReport {
    /// Nothing in the file was new. True of a second restore of the same file,
    /// and of a file that is a subset of what is already held.
    pub fn is_empty(&self) -> bool {
        self.tokens_added == 0 && self.pending_added == 0
    }
}

/// Is this note what it says it is?
///
/// Three questions, none of which needs the network, and all of which a
/// genuine note answers by construction:
///
/// 1. **Does the blob parse?** The container is the note. A record whose
///    blob is not a container describes something that does not exist.
/// 2. **Does the chain verify?** `verify_chain_integrity` is the same gate
///    every note passed on the way in (`TokenWallet::import`, and **G1** on
///    receive), so this refuses nothing a holder legitimately has.
/// 3. **Does the blob name this id?** The ephemeral address is *derived
///    from* the container, so a record whose id does not match its own blob
///    has had one of the two edited — and the id is what every on-chain
///    lookup uses, so a mismatch points the ledger check at a different
///    note than the one being stored.
///
/// `amount` is deliberately not checked here: it cannot be, offline. The
/// ledger settles it (`ReconciledToken::trusted_amount`).
///
/// **Refused rather than imported-and-flagged.** A note that fails these
/// can never be redeemed by anybody, so storing it would add a permanent
/// unusable row to the billfold in exchange for nothing. Refusing is also
/// the only answer that cannot be ignored: it is reported, counted, and the
/// bytes stay out of the store.
pub fn check(token: &HeldToken) -> Result<()> {
    let bearer = token.to_bearer().map_err(|e| {
        WalletError::Backup(format!("its container does not parse: {e}"))
    })?;
    bearer.verify_chain_integrity().map_err(|e| {
        WalletError::Backup(format!("its container does not verify: {e}"))
    })?;
    let derived = crate::models::note_id(&bearer.ephemeral_address(), bearer.slot_id);
    if derived != token.id {
        return Err(WalletError::Backup(format!(
            "its container is for a different note ({derived})"
        )));
    }
    // The slot decides which ledger record this note redeems against, so
    // a stored value that disagrees with its own container is the same
    // class of forgery as a mismatched id -- and a more useful one to an
    // attacker, since it points a real note at another record.
    if bearer.slot_id != token.slot_id {
        return Err(WalletError::Backup(format!(
            "its container was registered under slot {}, not {}",
            bearer.slot_id, token.slot_id
        )));
    }
    // The rest of what a record says about its note can be read off the
    // container too, so it must agree. `ephemeral_public_key` feeds the
    // spend digest; `event_id` and `amount` are what the holder is shown.
    // Owner fields and the mint binding are
    // the wallet's own bookkeeping, not facts about the container, and are
    // checked against the ledger instead (`verify_ownership`, `reconcile`).
    if bearer.ephemeral_public_key != token.ephemeral_public_key {
        return Err(WalletError::Backup(
            "its record names a different ephemeral key from its container".into(),
        ));
    }
    if bearer.header.event_id != token.event_id {
        return Err(WalletError::Backup(
            "its record names a different event from its container".into(),
        ));
    }
    if bearer.header.denomination.unwrap_or(0) != token.amount {
        return Err(WalletError::Backup(format!(
            "its record claims {} but its container is for {}",
            token.amount,
            bearer.header.denomination.unwrap_or(0)
        )));
    }
    Ok(())
}

/// Merge a backup into a store.
///
/// **Strictly additive: an entry the store already has is never overwritten.**
///
/// This is the whole safety argument, and the obvious implementation gets it
/// backwards. A backup is by construction a *past* state of the wallet. Writing
/// its copy of a note over the live one rolls that note back — and the field
/// most likely to differ is `spent_away`, so the failure mode is a wallet that
/// shows a holder a note they have already handed to somebody else, with no way
/// to tell from the record that they did. Restoring can therefore only ever
/// give value back, never resurrect it.
///
/// The consequence to live with: a note whose *local* record is damaged is not
/// repaired by restoring over it. That is the right trade — a damaged record
/// is visible and recoverable by removing it first, whereas a silently un-spent
/// note is neither.
///
/// The counter moves to the highest of: where the store already is, what the
/// file recorded, and one past every index any restored entry stands on. That
/// last term is belt-and-braces — a correctly written file's counter already
/// covers its own contents — but it is what keeps a hand-edited or truncated
/// file from handing out a live index.
///
/// Takes the wallet lock: every entry is a `get` then a `put`, and a receive
/// or sync landing between the two would be a lost write. The caller
/// must not already hold it -- it is not re-entrant.
pub async fn restore<S: Store>(store: &mut S, contents: &BackupContents) -> Result<RestoreReport> {
    let _guard = store.lock()?;
    let mut report = RestoreReport::default();

    for token in &contents.tokens {
        // Before the store, always. A backup is the one place notes arrive
        // without having come through a receive gate, so this is where the
        // gate has to be instead.
        if let Err(why) = check(token) {
            report
                .rejected
                .push((token.id.clone(), why.to_string()));
            continue;
        }
        if store.get(&token.id).await?.is_some() {
            report.tokens_kept += 1;
        } else {
            store.put(token.clone()).await?;
            report.tokens_added += 1;
        }
    }

    // One read, then a set: `Store` has no `get_pending`, and a linear scan per
    // entry would be quadratic in the size of the thing we are restoring.
    let held: std::collections::BTreeSet<u32> =
        store.pending().await?.into_iter().map(|p| p.index).collect();
    for pending in &contents.pending {
        if held.contains(&pending.index) {
            report.pending_kept += 1;
        } else {
            store.put_pending(pending.clone()).await?;
            report.pending_added += 1;
        }
    }

    let mut want = contents.next_owner_index.unwrap_or(FIRST_FRESH_INDEX);
    for token in &contents.tokens {
        if let Some(index) = token.owner_index {
            // Rejected notes count here too, deliberately. Burning an index
            // costs nothing; handing out one that a note somewhere claims -
            // even a note this wallet refused - risks two payers at one
            // commitment, and the counter only moves forward anyway.
            want = want.max(index.saturating_add(1));
        }
    }
    for pending in &contents.pending {
        want = want.max(pending.index.saturating_add(1));
    }
    want = want.max(FIRST_FRESH_INDEX);

    report.owner_index_before = store.advance_owner_index(0).await?;
    report.owner_index_after = store.advance_owner_index(want).await?;
    Ok(report)
}

/// Whether a backup file still covers what the wallet holds.
///
/// Not a bool, because the cases a holder has to act on are different
/// sentences: no file at all is "make one", a file for another wallet is
/// "you opened the wrong one", and stale is "you have received since".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// No file. Every note is on this machine only.
    Missing,
    /// A valid backup, but of a different wallet. Never silently overwritten:
    /// that file is the only copy of somebody's notes, possibly an earlier
    /// card of this same holder.
    OtherWallet { fingerprint: String },
    /// Not a backup, or damaged past the header.
    Unreadable { why: String },
    /// A v1 file: no digest, so coverage cannot be decided without the key.
    /// Treated as "not known to be covered", which is the safe reading.
    Unknown { created_at: i64 },
    Covered { created_at: i64, notes: usize },
    /// The wallet holds notes the file does not, or has shed notes it still
    /// carries. Either way the file is no longer a picture of this wallet.
    Stale {
        created_at: i64,
        in_file: usize,
        held: usize,
    },
}

impl Coverage {
    /// Whether every note now held is known to be in the file. Only
    /// [`Coverage::Covered`] qualifies — `Unknown` deliberately does not.
    pub fn is_covered(&self) -> bool {
        matches!(self, Coverage::Covered { .. })
    }

    /// Whether writing a fresh backup would change anything. False only when
    /// the file already covers the wallet.
    pub fn needs_refresh(&self) -> bool {
        !self.is_covered()
    }
}

/// Decide [`Coverage`] from a file's bytes and what the wallet holds.
///
/// Needs no key: that is the point. The answer has to be available on every
/// paint of the billfold, and the backup key costs a card tap.
///
/// Compares the **id set**, which is exactly the set of notes whose bytes
/// would be unrecoverable. A note that changed state without changing id —
/// spent, relabelled, exported — does not make the file stale, and should
/// not: that state is reconstructible from the ledger, whereas the bytes are
/// not reconstructible from anything.
pub fn coverage(file: Option<&[u8]>, fingerprint: &str, tokens: &[HeldToken]) -> Coverage {
    let Some(bytes) = file else {
        return Coverage::Missing;
    };
    let header = match inspect(bytes) {
        Ok(h) => h,
        Err(e) => return Coverage::Unreadable { why: e.to_string() },
    };
    if header.seed_fingerprint != fingerprint {
        return Coverage::OtherWallet {
            fingerprint: header.seed_fingerprint,
        };
    }
    let Some(digest) = header.content_digest.as_deref() else {
        return Coverage::Unknown {
            created_at: header.created_at,
        };
    };
    if digest == content_digest(tokens) {
        Coverage::Covered {
            created_at: header.created_at,
            notes: tokens.len(),
        }
    } else {
        Coverage::Stale {
            created_at: header.created_at,
            in_file: header.token_count,
            held: tokens.len(),
        }
    }
}

/// Coverage from the wallet's own record, without the file.
///
/// This is the one the billfold asks, and the file-reading [`coverage`] is
/// not a substitute for it: the backup that matters is on a stick in a
/// drawer, so it is not readable when the question is asked. What *is*
/// readable is the digest the wallet wrote down when it made the file, and
/// that answers the question exactly as well.
///
/// Returns only `Missing`, `Covered` and `Stale` — the other variants are
/// statements about a file, and there is no file here.
pub fn coverage_of_record(record: Option<&BackupRecord>, tokens: &[HeldToken]) -> Coverage {
    let Some(record) = record else {
        return Coverage::Missing;
    };
    if digest_of_ids(record.ids.iter().map(String::as_str)) == content_digest(tokens) {
        Coverage::Covered {
            created_at: record.at,
            notes: tokens.len(),
        }
    } else {
        Coverage::Stale {
            created_at: record.at,
            in_file: record.notes(),
            held: tokens.len(),
        }
    }
}

/// The record to write down once a backup has landed.
///
/// Built from the same tokens that went into the file, so the digest cannot
/// drift from the one in its header.
pub fn record_for(tokens: &[HeldToken], at: i64, whence: Option<String>) -> BackupRecord {
    let mut ids: Vec<String> = tokens.iter().map(|t| t.id.clone()).collect();
    // Sorted on the way in, because `covers` binary-searches and a record
    // read back from disk is trusted to be in order.
    ids.sort_unstable();
    BackupRecord { at, ids, whence }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x11; 32];
    const FP: &str = "0123456789abcdef";

    fn soft() -> SeedSource {
        SeedSource::software(FP)
    }

    /// A card-rooted wallet: the phrase is the root, this vault is child 7.
    fn child(index: u32, root: Option<&str>) -> SeedSource {
        SeedSource {
            fingerprint: FP.to_string(),
            origin: SeedOrigin::Bip85Child,
            bip85: Some(Bip85Derivation {
                index,
                words: 24,
                root_fingerprint: root.map(str::to_string),
            }),
        }
    }

    /// A backup whose nonce is the wrong
    /// length fails to open rather than taking the process with it.
    ///
    /// `Nonce::from_slice` panics on anything but 24 bytes, and this one
    /// is read straight out of a file — so a damaged backup, or one
    /// handed over by someone else, was an abort rather than an error.
    #[test]
    fn a_backup_with_a_malformed_nonce_is_refused_without_panicking() {
        let bytes = encode(&KEY, &soft(), &[], &[], None, 0).unwrap();
        let mut file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        for nonce_len in [0usize, 3, 23, 25, 64] {
            file["nonce"] = serde_json::json!(hex::encode(vec![0u8; nonce_len]));
            let broken = serde_json::to_vec(&file).unwrap();
            assert!(
                decode(&KEY, FP, &broken).is_err(),
                "a {nonce_len}-byte nonce must be refused"
            );
        }
    }

    /// A **genuine** note: a real chain, a real signature, and an id
    /// derived from its own container.
    ///
    /// Not a hand-built `HeldToken` with `blob: vec![seed; 64]`: a restore
    /// test built on that restores something that is not a note. `restore`
    /// parses the blob (see [`check`]), and a fixture that cannot survive
    /// that is not testing restore.
    ///
    /// No network is needed for this. The nodes in a print are just
    /// keypairs contributing chain links, and a test can play all of them.
    /// What it cannot fabricate is the **on-chain registration** — so these
    /// are valid notes that no ledger has heard of, which is exactly the
    /// right thing for testing the offline half.
    fn token(seed: u8, owner_index: Option<u32>) -> HeldToken {
        use kenter_crypto::container::{deserialize_bearer_token, serialize_bearer_token};
        use kenter_crypto::keypair::StellarKeypair;
        use kenter_crypto::token::{assemble_bearer_token, PartialToken};

        // Deterministic, so the same seed is the same note across calls and
        // a failure is reproducible.
        let kp = |role: u8| {
            let mut raw = [0u8; 32];
            raw[0] = seed;
            raw[1] = role;
            raw[2] = 0x5b;
            StellarKeypair::from_raw_secret(&raw)
        };

        // Two pairs is the shortest real chain: `initiate` lays the first
        // link and `assemble` needs exactly one pair outstanding.
        let (partial, _) = PartialToken::initiate(
            [seed.wrapping_add(1); 32],
            1_700_000_000 + seed as i64,
            Some(1_000 + seed as u64),
            2,
            &kp(0),
            &kp(1),
            vec![seed, 0x02, 0x03, 0x04],
        )
        .expect("initiate");
        let requestor = kp(2);
        let assembled =
            assemble_bearer_token(&partial, &requestor, &kp(3), 7, None).expect("assemble");

        // Through the container and back, as a real import does: the
        // signature is applied during serialization, so the in-memory token
        // is not yet the thing that will be stored.
        let blob = serialize_bearer_token(&assembled, &requestor).expect("serialize");
        let parsed = deserialize_bearer_token(&blob).expect("deserialize");

        let mut held = HeldToken::from_bearer(&parsed, blob, 1_700_000_000 + seed as i64);
        held.label = Some(format!("token {seed}"));
        held.owner_index = owner_index;
        held.owner_commitment = owner_index.map(|_| [seed.wrapping_add(2); 32]);
        held.spent_away = seed % 2 == 0;
        // Non-default on purpose: a round-trip test that only ever sees
        // zeroes would pass with the fields dropped entirely.
        held.exports = crate::models::ExportLog {
            backup: seed as u32,
            to_card: 0,
            handover: (seed % 3) as u32,
        };
        held.marked_spent = seed % 2 == 1;
        held
    }

    /// The fixture has to actually satisfy the gate, or every restore test
    /// below is measuring the gate instead of the restore.
    #[test]
    fn the_test_notes_are_real_notes() {
        for seed in [1u8, 2, 3, 7] {
            let t = token(seed, None);
            check(&t).unwrap_or_else(|e| panic!("fixture note {seed} does not verify: {e}"));
            assert_eq!(t.amount, 1_000 + seed as u64);
            assert!(t.id.starts_with('G'));
        }
        // Deterministic: the same seed is the same note.
        assert_eq!(token(5, None).id, token(5, None).id);
        assert_ne!(token(5, None).id, token(6, None).id);
    }

    #[test]
    fn round_trips_everything_that_matters() {
        let tokens = vec![token(1, Some(4)), token(2, None)];
        let pending = vec![PendingReceive {
            index: 9,
            commitment: [7u8; 32],
            created_at: 42,
        }];
        let bytes = encode(&KEY, &soft(), &tokens, &pending, Some(10), 1_700_000_999).unwrap();
        let out = decode(&KEY, FP, &bytes).unwrap();

        // owner_index is the field that makes a spend-mode token usable at all.
        assert_eq!(out.tokens, tokens);
        assert_eq!(out.tokens[0].owner_index, Some(4));
        // The bytes come back exactly, which is the whole job: the blob is
        // the note, and a byte lost here is money lost.
        assert_eq!(out.tokens[0].blob, tokens[0].blob);
        assert!(check(&out.tokens[0]).is_ok(), "a round trip broke the note");
        assert_eq!(out.pending, pending);
        // Without the counter a restore would hand out an index twice.
        assert_eq!(out.next_owner_index, Some(10));
        assert_eq!(out.created_at, 1_700_000_999);
    }

    #[test]
    fn the_blobs_are_not_readable_in_the_file() {
        let tokens = vec![token(0xAB, Some(1))];
        let bytes = encode(&KEY, &soft(), &tokens, &[], None, 0).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains(&hex::encode([0xABu8; 64])),
            "token bytes must not appear in the clear — the file is bearer value"
        );
        assert!(text.contains(FP), "the fingerprint is meant to be readable");
    }

    /// The header is for telling backups apart before committing to one.
    #[test]
    fn inspect_works_without_the_key() {
        let bytes = encode(&KEY, &soft(), &[token(3, None), token(4, None)], &[], None, 77).unwrap();
        let header = inspect(&bytes).unwrap();
        assert_eq!(header.seed_fingerprint, FP);
        assert_eq!(header.token_count, 2);
        assert_eq!(header.created_at, 77);
    }

    /// Restoring someone else's backup must say so, not look like a bad
    /// passphrase — the two call for completely different reactions.
    #[test]
    fn a_backup_from_another_wallet_is_named_as_such() {
        let bytes = encode(&KEY, &soft(), &[token(5, None)], &[], None, 0).unwrap();
        let err = decode(&KEY, "ffffffffffffffff", &bytes).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("different wallet"), "got {msg}");
    }

    #[test]
    fn a_damaged_backup_is_rejected() {
        let bytes = encode(&KEY, &soft(), &[token(6, None)], &[], None, 0).unwrap();
        let mut file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let ct = file["ciphertext"].as_str().unwrap().to_string();
        let mut flipped: Vec<char> = ct.chars().collect();
        flipped[0] = if flipped[0] == 'a' { 'b' } else { 'a' };
        file["ciphertext"] = serde_json::Value::String(flipped.into_iter().collect());
        let tampered = serde_json::to_vec(&file).unwrap();

        assert!(decode(&KEY, FP, &tampered).is_err());
    }

    #[test]
    fn the_wrong_key_cannot_open_it() {
        let bytes = encode(&KEY, &soft(), &[token(7, None)], &[], None, 0).unwrap();
        assert!(decode(&[0x22; 32], FP, &bytes).is_err());
    }

    #[test]
    fn a_foreign_file_is_not_mistaken_for_a_backup() {
        assert!(inspect(b"{\"hello\":1}").is_err());
        assert!(inspect(b"not json at all").is_err());
    }

    #[test]
    fn an_empty_wallet_backs_up_and_restores_cleanly() {
        let bytes = encode(&KEY, &soft(), &[], &[], None, 5).unwrap();
        let out = decode(&KEY, FP, &bytes).unwrap();
        assert!(out.tokens.is_empty() && out.pending.is_empty());
        assert_eq!(inspect(&bytes).unwrap().token_count, 0);
    }

    // ── v2: the derivation has to survive, or the file cannot be opened ──

    /// The whole point of v2. A card-rooted wallet's backup must say which
    /// child it is, in the clear, because the index is needed *to derive the
    /// key that would decrypt it*.
    #[test]
    fn a_card_rooted_backup_records_which_child_it_is() {
        let bytes = encode(&KEY, &child(7, Some("ab12cd34")), &[token(1, Some(0))], &[], None, 0)
            .unwrap();
        let header = inspect(&bytes).unwrap();

        assert_eq!(header.origin(), SeedOrigin::Bip85Child);
        let d = header.bip85.as_ref().expect("the derivation is the point");
        assert_eq!(d.index, 7);
        assert_eq!(d.words, 24, "the word count is part of the path");
        assert_eq!(d.root_fingerprint.as_deref(), Some("ab12cd34"));

        // Readable with no key at all: a holder who has lost everything but
        // the file and the phrase can still find out what to derive.
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("bip85-child"), "the origin must be in the clear");
        assert!(text.contains("\"index\": 7"), "the index must be in the clear");
    }

    /// The root fingerprint is declinable, because it links two files from one
    /// root. Declining must not make the file unopenable — only ambiguous
    /// about which root to try.
    #[test]
    fn the_root_fingerprint_can_be_left_out() {
        let bytes = encode(&KEY, &child(2, None), &[], &[], None, 0).unwrap();
        let header = inspect(&bytes).unwrap();
        let d = header.bip85.as_ref().unwrap();
        assert_eq!(d.index, 2);
        assert_eq!(d.root_fingerprint, None);
        assert!(decode(&KEY, FP, &bytes).is_ok());
    }

    /// A v1 file stays readable forever, and reads as software-seeded — which
    /// is a fact about when v1 was written, not a default.
    #[test]
    fn a_v1_file_still_restores_and_reads_as_software() {
        let tokens = vec![token(3, Some(1))];
        // Seal for real, then relabel the header as v1 and drop the fields v1
        // did not have. That is exactly what a file written last month is.
        let real = encode(&KEY, &soft(), &tokens, &[], Some(2), 5).unwrap();
        let f: serde_json::Value = serde_json::from_slice(&real).unwrap();
        let v1 = serde_json::json!({
            "kind": f["kind"],
            "version": 1,
            "seed_fingerprint": f["seed_fingerprint"],
            "created_at": f["created_at"],
            "token_count": f["token_count"],
            "nonce": f["nonce"],
            "ciphertext": f["ciphertext"],
        })
        .to_string();

        let header = inspect(v1.as_bytes()).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.origin(), SeedOrigin::Software);
        assert_eq!(header.content_digest, None, "v1 predates the digest");

        let out = decode(&KEY, FP, v1.as_bytes()).unwrap();
        assert_eq!(out.tokens, tokens);
        assert_eq!(out.next_owner_index, Some(2));
    }

    /// A v1 header carrying v2 fields is lying about one of the two. Refuse
    /// rather than derive a key from a header half of which is ignored.
    #[test]
    fn a_v1_file_claiming_v2_fields_is_refused() {
        let real = encode(&KEY, &soft(), &[], &[], None, 0).unwrap();
        let mut f: serde_json::Value = serde_json::from_slice(&real).unwrap();
        f["version"] = serde_json::json!(1);
        let err = inspect(f.to_string().as_bytes()).unwrap_err().to_string();
        assert!(err.contains("version 1"), "{err}");
    }

    /// The derivation is present exactly when the origin needs one — checked
    /// both ways, since either mismatch describes a seed the file was not
    /// sealed under.
    #[test]
    fn the_origin_and_the_derivation_must_agree() {
        let bad = SeedSource {
            fingerprint: FP.to_string(),
            origin: SeedOrigin::Bip85Child,
            bip85: None,
        };
        assert!(encode(&KEY, &bad, &[], &[], None, 0).is_err());

        let also_bad = SeedSource {
            fingerprint: FP.to_string(),
            origin: SeedOrigin::Software,
            bip85: Some(Bip85Derivation { index: 1, words: 24, root_fingerprint: None }),
        };
        assert!(encode(&KEY, &also_bad, &[], &[], None, 0).is_err());

        // And a file hand-edited past `encode` is caught on the way in.
        let real = encode(&KEY, &soft(), &[], &[], None, 0).unwrap();
        let mut f: serde_json::Value = serde_json::from_slice(&real).unwrap();
        f["bip85"] = serde_json::json!({"index": 1, "words": 24});
        let err = inspect(f.to_string().as_bytes()).unwrap_err().to_string();
        assert!(err.contains("inconsistent"), "{err}");
    }

    /// A word count that is not 12 or 24 is not a path, so it cannot derive.
    #[test]
    fn a_nonsense_word_count_is_refused() {
        let bytes = encode(&KEY, &child(1, None), &[], &[], None, 0).unwrap();
        let mut f: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        f["bip85"]["words"] = serde_json::json!(18);
        let err = inspect(f.to_string().as_bytes()).unwrap_err().to_string();
        assert!(err.contains("neither 12 nor 24"), "{err}");
    }

    // ── v2: is this backup current? ──

    /// The staleness check: the digest covers exactly the set of notes, and
    /// does not depend on the order they were stored in.
    #[test]
    fn the_digest_says_which_notes_are_covered() {
        let a = vec![token(1, None), token(2, None)];
        let reordered = vec![token(2, None), token(1, None)];
        let grown = vec![token(1, None), token(2, None), token(3, None)];

        assert_eq!(content_digest(&a), content_digest(&reordered), "order must not matter");
        assert_ne!(content_digest(&a), content_digest(&grown), "a new note must show");
        assert_ne!(content_digest(&a), content_digest(&a[..1]));

        // And it is the same value the file carries, so a wallet can compare
        // what it holds now against a file without opening it.
        let bytes = encode(&KEY, &soft(), &a, &[], None, 0).unwrap();
        assert_eq!(inspect(&bytes).unwrap().content_digest.as_deref(), Some(content_digest(&a).as_str()));
    }

    /// The standing pay tag (index 0) lives in `pending`. Losing it
    /// on a restore would silently retire a published address.
    #[test]
    fn the_standing_pay_tag_survives_a_round_trip() {
        let standing = PendingReceive {
            index: crate::models::STATIC_RECEIVE_INDEX,
            commitment: [0x5A; 32],
            created_at: 1,
        };
        let rotating = PendingReceive { index: 4, commitment: [0x5B; 32], created_at: 2 };
        let bytes =
            encode(&KEY, &soft(), &[], &[standing.clone(), rotating.clone()], None, 0).unwrap();
        let out = decode(&KEY, FP, &bytes).unwrap();
        assert!(
            out.pending.contains(&standing),
            "the standing tag was dropped — a published address would stop being watched"
        );
        assert!(out.pending.contains(&rotating));
    }

    // -------------------------------------------------------------------
    // Store-aware export / restore
    // -------------------------------------------------------------------

    use crate::store::MemoryStore;
    use pollster::block_on;

    fn pending(index: u32) -> PendingReceive {
        PendingReceive {
            index,
            commitment: [index as u8; 32],
            created_at: 1_700_000_500 + index as i64,
        }
    }

    /// A store holding `tokens` and `pendings`, with the counter run up past
    /// the highest index used, the way a live wallet's would be.
    fn stocked(tokens: &[HeldToken], pendings: &[PendingReceive]) -> MemoryStore {
        let mut store = MemoryStore::new();
        block_on(async {
            let mut high = FIRST_FRESH_INDEX;
            for t in tokens {
                high = high.max(t.owner_index.map_or(0, |i| i + 1));
                store.put(t.clone()).await.unwrap();
            }
            for p in pendings {
                high = high.max(p.index + 1);
                store.put_pending(p.clone()).await.unwrap();
            }
            store.advance_owner_index(high).await.unwrap();
        });
        store
    }

    #[test]
    fn export_carries_what_the_store_holds() {
        let tokens = [token(1, Some(4)), token(2, Some(9))];
        let pendings = [pending(11)];
        let mut store = stocked(&tokens, &pendings);

        let bytes = block_on(export(&mut store, &KEY, &soft(), 1_700_000_900)).unwrap();
        let out = decode(&KEY, FP, &bytes).unwrap();

        let mut got: Vec<&str> = out.tokens.iter().map(|t| t.id.as_str()).collect();
        got.sort_unstable();
        let mut want: Vec<&str> = tokens.iter().map(|t| t.id.as_str()).collect();
        want.sort_unstable();
        assert_eq!(got, want);
        assert_eq!(out.pending, pendings);
        assert_eq!(out.next_owner_index, Some(12));
        assert_eq!(out.created_at, 1_700_000_900);
    }

    /// The counter read must not consume. Before it was a forward-only setter
    /// the only way to read it was to allocate, so every export would have
    /// burned an index.
    #[test]
    fn export_does_not_burn_an_index() {
        let mut store = stocked(&[], &[]);
        let before = block_on(store.advance_owner_index(0)).unwrap();
        for _ in 0..3 {
            block_on(export(&mut store, &KEY, &soft(), 1)).unwrap();
        }
        assert_eq!(block_on(store.allocate_owner_index()).unwrap(), before);
    }

    /// The whole point: a wallet with nothing comes back whole.
    #[test]
    fn restore_into_an_empty_wallet_returns_everything() {
        let tokens = [token(1, Some(4)), token(2, Some(9)), token(3, None)];
        let pendings = [pending(11), pending(12)];
        let bytes = block_on(export(
            &mut stocked(&tokens, &pendings),
            &KEY,
            &soft(),
            1_700_000_900,
        ))
        .unwrap();

        let mut fresh = MemoryStore::new();
        let contents = decode(&KEY, FP, &bytes).unwrap();
        let report = block_on(restore(&mut fresh, &contents)).unwrap();

        assert_eq!(report.tokens_added, 3);
        assert_eq!(report.tokens_kept, 0);
        assert_eq!(report.pending_added, 2);
        assert_eq!(report.owner_index_before, FIRST_FRESH_INDEX);
        assert_eq!(report.owner_index_after, 13);

        let mut restored = block_on(fresh.all()).unwrap();
        restored.sort_by(|a, b| a.id.cmp(&b.id));
        let mut want = tokens.to_vec();
        want.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(restored, want);
        assert_eq!(block_on(fresh.pending()).unwrap(), pendings);
        // And the restored wallet allocates past everything it just restored.
        assert_eq!(block_on(fresh.allocate_owner_index()).unwrap(), 13);
    }

    /// The safety rule. A note spent since the backup was written must stay
    /// spent, or the holder is shown money they have already handed over.
    #[test]
    fn restore_never_overwrites_a_note_already_held() {
        let stale = token(1, Some(4));
        let bytes =
            block_on(export(&mut stocked(&[stale.clone()], &[]), &KEY, &soft(), 1)).unwrap();

        let mut live = stale.clone();
        live.spent_away = !stale.spent_away;
        live.marked_spent = true;
        live.label = Some("handed to Sam".into());
        let mut store = stocked(&[live.clone()], &[]);

        let contents = decode(&KEY, FP, &bytes).unwrap();
        let report = block_on(restore(&mut store, &contents)).unwrap();

        assert_eq!(report.tokens_added, 0);
        assert_eq!(report.tokens_kept, 1);
        assert!(report.is_empty());
        assert_eq!(block_on(store.get(&live.id)).unwrap(), Some(live));
    }

    /// Restoring the same file twice is a no-op, which is what makes it safe
    /// to offer as a button rather than a ceremony.
    #[test]
    fn restore_is_idempotent() {
        let tokens = [token(1, Some(4)), token(2, Some(9))];
        let pendings = [pending(11)];
        let bytes =
            block_on(export(&mut stocked(&tokens, &pendings), &KEY, &soft(), 1)).unwrap();
        let contents = decode(&KEY, FP, &bytes).unwrap();

        let mut store = MemoryStore::new();
        let first = block_on(restore(&mut store, &contents)).unwrap();
        let second = block_on(restore(&mut store, &contents)).unwrap();

        assert_eq!(first.tokens_added, 2);
        assert!(!first.is_empty());
        assert_eq!(second.tokens_added, 0);
        assert_eq!(second.tokens_kept, 2);
        assert_eq!(second.pending_kept, 1);
        assert!(second.is_empty());
        assert_eq!(second.owner_index_before, second.owner_index_after);
        assert_eq!(block_on(store.all()).unwrap().len(), 2);
    }

    /// The counter is the one thing a restore can get catastrophically wrong:
    /// an old file must not drag a live wallet back onto indices it has spent.
    #[test]
    fn restore_never_moves_the_counter_backwards() {
        let bytes = block_on(export(&mut stocked(&[], &[]), &KEY, &soft(), 1)).unwrap();
        let contents = decode(&KEY, FP, &bytes).unwrap();
        assert_eq!(contents.next_owner_index, Some(FIRST_FRESH_INDEX));

        let mut store = MemoryStore::new();
        block_on(store.advance_owner_index(40)).unwrap();
        let report = block_on(restore(&mut store, &contents)).unwrap();

        assert_eq!(report.owner_index_before, 40);
        assert_eq!(report.owner_index_after, 40);
        assert_eq!(block_on(store.allocate_owner_index()).unwrap(), 40);
    }

    /// A file whose counter does not cover its own contents — hand-edited,
    /// truncated, or written by something older. The restored indices still
    /// have to be out of reach.
    #[test]
    fn restore_clears_the_contents_even_if_the_counter_does_not() {
        let contents = BackupContents {
            tokens: vec![token(1, Some(30))],
            pending: vec![pending(44)],
            next_owner_index: Some(2),
            created_at: 1,
        };
        let mut store = MemoryStore::new();
        let report = block_on(restore(&mut store, &contents)).unwrap();

        assert_eq!(report.owner_index_after, 45);
        assert_eq!(block_on(store.allocate_owner_index()).unwrap(), 45);
    }

    /// A v1 file carries no counter at all. Restoring one must not reset a
    /// wallet to 1, and on a fresh wallet must still clear the contents.
    #[test]
    fn restore_handles_a_file_with_no_counter() {
        let contents = BackupContents {
            tokens: vec![token(1, Some(6))],
            pending: vec![],
            next_owner_index: None,
            created_at: 1,
        };
        let mut store = MemoryStore::new();
        assert_eq!(
            block_on(restore(&mut store, &contents))
                .unwrap()
                .owner_index_after,
            7
        );
    }

    /// A restore adds; it never removes. A note the file predates stays put.
    #[test]
    fn restore_leaves_notes_the_file_never_had() {
        let bytes = block_on(export(
            &mut stocked(&[token(1, Some(4))], &[]),
            &KEY,
            &soft(),
            1,
        ))
        .unwrap();
        let contents = decode(&KEY, FP, &bytes).unwrap();

        let newer = token(7, Some(20));
        let mut store = stocked(&[newer.clone()], &[]);
        block_on(restore(&mut store, &contents)).unwrap();

        assert_eq!(block_on(store.all()).unwrap().len(), 2);
        assert_eq!(block_on(store.get(&newer.id)).unwrap(), Some(newer));
    }

    /// `content_digest` is how the wallet answers "is what I hold covered by
    /// that file?" without the key — the staleness check.
    #[test]
    fn the_header_digest_tracks_the_store() {
        let mut store = stocked(&[token(1, Some(4))], &[]);
        let bytes = block_on(export(&mut store, &KEY, &soft(), 1)).unwrap();
        let header = inspect(&bytes).unwrap();

        assert_eq!(
            header.content_digest.as_deref(),
            Some(content_digest(&block_on(store.all()).unwrap()).as_str())
        );

        block_on(store.put(token(2, Some(5)))).unwrap();
        assert_ne!(
            header.content_digest.as_deref(),
            Some(content_digest(&block_on(store.all()).unwrap()).as_str())
        );
    }

    // -------------------------------------------------------------------
    // Counterfeit notes in a backup
    //
    // The threat is not someone tampering with *your* file — it is sealed
    // under your seed, and anyone who can write one already owns the
    // wallet. It is being handed a phrase and a file: "there is $500 in
    // here, buy it off me." A backup is the one way notes enter a wallet
    // without passing a receive gate, so the gate has to be here too.
    // -------------------------------------------------------------------

    /// A plausible record whose blob is not a note at all.
    fn fabricated(seed: u8, amount: u64) -> HeldToken {
        HeldToken {
            id: format!("G{seed:0>55}"),
            slot_id: seed as u32,
            ephemeral_public_key: [seed; 32],
            event_id: [seed; 32],
            amount,
            blob: vec![seed; 96],
            imported_at: 1,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        }
    }

    #[test]
    fn a_fabricated_note_never_reaches_the_store() {
        let contents = BackupContents {
            tokens: vec![token(1, None), fabricated(0xF0, 500_000_000), token(2, None)],
            pending: vec![],
            next_owner_index: Some(5),
            created_at: 1,
        };
        let mut store = MemoryStore::new();
        let report = block_on(restore(&mut store, &contents)).unwrap();

        assert_eq!(report.tokens_added, 2, "the real notes still restore");
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].0, format!("G{:0>55}", 0xF0));
        assert!(
            report.rejected[0].1.contains("does not parse"),
            "{}",
            report.rejected[0].1
        );
        // Not stored, not counted, not shown.
        assert_eq!(block_on(store.all()).unwrap().len(), 2);
        assert!(block_on(store.get(&format!("G{:0>55}", 0xF0)))
            .unwrap()
            .is_none());
    }

    /// A real note's bytes filed under someone else's id. The id is what
    /// every ledger lookup uses, so this would check one note and store
    /// another.
    #[test]
    fn a_note_filed_under_the_wrong_id_is_refused() {
        let mut swapped = token(1, None);
        swapped.id = token(2, None).id;
        assert!(check(&token(1, None)).is_ok());

        let err = check(&swapped).unwrap_err().to_string();
        assert!(err.contains("different note"), "{err}");
    }

    /// Tampered bytes. The chain is signed, so any edit breaks it.
    #[test]
    fn a_doctored_container_is_refused() {
        let mut t = token(3, None);
        let n = t.blob.len();
        t.blob[n / 2] ^= 0xFF;
        let err = check(&t).unwrap_err().to_string();
        assert!(
            err.contains("does not parse") || err.contains("does not verify"),
            "{err}"
        );
    }

    /// Refusing must not quietly lower the counter: an index a refused note
    /// claims is still an index somebody may have paid to.
    #[test]
    fn a_refused_note_still_advances_the_counter() {
        let mut fake = fabricated(0xF0, 1);
        fake.owner_index = Some(44);
        let contents = BackupContents {
            tokens: vec![fake],
            pending: vec![],
            next_owner_index: Some(2),
            created_at: 1,
        };
        let mut store = MemoryStore::new();
        let report = block_on(restore(&mut store, &contents)).unwrap();

        assert_eq!(report.tokens_added, 0);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.owner_index_after, 45);
    }

    /// A clean file reports nothing, so the UI can stay quiet.
    #[test]
    fn an_honest_file_rejects_nothing() {
        let bytes = block_on(export(
            &mut stocked(&[token(1, Some(4)), token(2, None)], &[]),
            &KEY,
            &soft(),
            1,
        ))
        .unwrap();
        let contents = decode(&KEY, FP, &bytes).unwrap();
        let mut store = MemoryStore::new();
        let report = block_on(restore(&mut store, &contents)).unwrap();
        assert!(report.rejected.is_empty());
        assert_eq!(report.tokens_added, 2);
    }

    // -------------------------------------------------------------------
    // Coverage — the staleness question, answered without the key
    // -------------------------------------------------------------------

    #[test]
    fn no_file_means_the_notes_are_on_this_machine_only() {
        assert_eq!(coverage(None, FP, &[token(1, None)]), Coverage::Missing);
        assert!(coverage(None, FP, &[]).needs_refresh());
    }

    #[test]
    fn a_file_matching_the_store_is_covered() {
        let tokens = [token(1, Some(4)), token(2, Some(9))];
        let bytes = encode(&KEY, &soft(), &tokens, &[], Some(10), 1_700_000_900).unwrap();

        let c = coverage(Some(&bytes), FP, &tokens);
        assert_eq!(
            c,
            Coverage::Covered {
                created_at: 1_700_000_900,
                notes: 2
            }
        );
        assert!(c.is_covered());
        assert!(!c.needs_refresh());

        // Order is not content: the digest sorts, so a reshuffled store is
        // still covered.
        let flipped = [tokens[1].clone(), tokens[0].clone()];
        assert!(coverage(Some(&bytes), FP, &flipped).is_covered());
    }

    #[test]
    fn a_note_received_since_makes_the_file_stale() {
        let tokens = [token(1, Some(4))];
        let bytes = encode(&KEY, &soft(), &tokens, &[], Some(5), 1_700_000_900).unwrap();
        let now = [token(1, Some(4)), token(2, Some(5))];

        assert_eq!(
            coverage(Some(&bytes), FP, &now),
            Coverage::Stale {
                created_at: 1_700_000_900,
                in_file: 1,
                held: 2
            }
        );
    }

    /// A note redeemed since also makes the file stale, which is worth
    /// stating: it is not only growth that moves the set.
    #[test]
    fn a_note_gone_since_also_makes_the_file_stale() {
        let tokens = [token(1, Some(4)), token(2, Some(9))];
        let bytes = encode(&KEY, &soft(), &tokens, &[], Some(10), 1).unwrap();
        assert!(matches!(
            coverage(Some(&bytes), FP, &tokens[..1]),
            Coverage::Stale { in_file: 2, held: 1, .. }
        ));
    }

    /// State that is reconstructible from the ledger does not count. The
    /// digest is over ids, so a spend does not invalidate the backup.
    #[test]
    fn spending_a_note_does_not_make_the_file_stale() {
        let tokens = [token(1, Some(4))];
        let bytes = encode(&KEY, &soft(), &tokens, &[], Some(5), 1).unwrap();

        let mut spent = tokens[0].clone();
        spent.spent_away = !spent.spent_away;
        spent.marked_spent = true;
        assert!(coverage(Some(&bytes), FP, &[spent]).is_covered());
    }

    #[test]
    fn another_wallets_file_is_named_rather_than_called_stale() {
        let bytes = encode(
            &KEY,
            &SeedSource::software("deadbeef"),
            &[token(1, None)],
            &[],
            None,
            1,
        )
        .unwrap();
        assert_eq!(
            coverage(Some(&bytes), FP, &[token(1, None)]),
            Coverage::OtherWallet {
                fingerprint: "deadbeef".into()
            }
        );
    }

    #[test]
    fn a_file_that_is_not_a_backup_says_so() {
        assert!(matches!(
            coverage(Some(b"{}"), FP, &[]),
            Coverage::Unreadable { .. }
        ));
    }

    /// A v1 file carries no digest. "Unknown" must not read as covered, or a
    /// holder is told they are safe on the strength of a missing field.
    #[test]
    fn a_v1_file_is_unknown_not_covered() {
        let v1 = br#"{"kind":"kenter-wallet-backup","version":1,
            "seed_fingerprint":"0123456789abcdef","created_at":99,
            "token_count":1,"nonce":"00","ciphertext":"00"}"#;
        let c = coverage(Some(v1), FP, &[token(1, None)]);
        assert_eq!(c, Coverage::Unknown { created_at: 99 });
        assert!(!c.is_covered());
        assert!(c.needs_refresh());
    }

    /// The loop the shell actually runs: export, confirm covered, receive,
    /// confirm stale, export again.
    #[test]
    fn export_then_coverage_closes_the_loop() {
        let mut store = stocked(&[token(1, Some(4))], &[]);
        let bytes = block_on(export(&mut store, &KEY, &soft(), 1)).unwrap();
        assert!(coverage(Some(&bytes), FP, &block_on(store.all()).unwrap()).is_covered());

        block_on(store.put(token(2, Some(5)))).unwrap();
        assert!(coverage(Some(&bytes), FP, &block_on(store.all()).unwrap()).needs_refresh());

        let fresh = block_on(export(&mut store, &KEY, &soft(), 2)).unwrap();
        assert!(coverage(Some(&fresh), FP, &block_on(store.all()).unwrap()).is_covered());
    }

    // -------------------------------------------------------------------
    // Coverage from the wallet's record — the question asked when the
    // backup itself is in a drawer
    // -------------------------------------------------------------------

    #[test]
    fn a_wallet_that_has_never_backed_up_says_so() {
        assert_eq!(
            coverage_of_record(None, &[token(1, None)]),
            Coverage::Missing
        );
    }

    #[test]
    fn the_record_answers_coverage_with_no_file_present() {
        let tokens = [token(1, Some(4)), token(2, Some(9))];
        let record = record_for(&tokens, 1_700_000_900, Some("E:/kenter.kbk".into()));

        assert_eq!(record.notes(), 2);
        assert_eq!(record.whence.as_deref(), Some("E:/kenter.kbk"));
        assert!(coverage_of_record(Some(&record), &tokens).is_covered());

        let mut grown = tokens.to_vec();
        grown.push(token(3, Some(10)));
        assert_eq!(
            coverage_of_record(Some(&record), &grown),
            Coverage::Stale {
                created_at: 1_700_000_900,
                in_file: 2,
                held: 3
            }
        );
    }

    /// The record and the file must agree, or the billfold and the file are
    /// answering the same question differently.
    #[test]
    fn the_record_digest_matches_the_file_header() {
        let mut store = stocked(&[token(1, Some(4)), token(2, Some(9))], &[]);
        let bytes = block_on(export(&mut store, &KEY, &soft(), 1_700_000_900)).unwrap();
        let held = block_on(store.all()).unwrap();
        let record = record_for(&held, 1_700_000_900, None);

        assert_eq!(
            inspect(&bytes).unwrap().content_digest,
            Some(digest_of_ids(record.ids.iter().map(String::as_str)))
        );
        assert_eq!(
            coverage(Some(&bytes), FP, &held),
            coverage_of_record(Some(&record), &held)
        );
    }

    /// The loop the shell runs: back up, receive, be told, back up again.
    #[test]
    fn the_store_remembers_its_last_backup_across_receipts() {
        let mut store = stocked(&[token(1, Some(4))], &[]);
        assert_eq!(block_on(store.last_backup()).unwrap(), None);

        let held = block_on(store.all()).unwrap();
        block_on(export(&mut store, &KEY, &soft(), 10)).unwrap();
        block_on(store.record_backup(record_for(&held, 10, None))).unwrap();

        let seen = block_on(store.last_backup()).unwrap();
        assert!(coverage_of_record(seen.as_ref(), &block_on(store.all()).unwrap()).is_covered());

        block_on(store.put(token(2, Some(5)))).unwrap();
        let seen = block_on(store.last_backup()).unwrap();
        assert!(matches!(
            coverage_of_record(seen.as_ref(), &block_on(store.all()).unwrap()),
            Coverage::Stale { created_at: 10, in_file: 1, held: 2 }
        ));
    }
}
