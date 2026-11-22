//! Pluggable key custody for Kenter.
//!
//! One [`KeyVault`] trait, multiple backends. The trait is the seam between
//! software custody and hardware (Keycard) custody behind the same
//! interface, so `kenter-desktop` (and eventually the mobile shell) depend on
//! the trait, not the backend.
//!
//! - [`SoftVault`] — keys encrypted at rest with a passphrase (this crate).
//! - `KeycardVault` — hardware secure element over PC/SC (future, in
//!   `stellar-keycard`, implementing this same trait).
//!
//! ## Two roles, two ports
//! - [`KeyVault`] — slot-based custody of individual **Ed25519 Stellar account
//!   keys** (the identity/signing key `kenter-desktop` uses).
//! - [`DerivingVault`] — one seed, **HD-derived spend-mode owner keys** at
//!   `m/44'/148'/n'` (see `docs/architecture/custody.md`). Separate rather
//!   than folded into `KeyVault` because the roles differ in lifetime and in
//!   what identifies a key: a slot id versus a derivation index recorded on a
//!   held token.
//!
//! The spend-mode owner key is Ed25519, not secp256k1: the mint verifies owner
//! authorizations with `ed25519_verify` (see `docs/architecture/spend-mode.md`),
//! so the hardware side is served by the Ed25519 applet fork rather than the
//! stock secp256k1 card.

use zeroize::Zeroizing;

pub mod bip85;
pub mod kdf;
pub mod mnemonic;
pub mod slip10;
pub mod soft;

pub use bip85::{
    ACCOUNT_KEY_INDEX, ACCOUNT_VAULT_KEY_INDEX, BACKUP_KEY_INDEX, Bip85, STORE_KEY_INDEX,
    account_key, account_vault_credential, vault_bound_credentials,
};
pub use soft::Custody;
pub use soft::SoftVault;

/// A backend that custodies one seed and derives spend-mode **owner keys** from
/// it on demand.
///
/// Association is by **derivation index**: a held token records the index of the
/// owner key that owns it, and the key itself is never stored — it is re-derived
/// when needed. That is what makes the backup story "one seed, once" instead of
/// "a new key to back up on every receipt", and what lets a card and a software
/// wallet take over each other's tokens.
///
/// Both methods take the credential. Unlike [`KeyVault::public_key`], which reads
/// cached public metadata, deriving needs the seed itself — encrypted at rest in
/// software, PIN-gated on a card.
pub trait DerivingVault {
    /// Ed25519 public key of the owner key at `index` (`m/44'/148'/index'`).
    ///
    /// `&mut self` for the same reason [`KeyVault::sign`] takes it: a software
    /// backend does not need it, but a card opens a secure channel and
    /// exchanges APDUs to answer, which mutates its transport. Taking `&self`
    /// and hiding that behind interior mutability would be a lie about what
    /// the call does, and would panic rather than fail if it were ever
    /// re-entered.
    fn derive_public(&mut self, index: u32, credential: &[u8]) -> Result<[u8; 32]>;

    /// Sign `message` with the owner key at `index`.
    ///
    /// Owner authorizations sign a 32-byte digest; this
    /// signs whatever it is given, so callers pass the digest, not the preimage.
    fn sign_derived(&mut self, index: u32, message: &[u8], credential: &[u8]) -> Result<[u8; 64]>;
}

pub use soft::backup_fingerprint as soft_backup_fingerprint;

/// What a wallet needs to seal and recognise its own backup.
///
/// Derived from the HD seed so recovery is **phrase + backup file**, with no
/// vault file required — which is the situation a backup exists for. That keeps
/// the two-factor shape the system already has (the seed recovers
/// authorization, blobs recover value, neither alone is enough);
/// sealing under the vault passphrase instead would make the vault file a third
/// thing you must not lose.
///
/// The seed itself never leaves the vault.
#[derive(Clone)]
pub struct BackupCredentials {
    /// AEAD key for the backup payload.
    pub key: Zeroizing<[u8; 32]>,
    /// Public, non-secret tag identifying which wallet a backup belongs to, so
    /// restoring the wrong file fails by name rather than as a decrypt error.
    /// Derived under a separate domain, so it reveals nothing about `key`.
    pub fingerprint: String,
}

/// Keys for the encrypted token store.
///
/// Two keys from one seed, under separate domains. The second exists because
/// encrypting a record is only half the job: a directory of files named after
/// token ids tells a reader exactly which notes are held, and every id is
/// looked up on a public ledger for its amount. Sealing the contents and
/// leaving the names would defeat most of the point.
///
/// Derived from the HD seed, like [`BackupCredentials`], so recovery stays
/// phrase-plus-files with no third artefact to keep safe.
#[derive(Clone)]
pub struct StoreCredentials {
    /// AEAD key for record contents.
    pub aead: Zeroizing<[u8; 32]>,
    /// MAC key that turns a record id into an opaque filename.
    pub name: Zeroizing<[u8; 32]>,
}

/// Opaque handle to a stored key within a vault.
pub type SlotId = u32;

/// Public, non-secret description of a stored key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlotInfo {
    pub slot: SlotId,
    pub label: String,
    /// Stellar address (G…) — derivable without the passphrase.
    pub stellar_address: String,
    pub created_at: i64,
}

/// A backend that custodies Ed25519 keys and signs with them on request.
///
/// `credential` is the unlock secret — a passphrase for [`SoftVault`], a PIN for
/// a future hardware backend. It is required for any operation that touches
/// secret key material, and never for read-only metadata.
pub trait KeyVault {
    /// Generate a fresh Ed25519 key, store it encrypted, return its slot.
    fn generate_key(&mut self, label: &str, credential: &[u8]) -> Result<SlotId>;

    /// Import an existing 32-byte Ed25519 seed, store it encrypted, return its slot.
    ///
    /// Note: a hardware backend using SLIP-0010/BIP-39 (64-byte seed + on-card HD
    /// derivation) cannot accept a raw 32-byte Ed25519 seed and returns
    /// [`VaultError::Unsupported`]; use its native seed loader instead.
    fn import_seed(&mut self, seed: &[u8; 32], label: &str, credential: &[u8]) -> Result<SlotId>;

    /// Sign a message with the key in `slot`. Unwraps in memory, signs, zeroizes.
    ///
    /// `&mut self`: software backends don't need it, but a hardware backend
    /// mutates its transport/secure-channel state per signature.
    fn sign(&mut self, slot: SlotId, message: &[u8], credential: &[u8]) -> Result<[u8; 64]>;

    /// Raw Ed25519 public key for a slot (no credential needed).
    ///
    /// Hardware backends that gate key export behind a PIN return a value cached
    /// at provision time, or [`VaultError::LockedMetadata`] if not yet cached.
    fn public_key(&self, slot: SlotId) -> Result<[u8; 32]>;

    /// Stellar address (G…) for a slot (no credential needed; see [`Self::public_key`]).
    fn stellar_address(&self, slot: SlotId) -> Result<String>;

    /// Enumerate stored keys.
    fn list_keys(&self) -> Result<Vec<KeySlotInfo>>;

    /// Delete a key. Requires the credential to authorize an irreversible removal.
    fn remove_key(&mut self, slot: SlotId, credential: &[u8]) -> Result<()>;
}

/// Vault error type.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault i/o error: {0}")]
    Io(String),
    #[error("vault serialization error: {0}")]
    Serde(String),
    #[error("vault file is corrupt: {0}")]
    Corrupt(String),
    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u8),
    #[error("no key in slot {0}")]
    SlotNotFound(SlotId),
    /// Decryption failed — wrong passphrase, or the entry was tampered with.
    #[error("wrong passphrase or corrupted key material")]
    BadCredential,
    /// The vault's plaintext metadata does not match its authentication
    /// tag: something edited the file's public fields — a public key, a
    /// label, a custody record, the KDF parameters — without the
    /// passphrase.
    ///
    /// Distinct from [`VaultError::BadCredential`] on purpose. A wrong
    /// passphrase is a thing the owner does by accident several times a
    /// year; this is not.
    #[error("vault metadata has been tampered with (header authentication failed)")]
    Tampered,
    /// The vault file asks for Argon2 parameters outside the range this
    /// build will use. Too weak means a cheap offline crack of whatever
    /// is sealed next; too strong is a denial of service.
    #[error("vault KDF parameters are out of range: {0}")]
    BadKdfParams(String),
    #[error("crypto error")]
    Crypto,
    /// A crypto operation that can say something useful about why it failed.
    #[error("crypto error: {0}")]
    Crypto2(String),
    /// A BIP-39 phrase failed to parse or checksum. Almost always a mistyped or
    /// misremembered word — rejecting loudly beats silently deriving a
    /// different wallet.
    #[error("invalid recovery phrase: {0}")]
    BadMnemonic(String),
    /// A hardware backend cannot serve this metadata without prior authentication
    /// (e.g. the address was not cached at provision time).
    #[error("metadata locked: authenticate/provision the key first")]
    LockedMetadata,
    /// Operation not supported by this backend (e.g. 32-byte import on an HD card).
    #[error("operation not supported by this backend: {0}")]
    Unsupported(String),
    /// A hardware backend error (transport, secure channel, card APDU).
    #[error("hardware vault error: {0}")]
    Hardware(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
