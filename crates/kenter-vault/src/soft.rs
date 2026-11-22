//! Software key vault: Ed25519 seeds encrypted at rest with a passphrase.
//!
//! On-disk format (JSON, v3): one Argon2id salt + cost triple for the file,
//! one AEAD-encrypted entry per key, and an HMAC over everything that is not
//! ciphertext. The passphrase never leaves this process; the derived
//! key-encryption key and any unwrapped seed are zeroized immediately after
//! use. Wrong passphrase or a tampered entry fails the Poly1305 tag →
//! [`VaultError::BadCredential`].
//!
//! AEAD is XSalsa20-Poly1305 (NaCl secretbox) — a 256-bit stream cipher with a
//! 24-byte nonce and Poly1305 tag, cryptographically equivalent to the
//! XChaCha20-Poly1305 named in the wallet design notes.
//!
//! # What the AEAD does not cover, and what does
//!
//! The AEAD protects each sealed secret. It protects nothing *around* them,
//! and the plaintext around them is what the user is shown: the entry's
//! `public_key` is the address the CLI and the UI display as the account to
//! fund or redeem into, and `custody.card_identity` is what a launch check
//! compares a card against. Without more, both are editable by anything that
//! can write the file, with no error on any path, because the secret still
//! unwraps.
//!
//! So v3 adds `mac`: HMAC-SHA256 over the version, the KDF triple and salt,
//! `next_slot`, every entry's slot/label/public key/nonce/ciphertext, the seed
//! entry, and the custody record — keyed by a domain-separated derivative of
//! the same Argon2 KEK. Every credentialed operation verifies it before acting,
//! reads included, and every mutation recomputes it. A file holding secrets
//! with no `mac` at all is refused, since otherwise deleting the field would
//! be the way around it.
//!
//! Three consequences worth knowing:
//!
//! - **One vault, one passphrase.** The MAC only verifies under the key the
//!   file was sealed with, so a write offered a different passphrase fails
//!   instead of silently sealing an entry under a credential the owner does
//!   not have.
//! - **Metadata writes need the credential.** [`SoftVault::set_custody`] takes
//!   one, because recording custody re-tags the file.
//! - **Credential-free reads stay unauthenticated**, necessarily:
//!   [`KeyVault::public_key`] and [`KeyVault::stellar_address`] have no key to
//!   check against. Callers about to present an address as "fund this" should
//!   use [`SoftVault::verified_stellar_address`], which derives it from the
//!   sealed seed.
//!
//! The KDF cost triple is the one input that cannot be authenticated this way
//! — the MAC cannot be checked without first deriving a key with it — so it is
//! range-checked instead, at open. See [`crate::kdf::validate_params`].

use std::path::{Path, PathBuf};

use crypto_secretbox::{
    Key, Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use kenter_crypto::keypair::StellarKeypair;
use serde::{Deserialize, Serialize};
use stellar_strkey::ed25519::PublicKey as StellarPublic;
use zeroize::{Zeroize, Zeroizing};

use crate::kdf::{
    DEFAULT_M_COST, DEFAULT_P_COST, DEFAULT_T_COST, KDF_NAME, argon2id_kek, validate_params,
};
use crate::mnemonic;
use crate::slip10;
use crate::{
    BackupCredentials, DerivingVault, KeySlotInfo, KeyVault, Result, SlotId, StoreCredentials,
    VaultError,
};

// v3 = authenticated header (v2 = Argon2id KDF, v1 = PBKDF2-HMAC-SHA256).
// No migration at any step — pre-mainnet vaults are disposable.
const VAULT_VERSION: u8 = 3;

/// Domain tag for the header-MAC key, so it cannot be confused with the
/// AEAD key derived from the same passphrase.
const MAC_TAG: &[u8] = b"kntr_v1:vault:header-mac";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XSalsa20-Poly1305 nonce

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u8,
    kdf: String,
    /// Argon2id cost parameters, recorded for forward-compatible re-wrapping.
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    kdf_salt: String, // hex, SALT_LEN bytes
    next_slot: SlotId,
    entries: Vec<Entry>,
    /// The HD seed spend-mode owner keys derive from.
    ///
    /// Optional and additive: vault files written before owner-key support parse
    /// unchanged, and serde ignores the field where it is not understood. The
    /// version stays 2 because nothing about existing entries changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed: Option<SeedEntry>,
    /// Which custody this installation uses.
    ///
    /// `None` means no custody has been recorded. It is **not** read as
    /// "software": inferring custody from the absence of a record is what
    /// this field exists to prevent, since a card wallet's vault has no seed
    /// either and would read as no wallet at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody: Option<Custody>,
    /// HMAC-SHA256 over every field in this file that is not ciphertext,
    /// keyed by a derivative of the passphrase.
    ///
    /// The AEAD protects the sealed secrets and nothing else, so without
    /// this the plaintext around them is free to edit: swap `public_key`
    /// for an attacker's and the CLI and the UI both display the attacker's
    /// G-address as the account to fund, with no error anywhere; swap
    /// `card_identity` and the launch check recognises the wrong card.
    ///
    /// Checking it also answers a second question for free. The MAC
    /// verifies only under the key the file was sealed with, so a write
    /// offered a *different* passphrase fails instead of quietly
    /// sealing one more entry under a credential the owner does not
    /// have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>, // hex, 32 bytes
}

/// What opens this wallet.
///
/// Recorded rather than inferred. Asking whether the vault holds a seed is
/// true of a software wallet and false of *both* a card wallet and an empty
/// machine — so a provisioned card would be indistinguishable from no
/// wallet, and the client would send its owner to first run.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Custody {
    /// The seed is in this file, behind a passphrase.
    Software,
    /// The seed is on a card. This file holds only the fee-paying account
    /// key, opened with a credential derived from that card.
    Card {
        /// Public tag of the seed, from `BackupCredentials`. Answers *is
        /// this the same wallet* and **survives card replacement**, so a
        /// card restored from the phrase is recognised as this wallet even
        /// though the silicon is different. PIN-gated to compute.
        seed_fingerprint: String,
        /// The card's identity key, hex, from its SELECT certificate.
        /// Answers *is this the same physical card* with **no PIN**, which
        /// is what a launch check can afford to ask.
        card_identity: String,
    },
    /// A card wallet's seed, recovered into this file because the card is
    /// gone. The phrase was the card's; there is no card any more.
    ///
    /// Distinct from both neighbours, and it has to be. [`Custody::Card`]
    /// would send every owner-key operation to a reader with nothing on it.
    /// [`Custody::Software`] looks right and is worse: it hashes the seed
    /// under a domain tag, where a card wallet's store and backup keys are
    /// **BIP85 children**. Same phrase, different
    /// keys — so a wallet recovered as `Software` would read its own notes
    /// as unopenable and its own backup as another wallet's.
    ///
    /// What changed is where the seed lives, not which wallet this is: the
    /// fingerprint is unchanged, so backups written before the card was
    /// lost still open, and ones written after are still the same wallet's.
    RecoveredCard {
        /// As [`Custody::Card::seed_fingerprint`]. No `card_identity`,
        /// because there is no card to be the same as.
        seed_fingerprint: String,
    },
}

/// The encrypted HD seed. Same AEAD and same file KEK as a key entry; only the
/// plaintext length differs (a BIP-39 seed, not a 32-byte Ed25519 secret).
#[derive(Serialize, Deserialize, Clone)]
struct SeedEntry {
    nonce: String,      // hex, NONCE_LEN bytes
    ciphertext: String, // hex, seed + 16-byte tag
    created_at: i64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    slot: SlotId,
    label: String,
    public_key: String, // hex, 32 bytes (Ed25519 public)
    nonce: String,      // hex, NONCE_LEN bytes
    ciphertext: String, // hex, 48 bytes (32-byte seed + 16-byte tag)
    created_at: i64,
}

/// A passphrase-encrypted, file-backed [`KeyVault`].
pub struct SoftVault {
    path: PathBuf,
    file: VaultFile,
}

impl SoftVault {
    /// Open a vault file, or create a fresh empty one (with a random salt) if it
    /// does not exist. The file is not written until the first mutating call.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| VaultError::Io(e.to_string()))?;
            let file: VaultFile =
                serde_json::from_slice(&bytes).map_err(|e| VaultError::Corrupt(e.to_string()))?;
            if file.version != VAULT_VERSION {
                return Err(VaultError::UnsupportedVersion(file.version));
            }
            // Before anything derives a key with them. These three
            // numbers come from the file, and the file is not
            // authenticated until a key has been derived -- so they
            // cannot be checked against the MAC, only against a range.
            validate_params(file.kdf_m_cost, file.kdf_t_cost, file.kdf_p_cost)
                .map_err(VaultError::BadKdfParams)?;
            // A file with something to protect must carry a tag.
            // Otherwise deleting the field is all it takes to turn the
            // protection off, which is no protection.
            if file.mac.is_none() && (!file.entries.is_empty() || file.seed.is_some()) {
                return Err(VaultError::Tampered);
            }
            Ok(Self { path, file })
        } else {
            let salt: [u8; SALT_LEN] = rand::random();
            Ok(Self {
                path,
                file: VaultFile {
                    version: VAULT_VERSION,
                    kdf: KDF_NAME.to_string(),
                    kdf_m_cost: DEFAULT_M_COST,
                    kdf_t_cost: DEFAULT_T_COST,
                    kdf_p_cost: DEFAULT_P_COST,
                    kdf_salt: hex::encode(salt),
                    next_slot: 0,
                    entries: Vec::new(),
                    seed: None,
                    custody: None,
                    mac: None,
                },
            })
        }
    }

    /// Everything in the file that is not ciphertext, length-prefixed so
    /// no two different files can produce the same bytes.
    fn header_bytes(&self) -> Vec<u8> {
        let mut m = Vec::new();
        let mut push = |b: &[u8]| {
            m.extend_from_slice(&(b.len() as u32).to_le_bytes());
            m.extend_from_slice(b);
        };
        push(&[self.file.version]);
        push(self.file.kdf.as_bytes());
        push(&self.file.kdf_m_cost.to_le_bytes());
        push(&self.file.kdf_t_cost.to_le_bytes());
        push(&self.file.kdf_p_cost.to_le_bytes());
        push(self.file.kdf_salt.as_bytes());
        push(&self.file.next_slot.to_le_bytes());
        push(&(self.file.entries.len() as u32).to_le_bytes());
        for e in &self.file.entries {
            push(&e.slot.to_le_bytes());
            push(e.label.as_bytes());
            push(e.public_key.as_bytes());
            push(e.nonce.as_bytes());
            push(e.ciphertext.as_bytes());
            push(&e.created_at.to_le_bytes());
        }
        match &self.file.seed {
            Some(sd) => {
                push(b"seed");
                push(sd.nonce.as_bytes());
                push(sd.ciphertext.as_bytes());
                push(&sd.created_at.to_le_bytes());
            }
            None => push(b"no-seed"),
        }
        // Serialized rather than field-by-field so a new custody variant
        // is covered the day it is added rather than the day someone
        // remembers to extend this.
        match &self.file.custody {
            Some(c) => {
                push(b"custody");
                push(serde_json::to_vec(c).unwrap_or_default().as_slice());
            }
            None => push(b"no-custody"),
        }
        m
    }

    fn header_mac(&self, kek: &[u8; 32]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&Sha256::digest([MAC_TAG, kek.as_slice()].concat()));
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_slice())
            .expect("HMAC accepts any key length");
        mac.update(&self.header_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        out
    }

    /// Confirm the file's plaintext is the plaintext this passphrase
    /// sealed. Every credentialed operation goes through here.
    ///
    /// A vault with no entries and no seed has nothing to authenticate
    /// and no credential to authenticate it with, so it passes.
    fn verify_header(&self, kek: &[u8; 32]) -> Result<()> {
        let Some(recorded) = self.file.mac.as_ref() else {
            if self.file.entries.is_empty() && self.file.seed.is_none() {
                return Ok(());
            }
            return Err(VaultError::Tampered);
        };
        let want = self.header_mac(kek);
        let got = hex::decode(recorded).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        if got.len() != 32 {
            return Err(VaultError::Corrupt("mac length != 32".into()));
        }
        // Constant time: this is compared against attacker-supplied bytes.
        use subtle::ConstantTimeEq;
        if got.ct_eq(&want).into() {
            Ok(())
        } else {
            // Ambiguous by nature -- a wrong passphrase and an edited
            // file fail identically, because the key that would tell
            // them apart is the one we do not have. `BadCredential` is
            // the likelier of the two and the one the owner can act on.
            Err(VaultError::BadCredential)
        }
    }

    /// Recompute the tag and write. Every mutation ends here.
    fn seal_and_save(&mut self, kek: &[u8; 32]) -> Result<()> {
        self.file.mac = Some(hex::encode(self.header_mac(kek)));
        self.save()
    }

    fn save(&self) -> Result<()> {
        let json =
            serde_json::to_vec_pretty(&self.file).map_err(|e| VaultError::Serde(e.to_string()))?;
        std::fs::write(&self.path, json).map_err(|e| VaultError::Io(e.to_string()))
    }

    /// Derive the file's key-encryption key from the passphrase. Caller zeroizes.
    fn derive_kek(&self, credential: &[u8]) -> Result<[u8; 32]> {
        let salt = hex::decode(&self.file.kdf_salt)
            .map_err(|e| VaultError::Corrupt(format!("bad kdf_salt: {e}")))?;
        argon2id_kek(
            credential,
            &salt,
            self.file.kdf_m_cost,
            self.file.kdf_t_cost,
            self.file.kdf_p_cost,
        )
        .map_err(|_| VaultError::Crypto)
    }

    fn find(&self, slot: SlotId) -> Result<&Entry> {
        self.file
            .entries
            .iter()
            .find(|e| e.slot == slot)
            .ok_or(VaultError::SlotNotFound(slot))
    }

    /// Encrypt a seed under the passphrase and append it as a new slot.
    fn insert(
        &mut self,
        seed: &[u8; 32],
        public: &[u8; 32],
        label: &str,
        credential: &[u8],
    ) -> Result<SlotId> {
        let mut kek = self.derive_kek(credential)?;
        // The passphrase has to be the one this vault is already sealed
        // with. Without this a typo on the second key would silently seal
        // it under a credential nobody knows, and the owner would find out
        // when they next tried to sign.
        if let Err(e) = self.verify_header(&kek) {
            kek.zeroize();
            return Err(e);
        }
        let cipher = XSalsa20Poly1305::new(Key::from_slice(&kek));

        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), seed.as_slice())
            .map_err(|_| VaultError::Crypto)?;

        let slot = self.file.next_slot;
        self.file.next_slot += 1;
        self.file.entries.push(Entry {
            slot,
            label: label.to_string(),
            public_key: hex::encode(public),
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(&ciphertext),
            created_at: unix_now(),
        });
        let r = self.seal_and_save(&kek);
        kek.zeroize();
        r?;
        Ok(slot)
    }
}

impl SoftVault {
    /// Whether this vault holds an HD seed (public metadata, no credential).
    pub fn has_seed(&self) -> bool {
        self.file.seed.is_some()
    }

    /// What opens this wallet, if the vault says.
    ///
    /// `None` on a vault written before the record existed. Callers must
    /// not read that as "software" — the whole point of the field is that
    /// absence of a seed was never evidence of anything.
    pub fn custody(&self) -> Option<&Custody> {
        self.file.custody.as_ref()
    }

    /// Record what opens this wallet. Written once, at setup.
    ///
    /// Refuses to change an existing record for the same reason `set_seed`
    /// refuses to overwrite a seed: the two custodies protect the account
    /// key with different credentials, so re-labelling a vault would
    /// describe a key nothing can open. Moving custody means moving the
    /// notes, deliberately.
    pub fn set_custody(&mut self, custody: Custody, credential: &[u8]) -> Result<()> {
        if let Some(existing) = &self.file.custody {
            if *existing != custody {
                return Err(VaultError::Corrupt(format!(
                    "this vault is already recorded as {existing:?}; changing custody                      would describe an account key nothing can open"
                )));
            }
            return Ok(());
        }
        // The record is inside the authenticated header, so writing it
        // means re-tagging the file, which means holding the
        // passphrase. That is the point: `card_identity` decides which
        // physical card a launch check will accept, so it must not be
        // editable by anything that can merely write the file.
        let mut kek = self.derive_kek(credential)?;
        if let Err(e) = self.verify_header(&kek) {
            kek.zeroize();
            return Err(e);
        }
        self.file.custody = Some(custody);
        let r = self.seal_and_save(&kek);
        kek.zeroize();
        r
    }

    /// Store the HD seed that owner keys derive from.
    ///
    /// Refuses to overwrite an existing seed: replacing it would silently orphan
    /// every token already owned by a key derived from the old one, and a bearer
    /// token cannot be reissued. Rotating means a new vault and moving the tokens
    /// across deliberately.
    pub fn set_seed(&mut self, seed: &[u8], credential: &[u8]) -> Result<()> {
        if self.file.seed.is_some() {
            return Err(VaultError::Corrupt(
                "vault already holds an HD seed; replacing it would orphan every                  token owned by a key derived from the old one"
                    .into(),
            ));
        }
        // Validate before storing, so a bad seed fails now rather than at the
        // first receive.
        slip10::master_from_seed(seed)?;

        let mut kek = self.derive_kek(credential)?;
        // As in `insert`: the seed has to go in under the passphrase the
        // rest of the vault already uses. A seed is
        // the worst thing to get this wrong on -- the phrase is shown
        // once, so a vault sealed under a typo'd passphrase can take the
        // whole wallet with it.
        if let Err(e) = self.verify_header(&kek) {
            kek.zeroize();
            return Err(e);
        }
        let cipher = XSalsa20Poly1305::new(Key::from_slice(&kek));
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), seed)
            .map_err(|_| VaultError::Crypto)?;

        self.file.seed = Some(SeedEntry {
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(&ciphertext),
            created_at: unix_now(),
        });
        let r = self.seal_and_save(&kek);
        kek.zeroize();
        r
    }

    /// Store the HD seed from a BIP-39 recovery phrase.
    ///
    /// `bip39_passphrase` is BIP-39's optional 25th-word secret, **not** the
    /// vault `credential`; pass `""` unless the user set one. The phrase is
    /// checksum-validated first, so a mistyped word is rejected here rather than
    /// quietly becoming a different wallet — though note a single wrong word
    /// still slips past a 12-word checksum about once in sixteen
    /// (`mnemonic` module docs), so a phrase parsing is not proof it is right.
    pub fn set_seed_from_mnemonic(
        &mut self,
        phrase: &str,
        bip39_passphrase: &str,
        credential: &[u8],
    ) -> Result<()> {
        let seed = mnemonic::to_seed(phrase, bip39_passphrase)?;
        self.set_seed(&*seed, credential)
    }

    /// Decrypt the HD seed. The caller must zeroize the result.
    fn unwrap_seed(&self, credential: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let entry = self
            .file
            .seed
            .as_ref()
            .ok_or_else(|| VaultError::Corrupt("vault holds no HD seed".into()))?;
        let nonce_bytes =
            hex::decode(&entry.nonce).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let ciphertext =
            hex::decode(&entry.ciphertext).map_err(|e| VaultError::Corrupt(e.to_string()))?;

        let mut kek = self.derive_kek(credential)?;
        // Every credentialed path checks the header, reads included --
        // the seed is what the store key, the backup key and every
        // owner key come from, so acting on a file whose metadata does
        // not authenticate is the last place to be relaxed about it.
        if let Err(e) = self.verify_header(&kek) {
            kek.zeroize();
            return Err(e);
        }
        let cipher = XSalsa20Poly1305::new(Key::from_slice(&kek));
        let seed = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .map_err(|_| VaultError::BadCredential)?;
        kek.zeroize();
        Ok(Zeroizing::new(seed))
    }

    /// Unwrap a slot's key into a usable keypair.
    ///
    /// **Software custody only, and a seam that should not survive.** Soroban
    /// transactions are signed by handing `TxBuilder` a whole keypair, so
    /// submitting anything means the private key leaving the vault — which a
    /// Keycard cannot do and should not be asked to. The right shape is a
    /// signing port on `TxBuilder`, the way `KeyVault` is a port for
    /// everything else; until that exists, this is the honest version of what
    /// the client is already doing, rather than a secret smuggled out through
    /// a more innocent-looking name.
    pub fn keypair(&self, slot: SlotId, credential: &[u8]) -> Result<StellarKeypair> {
        let entry = self.find(slot)?;
        let nonce_bytes =
            hex::decode(&entry.nonce).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let ciphertext =
            hex::decode(&entry.ciphertext).map_err(|e| VaultError::Corrupt(e.to_string()))?;

        let mut kek = self.derive_kek(credential)?;
        // The file's plaintext has to be the plaintext this passphrase
        // sealed, before its contents are acted on.
        if let Err(e) = self.verify_header(&kek) {
            kek.zeroize();
            return Err(e);
        }
        let cipher = XSalsa20Poly1305::new(Key::from_slice(&kek));
        let mut seed_vec = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .map_err(|_| VaultError::BadCredential)?; // tag mismatch = wrong pass / tamper
        kek.zeroize();

        if seed_vec.len() != 32 {
            seed_vec.zeroize();
            return Err(VaultError::Corrupt("seed length != 32".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_vec);
        seed_vec.zeroize();

        let kp = StellarKeypair::from_raw_secret(&seed);
        seed.zeroize();

        // The entry's own `public_key` has to be this key's.
        //
        // The header MAC already covers that field, so reaching here
        // with a mismatch should be impossible -- but this is the
        // comparison that makes the guarantee local. Everything that
        // displays an address to fund or redeem into reads the stored
        // value, and the cost of being wrong there is the whole
        // balance, so it is checked where the real key is in hand
        // rather than inferred from a tag checked elsewhere.
        if kp.raw_public() != self.public_key(slot)? {
            return Err(VaultError::Tampered);
        }
        Ok(kp)
    }

    /// Derive the token store's keys from the HD seed.
    ///
    /// Separate domains from the backup keys and from each other, so no one of
    /// these can be used to learn anything about another.
    pub fn store_credentials(&self, credential: &[u8]) -> Result<StoreCredentials> {
        use sha2::{Digest, Sha256};
        let seed = self.unwrap_seed(credential)?;

        let mut aead = Zeroizing::new([0u8; 32]);
        aead.copy_from_slice(&Sha256::digest(
            [b"kntr_v1:wallet:store:key".as_slice(), &seed].concat(),
        ));
        let mut name = Zeroizing::new([0u8; 32]);
        name.copy_from_slice(&Sha256::digest(
            [b"kntr_v1:wallet:store:name".as_slice(), &seed].concat(),
        ));
        Ok(StoreCredentials { aead, name })
    }

    /// The slot's Stellar address, proven rather than read.
    ///
    /// Unwraps the seed and derives the address from it, so what comes
    /// back is what the key actually is — not what the file says it is.
    /// Costs one Argon2 derivation, which is why the plain
    /// [`KeyVault::stellar_address`] still exists for the places that
    /// are only labelling a row.
    pub fn verified_stellar_address(&self, slot: SlotId, credential: &[u8]) -> Result<String> {
        Ok(address_of(self.keypair(slot, credential)?.raw_public()))
    }

    /// Derive this wallet's backup key and fingerprint from the HD seed.
    ///
    /// Two separate domain tags so the fingerprint, which is written in the
    /// clear, cannot be used to learn anything about the key.
    pub fn backup_credentials(&self, credential: &[u8]) -> Result<BackupCredentials> {
        use sha2::{Digest, Sha256};
        let seed = self.unwrap_seed(credential)?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&Sha256::digest(
            [b"kntr_v1:wallet:backup:key".as_slice(), &seed].concat(),
        ));

        Ok(BackupCredentials {
            key: Zeroizing::new(key),
            fingerprint: backup_fingerprint(&seed),
        })
    }

    /// Re-derive the owner keypair at `index`.
    fn owner_keypair(&self, index: u32, credential: &[u8]) -> Result<StellarKeypair> {
        let seed = self.unwrap_seed(credential)?;
        let mut secret = slip10::stellar_account_secret(&seed, index)?;
        let kp = StellarKeypair::from_raw_secret(&secret);
        secret.zeroize();
        Ok(kp)
    }
}

impl DerivingVault for SoftVault {
    fn derive_public(&mut self, index: u32, credential: &[u8]) -> Result<[u8; 32]> {
        Ok(self.owner_keypair(index, credential)?.raw_public())
    }

    fn sign_derived(&mut self, index: u32, message: &[u8], credential: &[u8]) -> Result<[u8; 64]> {
        Ok(self
            .owner_keypair(index, credential)?
            .sign(message)
            .to_bytes())
    }
}

impl KeyVault for SoftVault {
    fn generate_key(&mut self, label: &str, credential: &[u8]) -> Result<SlotId> {
        let kp = StellarKeypair::random();
        let seed = kp.raw_secret(); // Zeroizing<[u8; 32]>
        let public = kp.raw_public();
        self.insert(&*seed, &public, label, credential)
    }

    fn import_seed(&mut self, seed: &[u8; 32], label: &str, credential: &[u8]) -> Result<SlotId> {
        let kp = StellarKeypair::from_raw_secret(seed);
        let public = kp.raw_public();
        self.insert(seed, &public, label, credential)
    }

    fn sign(&mut self, slot: SlotId, message: &[u8], credential: &[u8]) -> Result<[u8; 64]> {
        Ok(self.keypair(slot, credential)?.sign(message).to_bytes())
    }

    /// The stored public key. **Not authenticated** — no credential is
    /// supplied, so there is nothing to check it against.
    ///
    /// The header MAC covers this field, but verifying it needs the
    /// passphrase. A caller about to show an address as "fund this" or
    /// "you will be paid here" should prefer
    /// [`SoftVault::verified_stellar_address`], which holds the key and
    /// can prove it.
    fn public_key(&self, slot: SlotId) -> Result<[u8; 32]> {
        let entry = self.find(slot)?;
        let bytes =
            hex::decode(&entry.public_key).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VaultError::Corrupt("public key length != 32".into()))?;
        Ok(arr)
    }

    /// As [`Self::public_key`]: a plaintext read, unauthenticated.
    fn stellar_address(&self, slot: SlotId) -> Result<String> {
        Ok(address_of(self.public_key(slot)?))
    }

    fn list_keys(&self) -> Result<Vec<KeySlotInfo>> {
        self.file
            .entries
            .iter()
            .map(|e| {
                let pk = hex::decode(&e.public_key)
                    .map_err(|err| VaultError::Corrupt(err.to_string()))?;
                let arr: [u8; 32] = pk
                    .try_into()
                    .map_err(|_| VaultError::Corrupt("public key length != 32".into()))?;
                Ok(KeySlotInfo {
                    slot: e.slot,
                    label: e.label.clone(),
                    stellar_address: address_of(arr),
                    created_at: e.created_at,
                })
            })
            .collect()
    }

    fn remove_key(&mut self, slot: SlotId, credential: &[u8]) -> Result<()> {
        // Authorize the irreversible delete by proving the passphrase decrypts
        // the target entry (also catches "wrong vault" mistakes).
        self.sign(slot, b"authorize-remove", credential)?;
        self.file.entries.retain(|e| e.slot != slot);
        self.save()
    }
}

/// Encode a raw Ed25519 public key as a Stellar address (G…) `std::String`.
/// Which wallet a seed is, as every backup header names it.
///
/// Extracted so there is exactly one copy of the formula. A restore has to
/// compute this from a phrase, before any vault exists to ask — and a second
/// copy of a hash that is written into files is a copy that will eventually
/// disagree with the first.
///
/// A separate domain from the backup key, so the fingerprint, which travels
/// in the clear, says nothing about the key.
pub fn backup_fingerprint(seed: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let fp = Sha256::digest([b"kntr_v1:wallet:backup:fp".as_slice(), seed].concat());
    hex::encode(&fp[..8])
}

/// (`stellar-strkey`'s `to_string` yields a `heapless::String`.)
fn address_of(pk: [u8; 32]) -> String {
    StellarPublic(pk).to_string().as_str().to_owned()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl crate::bip85::Bip85 for SoftVault {
    /// Computed here from the sealed seed. A card would run the same
    /// derivation on-chip and hand back only the entropy; this is the half
    /// that makes a phrase-restored wallet reproduce a card's keys.
    fn bip85_entropy(
        &mut self,
        path: &[u32],
        len: usize,
        credential: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let seed = self.unwrap_seed(credential)?;
        crate::bip85::entropy(&seed, path, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_crypto::keypair::StellarKeypair;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "kenter-vault-test-{}-{}.json",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// BIP-39 seed for SEP-0005 test vector 1 (see `slip10` tests).
    const SEP5_V1_SEED: &str = "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497e\
                                e4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186";

    fn sep5_seed() -> Vec<u8> {
        hex::decode(SEP5_V1_SEED).unwrap()
    }

    /// The owner key the vault derives must equal the one `slip10` derives from
    /// the same seed - i.e. storing the seed encrypted changes nothing about the
    /// keys, which is what keeps a software wallet and a card in agreement.
    #[test]
    fn derived_owner_keys_match_the_raw_derivation() {
        let path = tmp_path("derive-match");
        let pass = b"vault pass";
        let mut v = SoftVault::open(&path).unwrap();
        v.set_seed(&sep5_seed(), pass).unwrap();

        for index in [0u32, 1, 7, 1000] {
            let via_vault = v.derive_public(index, pass).unwrap();
            let raw = slip10::stellar_account_secret(&sep5_seed(), index).unwrap();
            let expected = StellarKeypair::from_raw_secret(&raw).raw_public();
            assert_eq!(via_vault, expected, "index {index}");
        }
        // And index 0 is still the published SEP-0005 address.
        let pk = v.derive_public(0, pass).unwrap();
        assert_eq!(
            address_of(pk),
            "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn seed_persists_and_signs_verifiably() {
        let path = tmp_path("derive-persist");
        let pass = b"vault pass";
        {
            let mut v = SoftVault::open(&path).unwrap();
            assert!(!v.has_seed());
            v.set_seed(&sep5_seed(), pass).unwrap();
            assert!(v.has_seed());
        }

        // Reopen from disk - the seed survives, so the owner keys do too.
        let mut v = SoftVault::open(&path).unwrap();
        assert!(v.has_seed());

        let msg = [0x5au8; 32]; // owner authorizations sign a 32-byte digest
        let sig = v.sign_derived(3, &msg, pass).unwrap();
        let pk = v.derive_public(3, pass).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        assert!(
            vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok()
        );

        // A signature from one index must not verify under another.
        let other = v.derive_public(4, pass).unwrap();
        let ovk = ed25519_dalek::VerifyingKey::from_bytes(&other).unwrap();
        assert!(
            ovk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_err()
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn derivation_needs_the_right_passphrase() {
        let path = tmp_path("derive-badpass");
        let mut v = SoftVault::open(&path).unwrap();
        v.set_seed(&sep5_seed(), b"right").unwrap();
        assert!(matches!(
            v.derive_public(0, b"wrong").unwrap_err(),
            VaultError::BadCredential
        ));
        assert!(matches!(
            v.sign_derived(0, &[0u8; 32], b"wrong").unwrap_err(),
            VaultError::BadCredential
        ));
        std::fs::remove_file(&path).ok();
    }

    /// Overwriting the seed would orphan every token owned by a key derived from
    /// the old one, and a bearer token cannot be reissued. Refuse it.
    #[test]
    fn seed_cannot_be_replaced() {
        let path = tmp_path("derive-noreplace");
        let pass = b"vault pass";
        let mut v = SoftVault::open(&path).unwrap();
        v.set_seed(&sep5_seed(), pass).unwrap();

        let mut other = sep5_seed();
        other[0] ^= 0xff;
        assert!(v.set_seed(&other, pass).is_err());

        // The original seed is untouched.
        assert_eq!(
            address_of(v.derive_public(0, pass).unwrap()),
            "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn deriving_without_a_seed_is_an_error() {
        let path = tmp_path("derive-noseed");
        let mut v = SoftVault::open(&path).unwrap();
        assert!(v.derive_public(0, b"pass").is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_an_out_of_range_seed() {
        let path = tmp_path("derive-badseed");
        let mut v = SoftVault::open(&path).unwrap();
        assert!(v.set_seed(&[0u8; 8], b"pass").is_err());
        assert!(!v.has_seed(), "a rejected seed must not be stored");
        std::fs::remove_file(&path).ok();
    }

    /// Account keys and owner keys coexist: the seed is additive to the slots.
    #[test]
    fn slots_and_seed_coexist() {
        let path = tmp_path("derive-coexist");
        let pass = b"vault pass";
        let mut v = SoftVault::open(&path).unwrap();
        let slot = v.generate_key("account", pass).unwrap();
        v.set_seed(&sep5_seed(), pass).unwrap();

        let mut v = SoftVault::open(&path).unwrap();
        assert_eq!(v.list_keys().unwrap().len(), 1);
        assert!(v.has_seed());
        assert!(v.public_key(slot).is_ok());
        assert_ne!(
            v.public_key(slot).unwrap(),
            v.derive_public(0, pass).unwrap(),
            "the account key and an owner key must be different keys"
        );
        std::fs::remove_file(&path).ok();
    }

    /// A vault file written before owner-key support must still open.
    #[test]
    fn opens_a_pre_seed_vault_file() {
        let path = tmp_path("derive-legacy");
        let pass = b"vault pass";
        {
            let mut v = SoftVault::open(&path).unwrap();
            v.generate_key("account", pass).unwrap();
        }
        // Strip the field the way an older writer would have left it out.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("\"seed\""),
            "no seed was set, so none should be written"
        );

        let mut v = SoftVault::open(&path).unwrap();
        assert!(!v.has_seed());
        v.set_seed(&sep5_seed(), pass).unwrap(); // and it can be upgraded in place
        assert!(SoftVault::open(&path).unwrap().has_seed());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn generate_persist_reopen_sign_verify() {
        let path = tmp_path("roundtrip");
        let pass = b"correct horse battery staple";

        let (slot, addr) = {
            let mut v = SoftVault::open(&path).unwrap();
            let slot = v.generate_key("savings", pass).unwrap();
            (slot, v.stellar_address(slot).unwrap())
        };

        // Reopen from disk — the key survives.
        let mut v = SoftVault::open(&path).unwrap();
        assert_eq!(v.list_keys().unwrap().len(), 1);
        assert_eq!(v.stellar_address(slot).unwrap(), addr);

        // Sign, then verify against the stored public key with a fresh verifier.
        let msg = b"redeem this token";
        let sig = v.sign(slot, msg, pass).unwrap();
        let pk = v.public_key(slot).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(vk.verify_strict(msg, &signature).is_ok());
        // address <-> public key agree
        assert_eq!(address_of(pk), addr);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_passphrase_fails() {
        let path = tmp_path("wrongpass");
        let mut v = SoftVault::open(&path).unwrap();
        let slot = v.generate_key("k", b"right-pass").unwrap();
        let err = v.sign(slot, b"msg", b"WRONG-pass").unwrap_err();
        assert!(matches!(err, VaultError::BadCredential));
        std::fs::remove_file(&path).ok();
    }

    /// Swapping the stored public key is detected.
    ///
    /// The attack: the AEAD covers the sealed seed and nothing around it,
    /// so without the header MAC `public_key` is free to edit — and
    /// `kenter keys`, `kenter keygen` and the UI all display that value as
    /// the account to fund or redeem into. The secret still unwraps, so
    /// nothing would complain.
    #[test]
    fn a_swapped_public_key_is_caught() {
        let path = tmp_path("c4-pubkey");
        let _ = std::fs::remove_file(&path);
        let mut v = SoftVault::open(&path).unwrap();
        let slot = v.generate_key("acct", b"pw").unwrap();
        let honest = v.stellar_address(slot).unwrap();
        drop(v);

        // An attacker rewrites the displayed key, leaving the sealed
        // seed untouched.
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["entries"][0]["public_key"] = serde_json::json!(hex::encode([0xEE; 32]));
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        let v = SoftVault::open(&path).unwrap();
        assert_ne!(v.stellar_address(slot).unwrap(), honest, "the file now lies");

        // But nothing that holds the passphrase will go along with it.
        assert!(matches!(
            v.keypair(slot, b"pw"),
            Err(VaultError::Tampered) | Err(VaultError::BadCredential)
        ));
        assert!(v.verified_stellar_address(slot, b"pw").is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// The custody record is covered too, so a swapped `card_identity`
    /// cannot point a launch check at the wrong card.
    #[test]
    fn a_swapped_card_identity_is_caught() {
        let path = tmp_path("c4-custody");
        let _ = std::fs::remove_file(&path);
        let mut v = SoftVault::open(&path).unwrap();
        v.generate_key("acct", b"pw").unwrap();
        v.set_custody(
            Custody::Card {
                seed_fingerprint: "aaaa".into(),
                card_identity: "1111".into(),
            },
            b"pw",
        )
        .unwrap();
        drop(v);

        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["custody"]["card_identity"] = serde_json::json!("2222");
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        let v = SoftVault::open(&path).unwrap();
        assert!(
            v.keypair(0, b"pw").is_err(),
            "an edited custody record must not pass authentication"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// And deleting the tag is not a way around it.
    #[test]
    fn a_vault_with_secrets_and_no_mac_is_refused() {
        let path = tmp_path("c4-stripped");
        let _ = std::fs::remove_file(&path);
        let mut v = SoftVault::open(&path).unwrap();
        v.generate_key("acct", b"pw").unwrap();
        drop(v);

        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json.as_object_mut().unwrap().remove("mac");
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        assert!(matches!(
            SoftVault::open(&path),
            Err(VaultError::Tampered)
        ));
        let _ = std::fs::remove_file(&path);
    }

    /// A planted cheap KDF is refused at open,
    /// before anything is sealed under it.
    #[test]
    fn a_weakened_kdf_cost_is_refused() {
        let path = tmp_path("c3-weak");
        let _ = std::fs::remove_file(&path);
        let mut v = SoftVault::open(&path).unwrap();
        v.generate_key("acct", b"pw").unwrap();
        drop(v);

        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["kdf_m_cost"] = serde_json::json!(8);
        json["kdf_t_cost"] = serde_json::json!(1);
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        assert!(matches!(
            SoftVault::open(&path),
            Err(VaultError::BadKdfParams(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    /// A second passphrase is refused, not silently accepted.
    ///
    /// Otherwise a typo while adding the seed would seal it under a
    /// credential the owner does not have. The phrase is shown once, so they
    /// might never get it back — and nothing would say anything until the
    /// next signature failed.
    #[test]
    fn a_second_passphrase_is_refused() {
        let path = tmp_path("c5-second");
        let _ = std::fs::remove_file(&path);
        let mut v = SoftVault::open(&path).unwrap();
        v.generate_key("first", b"correct horse").unwrap();

        assert!(
            matches!(
                v.generate_key("second", b"correct hosre"),
                Err(VaultError::BadCredential)
            ),
            "a typo'd passphrase must not open a second slot"
        );
        assert!(
            v.set_seed(&[9u8; 64], b"correct hosre").is_err(),
            "nor seal the seed"
        );

        // The real one still works, and nothing was written in between.
        assert!(v.generate_key("second", b"correct horse").is_ok());
        assert_eq!(v.list_keys().unwrap().len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tamper_ciphertext_fails() {
        let path = tmp_path("tamper");
        let pass = b"pw";
        {
            let mut v = SoftVault::open(&path).unwrap();
            v.generate_key("k", pass).unwrap();
        }
        // Flip a byte inside the stored ciphertext hex.
        let mut txt = std::fs::read_to_string(&path).unwrap();
        // corrupt the first hex nibble of the ciphertext field's value
        let marker = "\"ciphertext\": \"";
        let idx = txt.find(marker).unwrap() + marker.len();
        let ch = txt.as_bytes()[idx];
        let repl = if ch == b'a' { b'b' } else { b'a' };
        unsafe {
            txt.as_bytes_mut()[idx] = repl;
        }
        std::fs::write(&path, &txt).unwrap();

        let mut v = SoftVault::open(&path).unwrap();
        let err = v.sign(0, b"msg", pass).unwrap_err();
        assert!(matches!(err, VaultError::BadCredential));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn import_seed_roundtrips_address() {
        let path = tmp_path("import");
        let pass = b"pw";
        let kp = StellarKeypair::random();
        let seed = *kp.raw_secret();
        let expected = kp.stellar_address();

        let mut v = SoftVault::open(&path).unwrap();
        let slot = v.import_seed(&seed, "imported", pass).unwrap();
        assert_eq!(v.stellar_address(slot).unwrap(), expected);
        std::fs::remove_file(&path).ok();
    }
}

#[cfg(test)]
mod custody_tests {
    use super::*;

    /// The custody record lives inside the authenticated header, so
    /// writing it takes the passphrase.
    const PASS: &[u8] = b"custody-tests";

    fn vault(tag: &str) -> (SoftVault, std::path::PathBuf) {
        let p =
            std::env::temp_dir().join(format!("kenter-custody-{tag}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        (SoftVault::open(&p).unwrap(), p)
    }

    /// Absence must not be read as "software". That inference is the bug
    /// the field exists to kill: a card wallet's vault has no seed either.
    #[test]
    fn a_vault_with_no_record_says_so_rather_than_guessing() {
        let (v, p) = vault("none");
        assert!(v.custody().is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_custody_record_survives_a_reopen() {
        let (mut v, p) = vault("round");
        v.set_custody(
            Custody::Card {
                seed_fingerprint: "b955b8449197cad9".into(),
                card_identity: "03c7a53f".into(),
            },
            PASS,
        )
        .unwrap();
        drop(v);

        let again = SoftVault::open(&p).unwrap();
        match again.custody() {
            Some(Custody::Card {
                seed_fingerprint,
                card_identity,
            }) => {
                assert_eq!(seed_fingerprint, "b955b8449197cad9");
                assert_eq!(card_identity, "03c7a53f");
            }
            other => panic!("expected a card record, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    /// Re-labelling a vault would describe an account key nothing can open:
    /// the two custodies protect it with different credentials.
    #[test]
    fn custody_cannot_be_changed_once_recorded() {
        let (mut v, p) = vault("change");
        v.set_custody(Custody::Software, PASS).unwrap();
        let err = v
            .set_custody(
                Custody::Card {
                    seed_fingerprint: "x".into(),
                    card_identity: "y".into(),
                },
                PASS,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already recorded"), "{err}");
        // ...but writing the same record twice is not an error, so a retry
        // of a setup step that already got this far is harmless.
        v.set_custody(Custody::Software, PASS).unwrap();
        let _ = std::fs::remove_file(&p);
    }

    /// A seed and a card record together is the mixed state `provision`
    /// now refuses to create. The vault should not be the thing that
    /// enforces it, but it must at least round-trip both fields.
    #[test]
    fn a_seed_and_a_record_are_independent_fields() {
        let (mut v, p) = vault("both");
        // One vault, one passphrase -- using a second one here is
        // refused (see `a_second_passphrase_is_refused`).
        v.set_seed(&[7u8; 64], PASS).unwrap();
        v.set_custody(Custody::Software, PASS).unwrap();
        drop(v);
        let again = SoftVault::open(&p).unwrap();
        assert!(again.has_seed());
        assert_eq!(again.custody(), Some(&Custody::Software));
        let _ = std::fs::remove_file(&p);
    }
}
