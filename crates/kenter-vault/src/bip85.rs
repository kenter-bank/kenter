//! BIP85: deriving independent secrets from one seed.
//!
//! The wallet needs symmetric keys — for the sealed note store and for the
//! backup file — that a **card can produce without exporting its seed**, and
//! that a `SoftVault` restored from the same paper phrase reproduces bit for
//! bit. The second half is what keeps the backup promise (phrase plus backup
//! file restores the wallet) alive when the card is the thing that was lost.
//!
//! # Why not derive from a signature
//!
//! Deriving those keys from an **Ed25519 signature** over a fixed challenge,
//! on the grounds that RFC 8032 signing is deterministic, is unsound, and not
//! subtly:
//!
//! - Deterministic signing without verify-after-sign means *one glitched
//!   signature over a repeated message leaks the key*. Such a scheme signs
//!   **the same challenge on every unlock**, which is that attack performed
//!   on a schedule, with the key that guards every note in the wallet.
//! - The defence against that is hedged nonces, which make every signature
//!   different — and every backup sealed under an earlier value unopenable.
//!   A key-derivation scheme must not depend on a signing-nonce policy.
//! - It also put a key-derivation role on a signing key, which is the reason
//!   index 0 was avoided, one level up.
//!
//! BIP85 is purpose-built for this and has none of those properties: no nonce,
//! no signing key, and the card exposes it as a PIN-gated command that
//! exports neither the seed nor any key.
//!
//! # The two trees
//!
//! A card seeded by `LOAD KEY P1=SEED` holds **two** masters off one BIP-39
//! seed, and they are not interchangeable:
//!
//! | Tree | Master | Used for |
//! |---|---|---|
//! | BIP32 / secp256k1 | `HMAC-SHA512("Bitcoin seed", seed)` | **BIP85**, below |
//! | SLIP-0010 / ed25519 | `HMAC-SHA512("ed25519 seed", seed)` | owner keys at `m/44'/148'/n'` ([`crate::slip10`]) |
//!
//! Getting the master wrong is the kind of mistake that reproduces perfectly
//! in our own tests and not at all against a card, so the two are kept apart
//! here and the published BIP85 vectors are what pins this one.
//!
//! # Only a seeded card
//!
//! `GENERATE KEY` builds both trees from 64 random bytes, so such a card
//! signs and derives perfectly well — it simply has **no phrase behind it**,
//! and its BIP85 children are reproducible by nothing, anywhere. A wallet on
//! it is unrecoverable the moment the card is.
//!
//! It is also **indistinguishable from a seeded card** over the wire: same
//! trees, same answers. So this cannot be checked for, only controlled —
//! Kenter's provisioning always uses `LOAD KEY P1=SEED`, and a card a holder
//! brings has to be asked about rather than probed.
//! A *raw keypair* load is the detectable case (`SIGN P2=0x01` → `6985`), and
//! the easy one.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::{BackupCredentials, Result, StoreCredentials, VaultError};

type HmacSha512 = Hmac<Sha512>;

/// `m/83696968'` — the BIP85 purpose, "BIPS" on a phone keypad.
const BIP85_PURPOSE: u32 = 83696968;
/// The BIP85 **HEX** application: `…/128169'/{bytes}'/{index}'`.
const APP_HEX: u32 = 128169;
/// We want 32-byte keys.
const KEY_BYTES: u32 = 32;

/// Index of the sealed note store's keys under the HEX application.
pub const STORE_KEY_INDEX: u32 = 0;
/// Index of the backup file's key under the HEX application.
///
/// A different index, not a different tag off one secret: BIP85 children are
/// independent by construction, so a leak of one says nothing about the other.
pub const BACKUP_KEY_INDEX: u32 = 1;
/// Index of the credential that opens the **account vault** on a
/// card-custody wallet.
///
/// A card wallet still has one software key: the Stellar account that pays
/// fees. It stays off the card deliberately — a hot key gains nothing
/// from a secure element, and leaving it in software preserves the shape
/// where neither key alone moves a note. But it still needs protecting at
/// rest, and a card-custody wallet has no passphrase to protect it with.
///
/// So the `SoftVault` holding it is opened with this child. The card stays
/// the single unlock, and because BIP85 is a function of the seed, a holder
/// restoring from the paper phrase derives the same credential — and so can
/// open the same vault **file**, if they still have it.
///
/// That last clause is why [`ACCOUNT_KEY_INDEX`] exists: a credential that
/// opens a file is no use when the file is gone.
///
/// **Permanent once a wallet exists.** A wallet provisioned against index 2
/// cannot later be opened by a build that derives it elsewhere.
pub const ACCOUNT_VAULT_KEY_INDEX: u32 = 2;

/// Index of the fee-paying Stellar account's **secret key itself**.
///
/// Derived rather than random. A random account key stored in the vault and
/// nowhere else is recoverable from *phrase plus vault file*, never from the
/// phrase alone — which makes the vault file a third thing a holder must not
/// lose, the shape the backup design rejects for notes.
///
/// It matters because **redemption pays into this account**. With a random
/// key, a holder could recover every note from their phrase and a backup,
/// and still find the proceeds of the ones they had already redeemed sitting
/// in an address nobody could sign for.
///
/// Derived the same way for every custody, so one seed is one account
/// whether it is held on a card, in software, or recovered from a lost
/// card. Used directly as the 32-byte Ed25519 secret, which is what BIP85's
/// HEX application is for.
///
/// **Not** a `m/44'/148'/n'` index: those are owner keys, and an account
/// sharing a key with an owner would link a holder's fee payments to the
/// note they were paying for.
pub const ACCOUNT_KEY_INDEX: u32 = 3;

/// A BIP32 node: private key plus chain code.
struct Node {
    key: Zeroizing<[u8; 32]>,
    chain_code: [u8; 32],
}

/// BIP32 master from a BIP-39 seed — **"Bitcoin seed"**, not SLIP-0010's
/// "ed25519 seed". See the module docs.
fn bip32_master(seed: &[u8]) -> Result<Node> {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|_| VaultError::Crypto)?;
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&i[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&i[32..]);
    Ok(Node { key, chain_code })
}

/// One hardened BIP32 step. Hardened only — every BIP85 path element is, so
/// no public-key arithmetic is needed, just the scalar addition.
fn derive_hardened(parent: &Node, index: u32) -> Result<Node> {
    // k256 0.14's `Reduce` is the generic `reduce(&T)`, with
    // `Scalar: Reduce<FieldBytes>`; the published BIP85 and BIP39 vectors
    // below pin the arithmetic. k256 0.14 is required rather than 0.13:
    // 0.13 pulls in `crypto-bigint 0.5.5`, whose constant-time operations
    // are not, and this function reduces secret material on both lines.
    use k256::elliptic_curve::ops::Reduce;
    use k256::{FieldBytes, Scalar};

    let mut mac = HmacSha512::new_from_slice(&parent.chain_code).map_err(|_| VaultError::Crypto)?;
    mac.update(&[0x00]);
    mac.update(parent.key.as_slice());
    mac.update(&(0x8000_0000u32 | index).to_be_bytes());
    let i = mac.finalize().into_bytes();

    // k_i = (IL + k_par) mod n. BIP32 says to skip the index if IL >= n or the
    // result is zero; both are ~2^-127 events, and silently skipping would
    // make us derive a different key than any other implementation on the one
    // input where it mattered. Refuse instead.
    let mut il_bytes = [0u8; 32];
    il_bytes.copy_from_slice(&i[..32]);
    let il = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(il_bytes));
    let kpar = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*parent.key));
    let ki = il + kpar;
    if bool::from(ki.is_zero()) {
        return Err(VaultError::Crypto2(
            "BIP32 derivation produced a zero key — astronomically unlikely, and \
             skipping the index silently would diverge from every other \
             implementation"
                .into(),
        ));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&ki.to_bytes());
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&i[32..]);
    Ok(Node { key, chain_code })
}

/// Raw BIP85 entropy at a path, truncated to `len` bytes (1–64).
///
/// `HMAC-SHA512("bip-entropy-from-k", k)` over the derived node's private
/// key, exactly as the card's `INS_EXPORT_BIP85` computes it.
pub fn entropy(seed: &[u8], path: &[u32], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let master = bip32_master(seed)?;
    entropy_from_master(&master, path, len)
}

/// Same, from an already-derived BIP32 master.
///
/// Exists because the published BIP85 vectors are specified from an **xprv**
/// rather than from a BIP-39 seed, so pinning them means entering the tree at
/// the master rather than at the seed.
fn entropy_from_master(master: &Node, path: &[u32], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !(1..=64).contains(&len) {
        return Err(VaultError::Crypto2(format!(
            "BIP85 output length {len} is outside 1..=64"
        )));
    }
    let mut node = Node {
        key: master.key.clone(),
        chain_code: master.chain_code,
    };
    for &element in path {
        node = derive_hardened(&node, element)?;
    }
    let mut mac =
        HmacSha512::new_from_slice(b"bip-entropy-from-k").map_err(|_| VaultError::Crypto)?;
    mac.update(node.key.as_slice());
    let mut out = mac.finalize().into_bytes();
    let result = Zeroizing::new(out[..len].to_vec());
    out.zeroize();
    Ok(result)
}

/// The HEX application's path for a 32-byte secret at `index`.
pub fn hex_key_path(index: u32) -> [u32; 4] {
    [BIP85_PURPOSE, APP_HEX, KEY_BYTES, index]
}

/// A 32-byte secret from the HEX application at `index`, computed locally.
pub fn hex_key(seed: &[u8], index: u32) -> Result<Zeroizing<[u8; 32]>> {
    let e = entropy(seed, &hex_key_path(index), 32)?;
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&e);
    Ok(k)
}

/// The same, from whichever vault holds the seed.
fn hex_key_from<V: Bip85>(
    vault: &mut V,
    index: u32,
    credential: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let e = vault.bip85_entropy(&hex_key_path(index), 32, credential)?;
    if e.len() != 32 {
        return Err(VaultError::Crypto2(format!(
            "BIP85 returned {} bytes, expected 32",
            e.len()
        )));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&e);
    Ok(k)
}

/// A vault that can answer BIP85 queries.
///
/// A port rather than a free function over a seed, because **a card never
/// hands over its seed** — it runs the derivation itself and returns the
/// entropy (`INS_EXPORT_BIP85`). Taking a seed here would have quietly
/// excluded the one backend the whole mechanism exists for.
///
/// `credential` is the vault's unlock secret: a PIN for a card, a passphrase
/// for software.
pub trait Bip85 {
    /// Entropy at an all-hardened path under `m/83696968'`, truncated to
    /// `len` bytes (1..=64).
    fn bip85_entropy(
        &mut self,
        path: &[u32],
        len: usize,
        credential: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Store and backup credentials for a wallet whose seed may never leave its
/// vault.
///
/// Two independent BIP85 children rather than two tags off one secret:
/// children are independent by construction, so the backup key is not
/// recoverable from the store key or the reverse.
///
/// The fingerprint is a hash of the backup key's *child*, never of the key
/// itself — it is written in the clear in every backup header.
///
/// **Not** the values [`crate::SoftVault`]'s seed-hashing `store_credentials`
/// and `backup_credentials` produce. Which derivation a backup used is
/// recorded in its header as `SeedOrigin`, so a restorer
/// never has to guess.
/// The credential that opens a card wallet's account vault.
///
/// Thirty-two bytes of BIP85 entropy used directly as the vault's
/// credential, exactly as a passphrase would be. The vault runs it through
/// its own KDF, so there is no need to stretch it here — and unlike a
/// passphrase it already has full entropy.
pub fn account_vault_credential<V: Bip85>(
    vault: &mut V,
    credential: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    hex_key_from(vault, ACCOUNT_VAULT_KEY_INDEX, credential)
}

/// The fee-paying account's Ed25519 secret. See [`ACCOUNT_KEY_INDEX`].
///
/// A function of the seed and nothing else, so the same phrase always names
/// the same account — which is the whole point: the account has to come
/// back from the words, not from a file.
pub fn account_key<V: Bip85>(
    vault: &mut V,
    credential: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    hex_key_from(vault, ACCOUNT_KEY_INDEX, credential)
}

pub fn vault_bound_credentials<V: Bip85>(
    vault: &mut V,
    credential: &[u8],
) -> Result<(StoreCredentials, BackupCredentials)> {
    use sha2::{Digest, Sha256};

    let store = hex_key_from(vault, STORE_KEY_INDEX, credential)?;
    let backup = hex_key_from(vault, BACKUP_KEY_INDEX, credential)?;

    // The store needs two keys: one to seal a record, one to turn its id into
    // an opaque filename. Split by tag from the one child, since both are
    // equally secret and neither is ever published.
    let mut aead = Zeroizing::new([0u8; 32]);
    aead.copy_from_slice(&Sha256::digest(
        [
            b"kntr_v1:wallet:bip85:store:key".as_slice(),
            store.as_slice(),
        ]
        .concat(),
    ));
    let mut name = Zeroizing::new([0u8; 32]);
    name.copy_from_slice(&Sha256::digest(
        [
            b"kntr_v1:wallet:bip85:store:name".as_slice(),
            store.as_slice(),
        ]
        .concat(),
    ));

    Ok((
        StoreCredentials { aead, name },
        BackupCredentials {
            fingerprint: backup_fingerprint(&backup),
            key: Zeroizing::new(*backup),
        },
    ))
}

/// Which wallet a card-rooted seed is, as its backup headers name it.
///
/// A hash of the backup **child**, never of the key itself or of the seed:
/// the value travels in the clear in every header.
///
/// The card-wallet counterpart of [`crate::soft_backup_fingerprint`], and
/// deliberately a different value from it for the same seed — the two
/// derivations produce different wallets, and a header that could not tell
/// them apart would send a restore down the wrong one.
pub fn backup_fingerprint(child: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let fp = Sha256::digest(
        [b"kntr_v1:wallet:bip85:backup:fp".as_slice(), child.as_slice()].concat(),
    );
    hex::encode(&fp[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed in memory, standing in for any vault that holds one.
    struct Local([u8; 64]);
    impl Bip85 for Local {
        fn bip85_entropy(
            &mut self,
            path: &[u32],
            len: usize,
            _credential: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            entropy(&self.0, path, len)
        }
    }

    /// The master behind the published BIP85 vectors.
    ///
    /// The spec gives it as an xprv
    /// (`xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb`),
    /// not as a seed, so these are its decoded chain code and private key —
    /// base58check verified, version `0488ade4`, depth 0. The applet repo's
    /// `bip85PublishedVectorsTest` enters the tree at the same point.
    const VEC_CHAIN_CODE: &str = "1b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c";
    const VEC_PRIVKEY: &str = "3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed9";

    fn vector_master() -> Node {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hex::decode(VEC_PRIVKEY).unwrap());
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&hex::decode(VEC_CHAIN_CODE).unwrap());
        Node { key, chain_code }
    }

    /// Hardened BIP32 derivation, checked on its own before anything is built
    /// on it. If the scalar addition or the `0x00 || k || index` preimage were
    /// wrong, every BIP85 value would be wrong in a way the entropy vectors
    /// could not tell apart from a bad HMAC label.
    #[test]
    fn hardened_derivation_matches_the_published_child_key() {
        let mut node = vector_master();
        for element in [BIP85_PURPOSE, 0, 0] {
            node = derive_hardened(&node, element).unwrap();
        }
        assert_eq!(
            hex::encode(node.key.as_slice()),
            "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
            "BIP32 hardened CKD is wrong"
        );
    }

    /// The published raw vectors: `m/83696968'/0'/0'` and `/0'/1'`, 64 bytes.
    /// These pin the `bip-entropy-from-k` HMAC label.
    #[test]
    fn matches_the_published_bip85_vectors() {
        let m = vector_master();
        assert_eq!(
            hex::encode(&*entropy_from_master(&m, &[BIP85_PURPOSE, 0, 0], 64).unwrap()),
            concat!(
                "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0",
                "0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
            )
        );
        assert_eq!(
            hex::encode(&*entropy_from_master(&m, &[BIP85_PURPOSE, 0, 1], 64).unwrap()),
            concat!(
                "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872",
                "218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"
            )
        );
    }

    /// The BIP39 application — the path the card-custody wallet uses for the
    /// software vault's child seed, so it is worth pinning here and not only
    /// where it is consumed. Entropy is truncated to `words * 4 / 3` bytes.
    #[test]
    fn matches_the_published_bip39_application_vectors() {
        let m = vector_master();
        for (words, len, want) in [
            (12u32, 16usize, "6250b68daf746d12a24d58b4787a714b"),
            (18, 24, "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc"),
            (
                24,
                32,
                "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f",
            ),
        ] {
            let e = entropy_from_master(&m, &[BIP85_PURPOSE, 39, 0, words, 0], len).unwrap();
            assert_eq!(hex::encode(&*e), want, "{words}-word child");
        }
    }

    /// The two trees must not be confused: BIP85 is off the **Bitcoin seed**
    /// master, owner keys are off the **ed25519 seed** master. If these ever
    /// matched, one of the two labels would be wrong.
    #[test]
    fn bip85_does_not_use_the_ed25519_master() {
        let seed = [0x42u8; 64];
        let bip32 = bip32_master(&seed).unwrap();
        let slip10 = crate::slip10::master_from_seed(&seed).unwrap();
        assert_ne!(bip32.key.as_slice(), &slip10.key[..]);
        assert_ne!(bip32.chain_code, slip10.chain_code);
    }

    /// Store and backup keys come from independent children, so neither
    /// reveals the other, and the fingerprint reveals neither.
    #[test]
    fn the_credentials_are_independent() {
        let (store, backup) = vault_bound_credentials(&mut Local([0x42u8; 64]), b"").unwrap();
        let a = hex::encode(store.aead.as_slice());
        let b = hex::encode(store.name.as_slice());
        let c = hex::encode(backup.key.as_slice());
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        assert!(!c.contains(&backup.fingerprint));
        assert_eq!(backup.fingerprint.len(), 16);
    }

    /// The point of the whole exercise: one seed, one answer, every time and
    /// everywhere. A card and a phrase-restored software vault run this same
    /// code over the same seed.
    #[test]
    fn one_seed_gives_one_answer() {
        let (s1, b1) = vault_bound_credentials(&mut Local([0x42u8; 64]), b"").unwrap();
        let (s2, b2) = vault_bound_credentials(&mut Local([0x42u8; 64]), b"").unwrap();
        assert_eq!(s1.aead.as_slice(), s2.aead.as_slice());
        assert_eq!(b1.fingerprint, b2.fingerprint);

        let other = vault_bound_credentials(&mut Local([0x5Au8; 64]), b"").unwrap();
        assert_ne!(s1.aead.as_slice(), other.0.aead.as_slice());
        assert_ne!(b1.fingerprint, other.1.fingerprint);
    }

    #[test]
    fn an_impossible_output_length_is_refused() {
        let seed = [0x42u8; 64];
        assert!(entropy(&seed, &[BIP85_PURPOSE, 0, 0], 0).is_err());
        assert!(entropy(&seed, &[BIP85_PURPOSE, 0, 0], 65).is_err());
    }
}

#[cfg(test)]
mod account_vault_tests {
    use super::*;
    use crate::{SoftVault, mnemonic};

    const PASS: &[u8] = b"correct horse battery staple";
    const SEP5_V1: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";

    fn vault_with_seed(tag: &str) -> (SoftVault, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("kenter-acct-{tag}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut v = SoftVault::open(&path).unwrap();
        let seed = mnemonic::to_seed(SEP5_V1, "").unwrap();
        v.set_seed(&*seed, PASS).unwrap();
        (v, path)
    }

    /// The account vault's credential must be its own secret. A leak of the
    /// store key is bad; it must not also be the account key's.
    #[test]
    fn the_account_credential_differs_from_the_store_and_backup_keys() {
        let (mut v, path) = vault_with_seed("distinct");
        let acct = account_vault_credential(&mut v, PASS).unwrap();
        let (store, backup) = vault_bound_credentials(&mut v, PASS).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_ne!(acct.as_slice(), store.aead.as_slice());
        assert_ne!(acct.as_slice(), store.name.as_slice());
        assert_ne!(acct.as_slice(), backup.key.as_slice());
    }

    /// The whole point of deriving it rather than storing it: a holder who
    /// restores from the phrase gets back into the same account vault.
    #[test]
    fn the_same_seed_gives_back_the_same_account_credential() {
        let (mut a, pa) = vault_with_seed("same-a");
        let (mut b, pb) = vault_with_seed("same-b");
        let ka = account_vault_credential(&mut a, PASS).unwrap();
        let kb = account_vault_credential(&mut b, PASS).unwrap();
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
        assert_eq!(ka.as_slice(), kb.as_slice());
    }

    /// Index 2, and it has to stay index 2 - a wallet provisioned against
    /// it cannot be opened by a build that derives the credential elsewhere.
    #[test]
    fn the_account_vault_index_is_pinned() {
        assert_eq!(ACCOUNT_VAULT_KEY_INDEX, 2);
        assert_ne!(ACCOUNT_VAULT_KEY_INDEX, STORE_KEY_INDEX);
        assert_ne!(ACCOUNT_VAULT_KEY_INDEX, BACKUP_KEY_INDEX);
    }
}
