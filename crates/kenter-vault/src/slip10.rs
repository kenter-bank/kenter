//! SLIP-0010 ed25519 hierarchical key derivation.
//!
//! This is the software half of the owner-key model (see
//! `docs/architecture/custody.md`): one
//! wallet seed, an owner key derived per receipt at `m/44'/148'/n'`, and the
//! derivation index recorded on the held token as the association.
//!
//! # Why it must match the card byte for byte
//!
//! The Keycard applet fork implements the same scheme on-card
//! (kenter-keycard's `Ed25519.slip10Derive`). Identical
//! derivation is what lets a card and a software wallet take over each other's
//! tokens. Diverging here would not fail loudly — it would produce a wallet that
//! derives keys which cannot open its own tokens' commitments, discovered only at
//! redemption, when the value is already at stake. Hence the SEP-0005 vectors in
//! the tests: they are the same ones the applet's `StellarM4Test` reproduces
//! on-card.
//!
//! # The scheme
//!
//! Ed25519 has no public (non-hardened) derivation — a parent public key cannot
//! produce child public keys — so SLIP-0010's ed25519 variant is **hardened
//! only**:
//!
//! ```text
//! master:  I = HMAC-SHA512("ed25519 seed", seed)
//! child:   I = HMAC-SHA512(chain_code, 0x00 || key || ser32(index | 0x80000000))
//!          key = I[0..32]   chain_code = I[32..64]
//! ```
//!
//! The resulting 32 bytes are an Ed25519 *seed* (RFC 8032 expands it with
//! SHA-512 and clamps), which is exactly what `StellarKeypair::from_raw_secret`
//! takes and what the card's `signHash` expands internally.
//!
//! A practical consequence: hardened-only means
//! **no watch-only receive**. Generating a receive commitment requires the seed.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, VaultError};

type HmacSha512 = Hmac<Sha512>;

/// The hardened-derivation bit. Every SLIP-0010 ed25519 index carries it.
pub const HARDENED: u32 = 0x8000_0000;

/// BIP-44 purpose.
pub const PURPOSE: u32 = 44;

/// SLIP-0044 coin type for Stellar (SEP-0005 uses `m/44'/148'/n'`).
pub const STELLAR_COIN_TYPE: u32 = 148;

/// SLIP-0010 bounds on the master seed (128–512 bits).
const MIN_SEED_LEN: usize = 16;
const MAX_SEED_LEN: usize = 64;

/// A SLIP-0010 extended key: the key material plus its chain code.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedKey {
    pub key: [u8; 32],
    pub chain_code: [u8; 32],
}

/// Master key from a seed — `HMAC-SHA512("ed25519 seed", seed)`.
///
/// `seed` is the BIP-39 seed (64 bytes as produced by the standard mnemonic →
/// PBKDF2 path, which is what the card is loaded with).
pub fn master_from_seed(seed: &[u8]) -> Result<ExtendedKey> {
    if seed.len() < MIN_SEED_LEN || seed.len() > MAX_SEED_LEN {
        return Err(VaultError::Corrupt(format!(
            "seed must be {MIN_SEED_LEN}..={MAX_SEED_LEN} bytes, got {}",
            seed.len()
        )));
    }
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").map_err(|_| VaultError::Crypto)?;
    mac.update(seed);
    Ok(split(mac.finalize().into_bytes().as_slice()))
}

/// One hardened child step. `index` is the *unhardened* number; the hardening
/// bit is applied here, because the ed25519 variant admits nothing else.
pub fn derive_hardened(parent: &ExtendedKey, index: u32) -> Result<ExtendedKey> {
    if index >= HARDENED {
        return Err(VaultError::Corrupt(format!(
            "index {index} already carries the hardened bit"
        )));
    }
    let mut mac = HmacSha512::new_from_slice(&parent.chain_code).map_err(|_| VaultError::Crypto)?;
    mac.update(&[0x00]);
    mac.update(&parent.key);
    mac.update(&(index | HARDENED).to_be_bytes());
    Ok(split(mac.finalize().into_bytes().as_slice()))
}

/// Walk a path of unhardened index numbers from `seed`, hardening each step.
pub fn derive_path(seed: &[u8], path: &[u32]) -> Result<ExtendedKey> {
    let mut node = master_from_seed(seed)?;
    for &index in path {
        node = derive_hardened(&node, index)?;
    }
    Ok(node)
}

/// The Ed25519 secret at `m/44'/148'/account'` — the SEP-0005 account path, and
/// the owner key for a given derivation index.
pub fn stellar_account_secret(seed: &[u8], account: u32) -> Result<[u8; 32]> {
    let node = derive_path(seed, &[PURPOSE, STELLAR_COIN_TYPE, account])?;
    Ok(node.key)
}

fn split(i: &[u8]) -> ExtendedKey {
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    ExtendedKey { key, chain_code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_crypto::keypair::StellarKeypair;

    /// BIP-39 seed for SEP-0005 test vector 1, mnemonic:
    /// "illness spike retreat truth genius clock brain pass fit cave bargain toe"
    /// (PBKDF2-HMAC-SHA512, salt "mnemonic", 2048 rounds, 64 bytes).
    const SEP5_V1_SEED: &str = "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497e\
                                e4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186";

    /// The published SEP-0005 vector-1 accounts. Vector 0 is the one the applet
    /// fork's `StellarM4Test` reproduces on-card, so matching it here is the
    /// card/software interoperability check.
    const SEP5_V1_ACCOUNTS: [&str; 5] = [
        "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
        "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX",
        "GAY5PRAHJ2HIYBYCLZXTHID6SPVELOOYH2LBPH3LD4RUMXUW3DOYTLXW",
        "GAOD5NRAEORFE34G5D4EOSKIJB6V4Z2FGPBCJNQI6MNICVITE6CSYIAE",
        "GBCUXLFLSL2JE3NWLHAWXQZN6SQC6577YMAU3M3BEMWKYPFWXBSRCWV4",
    ];

    fn seed() -> Vec<u8> {
        hex::decode(SEP5_V1_SEED).unwrap()
    }

    #[test]
    fn matches_sep0005_vector_1() {
        for (account, expected) in SEP5_V1_ACCOUNTS.iter().enumerate() {
            let secret = stellar_account_secret(&seed(), account as u32).unwrap();
            let kp = StellarKeypair::from_raw_secret(&secret);
            assert_eq!(
                &kp.stellar_address(),
                expected,
                "m/44'/148'/{account}' diverged from SEP-0005 — a card and this \
                 wallet would derive different owner keys"
            );
        }
    }

    /// Pins the master step on its own, so a regression in `master_from_seed`
    /// cannot be masked by a compensating bug in the child steps.
    #[test]
    fn master_key_is_the_documented_hmac() {
        let m = master_from_seed(&seed()).unwrap();
        let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").unwrap();
        mac.update(&seed());
        let i = mac.finalize().into_bytes();
        assert_eq!(&m.key[..], &i[..32]);
        assert_eq!(&m.chain_code[..], &i[32..]);
    }

    #[test]
    fn distinct_indices_give_distinct_keys() {
        let a = stellar_account_secret(&seed(), 0).unwrap();
        let b = stellar_account_secret(&seed(), 1).unwrap();
        let far = stellar_account_secret(&seed(), 4_000_000).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, far);
        assert_ne!(b, far);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            stellar_account_secret(&seed(), 7).unwrap(),
            stellar_account_secret(&seed(), 7).unwrap()
        );
    }

    /// A different seed must not produce the same owner keys - otherwise one
    /// user's wallet could open another's commitments.
    #[test]
    fn a_different_seed_gives_different_keys() {
        let mut other = seed();
        other[0] ^= 0xff;
        assert_ne!(
            stellar_account_secret(&seed(), 0).unwrap(),
            stellar_account_secret(&other, 0).unwrap()
        );
    }

    #[test]
    fn rejects_out_of_range_seeds() {
        assert!(master_from_seed(&[0u8; 15]).is_err());
        assert!(master_from_seed(&[0u8; 65]).is_err());
        assert!(master_from_seed(&[0u8; 16]).is_ok());
        assert!(master_from_seed(&[0u8; 64]).is_ok());
    }

    /// The hardening bit is applied internally; passing it in is a caller bug,
    /// not a silently-accepted double-hardening.
    #[test]
    fn rejects_a_preharded_index() {
        let m = master_from_seed(&seed()).unwrap();
        assert!(derive_hardened(&m, HARDENED).is_err());
        assert!(derive_hardened(&m, HARDENED | 5).is_err());
        assert!(derive_hardened(&m, 5).is_ok());
    }
}
