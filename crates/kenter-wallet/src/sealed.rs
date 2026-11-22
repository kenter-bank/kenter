//! Encryption for records on disk.
//!
//! Notes are bearer instruments: for a pure-bearer note the container bytes
//! *are* the money, since `redeem_by_chain` needs nothing else. A store of
//! plaintext JSON therefore puts every bearer note within reach of anyone who
//! can read the directory. This module is what stops that.
//!
//! ## Two keys, because sealing the contents is half the job
//!
//! A directory of files named `GD7MDB….json` tells a reader exactly which
//! notes are held, and every one of those ids resolves to an amount on a
//! public ledger. So [`StoreCredentials`] carries a second key that turns a
//! record id into an opaque filename, and the directory listing stops being a
//! statement about anyone's holdings.
//!
//! Names are a **keyed hash, not a cipher**: deterministic, so a lookup by id
//! is still a single `open()` rather than a scan, and one-way, so a listing
//! yields nothing without the key.
//!
//! ## Format
//!
//! `MAGIC(5) || nonce(24) || XSalsa20-Poly1305(key, nonce, plaintext)`
//!
//! The magic exists to tell formats apart, not for the cipher: [`is_sealed`]
//! is how a plaintext JSON file is recognised as such rather than mistaken
//! for a corrupt sealed record.

use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use hmac::{Hmac, Mac};
use kenter_vault::StoreCredentials;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};

/// File prefix of a sealed record. The trailing digit is the format version.
pub const MAGIC: &[u8; 5] = b"KNST1";

const NONCE_LEN: usize = 24;

/// Does this look like a sealed record, as opposed to plaintext?
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() > MAGIC.len() + NONCE_LEN && bytes.starts_with(MAGIC)
}

/// Encrypt a record for disk.
pub fn seal(creds: &StoreCredentials, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XSalsa20Poly1305::new(Key::from_slice(&*creds.aead));
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| WalletError::Store("sealing a record failed".into()))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a record read from disk.
///
/// Returns `Zeroizing` because the plaintext is a token record — for a bearer
/// note, the money.
pub fn unseal(creds: &StoreCredentials, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !is_sealed(bytes) {
        return Err(WalletError::Store(
            "not a sealed record (not written by this wallet, or damaged)".into(),
        ));
    }
    let nonce = &bytes[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ciphertext = &bytes[MAGIC.len() + NONCE_LEN..];

    let cipher = XSalsa20Poly1305::new(Key::from_slice(&*creds.aead));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        // One message for a wrong key and for tampering, because the AEAD
        // cannot tell them apart and guessing would be worse than saying so.
        .map_err(|_| {
            WalletError::Store(
                "a store record would not decrypt — wrong wallet, or the file is damaged".into(),
            )
        })?;
    Ok(Zeroizing::new(plaintext))
}

/// The on-disk filename for a record, revealing nothing about its id.
///
/// `kind` separates namespaces, so the same id under two record kinds does not
/// produce the same name and let a reader correlate them.
pub fn record_name(creds: &StoreCredentials, kind: &str, id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*creds.name)
        .expect("HMAC accepts a key of any length");
    mac.update(kind.as_bytes());
    mac.update(&[0x00]); // domain separator: kind and id cannot run together
    mac.update(id.as_bytes());
    // 128 bits of name is far beyond collision range for a wallet's worth of
    // records, and keeps paths short.
    hex::encode(&mac.finalize().into_bytes()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(seed: u8) -> StoreCredentials {
        StoreCredentials {
            aead: Zeroizing::new([seed; 32]),
            name: Zeroizing::new([seed.wrapping_add(1); 32]),
        }
    }

    const RECORD: &[u8] = br#"{"id":"GD7MDB","amount":25000000}"#;

    #[test]
    fn round_trips() {
        let c = creds(1);
        let sealed = seal(&c, RECORD).unwrap();
        assert_eq!(&*unseal(&c, &sealed).unwrap(), RECORD);
    }

    /// The point of the exercise: the record must not be legible in the file.
    #[test]
    fn the_record_is_not_readable_in_the_file() {
        let sealed = seal(&creds(1), RECORD).unwrap();
        let haystack = String::from_utf8_lossy(&sealed);
        assert!(!haystack.contains("GD7MDB"));
        assert!(!haystack.contains("25000000"));
    }

    #[test]
    fn another_wallet_cannot_open_it() {
        let sealed = seal(&creds(1), RECORD).unwrap();
        assert!(unseal(&creds(2), &sealed).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let mut sealed = seal(&creds(1), RECORD).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(unseal(&creds(1), &sealed).is_err());
    }

    /// Two writes of identical content must not produce identical files, or
    /// the directory leaks which records are duplicates of each other.
    #[test]
    fn the_same_record_seals_differently_each_time() {
        let c = creds(1);
        assert_ne!(seal(&c, RECORD).unwrap(), seal(&c, RECORD).unwrap());
    }

    /// Migration depends on telling an old plaintext file from a new sealed
    /// one. Mistaking plaintext for corruption would look like losing notes.
    #[test]
    fn plaintext_is_recognised_as_not_sealed() {
        assert!(!is_sealed(RECORD));
        assert!(!is_sealed(b""));
        assert!(!is_sealed(MAGIC));
        assert!(is_sealed(&seal(&creds(1), RECORD).unwrap()));
    }

    #[test]
    fn names_are_deterministic_so_a_lookup_needs_no_scan() {
        let c = creds(1);
        assert_eq!(
            record_name(&c, "token", "GD7MDB"),
            record_name(&c, "token", "GD7MDB")
        );
    }

    #[test]
    fn names_reveal_nothing_about_the_id() {
        let name = record_name(&creds(1), "token", "GD7MDBXXCLHR");
        assert!(!name.contains("GD7MDB"));
        assert!(!name.to_uppercase().contains("GD7MDB"));
        assert_eq!(name.len(), 32);
    }

    #[test]
    fn a_different_wallet_names_the_same_record_differently() {
        assert_ne!(
            record_name(&creds(1), "token", "GD7MDB"),
            record_name(&creds(2), "token", "GD7MDB")
        );
    }

    /// Without separating kinds, pending record 7 and token "7" would collide,
    /// and a reader could correlate records across namespaces.
    #[test]
    fn kinds_are_separated() {
        let c = creds(1);
        assert_ne!(record_name(&c, "token", "7"), record_name(&c, "pending", "7"));
        // And the separator stops "ab"+"c" colliding with "a"+"bc".
        assert_ne!(record_name(&c, "ab", "c"), record_name(&c, "a", "bc"));
    }
}
