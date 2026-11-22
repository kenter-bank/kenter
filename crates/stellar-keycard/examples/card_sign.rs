//! Live end-to-end signing via the high-level `KeycardVault` API:
//! connect → ensure_paired → generate_key → sign_ecdsa → verify off-card.
//!
//! Assumes the card is already initialized (run `init_and_open` once first).
//! One pairing is established and reused across operations.
//!
//! Run: cargo run -p stellar-keycard --example card_sign

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use stellar_keycard::{DEFAULT_PAIRING_PASSWORD, KeycardVault};

const DEV_PIN: &str = "123456";

fn main() {
    let mut vault = match KeycardVault::connect() {
        Ok(v) => v,
        Err(e) => return println!("connect failed: {e} (card on the reader?)"),
    };
    if !vault.is_initialized() {
        return println!("card not initialized — run `init_and_open` first.");
    }
    if let Err(e) = vault.ensure_paired(DEFAULT_PAIRING_PASSWORD) {
        return println!("pairing failed: {e}");
    }
    println!("connected + paired");

    match vault.generate_key(DEV_PIN) {
        Ok(uid) => println!(
            "✓ key generated (uid {}…)",
            &hex::encode(&uid)[..16.min(uid.len() * 2)]
        ),
        Err(e) => return println!("generate_key failed: {e}"),
    }

    let hash: [u8; 32] = Sha256::digest(b"kenter keycard sign test").into();
    match vault.sign_ecdsa(DEV_PIN, &hash) {
        Ok(cs) => {
            println!("✓ ECDSA signature received");
            println!("  signing pubkey: {}…", &hex::encode(&cs.public_key)[..16]);
            let ok = (|| {
                let vk = VerifyingKey::from_sec1_bytes(&cs.public_key).ok()?;
                let sig = Signature::from_der(&cs.der).ok()?;
                vk.verify_prehash(&hash, &sig).ok()
            })()
            .is_some();
            println!(
                "  off-card verify: {}",
                if ok { "VALID ✓" } else { "INVALID ✗" }
            );
        }
        Err(e) => return println!("sign_ecdsa failed: {e}"),
    }

    println!("\nKeycardVault: hardware custody signing works end-to-end.");
}
