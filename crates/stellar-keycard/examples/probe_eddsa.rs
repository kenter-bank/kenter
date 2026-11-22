//! Probe the card's on-card Ed25519 signing: is it Stellar-compatible?
//! Dumps the raw EdDSA SIGN response and tries to verify with ed25519-dalek.
//!
//! Run: cargo run -p stellar-keycard --example probe_eddsa   (initialized card)

use sha2::{Digest, Sha256};

use stellar_keycard::{
    DEFAULT_PAIRING_PASSWORD, SecureChannel, Transport, pair, pairing_secret_from_password,
};

const DEV_PIN: &str = "123456";

fn main() {
    let mut t = match Transport::connect() {
        Ok(t) => t,
        Err(e) => return println!("connect failed: {e}"),
    };
    let info = match t.select_keycard() {
        Ok(i) => i,
        Err(e) => return println!("SELECT failed: {e}"),
    };
    if !info.initialized {
        return println!("card not initialized — run init_and_open first.");
    }
    let card_pub = info.secure_channel_public_key.clone();
    let secret = pairing_secret_from_password(DEFAULT_PAIRING_PASSWORD);
    let pairing = match pair(&mut t, &secret) {
        Ok(p) => p,
        Err(e) => return println!("PAIR failed: {e}"),
    };
    let mut sc = match SecureChannel::open(&mut t, &card_pub, &pairing) {
        Ok(s) => s,
        Err(e) => return println!("OPEN failed: {e}"),
    };
    if let Err(e) = sc.verify_pin(DEV_PIN) {
        return println!("VERIFY PIN failed: {e}");
    }
    if let Err(e) = sc.generate_key() {
        return println!("GENERATE KEY failed: {e}");
    }

    let hash: [u8; 32] = Sha256::digest(b"kenter stellar ed25519 test").into();
    let resp = match sc.sign_eddsa(&hash) {
        Ok(r) => r,
        Err(e) => return println!("EdDSA sign failed: {e}"),
    };

    println!("EdDSA response: {} bytes", resp.len());
    println!("  hex: {}", hex::encode(&resp));

    // Attempt to parse the signature template A0 { 80 pubkey, <sig> } and verify.
    // Ed25519 pubkey = 32 bytes; signature = 64 bytes.
    if let Some((pubkey, sig)) = parse_eddsa(&resp) {
        println!(
            "  parsed pubkey ({}b): {}",
            pubkey.len(),
            hex::encode(&pubkey)
        );
        println!("  parsed sig    ({}b): {}", sig.len(), hex::encode(&sig));
        if pubkey.len() == 32 && sig.len() == 64 {
            let verified = (|| {
                let vk =
                    ed25519_dalek::VerifyingKey::from_bytes(pubkey.as_slice().try_into().ok()?)
                        .ok()?;
                let signature = ed25519_dalek::Signature::from_slice(&sig).ok()?;
                use ed25519_dalek::Verifier;
                vk.verify(&hash, &signature).ok()
            })()
            .is_some();
            println!(
                "\nStellar-compatible (ed25519-dalek verify over the 32-byte hash): {}",
                if verified { "YES ✓" } else { "NO ✗" }
            );
        }
    } else {
        println!("  (could not parse a 0xA0 template — see raw hex above)");
    }
}

/// Best-effort TLV walk: pull the 0x80 pubkey and the largest primitive that
/// looks like a 64-byte signature out of the response.
fn parse_eddsa(resp: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Enter A0 template if present.
    let body = if resp.first() == Some(&0xA0) {
        let (len, hdr) = ber_len(&resp[1..])?;
        resp.get(1 + hdr..1 + hdr + len)?
    } else {
        resp
    };
    let mut pubkey = None;
    let mut sig = None;
    let mut i = 0;
    while i + 2 <= body.len() {
        let tag = body[i];
        let (len, hdr) = ber_len(&body[i + 1..])?;
        let start = i + 1 + hdr;
        let val = body.get(start..start + len)?;
        if tag == 0x80 && len == 32 {
            pubkey = Some(val.to_vec());
        } else if len == 64 {
            sig = Some(val.to_vec());
        }
        i = start + len;
    }
    Some((pubkey?, sig?))
}

fn ber_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 3 || data.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}
