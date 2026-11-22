//! End-to-end Stellar flow against the jcardsim `SimServer` (V2 secure channel):
//! reset → SELECT → OPEN (V2) → INIT → VERIFY PIN → LOAD KEY (SEP-0005 seed) →
//! EXPORT KEY (G-address) → SIGN (Ed25519) → verify with ed25519-dalek.
//!
//! Prereq: the applet repo's `gradlew simServer` running on 127.0.0.1:21345.
//! Run: cargo run -p stellar-keycard --example stellar_sim

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use stellar_keycard::transport::CardTransport;
use stellar_keycard::{DEFAULT_SIM_ADDR, SecureChannelV2, SimTransport, card_identity_pubkey};

const MNEMONIC: &str = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
const EXPECTED_G: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
// m/44'/148'/0' — SLIP-0010, all hardened.
const PATH: [u8; 12] = [
    0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x00, 0x94, 0x80, 0x00, 0x00, 0x00,
];
const PIN: &str = "000000";
const PUK: &str = "000000000000";

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];

fn main() {
    if let Err(e) = run() {
        println!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut t = SimTransport::connect(DEFAULT_SIM_ADDR)
        .map_err(|e| format!("connect (is simServer running?): {e}"))?;
    t.reset().map_err(|e| format!("reset: {e}"))?;

    let select = t.transmit(SELECT_AID).map_err(|e| e.to_string())?;
    let id_pub = card_identity_pubkey(&select).map_err(|e| format!("SELECT cert: {e}"))?;
    println!(
        "SELECT ok — card identity pubkey {}",
        &hex::encode(&id_pub)[..16]
    );

    let mut sc = SecureChannelV2::open(&mut t, &id_pub).map_err(|e| format!("OPEN v2: {e}"))?;
    println!("✓ secure channel V2 open + card authenticated");

    // INIT (PIN || PUK). Best-effort: on an already-initialized card it errors; we
    // continue and rely on VERIFY PIN.
    let mut init_data = PIN.as_bytes().to_vec();
    init_data.extend_from_slice(PUK.as_bytes());
    match sc.send(0x80, 0xFE, 0x00, 0x00, &init_data) {
        Ok(_) => println!("✓ INIT (PIN/PUK set)"),
        Err(e) => println!("  INIT skipped (already initialized?): {e}"),
    }

    sc.send(0x80, 0x20, 0x00, 0x00, PIN.as_bytes())
        .map_err(|e| format!("VERIFY PIN: {e}"))?;
    println!("✓ PIN verified");

    let seed = bip39_seed(MNEMONIC, "");
    sc.send(0x80, 0xD0, 0x03, 0x00, &seed)
        .map_err(|e| format!("LOAD KEY (seed): {e}"))?;
    println!("✓ SEP-0005 seed loaded (SLIP-0010 master)");

    // EXPORT KEY (Ed25519 pubkey) → strkey → G-address.
    let exp = sc
        .send(0x80, 0xC2, 0x00, 0x03, &PATH)
        .map_err(|e| format!("EXPORT KEY: {e}"))?;
    let pubkey = tlv_value(&exp, 0x80).ok_or("export: no pubkey TLV")?;
    if pubkey.len() != 32 {
        return Err(format!("export pubkey len {} != 32", pubkey.len()));
    }
    let g = stellar_strkey::ed25519::PublicKey(pubkey.clone().try_into().unwrap()).to_string();
    println!("  G-address: {g}");
    if g != EXPECTED_G {
        return Err(format!(
            "G-address mismatch:\n  got {g}\n  exp {EXPECTED_G}"
        ));
    }
    println!("✓ G-address matches SEP-0005 test vector 1");

    // SIGN a 32-byte hash, verify with ed25519-dalek over the same hash.
    let hash: [u8; 32] = sha2::Sha256::digest(b"kenter on-card stellar sign").into();
    let mut sign_data = hash.to_vec();
    sign_data.extend_from_slice(&PATH);
    let sig_resp = sc
        .send(0x80, 0xC0, 0x01, 0x01, &sign_data)
        .map_err(|e| format!("SIGN: {e}"))?;
    let sig_pub = tlv_value(&sig_resp, 0x80).ok_or("sign: no pubkey TLV")?;
    let sig = tlv_value(&sig_resp, 0x88).ok_or("sign: no signature TLV")?;
    if sig_pub != pubkey {
        return Err("SIGN pubkey != EXPORT pubkey".into());
    }
    let vk =
        VerifyingKey::from_bytes(&pubkey.clone().try_into().unwrap()).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&sig).map_err(|e| e.to_string())?;
    vk.verify(&hash, &signature)
        .map_err(|_| "ed25519-dalek rejected the card signature".to_string())?;
    println!("✓ Ed25519 signature VALID (verified off-card over the tx hash)");

    println!("\nFULL STELLAR FLOW WORKS on the simulator: V2 channel → SLIP-0010 → sign.");
    Ok(())
}

use sha2::Digest;

/// BIP-39 seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048) → 64 B
/// (single output block, since dkLen == hLen == 64).
fn bip39_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;
    let salt = format!("mnemonic{passphrase}");
    let mut u: [u8; 64] = {
        let mut m = <HmacSha512 as Mac>::new_from_slice(mnemonic.as_bytes()).unwrap();
        m.update(salt.as_bytes());
        m.update(&1u32.to_be_bytes());
        m.finalize().into_bytes().into()
    };
    let mut out = u;
    for _ in 1..2048 {
        let mut m = <HmacSha512 as Mac>::new_from_slice(mnemonic.as_bytes()).unwrap();
        m.update(&u);
        let next: [u8; 64] = m.finalize().into_bytes().into();
        u = next;
        for (o, b) in out.iter_mut().zip(next.iter()) {
            *o ^= b;
        }
    }
    out
}

/// Find the first primitive TLV with `tag` (1-byte tag, 1-byte length), entering
/// an outer constructed template (0xA0/0xA1, possibly BER long-form length).
fn tlv_value(resp: &[u8], tag: u8) -> Option<Vec<u8>> {
    let body = match resp.first()? {
        // Walk the remaining bytes after the template header (tolerant of the
        // applet's off-by-one outer length).
        0xA0 | 0xA1 => {
            let (_len, hdr) = ber_len(&resp[1..])?;
            resp.get(1 + hdr..)?
        }
        _ => resp,
    };
    let mut i = 0;
    while i + 2 <= body.len() {
        let t = body[i];
        let (len, hdr) = ber_len(&body[i + 1..])?;
        let start = i + 1 + hdr;
        let val = body.get(start..start + len)?;
        if t == tag {
            return Some(val.to_vec());
        }
        i = start + len;
    }
    None
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
