//! Dump the identity certificate the card on the reader presents.
//!
//! `card_identity_pubkey` takes the first 33 bytes of the `0x8A` TLV and
//! ignores whatever follows, so no CA check is made on the certificate.
//! Deciding what to verify needs the bytes: how long
//! the certificate is, whether there is a signature after the key at
//! all, and what shape it is.
//!
//! Non-destructive and PIN-free — SELECT only, no VERIFY PIN, so the
//! retry counter is untouched.
//!
//! ```text
//! cargo run -p stellar-keycard --example probe_cert
//! ```

use stellar_keycard::{Transport, card_identity_pubkey};

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];

/// Minimal BER length reader: returns `(value_len, header_len)`.
fn ber_len(b: &[u8]) -> Option<(usize, usize)> {
    match b.first()? {
        n if *n < 0x80 => Some((*n as usize, 1)),
        0x81 => Some((*b.get(1)? as usize, 2)),
        0x82 => Some((((*b.get(1)? as usize) << 8) | *b.get(2)? as usize, 3)),
        _ => None,
    }
}

fn main() -> Result<(), String> {
    let mut t = Transport::connect().map_err(|e| format!("no reader/card: {e}"))?;
    let resp = t.transmit(SELECT_AID).map_err(|e| e.to_string())?;

    println!("SELECT response: {} bytes", resp.len());
    println!("{}\n", hex::encode(&resp));

    // Walk the top level and print every TLV, so the certificate is seen
    // in context rather than on its own.
    let body = if resp.first() == Some(&0xA4) {
        let (_len, hdr) = ber_len(&resp[1..]).ok_or("bad A4 length")?;
        &resp[1 + hdr..]
    } else {
        &resp[..]
    };

    let mut i = 0;
    while i + 2 <= body.len() {
        let tag = body[i];
        let Some((len, hdr)) = ber_len(&body[i + 1..]) else {
            println!("(stopped: bad length at offset {i})");
            break;
        };
        let start = i + 1 + hdr;
        let Some(val) = body.get(start..start + len) else {
            println!("(stopped: TLV {tag:#04x} runs past the end)");
            break;
        };
        println!("tag {tag:#04x}  len {len:>3}  {}", hex::encode(val));
        if tag == 0x8A {
            println!("  identity key ({} bytes): {}", 33.min(val.len()), hex::encode(&val[..33.min(val.len())]));
            let rest = &val[33.min(val.len())..];
            if rest.is_empty() {
                println!("  ** no bytes after the key: this certificate is self-asserted **");
            } else {
                println!("  signature? ({} bytes): {}", rest.len(), hex::encode(rest));
                println!("  first byte {:#04x} ({})", rest[0],
                    if rest[0] == 0x30 { "looks like DER SEQUENCE" } else { "not DER" });
            }
        }
        i = start + len;
    }

    let id = card_identity_pubkey(&resp).map_err(|e| e.to_string())?;
    println!("\nparsed identity: {}", hex::encode(&id));

    // If the 65 bytes are a recoverable ECDSA signature (r||s||v), the
    // CA public key can be recovered from them -- which is how a card
    // certificate is checked without shipping the CA key on the card.
    // Try the obvious candidate message and report what recovers, since
    // that decides what a real verifier has to hash.
    if let Some(cert) = cert_bytes(body) {
        if cert.len() == 98 {
            let sig_bytes = &cert[33..];
            let v = sig_bytes[64];
            println!("\nrecovery attempt: trailing byte = {v}");
            use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
            use sha2::{Digest, Sha256};

            let sig = match Signature::from_slice(&sig_bytes[..64]) {
                Ok(s) => s,
                Err(e) => {
                    println!("  r||s did not parse: {e}");
                    return Ok(());
                }
            };
            // JavaCard ECDSA does not normalise `s`, and RustCrypto
            // enforces low-S -- the same thing that made the transcript
            // check fail on a coin flip. Try both forms.
            let norm = sig.normalize_s();
            let digest: [u8; 32] = Sha256::digest(&cert[..33]).into();
            println!("  message = sha256(id_pubkey_33) = {}", hex::encode(digest));

            for (label, s) in [("raw", &sig), ("normalised", &norm)] {
                for raw in 0u8..4 {
                    let Some(rid) = RecoveryId::from_byte(raw) else { continue };
                    if let Ok(vk) = VerifyingKey::recover_from_prehash(&digest, s, rid) {
                        println!(
                            "  {label} v={raw}: CA = {}",
                            hex::encode(vk.to_sec1_point(true).as_bytes())
                        );
                    }
                }
            }

            // Does it chain to *this repo's* test CA? SimServer
            // personalises the simulator with a fixed private key; if a
            // real card verifies against the same one, these cards were
            // personalised by this project's tooling rather than by
            // Status, and the whole chain is already ours to pin.
            const TEST_CA_PRIV: &str =
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
            let priv_bytes = hex::decode(TEST_CA_PRIV).unwrap();
            if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&priv_bytes) {
                let ca = *sk.verifying_key();
                println!(
                    "\n  repo test CA pubkey: {}",
                    hex::encode(ca.to_sec1_point(true).as_bytes())
                );
                use k256::ecdsa::signature::hazmat::PrehashVerifier;
                for (label, s) in [("raw", &sig), ("normalised", &norm)] {
                    match ca.verify_prehash(&digest, s) {
                        Ok(()) => println!("  verifies against repo test CA ({label}) ** YES **"),
                        Err(_) => println!("  does not verify against repo test CA ({label})"),
                    }
                }
            }
        }
    }
    Ok(())
}

/// The raw `0x8A` value, re-walked so the recovery block can see it.
fn cert_bytes(body: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 2 <= body.len() {
        let tag = body[i];
        let (len, hdr) = ber_len(&body[i + 1..])?;
        let start = i + 1 + hdr;
        let val = body.get(start..start + len)?;
        if tag == 0x8A {
            return Some(val.to_vec());
        }
        i = start + len;
    }
    None
}
