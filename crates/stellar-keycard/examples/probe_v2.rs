//! Empirical probe: does this card speak Keycard **Secure Channel v2**?
//!
//! V2 (Status keycard applet, master) OPEN SECURE CHANNEL:
//!   → 80 10 00 00 <LC> [ hkdf_salt(32) || client_eph_pub(65, 0x04||X||Y) ] 00
//!   ← card_eph_pub(65) || ECDSA-SHA256(transcript)   SW=9000
//!
//! Then both sides: shared = ECDH(eph, card_pub).X ; OKM = HKDF-SHA256(salt, shared,
//! info="sc_v2_ccm") ; keyH2C=OKM[0..16], keyC2H=OKM[16..32] (AES-128-CCM).
//!
//! If the card returns 65 bytes + a DER ECDSA signature with SW=9000, and the
//! ECDH+HKDF runs, it speaks V2 and we build the rest on that. Any other shape /
//! error means it is not V2 and we pivot.
//!
//! Run: cargo run -p stellar-keycard --example probe_v2   (card on the reader)

use hkdf::Hkdf;
use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::Generate;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{PublicKey, SecretKey};
use sha2::Sha256;

use stellar_keycard::{Transport, apdu};

const INS_OPEN_SECURE_CHANNEL: u8 = 0x10;
const CLA_GP: u8 = 0x80;
const SC_V2_INFO: &[u8] = b"sc_v2_ccm";

fn main() {
    let mut t = match Transport::connect() {
        Ok(t) => t,
        Err(e) => {
            println!("connect failed: {e} (is a card on the reader?)");
            return;
        }
    };

    match t.select_keycard() {
        Ok(info) => println!(
            "SELECT ok — initialized={}, SC pubkey={}…",
            info.initialized,
            &hex::encode(&info.secure_channel_public_key)
                [..16.min(info.secure_channel_public_key.len() * 2)]
        ),
        Err(e) => {
            println!("SELECT failed: {e}");
            return;
        }
    }

    // Client ephemeral secp256k1 keypair + random HKDF salt.
    let eph = SecretKey::generate();
    let eph_pub = eph.public_key().to_sec1_point(false); // 0x04||X||Y, 65 bytes
    let salt: [u8; 32] = rand::random();

    // Build OPEN SECURE CHANNEL (V2): data = salt(32) || client_pub(65).
    let mut data = Vec::with_capacity(97);
    data.extend_from_slice(&salt);
    data.extend_from_slice(eph_pub.as_bytes());
    let mut osc = vec![
        CLA_GP,
        INS_OPEN_SECURE_CHANNEL,
        0x00,
        0x00,
        data.len() as u8,
    ];
    osc.extend_from_slice(&data);
    osc.push(0x00); // Le

    println!("\n→ OPEN SECURE CHANNEL (v2): {} data bytes", data.len());
    let resp = match t.transmit(&osc) {
        Ok(r) => r,
        Err(e) => {
            println!("transmit failed: {e}");
            return;
        }
    };
    let sw = apdu::parse_sw(&resp);
    let body = apdu::response_data(&resp);
    println!("← SW={sw:04X}, {} response bytes", body.len());

    if sw != 0x9000 {
        println!("\nNOT V2 (or applet error). The card rejected the V2 open-channel");
        println!("format. Raw response: {}", hex::encode(&resp));
        println!("Next: try V1 / inspect Cryptnox-specific protocol.");
        return;
    }
    if body.len() < 66 || body[0] != 0x04 {
        println!("\nUnexpected response shape (expected 65-byte pubkey + sig).");
        println!("Raw: {}", hex::encode(body));
        return;
    }

    let card_pub_bytes = &body[..65];
    let sig = &body[65..];
    println!(
        "  card ephemeral pub : {}…",
        &hex::encode(card_pub_bytes)[..16]
    );
    println!("  transcript sig     : {} bytes (DER ECDSA)", sig.len());

    // Complete the client half: ECDH → HKDF-SHA256 → session keys.
    let card_pub = match PublicKey::from_sec1_bytes(card_pub_bytes) {
        Ok(p) => p,
        Err(e) => {
            println!("card pubkey parse failed: {e}");
            return;
        }
    };
    let sk = eph.to_nonzero_scalar();
    let shared = diffie_hellman(&sk, card_pub.as_affine());
    let shared_x = shared.raw_secret_bytes();

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_x);
    let mut okm = [0u8; 32];
    hk.expand(SC_V2_INFO, &mut okm).expect("hkdf expand");

    println!("  ECDH shared X      : {}…", &hex::encode(shared_x)[..16]);
    println!("  keyH2C (AES-128)   : {}", hex::encode(&okm[..16]));
    println!("  keyC2H (AES-128)   : {}", hex::encode(&okm[16..]));

    println!("\n✓ V2 CONFIRMED — card accepted the v2 OPEN SECURE CHANNEL format,");
    println!("  returned card_pub + transcript signature, and ECDH+HKDF derived");
    println!("  session keys. Next: AES-128-CCM wrapping + INIT + secp256k1 SIGN.");
}
