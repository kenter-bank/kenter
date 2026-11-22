//! Record what is on the card, changing nothing.
//!
//! Run before any destructive pass, so whatever the test suite left behind is
//! written down rather than discovered missing afterwards.
//!
//! **Only the main PIN is ever sent.** The duress PIN verifies with `9000`
//! and switches the card to a decoy tree — empty note list, unrelated
//! Ed25519 and BIP85 keys, its own index counter. Sent by mistake it does not
//! look like an error, it looks like the notes are gone and the keys are
//! wrong, so the PIN here is a constant and there is no fallback.
//!
//! Keys go through the library's own API rather than raw APDUs, so this
//! doubles as an on-metal exercise of `DerivingVault` and `Bip85`. The note
//! store has no client yet, so it is read with raw APDUs
//! (the note-store APDUs defined by the kenter-keycard applet).
//!
//! ```text
//! cargo run -p stellar-keycard --example card_inventory
//! ```

use kenter_vault::{Bip85, DerivingVault};
use stellar_keycard::{
    CardTransport, SecureChannelV2, StellarKeycard, Transport, card_identity_pubkey,
};

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];
/// The PIN this sends, overridable because **a wrong one costs an attempt
/// out of five** and a card that has been through the ceremony has
/// whatever PIN its owner chose:
///
/// ```text
/// KENTER_CARD_PIN=123456 cargo run -p stellar-keycard --example card_inventory
/// ```
///
/// A hardcoded PIN would make an *inventory* command — the thing you reach
/// for to find out what a card is — spend one of the five tries you may need
/// to recover it whenever the card's PIN differs. That is exactly backwards.
fn card_pin() -> Vec<u8> {
    std::env::var("KENTER_CARD_PIN")
        .unwrap_or_else(|_| "000000".into())
        .into_bytes()
}

const INS_VERIFY_PIN: u8 = 0x20;
const INS_NOTE_STATUS: u8 = 0xB0;
const INS_NOTE_LIST: u8 = 0xB1;
const INS_NOTE_ADVANCE_INDEX: u8 = 0xB9;

fn main() -> Result<(), String> {
    let pin = card_pin();
    // ---- note store, raw APDUs ---------------------------------------
    {
        let mut t = Transport::connect().map_err(|e| format!("reader/card: {e}"))?;
        let select = CardTransport::transmit(&mut t, SELECT_AID).map_err(|e| e.to_string())?;
        let info = stellar_keycard::transport::parse_application_info(&select[..select.len() - 2])
            .map_err(|e| e.to_string())?;

        println!("== card ==");
        println!(
            "  applet      : {}.{}",
            info.app_version.0, info.app_version.1
        );
        println!("  initialized : {}", info.initialized);
        println!("  seeded      : {}", info.key_initialized);
        println!("  PIN tries   : {:?}", info.pin_retries);
        println!(
            "  identity    : {}",
            hex::encode(&info.secure_channel_public_key)
        );

        let id = card_identity_pubkey(&select).map_err(|e| e.to_string())?;
        let mut sc = SecureChannelV2::open(&mut t, &id).map_err(|e| format!("channel: {e}"))?;
        sc.send(0x80, INS_VERIFY_PIN, 0x00, 0x00, &pin)
            .map_err(|e| format!("VERIFY PIN refused: {e} - stopping rather than guessing"))?;
        println!("\n  VERIFY PIN: accepted (main tree)");

        println!("\n== note store ==");
        match sc.send(0x80, INS_NOTE_STATUS, 0x00, 0x00, &[]) {
            Ok(d) if d.len() == 8 => {
                let be16 = |i: usize| u16::from_be_bytes([d[i], d[i + 1]]);
                let (bt, bf, et, ef) = (be16(1), be16(3), d[5], d[6]);
                println!("  version      : {}", d[0]);
                println!("  blocks       : {bf} of {bt} free ({} used)", bt - bf);
                println!("  entries      : {ef} of {et} free ({} stored)", et - ef);
                println!("  meta length  : {}", d[7]);
            }
            Ok(d) => println!("  STATUS unexpected shape: {}", hex::encode(&d)),
            Err(e) => println!("  STATUS error: {e}"),
        }

        // [entry:1 status:1 len:2 tag:32 meta:16]... then next index, or FF.
        match sc.send(0x80, INS_NOTE_LIST, 0x00, 0x00, &[]) {
            Ok(d) => {
                let rec = 1 + 1 + 2 + 32 + 16;
                let mut off = 0;
                while off + rec <= d.len() {
                    let e = &d[off..off + rec];
                    println!(
                        "  entry {:<3} status {}  {} bytes  tag {}",
                        e[0],
                        e[1],
                        u16::from_be_bytes([e[2], e[3]]),
                        hex::encode(&e[4..36])
                    );
                    off += rec;
                }
                match d.last() {
                    Some(0xFF) => println!("  (no further entries)"),
                    Some(n) => println!("  (continues at entry {n})"),
                    None => println!("  (empty list)"),
                }
            }
            Err(e) => println!("  LIST error: {e}"),
        }

        // ADVANCE INDEX with 0, *not* NEXT INDEX. B8 hands an index out and
        // increments; it is an allocation, not an accessor, and calling it to
        // look at the counter spends one every time - this example did that
        // twice before the difference showed up (15, then 16). B9 with a
        // value of 0 raises the counter to at least 0, which is to say it
        // reads it. The same trap is waiting for anything that wants to
        // *display* the index rather than use one.
        match sc.send(
            0x80,
            INS_NOTE_ADVANCE_INDEX,
            0x00,
            0x00,
            &0u32.to_be_bytes(),
        ) {
            Ok(d) if d.len() == 4 => println!(
                "  next owner index : {}  <- read, not consumed; survives FACTORY RESET (D7)",
                u32::from_be_bytes([d[0], d[1], d[2], d[3]])
            ),
            Ok(d) => println!("  ADVANCE INDEX unexpected: {}", hex::encode(&d)),
            Err(e) => println!("  ADVANCE INDEX error: {e}"),
        }
    }

    // ---- keys, through the real client API ---------------------------
    let t = Transport::connect().map_err(|e| format!("reconnect: {e}"))?;
    let mut card = StellarKeycard::connect(t).map_err(|e| e.to_string())?;

    println!("\n== owner keys (DerivingVault, m/44'/148'/n') ==");
    for n in [0u32, 1, 7] {
        match card.derive_public(n, &pin) {
            Ok(pk) => println!("  index {n:<4} {}", hex::encode(pk)),
            Err(e) => println!("  index {n:<4} ERROR {e}"),
        }
    }

    println!("\n== BIP85 vault-bound children ==");
    for idx in [0u32, 1] {
        let path = [
            0x8000_0000 | 83_696_968u32,
            0x8000_0000 | 128_169,
            0x8000_0000 | 32,
            0x8000_0000 | idx,
        ];
        match card.bip85_entropy(&path, 32, &pin) {
            Ok(k) => println!(
                "  child {idx} ({}) {}",
                if idx == 0 { "store " } else { "backup" },
                hex::encode(&k[..])
            ),
            Err(e) => println!("  child {idx} ERROR {e}"),
        }
    }
    Ok(())
}
