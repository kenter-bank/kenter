//! Identify the card on the reader without spending a PIN attempt.
//!
//! Two questions, both answerable from status words alone:
//!
//! 1. **Does Secure Channel V2 open against real hardware?** It has only ever
//!    is easy to get subtly wrong against real hardware: a card may sign with
//!    a high `s`, which RustCrypto rejects unless the signature is
//!    normalised to low-S first, and that fails about half of all opens.
//!    Opening needs no PIN.
//!
//! 2. **Is this the Ed25519 fork or a stock Keycard?** `6D00` means the
//!    instruction does not exist, so the applet is stock; `6985` means it
//!    exists and wants a verified PIN, so it is the fork. Neither answer
//!    touches the PIN retry counter — only VERIFY PIN decrements that, and
//!    this never sends one.
//!
//! ```text
//! cargo run -p stellar-keycard --example probe_card
//! ```

use stellar_keycard::{SecureChannelV2, Transport, card_identity_pubkey};

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];

/// `(instruction, p1, p2, what it would tell us)`
const PROBES: &[(u8, u8, u8, &str)] = &[
    (0xF2, 0x00, 0x00, "GET STATUS (application)"),
    (
        0xC2,
        0x00,
        0x03,
        "EXPORT KEY P2=03  -> Ed25519 export, fork only",
    ),
    (0xC4, 0x00, 0x00, "EXPORT BIP85      -> fork only"),
    (0xB0, 0x00, 0x00, "NOTE STATUS       -> note store present"),
    (0xB8, 0x00, 0x00, "NOTE NEXT INDEX   -> owner-index counter"),
    (
        0xD2,
        0x08,
        0x00,
        "GENERATE MNEMONIC -> present on stock too",
    ),
];

fn describe(sw: u16) -> &'static str {
    match sw {
        0x9000 => "OK",
        0x6985 => "exists, needs a verified PIN",
        0x6D00 => "INSTRUCTION NOT SUPPORTED (stock applet)",
        0x6A86 => "wrong P1/P2 (so the instruction exists)",
        0x6A80 => "wrong data (so the instruction exists)",
        0x6E00 => "wrong class",
        _ => "?",
    }
}

fn main() -> Result<(), String> {
    let mut t = Transport::connect().map_err(|e| format!("reader/card: {e}"))?;
    let select = t.transmit(SELECT_AID).map_err(|e| e.to_string())?;
    let id = card_identity_pubkey(&select).map_err(|e| format!("identity cert: {e}"))?;
    println!("identity key : {}", hex::encode(&id));

    // The client authenticates the card by this key alone and does not check
    // the CA signature over it, so a card issued under a different CA than
    // the simulator's opens fine. That is also the limitation: a counterfeit
    // card presenting its own self-made identity would be accepted.
    let mut sc = match SecureChannelV2::open(&mut t, &id) {
        Ok(sc) => {
            println!("secure channel: OPEN (V2 works on metal)\n");
            sc
        }
        Err(e) => {
            println!("secure channel: FAILED - {e}");
            return Err("could not open a secure channel".into());
        }
    };

    for (ins, p1, p2, what) in PROBES {
        let sw = match sc.send(0x80, *ins, *p1, *p2, &[]) {
            Ok(data) => {
                println!("  {:02X} {:-48} OK, {} bytes", ins, what, data.len());
                continue;
            }
            Err(stellar_keycard::KeycardError::Apdu { sw }) => sw,
            Err(e) => {
                println!("  {:02X} {:-48} transport error: {e}", ins, what);
                continue;
            }
        };
        println!("  {:02X} {:-48} {:04X}  {}", ins, what, sw, describe(sw));
    }
    Ok(())
}
