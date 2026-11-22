//! Does a new secure channel forget the previous channel's verified PIN?
//!
//! An applet that keeps the PIN validated across `OPEN SECURE CHANNEL` lets
//! whoever opens a fresh channel after the holder has entered their PIN get
//! a fully authorised session without it. The kenter-keycard applet calls
//! `resetAuthentication()` on channel open to prevent this, and tests it in
//! the simulator. This asks the card on the reader, which only behaves that
//! way if its applet was installed from a build that does so.
//!
//! 1. Channel A: VERIFY PIN (the one PIN attempt this spends, and only if
//!    the PIN is wrong).
//! 2. Channel B, opened fresh on the same connection: NOTE NEXT INDEX, which
//!    needs a verified PIN. `6985` means B starts unauthenticated -- fixed.
//!    `9000` means the PIN carried over -- the card's applet predates the fix.
//!
//! `KENTER_CARD_PIN` is the card's PIN (default `000000`, the applet
//! suite's value). A blank card is initialized first with that PIN, PUK
//! `012345678901` and duress `098765`; an initialized one is left as it is.
//!
//! ```text
//! KENTER_CARD_PIN=123456 cargo run -p stellar-keycard --example probe_pin_carryover
//! ```

use stellar_keycard::{
    card_identity_pubkey, DuressPin, InitParams, KeycardError, SecureChannelV2, StellarKeycard,
    Transport,
};

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];
const INS_VERIFY_PIN: u8 = 0x20;
const INS_NOTE_NEXT_INDEX: u8 = 0xB8;

fn sw_of(r: Result<Vec<u8>, KeycardError>) -> Result<u16, String> {
    match r {
        Ok(_) => Ok(0x9000),
        Err(KeycardError::Apdu { sw }) => Ok(sw),
        Err(e) => Err(e.to_string()),
    }
}

fn main() -> Result<(), String> {
    let pin = std::env::var("KENTER_CARD_PIN").unwrap_or_else(|_| "000000".into());
    {
        let t = Transport::connect().map_err(|e| format!("reader/card: {e}"))?;
        let mut card = StellarKeycard::connect(t).map_err(|e| e.to_string())?;
        if !card.application_info().map_err(|e| e.to_string())?.initialized {
            card.init(&InitParams::new(pin.as_bytes(), b"012345678901", DuressPin::Chosen(b"098765")))
                .map_err(|e| format!("INIT: {e}"))?;
            println!("blank card initialized with the given PIN");
        }
    }
    let mut t = Transport::connect().map_err(|e| format!("reader/card: {e}"))?;
    let select = t.transmit(SELECT_AID).map_err(|e| e.to_string())?;
    let id = card_identity_pubkey(&select).map_err(|e| format!("identity: {e}"))?;

    {
        let mut a = SecureChannelV2::open(&mut t, &id).map_err(|e| e.to_string())?;
        let sw = sw_of(a.send(0x80, INS_VERIFY_PIN, 0, 0, pin.as_bytes()))?;
        if sw != 0x9000 {
            return Err(format!("VERIFY PIN on channel A answered {sw:04X}; nothing proved"));
        }
        println!("channel A: PIN verified");
    }

    let mut b = SecureChannelV2::open(&mut t, &id).map_err(|e| e.to_string())?;
    let sw = sw_of(b.send(0x80, INS_NOTE_NEXT_INDEX, 0, 0, &[]))?;
    match sw {
        0x6985 => println!("channel B: {sw:04X} - a new channel starts without the PIN (PIN reset on channel open)"),
        0x9000 => println!("channel B: {sw:04X} - the PIN CARRIED OVER (this card's applet does not reset the PIN on channel open)"),
        other => println!("channel B: {other:04X} - unexpected; inconclusive"),
    }
    Ok(())
}
