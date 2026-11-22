//! Wipe the card on the reader back to blank.
//!
//! ```text
//! cargo run -p stellar-keycard --example card_wipe            # tries 000000
//! KENTER_CARD_PIN=123456 cargo run -p stellar-keycard --example card_wipe
//! ```
//!
//! `FACTORY RESET` needs one of three things (`factoryResetAllowed`): a card
//! that was never `INIT`ed, a verified PIN, or a PIN *and* PUK both
//! exhausted. So an initialized card cannot be wiped without its PIN — which
//! is the point of the PIN, and worth remembering before provisioning a card
//! with one nobody wrote down.
//!
//! **A wrong PIN costs an attempt.** This sends at most one, and says how
//! many are left rather than trying again, because the only thing a second
//! guess buys is being one closer to needing the PUK.

use stellar_keycard::{StellarKeycard, Transport};

fn main() -> Result<(), String> {
    let pin = std::env::var("KENTER_CARD_PIN").unwrap_or_else(|_| "000000".into());

    let t = Transport::connect().map_err(|e| format!("no card on the reader: {e}"))?;
    let mut card = StellarKeycard::connect(t).map_err(|e| e.to_string())?;

    let before = card.application_info().map_err(|e| e.to_string())?;
    println!(
        "before : initialized={} seeded={} pin_tries={:?}",
        before.initialized, before.key_initialized, before.pin_retries
    );

    if !before.initialized {
        println!("already blank - nothing to do");
        return Ok(());
    }

    println!("wiping with PIN {pin}...");
    match card.factory_reset(Some(pin.as_bytes())) {
        Ok(()) => {}
        Err(e) => {
            let now = card.application_info().ok().and_then(|i| i.pin_retries);
            return Err(format!(
                "{e}\nPIN {pin} was not accepted; {} attempt(s) left. \
                 Re-run with KENTER_CARD_PIN=<the PIN that was set>.",
                now.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
            ));
        }
    }

    let after = card.application_info().map_err(|e| e.to_string())?;
    println!(
        "after  : initialized={} seeded={}",
        after.initialized, after.key_initialized
    );
    if after.initialized {
        return Err("the card still reports itself initialized".into());
    }
    println!("blank - first run will offer to set it up");
    Ok(())
}
