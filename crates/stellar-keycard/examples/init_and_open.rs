//! Live Status Keycard V1 bring-up: SELECT → INIT → PAIR → OPEN SECURE CHANNEL →
//! MUTUALLY AUTHENTICATE. Proves the whole V1 secure channel against a real card.
//!
//! ⚠️ INIT is quasi-permanent (needs a factory reset to redo). Uses DEV defaults
//! (PIN 123456 / PUK 123456789012 / default pairing password) — fine for a
//! throwaway dev card, never for one holding value. `--no-init` skips INIT on an
//! already-initialized card.
//!
//! Run: cargo run -p stellar-keycard --example init_and_open [-- --no-init]

use stellar_keycard::{
    DEFAULT_PAIRING_PASSWORD, SecureChannel, Transport, init_card, pair,
    pairing_secret_from_password,
};

const DEV_PIN: &str = "123456";
const DEV_PUK: &str = "123456789012";

fn main() {
    let no_init = std::env::args().any(|a| a == "--no-init");

    let mut t = match Transport::connect() {
        Ok(t) => t,
        Err(e) => {
            println!("connect failed: {e} (card on the reader?)");
            return;
        }
    };

    let info = match t.select_keycard() {
        Ok(i) => i,
        Err(e) => {
            println!("SELECT failed: {e}");
            return;
        }
    };
    let card_pub = info.secure_channel_public_key.clone();
    println!("SELECT ok — initialized={}", info.initialized);

    let pairing_secret = pairing_secret_from_password(DEFAULT_PAIRING_PASSWORD);

    if !info.initialized && !no_init {
        println!("\n→ INIT (dev defaults: PIN {DEV_PIN}, PUK {DEV_PUK}, default pairing) …");
        match init_card(&mut t, &card_pub, DEV_PIN, DEV_PUK, &pairing_secret) {
            Ok(()) => println!("  INIT ok."),
            Err(e) => {
                println!("  INIT failed: {e}");
                return;
            }
        }
        if let Err(e) = t.select_keycard() {
            println!("re-SELECT after INIT failed: {e}");
            return;
        }
    } else if info.initialized {
        println!("(card already initialized — skipping INIT)");
    }

    println!("\n→ PAIR …");
    let pairing = match pair(&mut t, &pairing_secret) {
        Ok(p) => {
            println!("  paired — slot index {}", p.index);
            p
        }
        Err(e) => {
            println!("  PAIR failed: {e}");
            return;
        }
    };

    println!("\n→ OPEN SECURE CHANNEL + MUTUALLY AUTHENTICATE …");
    match SecureChannel::open(&mut t, &card_pub, &pairing) {
        Ok(_sc) => {
            println!("  ✓ secure channel OPEN and mutually authenticated.");
            println!("\nStatus Keycard V1 secure channel works end-to-end.");
        }
        Err(e) => println!("  secure channel failed: {e}"),
    }
}
