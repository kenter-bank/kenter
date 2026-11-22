//! Check the custody-C1 identity pinning against the card on the reader.
//!
//! Four questions, none of which spends a PIN attempt:
//!
//! 1. Does the card's certificate verify against the pinned CA?
//! 2. Does `connect_certified` accept it — the provisioning path?
//! 3. Does `connect_expecting` accept the identity it actually has?
//! 4. Does `connect_expecting` **refuse** a different one?
//!
//! The fourth is the one worth running. A check that only ever says yes
//! has not been tested.
//!
//! ```text
//! cargo run -p stellar-keycard --example probe_identity
//! ```

use stellar_keycard::{
    DEV_CA_PUBLIC_KEY, StellarKeycard, Transport, card_identity_certificate,
    card_identity_pubkey, verify_identity_certificate,
};

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];

fn main() -> Result<(), String> {
    let mut t = Transport::connect().map_err(|e| format!("no reader/card: {e}"))?;
    let select = t.transmit(SELECT_AID).map_err(|e| e.to_string())?;
    let claimed = card_identity_pubkey(&select).map_err(|e| e.to_string())?;
    println!("claimed identity : {}", hex::encode(&claimed));
    println!("pinned CA        : {}", hex::encode(DEV_CA_PUBLIC_KEY));

    // 1. The certificate itself.
    let cert = card_identity_certificate(&select).map_err(|e| e.to_string())?;
    match verify_identity_certificate(&cert, &DEV_CA_PUBLIC_KEY) {
        Ok(id) => println!("\n1. certificate   : OK, CA-signed, id = {}", hex::encode(&id)),
        Err(e) => {
            println!("\n1. certificate   : REJECTED ({e})");
            return Err("this card is not signed by the pinned CA".into());
        }
    }

    // 2. Provisioning: certified, no expectation yet.
    drop(t);
    let t = Transport::connect().map_err(|e| e.to_string())?;
    match StellarKeycard::connect_certified(t, &[DEV_CA_PUBLIC_KEY]) {
        Ok(_) => println!("2. connect_certified : OK"),
        Err(e) => println!("2. connect_certified : FAILED ({e})"),
    }

    // 3. The identity it really has.
    let t = Transport::connect().map_err(|e| e.to_string())?;
    match StellarKeycard::connect_expecting(t, &claimed, &[DEV_CA_PUBLIC_KEY]) {
        Ok(_) => println!("3. expecting self    : OK"),
        Err(e) => println!("3. expecting self    : FAILED ({e})"),
    }

    // 4. Someone else's. This must fail, and the run is worthless if it
    //    does not: a substitute card presents exactly this case.
    let mut other = claimed.clone();
    other[1] ^= 0xFF;
    let t = Transport::connect().map_err(|e| e.to_string())?;
    match StellarKeycard::connect_expecting(t, &other, &[DEV_CA_PUBLIC_KEY]) {
        Ok(_) => {
            println!("4. expecting another : ACCEPTED  ** the pinning does not work **");
            return Err("identity pinning accepted the wrong card".into());
        }
        Err(e) => println!("4. expecting another : refused, correctly ({e})"),
    }

    println!("\nall four as expected");
    Ok(())
}
