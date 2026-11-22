//! The receive address: how a payee hands a payer an owner commitment.
//!
//! A payer needs exactly one thing to pay into spend mode — the 32-byte owner
//! commitment to set as the token's new owner. Not the
//! derivation index, which is the payee's private bookkeeping and would link
//! their receipts to each other if it travelled.
//!
//! ## Why uppercase hex
//!
//! `KENTER:RECV/<64 uppercase hex>` is 76 characters drawn entirely from QR
//! **alphanumeric** mode (`0-9 A-Z $%*+-./: ` and space), which packs 5.5 bits
//! per character against 8 for byte mode. The same commitment in lowercase
//! forces byte mode and a visibly denser symbol for no gain. Scanning is the
//! point of this format, so it is shaped for the scanner.
//!
//! [`parse_receive_uri`] is deliberately laxer than [`receive_uri`]: it takes
//! either case, with or without the scheme, because the thing on the other side
//! of this is a person pasting something out of a chat window. Being strict
//! about what we emit and generous about what we accept costs nothing here —
//! there is no ambiguity to resolve, only 32 bytes to recover.

use crate::error::{Result, WalletError};

/// Scheme and path of a receive address.
pub const RECEIVE_PREFIX: &str = "KENTER:RECV/";

/// Render a commitment as a scannable receive address.
pub fn receive_uri(commitment: &[u8; 32]) -> String {
    format!("{RECEIVE_PREFIX}{}", hex::encode_upper(commitment))
}

/// Recover a commitment from a receive address, a lowercase one, or bare hex.
pub fn parse_receive_uri(s: &str) -> Result<[u8; 32]> {
    let t = s.trim();
    let body = match t.find('/') {
        // Check the scheme when one is present, so a URI for something else
        // fails by name instead of being silently read as a commitment.
        Some(slash) => {
            let (head, rest) = t.split_at(slash + 1);
            if !head.eq_ignore_ascii_case(RECEIVE_PREFIX) {
                return Err(WalletError::Codec(format!(
                    "not a Kenter receive address: {head:?}"
                )));
            }
            rest
        }
        None => t.strip_prefix("kenter:").unwrap_or(t),
    };

    let bytes = hex::decode(body).map_err(|e| WalletError::Codec(format!("receive address: {e}")))?;
    let out: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        WalletError::Codec(format!(
            "receive address is {} bytes, expected 32",
            v.len()
        ))
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: [u8; 32] = [
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
        0xf9, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff,
    ];

    #[test]
    fn round_trips() {
        assert_eq!(parse_receive_uri(&receive_uri(&C)).unwrap(), C);
    }

    /// The whole reason for the format. If a character outside QR alphanumeric
    /// mode creeps in, the symbol gets denser and nobody notices until it is
    /// hard to scan off a phone screen.
    #[test]
    fn stays_inside_qr_alphanumeric_mode() {
        const ALNUM: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        let uri = receive_uri(&C);
        for ch in uri.chars() {
            assert!(ALNUM.contains(ch), "{ch:?} is not QR-alphanumeric");
        }
        assert_eq!(uri.len(), RECEIVE_PREFIX.len() + 64);
    }

    #[test]
    fn accepts_what_a_person_might_paste() {
        let upper = receive_uri(&C);
        for input in [
            upper.clone(),
            upper.to_lowercase(),
            format!("  {upper}  "),
            hex::encode(C),
            hex::encode_upper(C),
        ] {
            assert_eq!(parse_receive_uri(&input).unwrap(), C, "input: {input:?}");
        }
    }

    #[test]
    fn another_scheme_fails_by_name_rather_than_being_read_as_a_commitment() {
        let other = format!("bitcoin:recv/{}", hex::encode(C));
        let err = parse_receive_uri(&other).unwrap_err().to_string();
        assert!(err.contains("not a Kenter receive address"), "{err}");
    }

    #[test]
    fn a_truncated_address_is_rejected() {
        let short = &receive_uri(&C)[..RECEIVE_PREFIX.len() + 62];
        assert!(parse_receive_uri(short).is_err());
    }
}
