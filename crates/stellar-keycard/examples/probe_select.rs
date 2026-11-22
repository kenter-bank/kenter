//! Dump the forked applet's SELECT response.
//!
//! `parse_application_info` was written against the stock Keycard template.
//! The fork signs a transcript with an identity certificate, which it has to
//! ship in SELECT, so the response is not necessarily the same shape. This
//! prints it so the parser can be judged against the bytes rather than the
//! documentation.
//!
//! ```text
//! cargo run -p stellar-keycard --example probe_select
//! ```

use stellar_keycard::{CardTransport, DEFAULT_SIM_ADDR, SimTransport};

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];

fn main() -> Result<(), String> {
    let mut t = SimTransport::connect(DEFAULT_SIM_ADDR)
        .map_err(|e| format!("no SimServer on {DEFAULT_SIM_ADDR}: {e}"))?;
    let resp = t.transmit(SELECT_AID).map_err(|e| e.to_string())?;

    println!("{} bytes", resp.len());
    println!("{}", hex::encode(&resp));
    let (body, sw) = resp.split_at(resp.len() - 2);
    println!("SW   = {:02X}{:02X}", sw[0], sw[1]);
    println!("tag  = {:02X}  len = {:02X}", body[0], body[1]);

    match stellar_keycard::transport::parse_application_info(body) {
        Ok(info) => println!(
            "parsed: initialized={} version={:?}",
            info.initialized, info.app_version
        ),
        Err(e) => println!("parse failed: {e}"),
    }
    Ok(())
}
