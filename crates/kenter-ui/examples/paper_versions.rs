//! What each symbol on the calibration sheet actually is.
//!
//! The sheet labels symbols by payload, which is the thing being varied,
//! but the thing a camera cares about is the **version** — and the thing an
//! eye can count is the grid of alignment patterns, whose size is set by
//! the version. So a holder reporting "the ones with more marker squares
//! failed" is reporting a version, and this is the table that turns one
//! into the other.
//!
//! ```text
//! cargo run -p kenter-ui --example paper_versions
//! ```

use kenter_wallet::paper::calibration_symbol;

fn main() {
    let sizes = [
        kenter_wallet::paper::CHUNK_PAYLOAD,
        636,
        530,
        477,
        424,
        371,
        318,
        265,
        212,
    ];

    println!("{:>5}  {:>8}  {:>7}  {:>4}  {:>8}  {:>10}",
        "label", "payload", "symbol", "ver", "modules", "alignment");
    println!("{}", "-".repeat(52));

    for (i, n) in sizes.iter().enumerate() {
        // Incompressible, and deliberately not ASCII. A payload of one
        // repeated letter is *alphanumeric*, and `qrcode`'s optimising
        // constructor packs that at 5.5 bits a character instead of 8 --
        // which quietly reports a version two or three lower than a
        // sealed payload would land at.
        let c = calibration_symbol("calibration", i as u16, sizes.len() as u16, &incompressible(*n));
        let Ok(code) = qrcode::QrCode::with_error_correction_level(&c.bytes, qrcode::EcLevel::H)
        else {
            println!("note {i}  will not encode");
            continue;
        };
        let width = code.width();
        let ver = width.saturating_sub(21) / 4 + 1;
        println!(
            "note {i}  {n:>8}  {:>7}  {ver:>4}  {width:>8}  {:>10}",
            c.bytes.len(),
            alignment_grid(ver)
        );
    }

    ec_table();

    println!();
    println!("`alignment` is the grid of 5x5 marker squares, written as");
    println!("rows x cols. Three of its corners are taken by the finder");
    println!("patterns, so the count printed is what the grid would be.");
}

/// How many alignment-pattern centres a version lays out per axis.
///
/// One per seven versions, plus the two edges. Version 1 has none at all,
/// which is why it is special-cased: it is the only version with no
/// alignment pattern anywhere.
fn alignment_grid(ver: usize) -> String {
    if ver <= 1 {
        return "none".into();
    }
    let n = ver / 7 + 2;
    format!("{n}x{n}")
}

/// Bytes deflate and the QR mode optimiser both have to take at face
/// value, so the version printed is the version a sealed payload lands at.
fn incompressible(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x: u64 = 0x243F_6A88_85A3_08D3;
    while v.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(n);
    v
}

/// What error-correction level costs, in version.
///
/// H spends ~30% of a symbol on recovery, Q ~25%, M ~15%, L ~7%. That
/// spend is why a sheet symbol sits at a high version, and version is the
/// thing a camera cares about -- so the level is a lever on readability
/// that costs no extra paper, unlike splitting.
///
/// The trade is real in the other direction: a backup in a drawer meets
/// folding, fading and coffee, which is what the redundancy is for.
#[allow(dead_code)]
fn ec_table() {
    use qrcode::EcLevel::{H, L, M, Q};
    println!("\n{:>8}  {:>12}  {:>12}  {:>12}  {:>12}", "payload", "H (30%)", "Q (25%)", "M (15%)", "L (7%)");
    println!("{}", "-".repeat(64));
    for n in [1725usize, 1300, 1087, 875, 662, 450, 343, 237, 131] {
        let bytes = incompressible(n);
        print!("{n:>8}");
        for ec in [H, Q, M, L] {
            let cell = match qrcode::QrCode::with_error_correction_level(&bytes, ec) {
                Ok(c) => {
                    let w = c.width();
                    format!("v{} ({}m)", w.saturating_sub(21) / 4 + 1, w)
                }
                Err(_) => "too big".into(),
            };
            print!("  {cell:>12}");
        }
        println!();
    }
}
