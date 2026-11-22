//! What QR version a paper backup's symbols actually land at, and how many
//! pixels per module that leaves a scanner.
//!
//! # Why this exists
//!
//! A full version-40 symbol reads through a camera when it fills the
//! frame, which suggests the density needs no cap. A *sheet* is a different question: nine symbols share an A4 page,
//! so each gets a fixed cell and the scan resolution is divided nine ways.
//!
//! The sheet lays every symbol out in the same cell — `SYMBOL_MODULES`,
//! which is a version-40 symbol plus its quiet zone — and the SVG scales
//! whatever it holds to fill it. So a symbol at a *lower* version gets
//! physically fatter modules in the same square. Splitting an item into
//! more, smaller symbols therefore buys resolution rather than spending it,
//! and costs only paper.
//!
//! This prints the trade so it can be read off rather than argued about.
//!
//! ```text
//! cargo run -p kenter-ui --example paper_density
//! ```
//!
//! Nothing here touches a wallet, a key or a camera: it seals with a stub
//! that returns incompressible bytes of a chosen length, which is what a
//! real sealed note looks like to the chunker.

use kenter_wallet::paper;
use qrcode::{EcLevel, QrCode};

/// Scan widths worth knowing about. The first is `scan::WANTED_WIDTH`, the
/// documented floor.
const WIDTHS: [u32; 3] = [3000, 3600, 4800];

/// A4 short side, millimetres.
const PAGE_W: f32 = 210.0;

fn main() {
    println!("sheet cell: {SHEET_MODULES} modules across, {CELL_MM:.1} mm\n");

    println!("A symbol is scaled to fill the cell, so px/module is");
    println!("  (scan width px / {PAGE_W:.0} mm) * {CELL_MM:.1} mm / its modules");
    println!("Floor is 4 px/module; 3 is the decoder's hard limit.\n");

    header();
    // A sealed note is a container plus AEAD overhead, and incompressible.
    // The range covers a 3-pair note through something well past 8 pairs.
    for body in [600usize, 900, 1200, 1500, 1800, 2100, 2400, 3000] {
        row(body);
    }

    println!();
    println!("`per symbol` is what the chunker gives each symbol after");
    println!("deflate, and the version is what qrcode picks for it at H.");
}

const SHEET_MODULES: f32 = 177.0 + 8.0;
const CELL_MM: f32 = SHEET_MODULES * 0.30;

fn header() {
    print!("{:>6}  {:>7}  {:>10}  {:>4}  {:>7}", "body", "symbols", "per symbol", "ver", "modules");
    for w in WIDTHS {
        print!("  {:>7}", format!("{w}px"));
    }
    println!();
    println!("{}", "-".repeat(44 + 9 * WIDTHS.len()));
}

/// One row: seal every note to `body` bytes and report what comes out.
fn row(body: usize) {
    let chunks = match encode_with_body(body) {
        Ok(c) => c,
        Err(e) => {
            println!("{body:>6}  {e}");
            return;
        }
    };
    // Report the note item, not the wallet item: the wallet's is small,
    // lands at a low version, and reads every time — which is exactly how
    // a real scan can come back with the wallet and none of the notes.
    let note: Vec<&paper::Chunk> = chunks.iter().filter(|c| c.item > 0).collect();
    let Some(first) = note.first() else {
        println!("{body:>6}  no note symbols");
        return;
    };
    let payload = first.bytes.len();
    let Ok(code) = QrCode::with_error_correction_level(&first.bytes, EcLevel::H) else {
        println!("{body:>6}  will not encode at H");
        return;
    };
    // `width()` is the symbol itself; the sheet adds the quiet zone.
    let modules = code.width() as f32 + 8.0;

    print!(
        "{body:>6}  {:>7}  {payload:>10}  {:>4}  {:>7.0}",
        note.len(),
        version_of(code.width()),
        modules
    );
    for w in WIDTHS {
        let px_per_mm = w as f32 / PAGE_W;
        let per_module = px_per_mm * CELL_MM / modules;
        let flag = if per_module < 4.0 { "!" } else { " " };
        print!("  {per_module:>6.2}{flag}");
    }
    println!();
}

/// Version from the module count: 21 modules at v1, four more each step.
fn version_of(width: usize) -> usize {
    (width.saturating_sub(21)) / 4 + 1
}

/// A backup of two notes, each sealing to exactly `body` incompressible
/// bytes.
fn encode_with_body(body: usize) -> Result<Vec<paper::Chunk>, String> {
    let held: Vec<_> = (1..=2u8)
        .map(|i| kenter_wallet::testing::spend_note(i, 1_000 + i as u64, i as u32))
        .collect();
    paper::encode("5e1f0c2a9d4b7368", &held, &[], Some(17), |_| {
        Ok(incompressible(body))
    })
    .map_err(|e| e.to_string())
}

/// Bytes deflate cannot shrink, so the chunker sees what a sealed note
/// looks like. A counter would compress to nothing and make every symbol
/// one version wide.
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
