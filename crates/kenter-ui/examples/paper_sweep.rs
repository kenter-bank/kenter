//! Does capping symbol density make a printed sheet readable?
//!
//! # The question
//!
//! A camera reading one symbol that fills the frame suggests the density
//! needs no cap. On a sheet nine symbols share the page, so each gets a
//! ninth of the resolution, and a whole-sheet scan can come back with only
//! its wallet symbol — the one item small enough to land at a low QR
//! version.
//!
//! `paper_density` showed the arithmetic: at the version-40 ceiling a sheet
//! symbol is 4.29 pixels per module at `scan::WANTED_WIDTH`, against a
//! documented floor of four. This runs the experiment the arithmetic only
//! predicts — render the page, rasterise it, decode it, count what came
//! back — across a range of caps.
//!
//! ```text
//! cargo run -p kenter-ui --example paper_sweep
//! ```
//!
//! # What it holds still
//!
//! Every cap sees the **same bytes**: the seal stub returns a fixed
//! incompressible blob of the size a real note measures at, so the only
//! thing changing between rows is the cap. That matters here more than
//! usual, because `testing::spend_note` randomises each note's claim
//! secret, and a sweep over a moving payload cannot tell a better cap from
//! a luckier draw, and a scan regression gets blamed on the wrong change.
//!
//! The cost of holding it still is that this measures the *format*, not any
//! particular wallet. Realism comes from the body size, which is measured:
//! see `--body`.

use kenter_wallet::paper;

/// A real 4-pair note is 1401 bytes on disk, self-printed and measured;
/// notes grow 290 bytes a pair. Sealing adds a nonce and a tag.
const DEFAULT_BODY: usize = 1441;

/// `scan::WANTED_WIDTH` and two better scans.
const WIDTHS: [u32; 3] = [3000, 3600, 4800];

fn main() {
    let body = std::env::args()
        .skip_while(|a| a != "--body")
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BODY);

    println!("two notes, each sealing to {body} bytes\n");
    print!("{:>6}  {:>7}  {:>6}  {:>5}", "cap", "symbols", "pages", "ver");
    for w in WIDTHS {
        print!("  {:>9}", format!("{w}px"));
    }
    println!();
    println!("{}", "-".repeat(28 + 11 * WIDTHS.len()));

    for cap in [paper::CHUNK_PAYLOAD, 900, 750, 600, 500, 400, 300] {
        row(cap, body);
    }

    println!();
    println!("`ver` is the QR version the note symbols land at.");
    println!("A row reads `recovered of printed`. The cap that is worth");
    println!("having is the least aggressive one that reads every symbol");
    println!("at {}px, since every step down costs paper.", WIDTHS[0]);
}

fn row(cap: usize, body: usize) {
    // Read by `paper::chunk_payload` when `encode` cuts the items up. The
    // example is single-threaded and does nothing else with the
    // environment.
    std::env::set_var("KENTER_PAPER_CHUNK_PAYLOAD", cap.to_string());

    let held: Vec<_> = (1..=2u8)
        .map(|i| kenter_wallet::testing::spend_note(i, 1_000 + i as u64, i as u32))
        .collect();
    let chunks = paper::encode("5e1f0c2a9d4b7368", &held, &[], Some(17), |_| {
        Ok(incompressible(body))
    })
    .expect("encode");
    let pages = kenter_ui::sheet::pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-28").expect("pages");

    let note_sym = chunks.iter().find(|c| c.item > 0).expect("a note symbol");
    let ver = qrcode::QrCode::with_error_correction_level(&note_sym.bytes, qrcode::EcLevel::H)
        .map(|c| (c.width().saturating_sub(21)) / 4 + 1)
        .unwrap_or(0);

    print!(
        "{cap:>6}  {:>7}  {:>6}  {ver:>5}",
        chunks.len(),
        pages.len()
    );

    for w in WIDTHS {
        let mut read = 0usize;
        for page in &pages {
            read += kenter_ui::scan::read_dynamic(&raster(page, w)).symbols.len();
        }
        let all = read == chunks.len();
        print!("  {:>8}{}", format!("{read}/{}", chunks.len()), if all { " " } else { "!" });
    }
    println!();
}

/// A page as a scanner would see it. A4 portrait, height follows width.
fn raster(svg: &str, px: u32) -> image::DynamicImage {
    let h = (px as f32 * 297.0 / 210.0).round() as u32;
    let img = pelt::Pelt::from_str(svg)
        .expect("the page is not valid SVG")
        .render(px, h)
        .expect("render");
    image::DynamicImage::ImageRgba8(
        image::RgbaImage::from_raw(img.width, img.height, img.rgba).expect("raster"),
    )
}

/// Bytes deflate cannot shrink, so the chunker sees what a sealed note
/// looks like rather than something that compresses to one small symbol.
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
