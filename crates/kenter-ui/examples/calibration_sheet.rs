//! One page that tells us the real resolution floor, on real paper.
//!
//! The density figures the tests rely on come from rasterising SVG, not
//! from paper. Real optics favour the *short* chunks, which are the ones
//! that fall to a lower QR version: the binding constraint is modules per
//! symbol.
//!
//! So: print this, photograph it the way you would in a real recovery,
//! and feed it back through the reader. Each symbol is labelled with the
//! payload that produced it, and they run from our current density down
//! to a quarter of it. Whichever ones come back tells us what to cap the
//! encoder at, measured rather than argued.
//!
//! Run: `cargo run -p kenter-ui --example calibration_sheet`

use kenter_wallet::paper::{calibration_symbol, Chunk};

/// Payload sizes to print, largest first.
///
/// The first is what the encoder emits today for every chunk but an
/// item's last. The rest step down so the threshold lands between two
/// printed symbols rather than off the end of the page.
fn sizes() -> Vec<usize> {
    // Centred on what the encoder actually prints, with rungs above and
    // below it. Above matters as much as below: a sheet where everything
    // reads measures nothing, and the point of the top rungs is to find
    // the new ceiling rather than re-confirm the floor.
    //
    // History, so the ladder is not re-derived: photographed off a phone
    // screen at 4032x3024 while symbols rendered at **H**, the threshold
    // sat between 424 bytes (version 23, read) and 477 (version 24, did
    // not) -- with 530 at version 26 reading, so that rung is one sample
    // and suspect. 636 and 1248, versions 29 and 40, found a grid and
    // failed to decode it. Symbols now render at **M**, where the same
    // byte counts land five to nine versions lower, so the byte figures
    // below are not comparable with those; the version is.
    let cap = kenter_wallet::paper::chunk_payload();
    let mut v: Vec<usize> = vec![
        cap * 2,
        (cap * 3) / 2,
        (cap * 5) / 4,
        cap, // what a sheet prints today, the control
        (cap * 3) / 4,
        cap / 2,
        (cap * 3) / 8,
        cap / 4,
        cap / 8,
    ];
    // The format cannot carry more than one symbol holds, whatever the
    // arithmetic above says.
    let ceiling = kenter_wallet::paper::CHUNK_PAYLOAD;
    for n in v.iter_mut() {
        *n = (*n).min(ceiling).max(16);
    }
    v
}

fn main() -> Result<(), String> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "calibration.pdf".to_string());

    // Payload bytes that are incompressible and not all one value, so the
    // symbol is as dense as a real sealed chunk rather than an easy case
    // a run-length-friendly pattern would make.
    let filler = |n: usize| -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x: u32 = 0x9e37_79b9;
        while v.len() < n {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.truncate(n);
        v
    };

    let all = sizes();
    // One "item" per size, so the sheet labels them separately and a
    // partial read is reported per density rather than in a lump. The
    // header is real: the first run of this sheet produced symbols that
    // decoded perfectly and were then rejected as foreign, because the
    // bytes were filler with no header at all.
    let chunks: Vec<Chunk> = all
        .iter()
        .enumerate()
        .map(|(i, n)| {
            calibration_symbol("calibration", i as u16, all.len() as u16, &filler(*n))
        })
        .collect();

    // Prove every symbol is ours before anyone prints it. The first
    // version of this sheet emitted valid QR codes full of headerless
    // filler: they decoded perfectly off a phone and were then counted
    // as somebody else's, which wasted a round of photographs.
    for (i, c) in chunks.iter().enumerate() {
        match kenter_wallet::paper::read_symbol(&c.bytes) {
            Ok(s) if s.item == i as u16 => {}
            Ok(s) => return Err(format!("item {i} came back as item {}", s.item)),
            Err(e) => return Err(format!("item {i} is not a readable symbol: {e}")),
        }
    }
    println!("all {} symbols parse as ours
", chunks.len());

    for (i, (n, c)) in all.iter().zip(chunks.iter()).enumerate() {
        println!("item {i}: {n} payload bytes, {} in the symbol", c.bytes.len());
    }
    println!("pages: {}", kenter_ui::sheet::layout(&chunks).len());

    let pdf = kenter_ui::pdf::render(&chunks, "calibration", "test sheet")?;
    std::fs::write(&out, &pdf).map_err(|e| format!("writing {out}: {e}"))?;
    println!(
        "\nwrote {out} ({} KB, {} symbols)\n\n\
         Print at 100% - no 'fit to page'. Then photograph or scan it the way\n\
         you would in a real recovery, and read it back with:\n\n    \
         cargo run -p kenter-ui --example read_back -- <image files>\n",
        pdf.len() / 1024,
        chunks.len()
    );
    Ok(())
}
