//! Which symbol on a rendered sheet fails to read, by name.
//!
//! A density sweep that comes back non-monotonic and always exactly one
//! symbol short is the signature of measuring the wrong variable. A count cannot tell the difference between "the densest
//! symbol failed" and "the same one always fails"; this prints the label.
//!
//! ```text
//! cargo run -p kenter-ui --example paper_which [--cap N] [--px N]
//! ```

use kenter_wallet::paper;

fn main() {
    let arg = |name: &str, default: usize| -> usize {
        std::env::args()
            .skip_while(|a| a != name)
            .nth(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let cap = arg("--cap", paper::CHUNK_PAYLOAD);
    let px = arg("--px", 3000) as u32;
    let body = arg("--body", 1441);

    std::env::set_var("KENTER_PAPER_CHUNK_PAYLOAD", cap.to_string());

    let notes: usize = arg("--notes", 2);
    // `--real` seals the way the scan tests do: a one-byte tag and the
    // container through. The wallet item then comes out small and the
    // notes come out at whatever they really are, which is the mix a
    // sheet actually carries -- a fixed synthetic body makes every item
    // the same size and hides exactly that.
    let real = std::env::args().any(|a| a == "--real");

    let held: Vec<_> = (1..=notes as u8)
        .map(|i| kenter_wallet::testing::spend_note(i, 1_000 + i as u64, i as u32))
        .collect();
    let chunks = paper::encode("5e1f0c2a9d4b7368", &held, &[], Some(17), |b| {
        if real {
            let mut v = vec![0xA7];
            v.extend_from_slice(b);
            Ok(v)
        } else {
            Ok(incompressible(body))
        }
    })
    .expect("encode");
    let pages = kenter_ui::sheet::pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-28").expect("pages");

    println!("cap {cap}, body {body}, raster {px}px, {} symbols on {} page(s)\n",
        chunks.len(), pages.len());

    println!("{:>4}  {:>5}  {:>5}  {:>7}  {:>4}  {:>7}  {}",
        "item", "index", "total", "payload", "ver", "modules", "read");
    println!("{}", "-".repeat(56));

    let mut got: Vec<(u16, u16)> = Vec::new();
    for (n, page) in pages.iter().enumerate() {
        let found = kenter_ui::scan::read_dynamic(&raster(page, px));
        for s in &found.symbols {
            got.push((s.item, s.index));
        }
        println!(
            "   (page {} of {}: {} read, {} unreadable, {} foreign)",
            n + 1,
            pages.len(),
            found.symbols.len(),
            found.unreadable,
            found.foreign
        );
    }
    println!();

    for c in &chunks {
        let code = qrcode::QrCode::with_error_correction_level(&c.bytes, qrcode::EcLevel::H);
        let (ver, modules) = match &code {
            Ok(q) => ((q.width().saturating_sub(21)) / 4 + 1, q.width() + 8),
            Err(_) => (0, 0),
        };
        let read = got.contains(&(c.item, c.index));
        println!(
            "{:>4}  {:>5}  {:>5}  {:>7}  {ver:>4}  {modules:>7}  {}",
            c.item,
            c.index,
            c.total,
            c.bytes.len(),
            if read { "yes" } else { "NO" }
        );
    }
}

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
