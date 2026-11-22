//! Which densities survive which capture resolutions, with no printer,
//! no camera and no scissors.
//!
//! The question that matters is not "can a symbol be read" but "can a
//! whole page be read in one frame", because hunting symbol by symbol is
//! the part that makes paper restore painful. That question is geometry:
//! a symbol of N modules drawn in a fixed box, sampled at a known
//! resolution. Rasterising our real sheet through the real decoder
//! answers it exactly, minus the optics.
//!
//! **This is an upper bound.** Real capture adds blur, skew, uneven
//! light and sensor noise, none of which are here, so a density that
//! only just survives this will fail in the room. Treat a pass as "worth
//! printing" rather than "proven".
//!
//! The resolutions are what the devices in hand actually deliver, in
//! pixels across the **page width** (A4 portrait, so the page's height
//! is what fills a landscape frame):
//!
//! | capture | across the page |
//! |---|---|
//! | Surface camera, 1920x1440, whole page | ~1020 |
//! | phone photo, 4032x3024, whole page | ~2140 |
//! | the documented file floor | 3000 |
//!
//! Run: `cargo run -p kenter-ui --example density_sweep`

use kenter_wallet::paper::calibration_symbol;

/// Pixels across the page width.
const WIDTHS: [u32; 8] = [800, 1020, 1200, 1500, 2140, 2400, 3000, 4000];

/// Payload sizes, densest first.
fn sizes() -> Vec<usize> {
    vec![
        // What a sheet prints today, not the format's ceiling: those
        // parted company when the cap was introduced.
        kenter_wallet::paper::chunk_payload(),
        636,
        530,
        424,
        318,
        265,
        212,
        160,
        120,
        80,
    ]
}

fn filler(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x: u32 = 0x9e37_79b9;
    while v.len() < n {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(n);
    v
}

/// Rasterise a page the way a camera or scanner would see it.
fn raster(svg: &str, px: u32) -> image::DynamicImage {
    let h = (px as f32 * 297.0 / 210.0).round() as u32;
    let img = pelt::Pelt::from_str(svg)
        .expect("valid SVG")
        .render(px, h)
        .expect("render");
    image::DynamicImage::ImageRgba8(
        image::RgbaImage::from_raw(img.width, img.height, img.rgba).expect("raster"),
    )
}

fn main() -> Result<(), String> {
    let all = sizes();

    // One density per sheet, so a failure is the density failing rather
    // than one symbol among nine being unlucky. Nine copies of the same
    // size fill a page the way a real backup would.
    println!("Each row is a page of 9 symbols, all at one density.");
    println!("A tick means every symbol on that page read in one frame.\n");

    print!("{:>8} |", "bytes");
    for w in WIDTHS {
        print!("{w:>10}");
    }
    println!();
    println!("{:->9}+{:->1$}", "", WIDTHS.len() * 6);

    for n in &all {
        let chunks: Vec<_> = (0..9)
            .map(|i| calibration_symbol("sweep", i, 9, &filler(*n)))
            .collect();
        let pages = kenter_ui::sheet::pages(&chunks, "sweep", "sweep")?;
        if pages.len() != 1 {
            return Err(format!("{n} bytes wanted {} pages", pages.len()));
        }

        print!("{n:>8} |");
        for w in WIDTHS {
            let found = kenter_ui::scan::read_page(&raster(&pages[0], w));
            // ours / undecodable / rejected: "3" alone hid whether the
            // other six were never seen or seen and thrown away, which
            // is the whole difference between a density problem and a
            // bug in this sweep.
            print!(
                "{:>10}",
                format!(
                    "{}/{}/{}",
                    found.symbols.len(),
                    found.unreadable,
                    found.foreign
                )
            );
        }
        println!();
    }

    println!(
        "\n'all' = every one of the 9 read; a number = how many; '.' = none.\n\
         The leftmost column that reads 'all' is the capture this density\n\
         needs. 1020 is the Surface camera on a whole page; 2140 is a phone\n\
         photo of one.\n\n\
         Remember this is rasterised, not photographed: no blur, no skew,\n\
         no glare. A density that only just passes here will not pass in\n\
         the room."
    );
    Ok(())
}
