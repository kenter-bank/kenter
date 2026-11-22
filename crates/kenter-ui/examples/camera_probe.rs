//! What this machine's cameras can actually give us, in raw formats.
//!
//! The paper reader needs a frame filling itself with one symbol, and the
//! only number that decides whether that reads is
//!
//! ```text
//! px per module = frame pixels (short side) * fill / modules per symbol
//! ```
//!
//! The physical module size cancels: a symbol is `modules * module_mm`
//! across, so framing it fills the sensor with exactly `modules` modules
//! whatever the millimetres are. That makes the QR **version** the lever,
//! not the 0.30mm module and not the page layout.
//!
//! Run: `cargo run -p kenter-ui --example camera_probe`

use nokhwa::utils::{ApiBackend, RequestedFormat, RequestedFormatType};
use nokhwa::Camera;

/// How much of the short side a holder can realistically fill with one
/// symbol while still seeing enough page to aim. Generous framing, not a
/// best case.
const FILL: f32 = 0.85;

/// A QR symbol's width in modules, by version, plus the 8-module quiet
/// zone the spec wants on each side (4) -- ours is version 40 today.
fn modules(version: u32) -> f32 {
    (17 + 4 * version) as f32 + 8.0
}

fn main() {
    let cams = match nokhwa::query(ApiBackend::Auto) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not enumerate cameras: {e}");
            return;
        }
    };
    if cams.is_empty() {
        println!("no cameras found");
        return;
    }

    for info in &cams {
        println!("\n=== {} ({}) ===", info.human_name(), info.index());
        let mut cam = match Camera::new(
            info.index().clone(),
            RequestedFormat::new::<nokhwa::pixel_format::RgbFormat>(
                RequestedFormatType::AbsoluteHighestResolution,
            ),
        ) {
            Ok(c) => c,
            Err(e) => {
                println!("  cannot open: {e}");
                continue;
            }
        };

        let mut formats = match cam.compatible_camera_formats() {
            Ok(f) => f,
            Err(e) => {
                println!("  cannot list formats: {e}");
                continue;
            }
        };
        // Widest first: the short side is what decides whether we read.
        formats.sort_by_key(|f| {
            std::cmp::Reverse(f.resolution().width_x.min(f.resolution().height_y))
        });

        let mut seen = std::collections::BTreeSet::new();
        for f in &formats {
            let r = f.resolution();
            let short = r.width_x.min(r.height_y) as f32;
            // One line per (format, resolution); frame rates do not change
            // the pixel budget.
            if !seen.insert((format!("{:?}", f.format()), r.width_x, r.height_y)) {
                continue;
            }
            let usable = short * FILL;
            let v40 = usable / modules(40);
            let v25 = usable / modules(25);
            println!(
                "  {:<6} {:>4}x{:<4}  v40 {:>4.2} px/mod  v25 {:>4.2} px/mod  {}",
                format!("{:?}", f.format()),
                r.width_x,
                r.height_y,
                v40,
                v25,
                if v40 >= 4.0 {
                    "v40 reads"
                } else if v25 >= 4.0 {
                    "needs a smaller version"
                } else {
                    "too thin"
                }
            );
        }
    }
}
