//! QR symbols, rendered as SVG.
//!
//! SVG rather than a bitmap because that is what the rest of this crate already
//! knows how to draw: a QR goes through [`Pelt`](pelt::Pelt) and the same
//! size-keyed raster cache as every other element, so it is crisp at any DPI
//! and at any window scale, and it costs no new compositing path. A bitmap
//! would have needed one, plus nearest-neighbour scaling rules to keep the
//! modules square.
//!
//! One `<path>` of module squares, not one `<rect>` each: a version-10 symbol
//! is 57×57, and up to ~1600 sibling nodes is real work for usvg on every
//! cache miss. `shape-rendering="crispEdges"` keeps module boundaries from
//! being antialiased into grey mush at small sizes, which is what a scanner
//! actually trips over.

use qrcode::bits::Bits;
use qrcode::{EcLevel, QrCode, Version};

/// Default quiet zone, in modules. Four is what the spec requires; scanners do
/// tolerate less, but a symbol printed onto a dark UI panel with no margin is
/// the classic "why won't it scan" bug, and four modules of background cost
/// almost nothing at the sizes we draw.
pub const QUIET: u32 = 4;

/// Render `data` as an SVG QR symbol.
///
/// `dark` and `light` are CSS colours for the modules and the background. The
/// background is painted rather than left transparent: scanners need the
/// contrast, and leaving it to whatever panel is behind would make scannability
/// depend on the theme.
///
/// Error correction is **M** (~15%). Not the lowest, because these are read off
/// a screen at an angle or from a photo of one, and not the highest, because a
/// receive address is already 76 characters and Q/H would push the symbol a
/// version or two larger for a payment that is retried in seconds if it fails.
pub fn svg(data: &str, dark: &str, light: &str) -> Result<String, qrcode::types::QrError> {
    svg_with(data, dark, light, EcLevel::M, QUIET)
}

/// [`svg`] with the error-correction level and quiet zone spelled out.
pub fn svg_with(
    data: &str,
    dark: &str,
    light: &str,
    ec: EcLevel,
    quiet: u32,
) -> Result<String, qrcode::types::QrError> {
    // The optimising constructor, deliberately. A receive URI is mostly
    // uppercase and digits, so letting the encoder segment it picks
    // alphanumeric mode and yields a smaller symbol than forcing bytes
    // would — which matters for something read off a screen at an angle.
    render(
        &QrCode::with_error_correction_level(data.as_bytes(), ec)?,
        dark,
        light,
        quiet,
    )
}

/// [`svg_with`] over arbitrary bytes rather than text.
///
/// A paper backup is compressed binary, not a URI, so it has nothing to say
/// in a string. QR byte mode carries it either way — the only thing that
/// changes is that nothing here can pretend the payload is UTF-8.
///
/// **Byte mode is forced here, and deliberately not in [`svg_with`].** The
/// optimising constructor is right for text and a liability for binary: a
/// run that happens to look numeric becomes its own segment, and every
/// segment pays a mode indicator and a length field. That overhead is
/// content-dependent, so a payload sized to the documented capacity
/// encodes for most inputs and fails for some — which is what happened, on
/// symbol 12 of a 14-symbol backup, after the first eleven went through.
/// One mode for the whole payload makes the capacity a constant again.
pub fn svg_bytes(
    data: &[u8],
    dark: &str,
    light: &str,
    ec: EcLevel,
    quiet: u32,
) -> Result<String, qrcode::types::QrError> {
    render(&QrCode::with_bits(byte_mode_bits(data, ec)?, ec)?, dark, light, quiet)
}

/// `data` as a single byte-mode segment at the smallest version that holds
/// it. See [`svg_bytes`].
pub fn byte_mode_bits(data: &[u8], ec: EcLevel) -> Result<Bits, qrcode::types::QrError> {
    // Smallest version that fits, found by asking rather than from a
    // table: the crate owns the capacity numbers, and a second copy here
    // would be a second thing to get wrong.
    for v in 1..=40 {
        let mut bits = Bits::new(Version::Normal(v));
        if bits.push_byte_data(data).is_ok() && bits.push_terminator(ec).is_ok() {
            return Ok(bits);
        }
    }
    Err(qrcode::types::QrError::DataTooLong)
}

/// Draw a built symbol. Shared, so the two constructors differ only in how
/// they encode and not in what comes out.
fn render(
    code: &QrCode,
    dark: &str,
    light: &str,
    quiet: u32,
) -> Result<String, qrcode::types::QrError> {
    let n = code.width() as u32;
    let side = n + quiet * 2;

    let modules = code.to_colors();
    let mut d = String::with_capacity(modules.len() * 12);
    for y in 0..n {
        // Run-length the row: a horizontal run of dark modules is one `h`
        // segment instead of several squares, which roughly halves the path on
        // a typical symbol.
        let mut x = 0;
        while x < n {
            if modules[(y * n + x) as usize] == qrcode::Color::Dark {
                let start = x;
                while x < n && modules[(y * n + x) as usize] == qrcode::Color::Dark {
                    x += 1;
                }
                let run = x - start;
                d.push_str(&format!("M{} {}h{run}v1h-{run}z", start + quiet, y + quiet));
            } else {
                x += 1;
            }
        }
    }

    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {side} {side}\" \
         shape-rendering=\"crispEdges\">\
         <rect width=\"{side}\" height=\"{side}\" fill=\"{light}\"/>\
         <path d=\"{d}\" fill=\"{dark}\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_wallet::paper::SYMBOL_CAPACITY;
    use kenter_wallet::receive_uri;

    /// A full-capacity symbol must encode whatever the bytes happen to be.
    ///
    /// The bug this pins: the optimising constructor segments by content,
    /// so a run that looks numeric becomes its own segment and pays a mode
    /// and length header. Overhead therefore depends on the data, and a
    /// payload sized to the documented capacity encoded for eleven symbols
    /// of a real backup and then failed on the twelfth.
    #[test]
    fn a_full_symbol_encodes_whatever_the_bytes_are() {
        // Deliberately adversarial: long digit runs, long ASCII runs and
        // high bytes, which is what the optimiser splits on.
        let shapes: [fn(usize) -> u8; 4] = [
            |i| b'0' + (i % 10) as u8,
            |i| if i % 64 < 40 { b'0' + (i % 10) as u8 } else { (i * 97) as u8 },
            |i| if i % 128 < 100 { b'A' + (i % 26) as u8 } else { 0xF0 },
            |i| (i * 31 + 7) as u8,
        ];
        for (n, shape) in shapes.iter().enumerate() {
            let data: Vec<u8> = (0..SYMBOL_CAPACITY).map(|i| shape(i)).collect();
            // M, because SYMBOL_CAPACITY is the version-40 capacity at the
            // level `sheet` renders, and that moved from H to M. Asserting
            // one against the other asks for 2331 bytes in a symbol that
            // holds 1273.
            svg_bytes(&data, "#000", "#fff", EcLevel::M, QUIET)
                .unwrap_or_else(|e| panic!("shape {n}: {SYMBOL_CAPACITY} bytes refused: {e}"));
        }
    }

    /// One byte past is still an error, so the capacity constant is not
    /// quietly generous.
    #[test]
    fn one_byte_too_many_is_refused() {
        let data = vec![0xA5u8; SYMBOL_CAPACITY + 1];
        assert!(svg_bytes(&data, "#000", "#fff", EcLevel::M, QUIET).is_err());
    }

    /// Text keeps the optimiser: forcing byte mode on a receive address
    /// would make its symbol bigger for no gain.
    #[test]
    fn a_receive_address_still_uses_the_denser_encoding() {
        let uri = receive_uri(&commitment());
        let text = svg(&uri, "#000", "#fff").unwrap();
        let forced = svg_bytes(uri.as_bytes(), "#000", "#fff", EcLevel::M, QUIET).unwrap();

        let side = |s: &str| {
            s.split("viewBox=\"0 0 ")
                .nth(1)
                .and_then(|r| r.split(' ').next())
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap()
        };
        assert!(
            side(&text) <= side(&forced),
            "byte mode produced a smaller symbol than the optimiser ({} vs {})",
            side(&text),
            side(&forced)
        );
    }

    fn commitment() -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        c
    }

    #[test]
    fn a_receive_address_renders() {
        let s = svg(&receive_uri(&commitment()), "#000", "#fff").unwrap();
        assert!(s.starts_with("<svg"));
        assert!(s.contains("<path d=\"M"));
    }

    /// The viewBox must be the module count plus two quiet zones, or the margin
    /// silently disappears when the symbol is scaled to fit its box.
    #[test]
    fn the_quiet_zone_is_inside_the_viewbox() {
        let data = receive_uri(&commitment());
        let n = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
            .unwrap()
            .width() as u32;
        let s = svg(&data, "#000", "#fff").unwrap();
        let side = n + QUIET * 2;
        assert!(
            s.contains(&format!("viewBox=\"0 0 {side} {side}\"")),
            "{s:.120}"
        );
    }

    /// pelt is the only thing that ever rasterizes this, so "valid SVG" means
    /// "pelt renders it", not "it looks like XML".
    #[test]
    fn pelt_rasterizes_it() {
        let s = svg(&receive_uri(&commitment()), "#0b0e16", "#ffffff").unwrap();
        let img = pelt::Pelt::from_str(&s).unwrap().render(220, 220).unwrap();
        assert_eq!((img.width, img.height), (220, 220));
        // A rendered QR is neither blank nor solid: both would rasterize fine
        // and scan as nothing at all.
        let dark = img.rgba.chunks_exact(4).filter(|p| p[0] < 64).count();
        let total = (img.width * img.height) as usize;
        assert!(
            dark > total / 20 && dark < total * 3 / 4,
            "{dark} dark of {total} - symbol looks blank or solid"
        );
    }

    /// The one test that would catch a wrong symbol rather than an ugly one.
    ///
    /// Rasterize with no quiet zone at exactly one pixel per module and compare
    /// every pixel against the encoder's own matrix. A transposed path, an
    /// off-by-one in the run-length loop, or dark and light swapped all render
    /// to something that looks like a QR code and scans as nothing; only
    /// checking the modules themselves finds them. There is no QR *decoder* in
    /// this tree to check against, so this stands in for one.
    #[test]
    fn every_module_lands_where_the_encoder_put_it() {
        let data = receive_uri(&commitment());
        let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M).unwrap();
        let n = code.width() as u32;
        let modules = code.to_colors();

        let svg = svg_with(&data, "#000000", "#ffffff", EcLevel::M, 0).unwrap();
        let img = pelt::Pelt::from_str(&svg).unwrap().render(n, n).unwrap();

        for y in 0..n {
            for x in 0..n {
                let px = img.rgba[((y * n + x) * 4) as usize];
                let drawn_dark = px < 128;
                let should_be_dark = modules[(y * n + x) as usize] == qrcode::Color::Dark;
                assert_eq!(
                    drawn_dark,
                    should_be_dark,
                    "module ({x},{y}) is {} but should be {}",
                    if drawn_dark { "dark" } else { "light" },
                    if should_be_dark { "dark" } else { "light" },
                );
            }
        }
    }

    /// A payload too large for any version must come back as an error rather
    /// than an unreadable symbol.
    #[test]
    fn an_oversized_payload_errors() {
        assert!(svg(&"A".repeat(8000), "#000", "#fff").is_err());
    }
}
