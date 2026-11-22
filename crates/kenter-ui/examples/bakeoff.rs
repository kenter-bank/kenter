//! Which QR reader actually reads our sheets?
//!
//! Tonight's detector is hand-rolled: one global Otsu threshold, blob
//! labelling, crop, decode. It took a photographed sheet from 1 symbol
//! to 6 of 9. But mature libraries already solve this, and at least one
//! capability we lack looks decisive:
//!
//! - **Adaptive local thresholding.** One threshold for a whole frame is
//!   wrong somewhere on a page that has glare on one side and shadow on
//!   the other. ZXing's hybrid binarizer and quirc both threshold in
//!   tiles. That is a very good explanation for item 6 failing while
//!   items 5 and 7, either side of it, read fine.
//! - **Multi-code detection** as a first-class operation rather than
//!   something built on top of a single-code API.
//!
//! So: same pixels, three readers, count what each one gets. No
//! argument survives a table.
//!
//! Run: `cargo run -p kenter-ui --example bakeoff -- <images...>`

use kenter_wallet::paper::read_symbol;

/// What one reader managed on one image.
struct Score {
    /// Codes it decoded at all, ours or not.
    codes: usize,
    /// Of those, the ones that parse as a Kenter paper symbol.
    ours: Vec<u16>,
}

impl Score {
    fn of(payloads: Vec<Vec<u8>>) -> Score {
        let mut ours: Vec<u16> = payloads
            .iter()
            .filter_map(|p| read_symbol(p).ok().map(|s| s.item))
            .collect();
        ours.sort_unstable();
        ours.dedup();
        Score {
            codes: payloads.len(),
            ours,
        }
    }
}

/// What this codebase does today, end to end.
fn ours(img: &image::DynamicImage) -> Score {
    let found = kenter_ui::scan::read_page(img);
    let mut items: Vec<u16> = found.symbols.iter().map(|s| s.item).collect();
    items.sort_unstable();
    items.dedup();
    Score {
        codes: found.symbols.len() + found.unreadable + found.foreign,
        ours: items,
    }
}

/// rqrr alone, whole image, no help from us. The baseline the rest of
/// tonight's work was built on top of.
fn plain_rqrr(img: &image::DynamicImage) -> Score {
    let mut prepared = rqrr::PreparedImage::prepare(img.to_luma8());
    let mut out = Vec::new();
    for grid in prepared.detect_grids() {
        let mut raw = Vec::new();
        if grid.decode_to(&mut raw).is_ok() {
            out.push(raw);
        }
    }
    Score::of(out)
}

/// quirc, which thresholds locally rather than globally.
fn quirc(img: &image::DynamicImage) -> Score {
    let luma = img.to_luma8();
    let mut q = quircs::Quirc::default();
    let mut out = Vec::new();
    for code in q.identify(luma.width() as usize, luma.height() as usize, &luma) {
        let Ok(code) = code else { continue };
        if let Ok(data) = code.decode() {
            out.push(data.payload);
        }
    }
    Score::of(out)
}

/// ZXing, via its Rust port, with the hybrid binarizer.
fn zxing(img: &image::DynamicImage) -> Score {
    use rxing::common::HybridBinarizer;
    use rxing::multi::{GenericMultipleBarcodeReader, MultipleBarcodeReader};
    use rxing::{BinaryBitmap, Luma8LuminanceSource, MultiFormatReader};

    let luma = img.to_luma8();
    let (w, h) = (luma.width(), luma.height());
    // Luminance straight in: no image codecs, no file path, nothing but
    // the pixels we already hold.
    let Ok(src) = Luma8LuminanceSource::new(luma.into_raw(), w, h) else {
        return Score { codes: 0, ours: Vec::new() };
    };
    let mut bitmap = BinaryBitmap::new(HybridBinarizer::new(src));
    let mut reader = GenericMultipleBarcodeReader::new(MultiFormatReader::default());
    match reader.decode_multiple(&mut bitmap) {
        Ok(results) => Score::of(
            results
                .iter()
                // ZXing hands byte-mode content back as text decoded
                // ISO-8859-1, which maps bytes one to one, so the
                // payload survives the round trip.
                .map(|r| r.getText().chars().map(|c| c as u32 as u8).collect())
                .collect(),
        ),
        Err(_) => Score {
            codes: 0,
            ours: Vec::new(),
        },
    }
}

fn main() {
    let paths: Vec<std::path::PathBuf> = std::env::args_os().skip(1).map(Into::into).collect();
    if paths.is_empty() {
        eprintln!("give me some images");
        std::process::exit(2);
    }

    for path in &paths {
        let Ok(img) = image::open(path) else {
            println!("{}: cannot open", path.display());
            continue;
        };
        println!(
            "\n=== {} ({}x{})",
            path.file_name().unwrap_or_default().to_string_lossy(),
            img.width(),
            img.height()
        );
        println!("{:<22} {:>7}  {:>5}  {}", "reader", "decoded", "ours", "items");
        println!("{:-<60}", "");

        let runs: Vec<(&str, Score)> = vec![
            ("rqrr, whole image", plain_rqrr(&img)),
            ("ours (regions+rqrr)", ours(&img)),
            ("quirc", quirc(&img)),
            ("zxing (rxing)", zxing(&img)),
        ];
        for (name, s) in runs {
            let items: Vec<String> = s.ours.iter().map(|i| (i + 1).to_string()).collect();
            println!(
                "{:<22} {:>7}  {:>5}  {}",
                name,
                s.codes,
                s.ours.len(),
                items.join(",")
            );
        }
    }

    println!(
        "\n'ours' counts distinct Kenter symbols recovered. On a calibration\n\
         sheet the items run densest first, so a reader that gets item 1 is\n\
         reading the hardest symbol on the page."
    );
}
