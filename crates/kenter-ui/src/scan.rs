//! Reading a paper backup back: QR symbols out of a scan or a photograph.
//!
//! # Why an image file and not a camera
//!
//! A camera is what most people would reach for, and it is the thing this
//! client has deliberately not needed so far — no capture device, no
//! permission prompt, no preview surface, nothing listening. Recovery is
//! also the one moment where a holder is least likely to be holding a phone
//! steady over a desk and most likely to have a flatbed, a photo they
//! already took, or a scan someone emailed them.
//!
//! So this takes files. A phone photo saved to disk works, which is the
//! camera path with one extra step and none of the dependency. If a live
//! camera is wanted later it feeds the same [`crate::scan::read_image`] with
//! frames instead of files, and everything downstream is unchanged.
//!
//! # Several symbols per image
//!
//! A page holds up to nine, and a holder will photograph the page rather
//! than each symbol, so every image is searched exhaustively rather than
//! stopping at the first hit.

use std::path::Path;

use kenter_wallet::paper::{self, Scanned};

/// Longest edge, in pixels, that symbols are looked for at.
///
/// Downsampling is the usual advice for QR decoding, and the usual advice
/// is about *one* symbol filling a frame. A page of nine is the opposite
/// problem: each symbol is a small part of the image, and shrinking the
/// page shrinks every module with it.
///
/// Measured, by rasterising a real page and reading it back. A 0.30mm
/// module across a 210mm page needs roughly 2400 pixels — about 290dpi,
/// which is a normal scan — before every symbol reads. At 1600 it is
/// marginal and at 1200 nothing decodes at all. So this only exists to
/// stop a 48-megapixel phone photo spending minutes in the grid search,
/// and is set well above anything that would cost symbols.
const WORK_WIDTH: u32 = 4000;

/// What a scan needs to be, so the UI can say so before the holder tries.
///
/// Across the page, not per symbol. Below this some symbols read and
/// others do not, which is the worst failure to debug by hand.
///
/// 3000px — about 360dpi — and deliberately **not** the lowest value that
/// works. Every symbol reads at 2400, but only just: the test asserting
/// it failed once under parallel load and passed five runs in a row
/// afterwards, which is what sitting on a margin looks like. A holder
/// scanning at exactly the documented minimum should have room, not be at
/// the edge of one.
pub const WANTED_WIDTH: u32 = 3000;

/// What one image turned out to contain.
#[derive(Debug, Clone, Default)]
pub struct Found {
    /// Symbols that decoded and belong to a Kenter paper backup.
    pub symbols: Vec<Scanned>,
    /// Symbols that decoded into something else entirely. Counted rather
    /// than reported one by one: a photo of a desk may have a parcel label
    /// in it, and that is not an error worth a sentence.
    pub foreign: usize,
    /// Symbols the decoder found and could not read. Worth saying, because
    /// it is the difference between "this page has nothing on it" and
    /// "this page is too blurry".
    pub unreadable: usize,
}

/// Find every Kenter symbol in an image.
///
/// Never fails on content — an image with no symbols, or somebody else's
/// QR codes, is a legitimate answer and not an error. It fails only when
/// the file cannot be opened or decoded as an image at all.
pub fn read_image(path: &Path) -> Result<Found, String> {
    let img = image::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(read_dynamic(&img))
}

/// [`read_image`] on an image already in memory, for tests and for a
/// camera that may arrive later.
pub fn read_dynamic(img: &image::DynamicImage) -> Found {
    let img = if img.width() > WORK_WIDTH {
        img.resize(
            WORK_WIDTH,
            u32::MAX,
            // Nearest-neighbour would alias module edges into noise at the
            // exact scale that matters; a smooth filter keeps the
            // black/white transition where the decoder expects it.
            image::imageops::FilterType::Triangle,
        )
    } else {
        img.clone()
    };

    read_luma(img.to_luma8())
}

/// [`read_dynamic`] on luminance that is already the right size.
///
/// The camera path comes through here: its frames are well under
/// [`WORK_WIDTH`] and are luminance already, so resizing and converting
/// would be two full copies a frame for nothing. Everything after the
/// pixels -- grid search, decode, and what counts as ours -- is shared,
/// which is the point: a symbol must not read differently depending on
/// whether it arrived from a file or a lens.
pub fn read_luma(img: image::GrayImage) -> Found {
    let mut found = Found::default();
    let mut seen: Vec<(u16, u16)> = Vec::new();
    let mut keep = |part: Found, found: &mut Found, seen: &mut Vec<(u16, u16)>| {
        for sym in part.symbols {
            if !seen.contains(&(sym.item, sym.index)) {
                seen.push((sym.item, sym.index));
                found.symbols.push(sym);
            }
        }
        found.unreadable += part.unreadable;
        found.foreign += part.foreign;
    };

    keep(with_rqrr(&img), &mut found, &mut seen);
    keep(with_zxing(&img), &mut found, &mut seen);

    // A page of symbols in tidy rows defeats both detectors in a way no
    // single symbol does: their finder patterns line up across symbols, so
    // grids get assembled from the corners of neighbours and fail. Every
    // symbol on a failing page was measured to read alone, at every scale
    // from 4 to 7 pixels a module, so the fix is to hand them over alone.
    //
    // Finding candidates is a cheap pass over coarse cells; reading them is
    // not. So the closer look only happens when the image shows more
    // candidates than were read -- a frame with one symbol filling it, read
    // already, never pays for it.
    let boxes = regions(&img);
    if boxes.len() > found.symbols.len() + found.foreign {
        for b in boxes {
            let crop = isolate(&img, b);
            // Only symbols: the whole-image passes already counted what
            // they could not read, and a crop of a caption is not news.
            for part in [with_rqrr(&crop), with_zxing(&crop)] {
                keep(
                    Found { symbols: part.symbols, ..Found::default() },
                    &mut found,
                    &mut seen,
                );
            }
        }
    }
    found
}

/// Boxes around anything dense and roughly square: candidate symbols.
///
/// The image is cut into cells about a 600th of its width; a cell counts as
/// ink if it holds an edge, the ink is fattened so a symbol's solid
/// patches close up into one blob, and each blob that is square enough and
/// big enough is a box. Text lines come out long and thin, captions small,
/// and both are dropped. Nothing here needs to be exact: a box that holds
/// a symbol with some margin is all the readers want, and a box that holds
/// nothing costs one failed read.
fn regions(img: &image::GrayImage) -> Vec<(u32, u32, u32, u32)> {
    /// Black-to-white spread inside a cell, out of 255, that counts as
    /// an edge rather than noise or shading. Measured off a phone photo
    /// of a screen, the worst case on hand.
    const MIN_CONTRAST: u8 = 64;
    let k = (img.width() / 600).max(1);
    let (w, h) = (img.width() / k, img.height() / k);
    if w == 0 || h == 0 {
        return Vec::new();
    }
    let at = |x: u32, y: u32| (y * w + x) as usize;

    // A cell is ink when it holds both dark and light against its OWN
    // contrast. A fixed threshold is fine on a clean page and wrong on a
    // photo: there a black bezel and a shaded background are dark too,
    // and they tied every symbol on the sheet into one blob. Solid areas
    // of any shade have no contrast, and are not ink.
    let mut ink = vec![false; (w * h) as usize];
    for cy in 0..h {
        for cx in 0..w {
            let (mut lo, mut hi) = (u8::MAX, 0u8);
            for y in 0..k {
                for x in 0..k {
                    let v = img.get_pixel(cx * k + x, cy * k + y).0[0];
                    (lo, hi) = (lo.min(v), hi.max(v));
                }
            }
            ink[at(cx, cy)] = hi.saturating_sub(lo) >= MIN_CONTRAST;
        }
    }

    // Two cells is a module or two at any scan this can read: enough to
    // close a symbol's solid patches into it, and well under the gap the
    // sheet leaves between symbols.
    const GROW: i64 = 2;
    let mut fat = vec![false; ink.len()];
    for cy in 0..h {
        for cx in 0..w {
            if !ink[at(cx, cy)] {
                continue;
            }
            for dy in -GROW..=GROW {
                for dx in -GROW..=GROW {
                    let (x, y) = (cx as i64 + dx, cy as i64 + dy);
                    if x >= 0 && y >= 0 && x < w as i64 && y < h as i64 {
                        fat[at(x as u32, y as u32)] = true;
                    }
                }
            }
        }
    }

    let mut seen = vec![false; fat.len()];
    let mut boxes = Vec::new();
    for start in 0..fat.len() {
        if !fat[start] || seen[start] {
            continue;
        }
        let (mut x0, mut y0, mut x1, mut y1) = (u32::MAX, u32::MAX, 0, 0);
        let mut stack = vec![start];
        seen[start] = true;
        while let Some(i) = stack.pop() {
            let (x, y) = (i as u32 % w, i as u32 / w);
            (x0, y0, x1, y1) = (x0.min(x), y0.min(y), x1.max(x), y1.max(y));
            let next = [
                (x.wrapping_sub(1), y),
                (x + 1, y),
                (x, y.wrapping_sub(1)),
                (x, y + 1),
            ];
            for (nx, ny) in next {
                if nx < w && ny < h && fat[at(nx, ny)] && !seen[at(nx, ny)] {
                    seen[at(nx, ny)] = true;
                    stack.push(at(nx, ny));
                }
            }
        }
        let (bw, bh) = (x1 - x0 + 1, y1 - y0 + 1);
        let aspect = bw as f32 / bh as f32;
        if bw.min(bh) >= 16 && (0.5..2.0).contains(&aspect) {
            let (x, y) = (x0 * k, y0 * k);
            boxes.push((x, y, (bw * k).min(img.width() - x), (bh * k).min(img.height() - y)));
        }
    }
    boxes
}

/// One box cut out with a fifth of its size spare on every side, as far
/// as the image goes.
///
/// The spare is the image's own surroundings and nothing else. Pasting
/// the crop onto white was tried and is worse both ways it was measured:
/// beside a photo's grey paper the white makes an edge of its own, and on
/// the photo in `tests/fixtures` a strip of it beside one symbol took that
/// symbol from read to unread.
fn isolate(img: &image::GrayImage, (x, y, w, h): (u32, u32, u32, u32)) -> image::GrayImage {
    let (mx, my) = (w / 5, h / 5);
    let (x0, y0) = (x.saturating_sub(mx), y.saturating_sub(my));
    let (x1, y1) = ((x + w + mx).min(img.width()), (y + h + my).min(img.height()));
    image::imageops::crop_imm(img, x0, y0, x1 - x0, y1 - y0).to_image()
}

/// rqrr. Strong on a crisp page, weak at finding symbols in a
/// photograph: on a phone photo of nine it found one.
fn with_rqrr(img: &image::GrayImage) -> Found {
    let mut prepared = rqrr::PreparedImage::prepare(img.clone());
    let mut found = Found::default();
    for grid in prepared.detect_grids() {
        let mut raw = Vec::new();
        if grid.decode_to(&mut raw).is_err() {
            found.unreadable += 1;
            continue;
        }
        match paper::read_symbol(&raw) {
            Ok(s) => found.symbols.push(s),
            Err(_) => found.foreign += 1,
        }
    }
    found
}

/// ZXing. The reverse: nine of nine off a photograph where rqrr managed
/// one. Poor on our rendered pages for the reason rqrr is: symbols in
/// rows lend each other finder patterns. [`read_luma`] isolates them.
///
/// Both run because each covers the other's measured failure, and a
/// backup that will not read is the one failure this product cannot
/// have. Neither is trusted alone.
fn with_zxing(img: &image::GrayImage) -> Found {
    use rxing::common::HybridBinarizer;
    use rxing::multi::{GenericMultipleBarcodeReader, MultipleBarcodeReader};
    use rxing::{
        BinaryBitmap, Luma8LuminanceSource, MultiFormatReader, RXingResultMetadataType,
        RXingResultMetadataValue,
    };

    let (w, h) = (img.width(), img.height());
    let mut found = Found::default();
    let Ok(src) = Luma8LuminanceSource::new(img.clone().into_raw(), w, h) else {
        return found;
    };
    let mut bitmap = BinaryBitmap::new(HybridBinarizer::new(src));
    let mut reader = GenericMultipleBarcodeReader::new(MultiFormatReader::default());
    let Ok(results) = reader.decode_multiple(&mut bitmap) else {
        return found;
    };

    for r in results {
        // BYTE_SEGMENTS, never getText(): the payload is sealed binary,
        // so any character-set interpretation corrupts it, and which
        // bytes survive depends on what they happen to be.
        let raw: Option<Vec<u8>> = r
            .getRXingResultMetadata()
            .get(&RXingResultMetadataType::BYTE_SEGMENTS)
            .and_then(|v| match v {
                RXingResultMetadataValue::ByteSegments(segs) => {
                    Some(segs.iter().flatten().copied().collect())
                }
                _ => None,
            });
        if let Some(Ok(sym)) = raw.as_deref().map(paper::read_symbol) {
            found.symbols.push(sym);
        }
    }
    found
}

/// Read a camera frame.
///
/// The same reader as everything else: it finds every symbol in the
/// image by itself, so a frame holding one symbol and a frame holding a
/// whole sheet take the same path.
pub fn read_frame(luma: image::GrayImage) -> Found {
    read_luma(luma)
}

/// Read a page.
///
/// Was once slot-cropping, region detection and a hand-rolled
/// threshold, all of it built to help a decoder that could not find
/// more than one symbol on a page. ZXing replaced it on photographs, but
/// a crisp page still lost symbols to both readers, so a lighter region
/// pass came back inside [`read_luma`] -- as a second look after both
/// readers, never instead of them.
pub fn read_page(img: &image::DynamicImage) -> Found {
    read_dynamic(img)
}

/// Read a stack of images into one sheet.
///
/// Order does not matter and neither do duplicates, so a holder can throw
/// every photo they took at it. Per-file failures are collected rather
/// than fatal: one unopenable file out of six should not stop the other
/// five being scanned.
pub fn read_all(paths: &[std::path::PathBuf]) -> (paper::Sheet, Found, Vec<String>) {
    let mut sheet = paper::Sheet::new();
    let mut total = Found::default();
    let mut problems = Vec::new();

    for path in paths {
        match read_image(path) {
            Err(e) => problems.push(e),
            Ok(found) => {
                total.foreign += found.foreign;
                total.unreadable += found.unreadable;
                for s in found.symbols {
                    // A symbol from another sheet is the holder's mistake,
                    // not a broken file: name it and keep going, so one
                    // stray page does not abandon the scan.
                    if let Err(e) = sheet.add(s.clone()) {
                        problems.push(format!("{}: {e}", path.display()));
                    } else {
                        total.symbols.push(s);
                    }
                }
            }
        }
    }
    (sheet, total, problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_wallet::HeldToken;

    /// Stand-in for the AEAD, so these tests need no key.
    fn seal(b: &[u8]) -> kenter_wallet::Result<Vec<u8>> {
        let mut v = vec![0xA7];
        v.extend_from_slice(b);
        Ok(v)
    }
    fn open(b: &[u8]) -> kenter_wallet::Result<Vec<u8>> {
        match b.split_first() {
            Some((0xA7, rest)) => Ok(rest.to_vec()),
            _ => Err(kenter_wallet::WalletError::Backup("wrong key".into())),
        }
    }

    /// Real notes, unpadded.
    ///
    /// An earlier version padded the blob to the size a production note
    /// comes out at, to make the page arithmetic honest. That cannot work
    /// here: `paper` derives a note's id from its own container rather
    /// than carrying it, so a blob stuffed with random bytes is not a
    /// note and does not come back as one. The page-count tests in
    /// `sheet` still pad, because they only count symbols.
    fn notes(n: u8) -> Vec<HeldToken> {
        (1..=n)
            .map(|i| kenter_wallet::testing::spend_note(i, 1_000 + i as u64, i as u32))
            .collect()
    }

    /// Rasterise a page the way a scanner would see it.
    ///
    /// `pelt` is already here for the skins, so the whole chain — encode,
    /// lay out, draw, rasterise, decode — is testable without a printer or
    /// a camera. That matters more than usual here: every other way of
    /// checking this format is us reading our own encoder back.
    fn raster(svg: &str, px: u32) -> image::DynamicImage {
        // A4 portrait: height follows width.
        let h = (px as f32 * 297.0 / 210.0).round() as u32;
        let img = pelt::Pelt::from_str(svg)
            .expect("the page is not valid SVG")
            .render(px, h)
            .expect("render");
        image::DynamicImage::ImageRgba8(
            image::RgbaImage::from_raw(img.width, img.height, img.rgba).expect("raster"),
        )
    }

    fn pages_of(n: u8) -> Vec<String> {
        let chunks = paper::encode("5e1f0c2a9d4b7368", &notes(n), &[], Some(17), seal).unwrap();
        crate::sheet::pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap()
    }

    /// The whole loop, with no printer and no camera: a wallet becomes a
    /// page, the page becomes pixels, and the pixels become the wallet.
    #[test]
    fn a_rendered_page_scans_back_into_the_notes_it_came_from() {
        let held = notes(3);
        let chunks = paper::encode("5e1f0c2a9d4b7368", &held, &[], Some(17), seal).unwrap();
        let pages = crate::sheet::pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap();

        let mut sheet = paper::Sheet::new();
        for page in &pages {
            let found = read_dynamic(&raster(page, 2400));
            assert!(!found.symbols.is_empty(), "a page decoded to nothing");
            for s in found.symbols {
                sheet.add(s).unwrap();
            }
        }

        let progress = sheet.progress();
        assert!(progress.is_complete(), "{}", progress.describe());

        let out = sheet.finish(open).unwrap();
        assert!(out.failed.is_empty(), "{:?}", out.failed);
        assert_eq!(out.next_owner_index, Some(17));

        let mut got = out.tokens;
        got.sort_by(|a, b| a.id.cmp(&b.id));
        let mut want = held;
        want.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(got, want, "every field of every note survived paper");
    }

    /// Binary has to survive the decoder. A `String`-returning path would
    /// replace most of a sealed payload with U+FFFD and still look like it
    /// worked.
    #[test]
    fn the_payload_comes_back_byte_for_byte() {
        let chunks = paper::encode("5e1f0c2a9d4b7368", &notes(1), &[], None, seal).unwrap();
        let pages = crate::sheet::pages(&chunks, "f", "d").unwrap();

        let found = read_dynamic(&raster(&pages[0], 2400));
        assert_eq!(found.symbols.len(), chunks.len());
        for original in &chunks {
            let scanned = paper::read_symbol(&original.bytes).unwrap();
            assert!(
                found.symbols.iter().any(|s| *s == scanned),
                "symbol {} did not come back identical",
                original.label()
            );
        }
    }

    /// One symbol framed the way a **camera** frames it.
    ///
    /// This is the path the product actually uses, and until now nothing
    /// tested it. Everything else in this module rasterises a whole A4
    /// page, which is the image-file and flatbed path: a different number
    /// of pixels per module, and no answer at all about the viewfinder.
    ///
    /// A camera is pointed at one symbol until it fills the frame, so the
    /// symbol spans `short side * FILL` pixels whatever the millimetres
    /// are. The symbol under test is the densest a sheet can carry -- the
    /// cap, with its header -- because that is the one that decides
    /// whether the format works.
    ///
    /// 720p is included deliberately. `camera::good_enough` accepts it,
    /// and a gate that accepts a camera which cannot read is the same
    /// false promise as one that refuses a camera that can.
    #[test]
    fn one_symbol_filling_a_frame_reads_at_every_accepted_resolution() {
        let header = paper::SYMBOL_CAPACITY - paper::CHUNK_PAYLOAD;
        let payload = incompressible(paper::chunk_payload() - header);
        let chunk = paper::calibration_symbol("5e1f0c2a9d4b7368", 1, 2, &payload);

        let svg = crate::qr::svg_bytes(&chunk.bytes, "#000000", "#ffffff", qrcode::EcLevel::M, 4)
            .expect("the densest symbol a sheet carries must encode");

        // Every raw format `camera_probe` reports and the gate accepts.
        for short in [1440u32, 1280, 1080, 720] {
            let span = (short as f32 * 0.85).round() as u32;
            let img = pelt::Pelt::from_str(&svg)
                .expect("symbol svg")
                .render(span, span)
                .expect("render");
            let rgba = image::RgbaImage::from_raw(img.width, img.height, img.rgba)
                .expect("raster");
            let found = read_frame(image::DynamicImage::ImageRgba8(rgba).to_luma8());
            assert_eq!(
                found.symbols.len(),
                1,
                "{short}p frame ({span}px of symbol, {:.1} px/module): not read",
                crate::camera::pixels_per_module(short)
            );
        }
    }

    /// Bytes neither deflate nor the QR mode optimiser can shrink, so the
    /// symbol is as dense as a real sealed chunk rather than an easy case.
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

    /// Every symbol on a page reads at a normal scan resolution.
    ///
    /// **This is the image-file path, not the camera one.** A whole A4
    /// page is rasterised from SVG into one synthetic, noiseless image
    /// and handed to the same decoder a lens feeds. That is what a
    /// flatbed or a scanned PDF looks like, and it is a real supported
    /// path -- but at 3000px across A4 each symbol gets about a quarter
    /// of the pixels per module a camera gives it, so nothing here says
    /// anything about the viewfinder. See the camera test above.
    ///
    /// Two further gaps worth knowing: it renders the **SVG** emitter,
    /// while the app exports **PDF** from a separate emitter that draws
    /// its own rectangles, and no test rasterises that one at all; and
    /// synthetic pixels have no lens blur, noise or perspective.
    ///
    /// The number is measured rather than assumed. It depends heavily on
    /// the renderer not antialiasing module edges: with antialiasing a
    /// page gives five symbols of nine at *any* resolution.
    ///
    /// **Currently failing, and known.** It reads two to four of five,
    /// varying between runs on identical input, and a *higher* resolution
    /// sometimes reads fewer. Symbols that are byte-identical in size and
    /// version read or fail inconsistently. That is the signature of something other than density being the
    /// variable, and what that something is has not been found.
    #[test]
    fn a_whole_page_reads_at_a_normal_scan_resolution() {
        let chunks = paper::encode("5e1f0c2a9d4b7368", &notes(4), &[], Some(17), seal).unwrap();
        let pages = crate::sheet::pages(&chunks, "f", "d").unwrap();
        assert_eq!(pages.len(), 1, "four notes should be one page");

        for px in [WANTED_WIDTH, 3600, 4000] {
            let found = read_dynamic(&raster(&pages[0], px));
            assert_eq!(
                found.symbols.len(),
                chunks.len(),
                "{px}px: {} of {} symbols read",
                found.symbols.len(),
                chunks.len()
            );
        }
    }

    /// A real photograph: a phone held at a monitor showing an early
    /// sheet, with moire, glare and a bezel in frame. Five symbols, the
    /// densest two of which nothing here reads in any crop at any margin.
    /// Before the region pass it gave one symbol; this pins the three.
    #[test]
    fn a_photo_of_a_screen_gives_up_its_readable_symbols() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sheet-photo-of-screen.jpg");
        let found = read_dynamic(&image::open(path).expect("fixture"));
        let mut got: Vec<(u16, u16)> = found.symbols.iter().map(|s| (s.item, s.index)).collect();
        got.sort();
        assert!(got.len() >= 3, "read {got:?}, want at least the wallet and two note halves");
    }

    /// And the floor is real, so the UI can warn rather than half-work.
    #[test]
    fn too_small_a_scan_does_not_quietly_half_work() {
        let chunks = paper::encode("5e1f0c2a9d4b7368", &notes(4), &[], Some(17), seal).unwrap();
        let pages = crate::sheet::pages(&chunks, "f", "d").unwrap();
        let found = read_dynamic(&raster(&pages[0], 1200));
        assert!(
            found.symbols.len() < chunks.len(),
            "1200px across A4 should not be enough - if it is, WANTED_WIDTH is too high"
        );
    }

    /// Somebody else's QR code in the frame is not an error.
    #[test]
    fn a_foreign_symbol_is_counted_and_ignored() {
        let other = crate::qr::svg("https://example.com/not-a-backup", "#000", "#fff").unwrap();
        let found = read_dynamic(&raster(&other, 600));
        assert!(found.symbols.is_empty());
        assert_eq!(found.foreign, 1);
    }

    /// An image with nothing in it is an answer, not a failure.
    #[test]
    fn a_blank_image_finds_nothing_and_does_not_fail() {
        let blank = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            800,
            600,
            image::Rgba([255, 255, 255, 255]),
        ));
        let found = read_dynamic(&blank);
        assert!(found.symbols.is_empty());
        assert_eq!(found.foreign, 0);
        assert_eq!(found.unreadable, 0);
    }

    /// Losing a page loses its notes and nothing else — the property the
    /// item format exists for, now proven through actual pixels.
    #[test]
    fn a_missing_page_costs_only_what_was_on_it() {
        let pages = pages_of(12);
        assert!(pages.len() > 1, "need several pages to drop one");

        let mut sheet = paper::Sheet::new();
        for page in pages.iter().skip(1) {
            for s in read_dynamic(&raster(page, 2400)).symbols {
                sheet.add(s).unwrap();
            }
        }
        let progress = sheet.progress();
        assert!(!progress.is_complete());
        assert!(progress.has_anything(), "the remaining pages still carry notes");

        let out = sheet.finish(open).unwrap();
        assert!(
            !out.tokens.is_empty() && out.tokens.len() < 12,
            "{} notes recovered from a partial stack",
            out.tokens.len()
        );
    }

    /// A measurement, not a pass/fail — run it with `--nocapture`.
    ///
    /// `a_whole_page_reads_at_a_normal_scan_resolution` reports "2 of 5"
    /// and stops, which does not say *why*. Before anyone photographs a
    /// page and re-presents it to a camera — two lossy hops on top of
    /// whatever this already loses — it is worth knowing whether the
    /// limit is payload size, module size, or the rasteriser.
    ///
    /// ```text
    /// cargo test -p kenter-ui --lib what_a_page_actually_contains \
    ///     -- --ignored --nocapture
    /// ```
    ///
    /// Ignored by default: it rasterises the same page at six
    /// resolutions and takes over a minute, which is not a cost every
    /// run should pay for a number nobody is asserting on.
    #[test]
    #[ignore = "measurement, not an assertion; run with --ignored --nocapture"]
    fn what_a_page_actually_contains() {
        let notes = notes(4);
        let chunks = paper::encode("5e1f0c2a9d4b7368", &notes, &[], Some(17), seal).unwrap();

        println!("\n--- payload ---");
        for (i, c) in chunks.iter().enumerate() {
            println!("  chunk {i}: {} bytes  ({})", c.bytes.len(), c.label());
        }
        let total: usize = chunks.iter().map(|c| c.bytes.len()).sum();
        println!("  {} chunks, {total} bytes total", chunks.len());

        println!("\n--- symbol density by error-correction level ---");
        println!("  (sheet.rs uses M; H shown for comparison)");
        for (i, c) in chunks.iter().enumerate() {
            let mut line = format!("  chunk {i}: {:>4} bytes ->", c.bytes.len());
            for (name, ec) in [
                ("L", qrcode::EcLevel::L),
                ("M", qrcode::EcLevel::M),
                ("Q", qrcode::EcLevel::Q),
                ("H", qrcode::EcLevel::H),
            ] {
                match crate::qr::byte_mode_bits(&c.bytes, ec)
                    .and_then(|b| qrcode::QrCode::with_bits(b, ec))
                {
                    Ok(code) => line.push_str(&format!("  {name}:{:>3}", code.width())),
                    Err(_) => line.push_str(&format!("  {name}: --")),
                }
            }
            println!("{line}");
        }
        // Halving a note's payload is the other lever: two symbols of
        // ~420 bytes instead of one of ~843.
        let half = vec![0u8; 420];
        for (name, ec) in [("M", qrcode::EcLevel::M), ("H", qrcode::EcLevel::H)] {
            if let Ok(code) = crate::qr::byte_mode_bits(&half, ec)
                .and_then(|b| qrcode::QrCode::with_bits(b, ec))
            {
                println!("  a 420-byte half-note at {name}: {}x{}", code.width(), code.width());
            }
        }

        let pages = crate::sheet::pages(&chunks, "f", "d").unwrap();
        println!("  {} page(s)", pages.len());

        println!("\n--- decode by resolution ---");
        for px in [2000u32, 2400, 3000, 3600, 4000, 5000] {
            let found = read_dynamic(&raster(&pages[0], px));
            println!(
                "  {px:>5}px -> {} of {} symbols",
                found.symbols.len(),
                chunks.len()
            );
        }
    }
}



