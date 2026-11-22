//! The paper backup as a PDF.
//!
//! # Why not SVG
//!
//! SVG was the first cut and it prints, but it prints at whatever size the
//! viewer decides. The sheet's whole correctness rests on a module being
//! 0.30mm on the paper, and "print at 100%, no fit-to-page" is a plea
//! rather than a guarantee. A PDF carries its MediaBox: A4 is A4, and a
//! reader that scales has to be told to. Several pages also arrive as one
//! file instead of four, which is the difference between printing a backup
//! and assembling one.
//!
//! # Why written by hand
//!
//! `svg2pdf` would mean a second copy of `usvg` in the tree — it tracks a
//! different release from the one `pelt` uses — and it converts a single
//! tree, so multi-page would still mean assembling chunks underneath it.
//!
//! What a sheet actually contains is **filled rectangles and a few lines of
//! Helvetica**, which are the two simplest things in PDF: no images, no
//! embedded fonts, no transparency, no colour space beyond DeviceGray.
//! Writing that directly costs about a hundred lines, needs no dependency,
//! and keeps page geometry exactly where the SVG emitter's is. The tests
//! parse the result back with a real PDF library rather than trusting it.
//!
//! Everything is PDF 1.4 with base-14 fonts, which is the most boring and
//! most widely readable thing a generator can emit.

use kenter_wallet::paper::Chunk;
use qrcode::EcLevel;

use crate::sheet;

/// Millimetres to PDF points (1/72 inch).
fn pt(mm: f32) -> f32 {
    mm * 72.0 / 25.4
}

/// Escape a string for a PDF literal. Only the three characters that can
/// break one; everything we print is ASCII by construction.
fn esc(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .flat_map(|c| match c {
            '(' | ')' | '\\' => vec!['\\', c],
            c => vec![c],
        })
        .collect()
}

/// The content stream for one page, in PDF operators.
fn content(page: &sheet::Page<'_>, fingerprint: &str, created: &str, symbols: usize) -> String {
    let h = pt(sheet::PAGE_H);
    let mut out = String::new();

    // White page. A scanner meeting an unpainted background is at the
    // mercy of the paper, and the symbols assume a light field.
    out.push_str(&format!(
        "1 g 0 0 {:.2} {:.2} re f\n0 g\n",
        pt(sheet::PAGE_W),
        h
    ));

    for (y, size, bold, text) in sheet::heading_lines(page, fingerprint, created, symbols) {
        out.push_str(&format!(
            "BT /{} {:.2} Tf {:.2} {:.2} Td ({}) Tj ET\n",
            if bold { "FB" } else { "FR" },
            pt(size),
            pt(sheet::MARGIN),
            // PDF's origin is bottom-left; the layout thinks top-down.
            h - pt(y),
            esc(&text)
        ));
    }

    for placed in &page.symbols {
        out.push_str(&symbol_ops(placed, h));
        out.push_str(&format!(
            "BT /FM {:.2} Tf {:.2} {:.2} Td ({}) Tj ET\n",
            pt(3.2),
            pt(placed.x + placed.size / 2.0) - 0.28 * pt(3.2) * placed.chunk.label().len() as f32,
            h - pt(placed.y + placed.size + 3.4),
            esc(&placed.chunk.label())
        ));
    }
    out
}

/// One symbol as filled rectangles.
///
/// Run-length merged along each row, exactly as the SVG emitter does: a
/// version-40 symbol is 177 rows of up to 177 modules, and one rectangle
/// per dark module would be thirty thousand operators per symbol.
fn symbol_ops(placed: &sheet::Placed<'_>, page_h: f32) -> String {
    // M, matching the SVG emitter. Both read it from the same place for
    // a reason: a sheet printed from the PDF and one engraved from the SVG
    // have to be the same symbol, and an emitter that disagreed about the
    // level would produce pages that decode differently.
    let Ok(code) = qrcode::QrCode::with_bits(
        match crate::qr::byte_mode_bits(&placed.chunk.bytes, EcLevel::M) {
            Ok(b) => b,
            Err(_) => return String::new(),
        },
        EcLevel::M,
    ) else {
        return String::new();
    };

    let n = code.width() as u32;
    let quiet = crate::qr::QUIET;
    let side = n + quiet * 2;
    // Points per module. The quiet zone is inside `size`, as it is in the
    // SVG, so the two emitters put the dark area in the same place.
    let m = pt(placed.size) / side as f32;
    let left = pt(placed.x);
    let top = page_h - pt(placed.y);

    let modules = code.to_colors();
    let mut out = String::from("0 g\n");
    for y in 0..n {
        let mut x = 0;
        while x < n {
            if modules[(y * n + x) as usize] == qrcode::Color::Dark {
                let start = x;
                while x < n && modules[(y * n + x) as usize] == qrcode::Color::Dark {
                    x += 1;
                }
                let run = (x - start) as f32;
                out.push_str(&format!(
                    "{:.3} {:.3} {:.3} {:.3} re\n",
                    left + (start + quiet) as f32 * m,
                    top - (y + quiet + 1) as f32 * m,
                    run * m,
                    m
                ));
            } else {
                x += 1;
            }
        }
    }
    out.push_str("f\n");
    out
}

/// The whole backup as one PDF.
pub fn render(chunks: &[Chunk], fingerprint: &str, created: &str) -> Result<Vec<u8>, String> {
    if chunks.is_empty() {
        return Err("nothing to print".into());
    }
    let pages = sheet::layout(chunks);

    // Object numbering: 1 catalog, 2 page tree, 3..5 fonts, then a page
    // and a content stream each.
    let first_page = 6;
    let mut objects: Vec<String> = Vec::new();

    objects.push("<< /Type /Catalog /Pages 2 0 R >>".into());

    let kids: Vec<String> = (0..pages.len())
        .map(|i| format!("{} 0 R", first_page + i * 2))
        .collect();
    objects.push(format!(
        "<< /Type /Pages /Count {} /Kids [{}] >>",
        pages.len(),
        kids.join(" ")
    ));

    for (name, base) in [
        ("FR", "Helvetica"),
        ("FB", "Helvetica-Bold"),
        ("FM", "Courier"),
    ] {
        let _ = name;
        objects.push(format!(
            "<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>"
        ));
    }

    // Content streams are deflated. A page of symbols is tens of thousands
    // of rectangle operators, and uncompressed that is 700KB for one sheet
    // — a size that matters for a file a holder may well email to
    // themselves. Flate is the one filter every PDF reader has had since
    // 1.2, so it costs no compatibility.
    let mut page_count = 0usize;
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    for page in &pages {
        let raw = content(page, fingerprint, created, chunks.len());
        let packed = miniz_oxide::deflate::compress_to_vec_zlib(raw.as_bytes(), 9);
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.2} {:.2}] \
             /Resources << /Font << /FR 3 0 R /FB 4 0 R /FM 5 0 R >> >> \
             /Contents {} 0 R >>",
            pt(sheet::PAGE_W),
            pt(sheet::PAGE_H),
            first_page + page_count * 2 + 1
        ));
        // A placeholder: the stream body is binary, so it is spliced in
        // during serialization rather than carried as a `String`.
        objects.push(format!(
            "<< /Length {} /Filter /FlateDecode >>\n\u{0}STREAM{}\u{0}",
            packed.len(),
            bodies.len()
        ));
        bodies.push(packed);
        page_count += 1;
    }

    // Serialize, recording byte offsets for the cross-reference table.
    let mut out = Vec::from(&b"%PDF-1.4\n"[..]);
    // A comment of high bytes, which is how a reader is told the file is
    // binary and must not be line-ending-converted in transit.
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        match body.split_once('\u{0}') {
            // A stream object: dictionary, then raw bytes.
            Some((dict, rest)) => {
                let n: usize = rest
                    .trim_matches('\u{0}')
                    .trim_start_matches("STREAM")
                    .parse()
                    .expect("stream index");
                out.extend_from_slice(dict.as_bytes());
                out.extend_from_slice(b"stream\n");
                out.extend_from_slice(&bodies[n]);
                out.extend_from_slice(b"\nendstream");
            }
            None => out.extend_from_slice(body.as_bytes()),
        }
        out.extend_from_slice(b"\nendobj\n");
    }

    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_wallet::paper;

    fn chunks_for(notes: usize) -> Vec<paper::Chunk> {
        let held: Vec<kenter_wallet::HeldToken> = (1..=notes)
            .map(|i| kenter_wallet::testing::spend_note(i as u8, 1_000, i as u32))
            .collect();
        paper::encode("5e1f0c2a9d4b7368", &held, &[], Some(17), |p| {
            let mut v = vec![0u8; 24];
            v.extend_from_slice(p);
            v.extend_from_slice(&[0u8; 16]);
            Ok(v)
        })
        .unwrap()
    }

    /// A real parser, not our own eyes. A hand-written PDF that only this
    /// code can read is the failure worth guarding against.
    #[test]
    fn the_output_is_a_pdf_a_parser_accepts() {
        let bytes = render(&chunks_for(4), "5e1f0c2a9d4b7368", "2026-10-24").unwrap();
        let doc = lopdf::Document::load_mem(&bytes).expect("lopdf could not read it");
        assert_eq!(doc.version, "1.4");
        assert!(doc.get_pages().len() >= 1);
    }

    /// A4, in points, because the module size on paper is the whole
    /// correctness argument and a scaled page silently breaks it.
    #[test]
    fn every_page_is_a4() {
        let bytes = render(&chunks_for(4), "f", "d").unwrap();
        let doc = lopdf::Document::load_mem(&bytes).unwrap();
        for (_, id) in doc.get_pages() {
            let page = doc.get_object(id).unwrap().as_dict().unwrap();
            let media = page.get(b"MediaBox").unwrap().as_array().unwrap();
            let got: Vec<f32> = media.iter().map(|o| o.as_float().unwrap()).collect();
            // 210 x 297 mm
            assert!((got[2] - 595.28).abs() < 0.5, "width {} pt", got[2]);
            assert!((got[3] - 841.89).abs() < 0.5, "height {} pt", got[3]);
        }
    }

    #[test]
    fn several_pages_arrive_as_one_file() {
        let many = chunks_for(40);
        let pages = sheet::layout(&many).len();
        assert!(pages > 1, "need a multi-page backup to test one file");

        let doc = lopdf::Document::load_mem(&render(&many, "f", "d").unwrap()).unwrap();
        assert_eq!(doc.get_pages().len(), pages);
    }

    /// The text has to be there, and has to be the same text the SVG
    /// shows, or a holder printing the PDF gets a different sheet from
    /// the one they previewed.
    #[test]
    fn the_pdf_says_what_the_sheet_says() {
        let chunks = chunks_for(2);
        let pdf = render(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap();
        let doc = lopdf::Document::load_mem(&pdf).unwrap();
        let pages: Vec<_> = doc.get_pages().values().copied().collect();
        let text = doc.extract_text(&[1]).unwrap_or_default();
        let _ = pages;

        for want in ["5e1f0c2a9d4b7368", "2026-10-24", "recovery phrase"] {
            assert!(text.contains(want), "the page does not say {want:?}: {text}");
        }
        // And must not advertise what it is worth.
        for word in ["USDC", "balance", "worth"] {
            assert!(!text.contains(word), "the page mentions {word}");
        }
    }

    /// Uncompressed, one sheet of symbols was 700KB. A backup a holder
    /// might email themselves should not be.
    #[test]
    fn the_content_streams_are_compressed() {
        let chunks = chunks_for(4);
        let bytes = render(&chunks, "f", "d").unwrap();
        assert!(
            bytes.windows(13).any(|w| w == b"/FlateDecode "),
            "no compressed stream in the file"
        );
        // Still has to parse, which is the thing compression most easily
        // breaks.
        let doc = lopdf::Document::load_mem(&bytes).expect("lopdf could not read it");
        assert_eq!(doc.get_pages().len(), sheet::layout(&chunks).len());
    }

    /// Paint a page of the PDF the way a printer would, from the file.
    ///
    /// There is no PDF renderer in the tree and adding one for a test is a
    /// heavy price, so this paints the operators the emitter uses — and
    /// **only** those: anything else in a content stream fails the test
    /// rather than being skipped, so the emitter cannot grow a way of
    /// drawing that this quietly ignores. Text is the one thing passed
    /// over, because no scanner reads it.
    ///
    /// What it does check is everything a renderer would get from the
    /// file and nothing it would get from us: lopdf parses the document
    /// and inflates the stream, the rectangles land where PDF's own
    /// bottom-left coordinates put them, and module edges round to whole
    /// pixels as a printer's dots do.
    fn paint(doc: &lopdf::Document, page: lopdf::ObjectId, px: u32) -> image::DynamicImage {
        let s = px as f32 / pt(sheet::PAGE_W);
        let h = (pt(sheet::PAGE_H) * s).round() as u32;
        // Unpainted is not white: the emitter has to paint its own page.
        let mut img = image::GrayImage::from_pixel(px, h, image::Luma([128]));

        let ops = lopdf::content::Content::decode(&doc.get_page_content(page))
            .expect("the content stream does not parse")
            .operations;
        let num = |o: &lopdf::Object| o.as_float().expect("a number");
        let (mut gray, mut pending) = (0u8, Vec::<[f32; 4]>::new());
        for op in ops {
            match op.operator.as_str() {
                "g" => gray = (num(&op.operands[0]) * 255.0).round() as u8,
                "re" => pending.push(std::array::from_fn(|i| num(&op.operands[i]))),
                "f" => {
                    for [x, y, w, rh] in pending.drain(..) {
                        let x0 = (x * s).round().max(0.0) as u32;
                        let x1 = (((x + w) * s).round() as u32).min(px);
                        // Flip: PDF counts up from the bottom edge.
                        let y0 = ((h as f32 - (y + rh) * s).round().max(0.0)) as u32;
                        let y1 = ((h as f32 - y * s).round() as u32).min(h);
                        for yy in y0..y1 {
                            for xx in x0..x1 {
                                img.put_pixel(xx, yy, image::Luma([gray]));
                            }
                        }
                    }
                }
                "BT" | "ET" | "Tf" | "Td" | "Tj" => {}
                other => panic!("the emitter draws with {other:?}, which this cannot paint"),
            }
        }
        assert!(pending.is_empty(), "rectangles were built and never filled");
        image::DynamicImage::ImageLuma8(img)
    }

    /// The whole loop through the file a holder actually prints: notes
    /// become a PDF, the PDF becomes pixels at an ordinary scan
    /// resolution, and the pixels become the same notes.
    ///
    /// Two pages, because a second page is where an offset or a page
    /// tree mistake would show and a single page would hide it.
    #[test]
    fn the_pdf_scans_back_into_the_notes_it_came_from() {
        let seal = |b: &[u8]| -> kenter_wallet::Result<Vec<u8>> {
            let mut v = vec![0xA7];
            v.extend_from_slice(b);
            Ok(v)
        };
        let open = |b: &[u8]| match b.split_first() {
            Some((0xA7, rest)) => Ok(rest.to_vec()),
            _ => Err(kenter_wallet::WalletError::Backup("wrong key".into())),
        };
        let held: Vec<kenter_wallet::HeldToken> = (1..=10u8)
            .map(|i| kenter_wallet::testing::spend_note(i, 1_000 + i as u64, i as u32))
            .collect();
        let chunks = paper::encode("5e1f0c2a9d4b7368", &held, &[], Some(17), seal).unwrap();
        assert!(sheet::layout(&chunks).len() >= 2, "want a second page to test");

        let doc = lopdf::Document::load_mem(&render(&chunks, "5e1f0c2a9d4b7368", "d").unwrap())
            .unwrap();
        let mut sheet = paper::Sheet::new();
        for (n, id) in doc.get_pages() {
            let found = crate::scan::read_dynamic(&paint(&doc, id, crate::scan::WANTED_WIDTH));
            assert!(!found.symbols.is_empty(), "page {n} decoded to nothing");
            for sym in found.symbols {
                sheet.add(sym).unwrap();
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
        assert_eq!(got, want, "every field of every note survived the PDF");
    }

    #[test]
    fn an_empty_backup_prints_nothing() {
        assert!(render(&[], "f", "d").is_err());
    }
}
