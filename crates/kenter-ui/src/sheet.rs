//! The printable page: a backup laid out as QR symbols.
//!
//! # SVG and PDF, both
//!
//! [`crate::pdf`] is what a holder prints: it carries its own page size, so
//! a module is 0.30mm on the paper rather than whatever a viewer decided,
//! and several pages arrive as one file.
//!
//! This emitter stays, and not merely as a preview. SVG is **vector paths**,
//! which is what a laser engraver or a CNC takes — so the same sheet can be
//! cut into metal, which outlives paper by a wide margin and is what a
//! serious long-term backup actually wants. Both emitters share
//! [`layout`] so the geometry cannot differ between the thing that was
//! tested and the thing that gets made.
//!
//! An SVG written to a file, not a screen. The artefact is a sheet of paper
//! that has to be printable by whatever the holder owns and readable years
//! later, and neither of those is served by rendering it into a window
//! first. SVG also means the printer's resolution decides the module size
//! rather than ours, which is exactly the right way round for something a
//! scanner will read.
//!
//! # What is on the page, besides the codes
//!
//! Everything a person needs to use the sheet without this program in front
//! of them, because the situation a paper backup is for is the one where
//! they have lost the machine:
//!
//! - **Which wallet**, by fingerprint. A holder with two sheets has no
//!   other way to tell them apart, and the fingerprint is already public in
//!   the file header.
//! - **What else is needed** — the recovery phrase. A sheet alone is not a
//!   wallet, and somebody finding one should learn that from the sheet
//!   rather than from hope.
//! - **How many symbols there are**, numbered, so a missing one is
//!   countable rather than discovered at the end of a scan.
//! - **The date**, because the only question a holder asks of two backups
//!   is which is newer.
//!
//! What is deliberately *not* on it: the amount, the note count, anything
//! about what the wallet is worth. A sheet in a drawer should not advertise
//! that it is worth stealing, and the header already gives a thief the
//! fingerprint whether we print it or not.

use kenter_wallet::paper::Chunk;
use qrcode::EcLevel;

/// Millimetres, A4 portrait. Letter is shorter (279mm) and the layout is
/// computed from the page height, so a Letter printer simply gets a tighter
/// bottom margin rather than a clipped sheet.
pub const PAGE_W: f32 = 210.0;
pub const PAGE_H: f32 = 297.0;
pub const MARGIN: f32 = 14.0;

/// The module size, in millimetres — the single number that decides how
/// many pages a backup is.
///
/// **0.30mm**, which is roughly seven dots at 600dpi: a laser printer holds
/// it and a phone camera resolves it at normal reading distance. It was
/// 0.42mm, chosen cautiously before anything had been printed, and that
/// caution cost real pages: a four-note wallet was four sheets at 0.42 and
/// is two at 0.30. That is most of the gain a higher-density symbology
/// would have bought, without writing an encoder and a decoder whose bugs
/// would only surface on the day someone needed them.
///
/// A function rather than a constant so it can be overridden, because this
/// is a claim about printers and cameras and should be settled by printing
/// one and scanning it rather than by argument:
///
/// ```text
/// KENTER_PAPER_MODULE_MM=0.25 cargo run -p kenter-ui --example paper_sheet -- <file>
/// ```
///
/// Clamped, so a typo cannot quietly produce a sheet nothing can read.
pub fn module_mm() -> f32 {
    std::env::var("KENTER_PAPER_MODULE_MM")
        .ok()
        .and_then(|v| v.parse::<f32>().ok())
        .filter(|m| (0.15..=2.0).contains(m))
        .unwrap_or(0.30)
}

/// A version-40 symbol, plus the four modules of quiet zone each side that
/// the spec requires and scanners genuinely need.
pub(crate) const SYMBOL_MODULES: f32 = 177.0 + 8.0;
/// Space between symbols, and under each for its number.
const GAP: f32 = 4.0;
const CAPTION: f32 = 4.0;
/// Room at the top for the title and the four lines of instructions.
const HEAD: f32 = 30.0;

/// How many symbols fit on one page, and in what grid.
///
/// Computed rather than chosen, because the answer is not obvious and was
/// not what this module first assumed: a version-40 symbol at error
/// correction H is 185 modules across, and at the smallest module a printer
/// and a phone camera can agree on that is a square roughly 78mm on a side.
/// Four of those fill an A4 page. Eight — which is what a two-note wallet
/// needs — do not.
///
/// Lowering [`min_module`] to fit more would trade a visible problem now
/// for an invisible one later: a sheet that prints fine and fails to scan
/// in five years. Paginating is the honest answer.
fn grid() -> (usize, usize) {
    let symbol = SYMBOL_MODULES * module_mm();
    let cols = (((PAGE_W - 2.0 * MARGIN) + GAP) / (symbol + GAP)).floor().max(1.0) as usize;
    let rows = (((PAGE_H - 2.0 * MARGIN - HEAD) + GAP) / (symbol + CAPTION + GAP))
        .floor()
        .max(1.0) as usize;
    (cols, rows)
}

/// One symbol, placed on a page. Millimetres from the top-left.
#[derive(Debug, Clone)]
pub struct Placed<'a> {
    pub chunk: &'a Chunk,
    pub x: f32,
    pub y: f32,
    /// Side length of the symbol, quiet zone included.
    pub size: f32,
}

/// What goes on one page.
#[derive(Debug, Clone)]
pub struct Page<'a> {
    /// 1-based.
    pub number: usize,
    pub of: usize,
    pub symbols: Vec<Placed<'a>>,
}

/// Every place a symbol can sit on a page, as fractions of the page.
///
/// The positions do not depend on what is printed, so a **reader** can
/// use them without knowing the contents. That matters: handing a
/// decoder a whole page makes it hunt for finder patterns among eight
/// other symbols, and neighbouring patterns are exactly the clutter that
/// defeats it. Cropping to one slot hands it a clean, isolated symbol.
///
/// Returned as `(x, y, w, h)` in 0..1 of page width and height, so they
/// apply to an image of any resolution.
pub fn slots() -> Vec<(f32, f32, f32, f32)> {
    let (cols, rows) = grid();
    let size = SYMBOL_MODULES * module_mm();
    (0..cols * rows)
        .map(|i| {
            let x = MARGIN + (i % cols) as f32 * (size + GAP);
            let y = MARGIN + HEAD + (i / cols) as f32 * (size + CAPTION + GAP);
            (x / PAGE_W, y / PAGE_H, size / PAGE_W, size / PAGE_H)
        })
        .collect()
}

/// Where every symbol goes.
///
/// Geometry lives here and only here, because there are two emitters — SVG
/// for the screen and tests, PDF for the printer — and a page that differs
/// between them is a page whose scanning was proven in the wrong one.
pub fn layout(chunks: &[Chunk]) -> Vec<Page<'_>> {
    let (cols, rows) = grid();
    let per = cols * rows;
    let size = SYMBOL_MODULES * module_mm();
    let of = chunks.len().div_ceil(per).max(1);

    chunks
        .chunks(per)
        .enumerate()
        .map(|(p, group)| Page {
            number: p + 1,
            of,
            symbols: group
                .iter()
                .enumerate()
                .map(|(i, chunk)| Placed {
                    chunk,
                    x: MARGIN + (i % cols) as f32 * (size + GAP),
                    y: MARGIN + HEAD + (i / cols) as f32 * (size + CAPTION + GAP),
                    size,
                })
                .collect(),
        })
        .collect()
}

/// The four lines of heading every page carries, as `(y, size, bold, text)`.
///
/// Shared for the same reason as [`layout`]: a holder comparing the PDF
/// they printed with the preview they saw should not find different words.
pub fn heading_lines(page: &Page<'_>, fingerprint: &str, created: &str, symbols: usize) -> Vec<(f32, f32, bool, String)> {
    vec![
        (
            MARGIN + 7.0,
            6.0,
            true,
            format!("Kenter wallet backup - page {} of {}", page.number, page.of),
        ),
        (
            MARGIN + 13.0,
            3.4,
            false,
            format!("wallet {fingerprint} - saved {created} - {symbols} symbols in all"),
        ),
        (
            MARGIN + 19.0,
            3.4,
            false,
            "Scan every symbol on every page. This sheet is useless without your recovery phrase,"
                .into(),
        ),
        (
            MARGIN + 24.0,
            3.4,
            false,
            "and your phrase is useless without these sheets. Keep them apart.".into(),
        ),
    ]
}

/// Symbols per page. See [`grid`].
pub fn per_page() -> usize {
    let (c, r) = grid();
    c * r
}

/// Render the backup as printable pages.
///
/// One SVG per page, each self-describing: a holder who drops the stack can
/// put it back in order, and a missing page is countable rather than
/// discovered halfway through a scan.
pub fn pages(chunks: &[Chunk], fingerprint: &str, created: &str) -> Result<Vec<String>, String> {
    if chunks.is_empty() {
        return Err("nothing to print".into());
    }
    let (cols, rows) = grid();
    let per = cols * rows;
    let page_count = chunks.len().div_ceil(per);

    chunks
        .chunks(per)
        .enumerate()
        .map(|(p, group)| page(group, cols, p + 1, page_count, chunks.len(), fingerprint, created))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn page(
    group: &[Chunk],
    cols: usize,
    page_no: usize,
    page_count: usize,
    symbols: usize,
    fingerprint: &str,
    created: &str,
) -> Result<String, String> {
    let symbol = SYMBOL_MODULES * module_mm();
    let mut body = String::new();

    for (i, chunk) in group.iter().enumerate() {
        let col = i % cols;
        let row = i / cols;
        let x = MARGIN + col as f32 * (symbol + GAP);
        let y = MARGIN + HEAD + row as f32 * (symbol + CAPTION + GAP);

        // M, and the reason is in `kenter_wallet::paper`. It was H, on the
        // argument that the chunks carry no redundancy between them so one
        // unreadable symbol loses a whole item. That argument is sound and
        // it pointed the wrong way: the 30% H spends on recovery comes out
        // of the same symbol, and it pushed a sheet symbol to version 31,
        // which a camera could not read at all. Tolerating damage is worth
        // nothing to a symbol that cannot be read undamaged.
        let code = crate::qr::svg_bytes(&chunk.bytes, "#000000", "#ffffff", EcLevel::M, 4)
            .map_err(|e| format!("symbol {}: {e}", chunk.index + 1))?;
        // Inlining drops the symbol's own opening tag, and with it
        // `shape-rendering="crispEdges"` — so it is reapplied on the
        // group. Without it the renderer antialiases every module edge
        // into grey, and a page that looks perfect decodes at about half
        // its symbols no matter how large the scan is, which a raster
        // round trip shows at once.
        let inner = code
            .split_once('>')
            .map(|(_, rest)| rest.trim_end_matches("</svg>"))
            .unwrap_or("");

        body.push_str(&format!(
            "<g shape-rendering=\"crispEdges\" transform=\"translate({x:.2} {y:.2}) \
             scale({:.5})\">{inner}</g>\
             <text x=\"{:.2}\" y=\"{:.2}\" font-family=\"monospace\" font-size=\"3.2\" \
             text-anchor=\"middle\" fill=\"#000\">{}</text>",
            symbol / SYMBOL_MODULES,
            x + symbol / 2.0,
            y + symbol + 3.4,
            chunk.label(),
        ));
    }

    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{PAGE_W}mm\" height=\"{PAGE_H}mm\" \
         viewBox=\"0 0 {PAGE_W} {PAGE_H}\">\
         <rect width=\"{PAGE_W}\" height=\"{PAGE_H}\" fill=\"#ffffff\"/>\
         <text x=\"{MARGIN}\" y=\"{:.1}\" font-family=\"sans-serif\" font-size=\"6\" \
         font-weight=\"bold\" fill=\"#000\">Kenter wallet backup &#183; page {page_no} of \
         {page_count}</text>\
         <text x=\"{MARGIN}\" y=\"{:.1}\" font-family=\"monospace\" font-size=\"3.4\" \
         fill=\"#000\">wallet {fingerprint} &#183; saved {created} &#183; {symbols} symbols \
         in all</text>\
         <text x=\"{MARGIN}\" y=\"{:.1}\" font-family=\"sans-serif\" font-size=\"3.4\" \
         fill=\"#000\">Scan every symbol on every page. This sheet is useless without \
         your recovery phrase,</text>\
         <text x=\"{MARGIN}\" y=\"{:.1}\" font-family=\"sans-serif\" font-size=\"3.4\" \
         fill=\"#000\">and your phrase is useless without these sheets. Keep them \
         apart.</text>\
         {body}</svg>",
        MARGIN + 7.0,
        MARGIN + 13.0,
        MARGIN + 19.0,
        MARGIN + 24.0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_wallet::paper;

    /// A wallet of `notes` notes, as paper chunks.
    ///
    /// Notes are padded to the size a real one came out at (~1.6KB), so
    /// the page arithmetic these tests pin is the arithmetic a holder
    /// gets rather than one a small fixture flatters.
    /// A four-pair note's container, measured rather than assumed:
    /// `kenter print --pairs 4` writes 1401 bytes. Each further pair adds
    /// 290, so an eight-pair note is 2561 -- which is why the one-sheet
    /// property below is stated for four pairs and not in general.
    const NOTE_BYTES_4_PAIR: usize = 1401;

    fn chunks_for(notes: usize) -> Vec<paper::Chunk> {
        let held: Vec<kenter_wallet::HeldToken> = (1..=notes)
            .map(|i| {
                let mut t = kenter_wallet::testing::note(i as u8, 1_000);
                let mut x: u64 = 0x1234_5678_9ABC_DEF0 ^ i as u64;
                // The measured size of a real four-pair note, 1401 bytes;
                // notes grow 290 bytes a pair. The size matters: a figure
                // just over a symbol boundary would make the page count
                // look worse than production.
                t.blob.resize(NOTE_BYTES_4_PAIR, 0);
                for b in t.blob.iter_mut() {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *b = (x >> 24) as u8;
                }
                t
            })
            .collect();
        paper::encode("5e1f0c2a9d4b7368", &held, &[], Some(17), |plain| {
            // Stand-in for the AEAD: nonce plus tag, so the sizes are
            // honest without this test needing a key.
            let mut v = vec![0u8; 24];
            v.extend_from_slice(plain);
            v.extend_from_slice(&[0u8; 16]);
            Ok(v)
        })
        .unwrap()
    }

    /// The constraint that forced pagination, pinned so a later tweak to
    /// the margins cannot quietly make the sheet unscannable.
    #[test]
    fn a_page_holds_what_it_can_actually_print() {
        let (cols, rows) = grid();
        assert!(cols >= 1 && rows >= 1);
        let symbol = SYMBOL_MODULES * module_mm();
        assert!(
            MARGIN * 2.0 + cols as f32 * symbol + (cols as f32 - 1.0) * GAP <= PAGE_W,
            "{cols} columns overflow the page width"
        );
        assert!(
            MARGIN * 2.0 + HEAD + rows as f32 * (symbol + CAPTION) + (rows as f32 - 1.0) * GAP
                <= PAGE_H,
            "{rows} rows overflow the page height"
        );
        assert_eq!(per_page(), cols * rows);
    }

    #[test]
    fn every_symbol_lands_on_exactly_one_page() {
        for notes in [1usize, 2, 4] {
            let chunks = chunks_for(notes);
            let pages = pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap();

            assert_eq!(pages.len(), chunks.len().div_ceil(per_page()), "{notes} notes");
            let drawn: usize = pages.iter().map(|p| p.matches("<g shape-rendering").count()).sum();
            assert_eq!(drawn, chunks.len(), "{notes} notes: symbols drawn");

            // Every number appears exactly once across the stack, so a
            // holder can tell a missing page from a missing symbol.
            //
            // Matched as a whole text node: a caption reading "1 of 4" is a
            // substring of the header "page 1 of 4", and counting raw
            // substrings found the symbol twice on its own page.
            for c in &chunks {
                let node = format!(">{}</text>", c.label());
                let seen: usize = pages.iter().map(|p| p.matches(&node).count()).sum();
                assert_eq!(seen, 1, "symbol {} appears {seen} times", c.index + 1);
            }
        }
    }

    /// A dropped stack has to go back in order.
    /// The redesign's payoff, pinned: a four-note wallet of four-pair
    /// notes is one sheet. It was four sheets, when paper was one blob at
    /// a 0.42mm module.
    ///
    /// Stated for a pair count because it depends on one. A note grows
    /// 290 bytes a pair, and `DEFAULT_CHUNK_PAYLOAD` turns roughly every
    /// 850 of those into another symbol, so a wallet of eight-pair notes
    /// is two sheets. That is the honest cost of pairs, not a regression.
    #[test]
    fn a_four_note_wallet_is_a_single_sheet() {
        let chunks = chunks_for(4);
        let pages = pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap();
        assert_eq!(pages.len(), 1, "{} symbols", chunks.len());
    }

    #[test]
    fn each_page_says_which_page_it_is() {
        let chunks = chunks_for(12);
        let pages = pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap();
        assert!(pages.len() > 1, "twelve notes should need several pages");

        for (i, page) in pages.iter().enumerate() {
            assert!(
                page.contains(&format!("page {} of {}", i + 1, pages.len())),
                "page {} does not number itself",
                i + 1
            );
            assert!(page.starts_with("<svg"));
            assert!(page.ends_with("</svg>"));
        }
    }

    /// Each page must be usable by someone who no longer has the machine.
    #[test]
    fn every_page_says_what_a_person_needs_to_know() {
        let chunks = chunks_for(2);
        for page in pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap() {
            assert!(page.contains("5e1f0c2a9d4b7368"), "which wallet");
            assert!(page.contains("2026-10-24"), "which is newer");
            assert!(page.contains("recovery phrase"), "what else is needed");
            assert!(page.contains("symbols in all"), "how many to look for");
        }
    }

    /// And must not advertise that it is worth stealing.
    #[test]
    fn the_pages_do_not_advertise_the_balance() {
        let chunks = chunks_for(2);
        for page in pages(&chunks, "5e1f0c2a9d4b7368", "2026-10-24").unwrap() {
            for word in ["USDC", "balance", "amount", "worth", "notes held"] {
                assert!(!page.contains(word), "a page mentions {word}");
            }
        }
    }

    #[test]
    fn an_empty_backup_prints_nothing() {
        assert!(pages(&[], "f", "d").is_err());
    }
}
