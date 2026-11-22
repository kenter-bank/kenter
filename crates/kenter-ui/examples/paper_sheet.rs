//! Render a wallet as a printable paper backup — the wallet record and
//! each note as its own set of QR symbols.
//!
//! ```text
//! KENTER_CARD_PIN=123456 \
//!   cargo run -p kenter-ui --example paper_sheet -- <backup.kbk> [out-dir]
//! ```
//!
//! Needs the wallet's backup key, because paper seals each item
//! separately rather than the file once: the `.kbk` has to be opened and
//! its notes re-sealed individually.
//!
//! The key comes **from the card on the reader**, derived the same way a
//! session derives it. It is deliberately not taken as a value: a backup
//! key on a command line is in the shell history, and in an environment
//! variable it is in every child process and in `/proc`. `KENTER_VAULT`
//! must point at the wallet whose card this is.
//!
//! A dev tool, and the thing that answers "how many pages is my wallet"
//! before any of this is wired to a button.

use std::path::PathBuf;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let src = PathBuf::from(
        args.next()
            .ok_or("usage: paper_sheet <backup.kbk> [out-dir]")?,
    );
    let out = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| src.parent().unwrap_or(&PathBuf::from(".")).to_path_buf());

    let bytes = std::fs::read(&src).map_err(|e| format!("reading {}: {e}", src.display()))?;
    let header = kenter_wallet::backup::inspect(&bytes).map_err(|e| e.to_string())?;

    let key = backup_key(&header.seed_fingerprint)?;

    let contents = kenter_wallet::backup::decode(&key, &header.seed_fingerprint, &bytes)
        .map_err(|e| e.to_string())?;

    // Date only. The page sits in a drawer, and the only question asked of
    // two sheets is which is newer.
    let created = {
        let days = header.created_at / 86_400;
        let (y, m, d) = civil_from_days(days);
        format!("{y:04}-{m:02}-{d:02}")
    };

    let chunks = kenter_wallet::paper::encode(
        &header.seed_fingerprint,
        &contents.tokens,
        &contents.pending,
        contents.next_owner_index,
        |plain| kenter_wallet::backup::seal_item(&key, plain),
    )
    .map_err(|e| e.to_string())?;
    let pages = kenter_ui::sheet::pages(&chunks, &header.seed_fingerprint, &created)?;
    let pdf = kenter_ui::pdf::render(&chunks, &header.seed_fingerprint, &created)?;

    std::fs::create_dir_all(&out).map_err(|e| format!("creating {}: {e}", out.display()))?;

    // The PDF is the thing to print: it carries A4 in its MediaBox, so the
    // module is 0.30mm on the paper rather than whatever a viewer chose.
    let pdf_path = out.join("backup.pdf");
    std::fs::write(&pdf_path, &pdf).map_err(|e| format!("writing {}: {e}", pdf_path.display()))?;
    println!("  {}", pdf_path.display());

    // The SVGs are the same pages as vector paths, for a laser engraver or
    // a CNC - a backup cut into metal outlives one printed on paper.
    for (i, page) in pages.iter().enumerate() {
        let path = out.join(format!("backup-page-{}.svg", i + 1));
        std::fs::write(&path, page).map_err(|e| format!("writing {}: {e}", path.display()))?;
        println!("  {}", path.display());
    }

    println!();
    println!("  wallet    {}", header.seed_fingerprint);
    println!("  notes     {}", header.token_count);
    println!("  file      {} bytes", bytes.len());
    println!("  module    {:.2}mm", kenter_ui::sheet::module_mm());
    println!(
        "  symbols   {} across {} page{} ({} per page)",
        chunks.len(),
        pages.len(),
        if pages.len() == 1 { "" } else { "s" },
        kenter_ui::sheet::per_page(),
    );
    println!();
    println!("  Print backup.pdf at 100%. The SVGs are the same pages as paths,");
    println!("  for engraving rather than printing.");
    Ok(())
}

/// The wallet's backup key, from the card on the reader.
///
/// Checks the fingerprint before returning it, so a card for a different
/// wallet says so here rather than as a decryption failure per item.
fn backup_key(expected: &str) -> Result<[u8; 32], String> {
    let pin = std::env::var("KENTER_CARD_PIN").unwrap_or_else(|_| "123456".into());
    let (_, backup) = kenter_ui::card_setup::unlock(pin.as_bytes())
        .map_err(|e| format!("the card would not unlock: {e}"))?;
    if backup.fingerprint != expected {
        return Err(format!(
            "the card on the reader holds wallet {}, but that backup is for {expected}",
            backup.fingerprint
        ));
    }
    Ok(*backup.key)
}

/// Days since the Unix epoch to a civil date. Howard Hinnant's algorithm,
/// inlined rather than taking a date crate for one line of printing.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
