//! The results log.
//!
//! A run that leaves nothing behind cannot be argued with afterwards, so every
//! assertion is recorded with the value that was actually observed — not just
//! whether it passed. A failure is only useful if it says what the ledger
//! said.
//!
//! Written to disk as the run goes rather than at the end: a run that is
//! interrupted, or that wedges on a step, still leaves everything up to that
//! point.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub struct Recorder {
    path: PathBuf,
    body: String,
    pub passed: usize,
    pub failed: usize,
}

impl Recorder {
    pub fn new(dir: &Path, title: &str) -> std::io::Result<Recorder> {
        std::fs::create_dir_all(dir)?;
        let stamp = stamp();
        let path = dir.join(format!("{stamp}.md"));
        let mut rec = Recorder {
            path,
            body: String::new(),
            passed: 0,
            failed: 0,
        };
        let _ = writeln!(rec.body, "# {title}\n");
        let _ = writeln!(rec.body, "Run started {stamp}.\n");
        rec.flush()?;
        Ok(rec)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn phase(&mut self, name: &str) {
        println!("\n=== {name} ===");
        let _ = writeln!(self.body, "\n## {name}\n");
        let _ = self.flush();
    }

    /// Something that happened, with no pass/fail attached.
    pub fn note(&mut self, line: &str) {
        println!("  {line}");
        let _ = writeln!(self.body, "- {line}");
        let _ = self.flush();
    }

    /// A fact the run depends on, with what was actually seen.
    ///
    /// `observed` is recorded on success as well as failure. A log that only
    /// records values when something broke cannot be used to check a later
    /// run against an earlier one.
    pub fn check(&mut self, ok: bool, what: &str, observed: impl std::fmt::Display) -> bool {
        if ok {
            self.passed += 1;
            println!("  [pass] {what} — {observed}");
            let _ = writeln!(self.body, "- **pass** — {what} (`{observed}`)");
        } else {
            self.failed += 1;
            println!("  [FAIL] {what} — {observed}");
            let _ = writeln!(self.body, "- **FAIL** — {what} (`{observed}`)");
        }
        let _ = self.flush();
        ok
    }

    /// A block of captured output — a daemon's log, usually.
    pub fn block(&mut self, title: &str, text: &str) {
        let _ = writeln!(self.body, "\n<details><summary>{title}</summary>\n");
        let _ = writeln!(self.body, "```\n{}\n```\n", text.trim_end());
        let _ = writeln!(self.body, "</details>\n");
        let _ = self.flush();
    }

    pub fn verdict(&mut self) {
        let v = if self.failed == 0 {
            format!("**PASS** — {} checks", self.passed)
        } else {
            format!("**FAIL** — {} passed, {} failed", self.passed, self.failed)
        };
        println!("\n=== {v} ===");
        let _ = writeln!(self.body, "\n## Verdict\n\n{v}\n");
        let _ = self.flush();
    }

    fn flush(&self) -> std::io::Result<()> {
        let mut f = std::fs::File::create(&self.path)?;
        f.write_all(self.body.as_bytes())
    }
}

/// `YYYY-MM-DD-HHMMSS` in UTC, without pulling in a date crate for one line.
fn stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Civil-from-days (Howard Hinnant's algorithm), era-based.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}-{h:02}{m:02}{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stamp is the run's filename, so a wrong one silently overwrites a
    /// previous run's log.
    #[test]
    fn the_stamp_looks_like_a_date() {
        let s = stamp();
        assert_eq!(s.len(), 17, "{s}");
        let (date, time) = s.split_at(10);
        assert_eq!(date.matches('-').count(), 2, "{s}");
        assert!(time.starts_with('-') && time[1..].chars().all(|c| c.is_ascii_digit()), "{s}");
        let year: i64 = date[..4].parse().unwrap();
        assert!((2025..2100).contains(&year), "{s}");
        let month: u32 = date[5..7].parse().unwrap();
        assert!((1..=12).contains(&month), "{s}");
        let day: u32 = date[8..10].parse().unwrap();
        assert!((1..=31).contains(&day), "{s}");
    }

    #[test]
    fn a_failed_check_is_counted_and_reported() {
        // Per-process, because the recorder names its file from a stamp with
        // one-second granularity. A fixed directory meant two concurrent runs
        // of this binary wrote the same path, and a read could land on the
        // other process's header-only flush. Reproduced at ~12% across 80
        // interleaved runs before this line changed.
        let dir = std::env::temp_dir()
            .join(format!("kenter-systest-log-test-{}", std::process::id()));
        let mut r = Recorder::new(&dir, "test").unwrap();
        assert!(r.check(true, "a", 1));
        assert!(!r.check(false, "b", 2));
        assert_eq!((r.passed, r.failed), (1, 1));
        let written = std::fs::read_to_string(r.path()).unwrap();
        // Observed values are recorded on success too, so runs can be compared.
        assert!(written.contains("**pass** — a (`1`)"), "{written}");
        assert!(written.contains("**FAIL** — b (`2`)"), "{written}");
        let _ = std::fs::remove_file(r.path());
        let _ = std::fs::remove_dir(&dir);
    }
}
