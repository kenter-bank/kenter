//! The wallet's backup file: writing one, remembering it, restoring from it.
//!
//! `kenter_wallet::backup` is the format and the merge rules; this is the part
//! that touches a disk and so cannot live in the wasm-safe core.
//!
//! # Two different files, deliberately not conflated
//!
//! Card provisioning writes a backup next to the vault, and that file is
//! **not a backup**. It is on the same disk as the wallet it backs up, so it
//! survives a corrupt store and nothing else — not a lost laptop, which is the
//! case a holder means. It exists so that "save a backup" always has something
//! current to hand over, and so a fresh card wallet has a file recording its
//! origin and fingerprint before it holds anything worth losing.
//!
//! The backup that counts is the one the holder puts somewhere else. Only that
//! one is recorded with [`kenter_wallet::Store::record_backup`], and only that
//! record answers "am I covered?" on the billfold. Writing the local copy must
//! never move that date forward, or the wallet reassures a holder on the
//! strength of a file that will be lost alongside everything else.

use std::path::{Path, PathBuf};

use kenter_wallet::backup::{
    self, BackupContents, Coverage, RestoreReport, SeedOrigin, SeedSource,
};
use kenter_wallet::{FileStore, Store, WalletError};

/// Extension for a Kenter wallet backup. Matches what provisioning writes.
pub const EXT: &str = "kbk";

/// Suggested filename, which includes the fingerprint so a holder with two
/// cards ends up with two files rather than one overwritten one.
pub fn file_name(fingerprint: &str) -> String {
    format!("kenter-backup-{fingerprint}.{EXT}")
}

/// The wallet's own working copy, beside the vault. See the module note on
/// why this is not the backup.
pub fn working_copy_path(fingerprint: &str) -> Option<PathBuf> {
    Some(
        crate::receive::default_vault_path()?.with_file_name(file_name(fingerprint)),
    )
}

/// How a restorer gets to this wallet's seed.
///
/// A card wallet's phrase *is* the card's seed, so the origin is
/// [`SeedOrigin::Card`] and there is no BIP85 derivation to record — the
/// child index concerns the *account* vault, which a backup does not restore.
///
/// [`Custody::RecoveredCard`] writes `Card` too, and that is the whole point
/// rather than a loose end. The origin does not say where the seed is kept;
/// it says **which derivation opens the file**, and a recovered wallet still
/// derives its keys the card's way. Stamping its backups `Software` — which
/// a `_ =>` arm does, silently — would make every file it writes after the
/// recovery unrestorable, which is a worse failure than the one the recovery
/// was for: this time the holder would have done everything right.
pub fn seed_source(custody: Option<&kenter_vault::Custody>, fingerprint: &str) -> SeedSource {
    match custody {
        Some(kenter_vault::Custody::Card { .. } | kenter_vault::Custody::RecoveredCard { .. }) => {
            SeedSource {
                fingerprint: fingerprint.to_string(),
                origin: SeedOrigin::Card,
                bip85: None,
            }
        }
        Some(kenter_vault::Custody::Software) | None => SeedSource::software(fingerprint),
    }
}

/// Write a backup where the holder asked, and remember that it happened.
///
/// The order is the point. The record is written **after** the bytes have
/// landed, so a failed write leaves the wallet still saying "not backed up"
/// rather than claiming a file that is not there.
///
/// Returns where it went.
pub async fn save(
    store: &mut FileStore,
    key: &[u8; 32],
    seed: &SeedSource,
    dest: &Path,
    now: i64,
) -> Result<PathBuf, String> {
    // Snapshot first, and build the record from the same slice that is
    // sealed: taking `store.all()` twice could straddle an arriving note and
    // record a digest the file does not have.
    let tokens = store.all().await.map_err(|e| e.to_string())?;
    let pending = store.pending().await.map_err(|e| e.to_string())?;
    let next = store.advance_owner_index(0).await.map_err(|e| e.to_string())?;
    let bytes = backup::encode(key, seed, &tokens, &pending, Some(next), now)
        .map_err(|e| e.to_string())?;

    write_atomic(dest, &bytes)?;
    store
        .record_backup(backup::record_for(
            &tokens,
            now,
            Some(dest.display().to_string()),
        ))
        .await
        .map_err(|e| format!("the backup was written to {} but could not be recorded: {e}", dest.display()))?;
    Ok(dest.to_path_buf())
}

/// Refresh the working copy beside the vault, if it is not already current.
///
/// Deliberately **not** recorded as a backup, and deliberately quiet: this
/// runs after anything that changes the store, and a holder who is paid twice
/// should not be told about it twice. Failure is returned for logging, not
/// for a dialog — the working copy is a convenience, and a wallet that
/// refused to accept a note because it could not rewrite a spare copy would
/// have its priorities backwards.
pub async fn refresh_working_copy(
    store: &mut FileStore,
    key: &[u8; 32],
    seed: &SeedSource,
    now: i64,
) -> Result<Option<PathBuf>, String> {
    let path = working_copy_path(&seed.fingerprint).ok_or("set KENTER_VAULT")?;
    let tokens = store.all().await.map_err(|e| e.to_string())?;

    // Read the file rather than the record: this copy's freshness is its own
    // question, and the record is about the holder's real backup.
    let on_disk = std::fs::read(&path).ok();
    if backup::coverage(on_disk.as_deref(), &seed.fingerprint, &tokens).is_covered() {
        return Ok(None);
    }

    let pending = store.pending().await.map_err(|e| e.to_string())?;
    let next = store.advance_owner_index(0).await.map_err(|e| e.to_string())?;
    let bytes = backup::encode(key, seed, &tokens, &pending, Some(next), now)
        .map_err(|e| e.to_string())?;
    write_atomic(&path, &bytes)?;
    Ok(Some(path))
}

/// What the billfold shows: coverage against the holder's real backup.
pub async fn coverage(store: &FileStore) -> Result<Coverage, String> {
    let record = store.last_backup().await.map_err(|e| e.to_string())?;
    let tokens = store.all().await.map_err(|e| e.to_string())?;
    Ok(backup::coverage_of_record(record.as_ref(), &tokens))
}

/// Read a file's header, without any key: the first step of a restore.
pub fn inspect_file(path: &Path) -> Result<kenter_wallet::backup::BackupFile, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    backup::inspect(&bytes).map_err(|e| e.to_string())
}

/// Open a file and merge it into the store: the last steps of a restore.
///
/// Additive, per [`kenter_wallet::backup::restore`]: this can only give notes
/// back, never un-spend one that is already held.
pub async fn restore_file(
    store: &mut FileStore,
    key: &[u8; 32],
    fingerprint: &str,
    path: &Path,
) -> Result<RestoreReport, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let contents = open(key, fingerprint, &bytes)?;
    let report = backup::restore(store, &contents)
        .await
        .map_err(|e| e.to_string())?;
    adopt(store, &contents, Some(path.display().to_string())).await?;
    Ok(report)
}

/// Take the restored file on as this wallet's backup, if it has none.
///
/// A wallet that has just restored four notes **is** backed up: the file is
/// in the holder's drawer and holds exactly those notes. Without this the
/// billfold greets them with "4 notes in no backup - if this computer is
/// lost, so are they", which is false, and a false alarm on the first
/// screen after a recovery is how a holder learns to stop reading the line.
///
/// Recorded at the file's own date, not now, so "saved 3 days ago" stays
/// true and a note arriving tomorrow still makes it stale.
///
/// Only when there is no record yet. Restoring an old file into a wallet
/// that already has a newer backup must not talk it down — that direction
/// is the one that loses notes, and it is the same argument that makes
/// `backup::restore` additive.
pub async fn adopt(
    store: &mut FileStore,
    contents: &BackupContents,
    whence: Option<String>,
) -> Result<(), String> {
    if store
        .last_backup()
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Ok(());
    }
    store
        .record_backup(backup::record_for(
            &contents.tokens,
            contents.created_at,
            whence,
        ))
        .await
        .map_err(|e| e.to_string())
}

/// Decrypt, with the fingerprint check that makes a wrong file say so.
pub fn open(key: &[u8; 32], fingerprint: &str, bytes: &[u8]) -> Result<BackupContents, String> {
    backup::decode(key, fingerprint, bytes).map_err(|e| match e {
        WalletError::Backup(m) => m,
        other => other.to_string(),
    })
}

/// Unix seconds, as a holder would say it.
///
/// Relative rather than a date, because the question behind "when did I last
/// back up" is "how much has happened since", and nobody converts a date to
/// that in their head. Coarse on purpose: the difference between six and
/// seven days does not change what anyone does.
pub fn when(at: i64) -> String {
    when_since(at, now())
}

/// The clock, in Unix seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn when_since(at: i64, now: i64) -> String {
    let secs = now - at;
    // A backup stamped in the future is a clock that has been changed, not a
    // backup from the future. Saying "in 3 days" would be absurd; saying
    // "just now" is close enough and is not a claim about anything.
    if secs < 60 {
        return "just now".into();
    }
    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    let (n, unit) = if secs < HOUR {
        (secs / MINUTE, "minute")
    } else if secs < DAY {
        (secs / HOUR, "hour")
    } else if secs < 60 * DAY {
        (secs / DAY, "day")
    } else {
        (secs / (30 * DAY), "month")
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

/// Write via a temporary beside the target, then rename.
///
/// A backup is the one file where a partial write is worse than no write at
/// all: it would replace a good file with a truncated one, and the holder
/// would not find out until they needed it. The temp lives in the
/// destination directory so the rename stays on one filesystem, which is what
/// makes it atomic.
fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = dest.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let tmp = dest.with_extension(format!("{EXT}.tmp"));
    std::fs::write(&tmp, bytes).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    // Windows `rename` refuses an existing target, unlike POSIX.
    match std::fs::rename(&tmp, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::remove_file(dest).ok();
            std::fs::rename(&tmp, dest).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                format!("replacing {}: {e}", dest.display())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kenter_wallet::models::HeldToken;

    fn creds() -> kenter_vault::StoreCredentials {
        kenter_vault::StoreCredentials {
            aead: zeroize::Zeroizing::new([7u8; 32]),
            name: zeroize::Zeroizing::new([9u8; 32]),
        }
    }

    /// A genuine note: real chain, real signature, and an id derived from
    /// its own container.
    ///
    /// It was a hand-built record with a blob of repeated bytes, which
    /// `restore` now refuses rather than stores. Shared with every other
    /// fixture through `kenter_wallet::testing`, so the four places that
    /// need real notes cannot drift apart.
    fn token(seed: u8) -> HeldToken {
        kenter_wallet::testing::spend_note(seed, 1_000 + seed as u64, seed as u32)
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kenter-bk-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    const KEY: [u8; 32] = [0x33; 32];
    const FP: &str = "abcdef0123456789";

    /// The whole promise, end to end over a real filesystem: a wallet with
    /// notes, a file, a wallet with nothing, the notes back.
    #[tokio::test]
    async fn a_saved_file_restores_into_an_empty_wallet() {
        let root = tmp("roundtrip");
        let seed = SeedSource::software(FP);
        let dest = root.join("backup.kbk");

        let mut store = FileStore::open(&root.join("a"), creds()).unwrap();
        store.put(token(1)).await.unwrap();
        store.put(token(2)).await.unwrap();
        store.advance_owner_index(9).await.unwrap();
        save(&mut store, &KEY, &seed, &dest, 1_700_000_900)
            .await
            .unwrap();

        let mut fresh = FileStore::open(&root.join("b"), creds()).unwrap();
        let report = restore_file(&mut fresh, &KEY, FP, &dest).await.unwrap();

        assert_eq!(report.tokens_added, 2);
        assert_eq!(fresh.all().await.unwrap().len(), 2);
        assert_eq!(fresh.allocate_owner_index().await.unwrap(), 9);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Saving records the backup; receiving afterwards makes it stale. This
    /// is the sentence on the billfold, so it has to be the truth.
    #[tokio::test]
    async fn saving_records_coverage_and_a_receipt_breaks_it() {
        let root = tmp("coverage");
        let seed = SeedSource::software(FP);
        let mut store = FileStore::open(&root.join("w"), creds()).unwrap();
        store.put(token(1)).await.unwrap();

        assert_eq!(coverage(&store).await.unwrap(), Coverage::Missing);

        save(&mut store, &KEY, &seed, &root.join("b.kbk"), 1_700_000_900)
            .await
            .unwrap();
        let c = coverage(&store).await.unwrap();
        assert!(c.is_covered(), "{c:?}");

        store.put(token(2)).await.unwrap();
        assert!(matches!(
            coverage(&store).await.unwrap(),
            Coverage::Stale { in_file: 1, held: 2, .. }
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Replacing an existing file must work (Windows rename refuses a live
    /// target) and must leave no `.tmp` behind.
    #[tokio::test]
    async fn saving_over_an_existing_file_replaces_it_cleanly() {
        let root = tmp("replace");
        let seed = SeedSource::software(FP);
        let dest = root.join("b.kbk");
        let mut store = FileStore::open(&root.join("w"), creds()).unwrap();

        store.put(token(1)).await.unwrap();
        save(&mut store, &KEY, &seed, &dest, 10).await.unwrap();
        store.put(token(2)).await.unwrap();
        save(&mut store, &KEY, &seed, &dest, 20).await.unwrap();

        let header = inspect_file(&dest).unwrap();
        assert_eq!(header.token_count, 2);
        assert_eq!(header.created_at, 20);
        assert!(!dest.with_extension("kbk.tmp").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The distinction the module note is about: the working copy keeps
    /// itself current, and that must not count as having backed up.
    #[tokio::test]
    async fn the_working_copy_does_not_count_as_a_backup() {
        let root = tmp("working");
        std::env::set_var("KENTER_VAULT", root.join("vault.json"));
        let seed = SeedSource::software(FP);
        let mut store = FileStore::open(&root.join("w"), creds()).unwrap();
        store.put(token(1)).await.unwrap();

        let written = refresh_working_copy(&mut store, &KEY, &seed, 10)
            .await
            .unwrap();
        assert_eq!(written, working_copy_path(FP));
        assert!(written.unwrap().exists());

        // The file is current, so a second call writes nothing...
        assert_eq!(
            refresh_working_copy(&mut store, &KEY, &seed, 11).await.unwrap(),
            None
        );
        // ...and the wallet still has no backup to its name.
        assert_eq!(coverage(&store).await.unwrap(), Coverage::Missing);

        store.put(token(2)).await.unwrap();
        assert!(refresh_working_copy(&mut store, &KEY, &seed, 12)
            .await
            .unwrap()
            .is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A file for another wallet fails by name, not as a decrypt error.
    #[tokio::test]
    async fn another_wallets_file_is_refused_by_name() {
        let root = tmp("wrong");
        let dest = root.join("b.kbk");
        let mut store = FileStore::open(&root.join("w"), creds()).unwrap();
        store.put(token(1)).await.unwrap();
        save(
            &mut store,
            &KEY,
            &SeedSource::software("0000000000000000"),
            &dest,
            10,
        )
        .await
        .unwrap();

        let mut fresh = FileStore::open(&root.join("b"), creds()).unwrap();
        let err = restore_file(&mut fresh, &KEY, FP, &dest).await.unwrap_err();
        assert!(err.contains("different wallet"), "{err}");
        assert!(fresh.all().await.unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A wallet that has just restored is backed up, and must not be told
    /// otherwise on the first screen it shows after a recovery.
    #[tokio::test]
    async fn restoring_adopts_the_file_as_this_wallet_s_backup() {
        let root = tmp("adopt");
        let seed = SeedSource::software(FP);
        let dest = root.join("b.kbk");

        let mut old = FileStore::open(&root.join("a"), creds()).unwrap();
        old.put(token(1)).await.unwrap();
        old.put(token(2)).await.unwrap();
        save(&mut old, &KEY, &seed, &dest, 1_700_000_900).await.unwrap();

        let mut fresh = FileStore::open(&root.join("b"), creds()).unwrap();
        assert_eq!(coverage(&fresh).await.unwrap(), Coverage::Missing);
        restore_file(&mut fresh, &KEY, FP, &dest).await.unwrap();

        let c = coverage(&fresh).await.unwrap();
        assert!(c.is_covered(), "{c:?}");
        // The file's own date, so "saved 3 days ago" stays true.
        assert_eq!(
            c,
            Coverage::Covered {
                created_at: 1_700_000_900,
                notes: 2
            }
        );
        // And where it came from, so "make another" has an obvious answer.
        let record = fresh.last_backup().await.unwrap().unwrap();
        assert_eq!(record.whence.as_deref(), Some(dest.display().to_string().as_str()));

        // A note arriving afterwards still makes it stale - adopting is not
        // a way to stop being warned.
        fresh.put(token(3)).await.unwrap();
        assert!(coverage(&fresh).await.unwrap().needs_refresh());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Restoring an old file into a wallet that already has a newer backup
    /// must not talk it down. Same direction of travel as `restore` itself.
    #[tokio::test]
    async fn restoring_an_old_file_does_not_downgrade_a_newer_record() {
        let root = tmp("no-downgrade");
        let seed = SeedSource::software(FP);

        let mut store = FileStore::open(&root.join("w"), creds()).unwrap();
        store.put(token(1)).await.unwrap();
        let old_file = root.join("old.kbk");
        save(&mut store, &KEY, &seed, &old_file, 10).await.unwrap();

        // Later: another note, and a fresh backup.
        store.put(token(2)).await.unwrap();
        save(&mut store, &KEY, &seed, &root.join("new.kbk"), 20)
            .await
            .unwrap();
        assert!(coverage(&store).await.unwrap().is_covered());

        // Restoring the stale file changes nothing and says nothing new.
        let report = restore_file(&mut store, &KEY, FP, &old_file).await.unwrap();
        assert!(report.is_empty());
        assert_eq!(
            coverage(&store).await.unwrap(),
            Coverage::Covered {
                created_at: 20,
                notes: 2
            },
            "an older file talked the record backwards"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn when_reads_the_way_a_person_would_say_it() {
        const M: i64 = 60;
        const H: i64 = 60 * M;
        const D: i64 = 24 * H;
        for (ago, want) in [
            (0, "just now"),
            (59, "just now"),
            (M, "1 minute ago"),
            (5 * M, "5 minutes ago"),
            (H, "1 hour ago"),
            (23 * H, "23 hours ago"),
            (D, "1 day ago"),
            (9 * D, "9 days ago"),
            (59 * D, "59 days ago"),
            (90 * D, "3 months ago"),
        ] {
            assert_eq!(when_since(1_000_000 - ago, 1_000_000), want, "{ago}s ago");
        }
    }

    /// A clock moved backwards must not produce "in 3 days", which reads as
    /// nonsense and tells the holder nothing.
    #[test]
    fn a_backup_stamped_in_the_future_is_not_announced_as_such() {
        assert_eq!(when_since(2_000_000, 1_000_000), "just now");
    }

    #[test]
    fn a_card_wallet_records_a_card_origin() {
        let s = seed_source(
            Some(&kenter_vault::Custody::Card {
                seed_fingerprint: FP.into(),
                card_identity: "03ab".into(),
            }),
            FP,
        );
        assert_eq!(s.origin, SeedOrigin::Card);
        assert!(s.bip85.is_none());
        assert_eq!(seed_source(None, FP).origin, SeedOrigin::Software);
        assert_eq!(
            seed_source(Some(&kenter_vault::Custody::Software), FP).origin,
            SeedOrigin::Software
        );
    }

    /// A wallet recovered from a lost card still derives the card's way, so
    /// its own backups must say so. A `_ =>` arm here would mark them
    /// `Software` without a word, and every file written after the recovery
    /// would be unrestorable - with the holder having done nothing wrong.
    #[test]
    fn a_recovered_card_wallet_keeps_writing_card_origin() {
        let s = seed_source(
            Some(&kenter_vault::Custody::RecoveredCard {
                seed_fingerprint: FP.into(),
            }),
            FP,
        );
        assert_eq!(s.origin, SeedOrigin::Card);
        assert!(s.bip85.is_none());
        assert_eq!(s.fingerprint, FP);
    }
}
