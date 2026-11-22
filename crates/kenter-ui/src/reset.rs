//! Resetting a wallet that cannot be opened.
//!
//! A vault can become impossible to open for good: its card wiped or lost,
//! its passphrase forgotten. Without a reset the wallet would sit on its own
//! front door with no way back to a first run short of deleting
//! `vault.json` by hand.
//!
//! **A reset moves, it never deletes.** The vault file, the note store and any
//! paper-backup files beside the vault go into a dated folder next to them.
//! Then the client finds no vault and offers a first run. What was moved can
//! be moved back, and the notes in it are as recoverable as they ever were:
//! with the old card or passphrase, or from a paper backup. Nothing here
//! decides that a wallet is gone, because it cannot know. It only stops the
//! client insisting on one.

use std::path::{Path, PathBuf};

/// What a reset would move, worked out before anything is touched, so the
/// screen can show exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Where everything goes: `reset-<unix seconds>` beside the vault.
    pub archive: PathBuf,
    /// `(from, to)` for each thing that exists and will be moved.
    pub moves: Vec<(PathBuf, PathBuf)>,
    /// The paper-backup files among them (`*.kbk`), by name, for the screen
    /// to point at: they are the way back to these notes on a new wallet.
    pub backups: Vec<String>,
}

/// Plan a reset of the vault at `vault` and the store at `store`, stamped
/// `now` (unix seconds).
pub fn plan(vault: &Path, store: &Path, now: u64) -> Plan {
    let base = vault.parent().map(Path::to_path_buf).unwrap_or_default();
    let archive = base.join(format!("reset-{now}"));
    let mut moves = Vec::new();
    let mut backups = Vec::new();
    let mut take = |from: &Path| {
        if from.exists() {
            if let Some(name) = from.file_name() {
                moves.push((from.to_path_buf(), archive.join(name)));
            }
        }
    };
    take(vault);
    take(store);
    // Paper-backup files sit beside the vault (`backup.rs`). Moving them
    // with the vault keeps one folder that holds everything this wallet was.
    if let Ok(entries) = std::fs::read_dir(&base) {
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "kbk"))
            .collect();
        found.sort();
        for p in found {
            if let Some(name) = p.file_name() {
                backups.push(name.to_string_lossy().into_owned());
            }
            take(&p);
        }
    }
    Plan { archive, moves, backups }
}

/// Carry out `plan`. Stops at the first failure and says which move it was;
/// what moved before it stays moved, and is in the archive.
pub fn perform(plan: &Plan) -> Result<(), String> {
    if plan.moves.is_empty() {
        return Err("there is nothing here to reset".into());
    }
    std::fs::create_dir_all(&plan.archive)
        .map_err(|e| format!("creating {}: {e}", plan.archive.display()))?;
    for (from, to) in &plan.moves {
        std::fs::rename(from, to)
            .map_err(|e| format!("moving {} to {}: {e}", from.display(), to.display()))?;
    }
    Ok(())
}

/// The word the holder types to confirm. Capitals, so it is typed on
/// purpose and not slipped into from a passphrase field.
pub const CONFIRM_WORD: &str = "RESET";

/// Whether `typed` confirms the reset.
pub fn confirmed(typed: &str) -> bool {
    typed.trim() == CONFIRM_WORD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rig() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.json");
        let store = dir.path().join("wallet");
        std::fs::write(&vault, b"{}").unwrap();
        std::fs::create_dir_all(store.join("tokens")).unwrap();
        std::fs::write(store.join("tokens").join("n.json"), b"note").unwrap();
        std::fs::write(dir.path().join("kenter-backup-1.kbk"), b"paper").unwrap();
        (dir, vault, store)
    }

    #[test]
    fn a_reset_moves_everything_and_deletes_nothing() {
        let (dir, vault, store) = rig();
        let p = plan(&vault, &store, 42);
        assert_eq!(p.archive, dir.path().join("reset-42"));
        assert_eq!(p.moves.len(), 3);
        assert_eq!(p.backups, vec!["kenter-backup-1.kbk".to_string()]);
        perform(&p).unwrap();

        // Gone from where the client looks, so it offers a first run...
        assert!(!vault.exists() && !store.exists());
        // ...and every byte is in the archive.
        assert_eq!(std::fs::read(p.archive.join("vault.json")).unwrap(), b"{}");
        assert_eq!(
            std::fs::read(p.archive.join("wallet").join("tokens").join("n.json")).unwrap(),
            b"note"
        );
        assert_eq!(std::fs::read(p.archive.join("kenter-backup-1.kbk")).unwrap(), b"paper");
    }

    #[test]
    fn a_missing_store_is_not_an_error() {
        let (_dir, vault, store) = rig();
        std::fs::remove_dir_all(&store).unwrap();
        let p = plan(&vault, &store, 1);
        assert_eq!(p.moves.len(), 2, "the vault and the backup");
        perform(&p).unwrap();
    }

    #[test]
    fn nothing_to_reset_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = plan(&dir.path().join("vault.json"), &dir.path().join("wallet"), 1);
        assert!(perform(&p).is_err());
    }

    #[test]
    fn only_the_word_confirms() {
        assert!(confirmed("RESET"));
        assert!(confirmed(" RESET "));
        assert!(!confirmed("reset"));
        assert!(!confirmed("RESE"));
        assert!(!confirmed(""));
    }
}
