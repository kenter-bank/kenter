//! `FileStore` — the filesystem implementation of [`Store`](crate::ports::Store).
//!
//! Behind the `fs` feature, so the wasm build (which has no filesystem) simply
//! does not compile it. The PWA supplies IndexedDB against the same trait.
//!
//! It lives in the core rather than in a shell. Port impls that wrap a foreign
//! type (`ChainRead for MintClient`) must sit in the shell because of orphan
//! rules, but those do not apply to a type the impl defines itself, as
//! `MemoryStore` here shows. Both desktop shells (the `kenter` CLI and
//! `kenter-ui`) need it, and a binary-only crate is one the GUI cannot reach.
//!
//! # Layout
//!
//! ```text
//! <root>/
//!   tokens/
//!     <keyed-hash>.rec   one sealed file per held token, named by a keyed hash of its id
//!   pending/
//!     <keyed-hash>.rec   one sealed file per reserved-but-unconsummated receive
//!   state.json           sealed: the monotonic owner-index counter and last backup
//! ```
//!
//! One file per token rather than a single index: a write touches only the token
//! it concerns, so a crash mid-write can at worst damage that one record instead
//! of the whole wallet, and the directory is greppable.
//!
//! # On-disk format
//!
//! [`HeldToken`] carries the raw container bytes, which `serde_json` would render
//! as a JSON array of integers (~4x blowup, unreadable). So the file is a
//! shell-local [`StoredToken`] mirror with the byte fields hex-encoded — compact,
//! inspectable, and it keeps the core's type free of storage concerns.
//!
//! # Durability
//!
//! Writes go to a `.tmp` sibling which is then renamed over the target
//! (`std::fs::rename` replaces an existing file on both Windows and Unix), so a
//! reader never observes a half-written record.

use std::path::{Path, PathBuf};

use crate::models::{BackupRecord, HeldToken, PendingReceive, FIRST_FRESH_INDEX};
use crate::error::{Result, WalletError};
use crate::sealed::{record_name, seal, unseal};
use kenter_vault::StoreCredentials;
use crate::ports::{Store, StoreGuard};
use serde::{Deserialize, Serialize};

const TOKENS_DIR: &str = "tokens";
const PENDING_DIR: &str = "pending";
/// Extension on a sealed record. Keeps `.tmp` filtering working and marks the
/// files as ours without saying what is in them.
const RECORD_EXT: &str = "rec";

const STATE_FILE: &str = "state.json";

/// The advisory lock's file. Empty and never read — only its open handle
/// matters. Named so a holder who finds it knows it is not data.
const LOCK_FILE: &str = ".write-lock";

/// The state file's own lock. Separate from [`LOCK_FILE`] so it can be taken
/// inside a call path that already holds the wallet lock: that one is not
/// re-entrant (`Store::lock`). Held only across a read and a write of
/// `state.json`, never while anything else is taken, so the order is always
/// wallet lock then state lock and the two cannot deadlock.
const STATE_LOCK_FILE: &str = ".state-lock";

/// A held-token store backed by a directory of JSON files.
pub struct FileStore {
    tokens_dir: PathBuf,
    pending_dir: PathBuf,
    state_path: PathBuf,
    lock_path: PathBuf,
    state_lock_path: PathBuf,
    creds: StoreCredentials,
}


/// Wallet-level counters. Separate from the token records so allocating an index
/// never rewrites a token.
#[derive(Debug, Default, Serialize, Deserialize)]
struct WalletState {
    /// Next fresh owner-derivation index. Absent on a new wallet, meaning
    /// [`FIRST_FRESH_INDEX`] — index 0 stays reserved for the static receive
    /// address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_owner_index: Option<u32>,
    /// The last backup this wallet wrote. Sealed with the
    /// rest of the state: it names a path and a note count, which is a
    /// statement about what is held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_backup: Option<BackupRecord>,
}

/// The on-disk shape of a [`HeldToken`] (byte fields hex-encoded).
#[derive(Debug, Serialize, Deserialize)]
struct StoredToken {
    id: String,
    slot_id: u32,
    ephemeral_public_key: String,
    event_id: String,
    amount: u64,
    imported_at: i64,
    /// The mint whose ledger confirmed these bytes. Absent means unbound,
    /// never "whatever mint is configured now".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_index: Option<u32>,
    /// Hex; recorded at bind time so spent-away detection needs no vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    spent_away: bool,
    #[serde(default)]
    exports: crate::models::ExportLog,
    #[serde(default)]
    marked_spent: bool,
    blob: String,
}

impl FileStore {
    /// Open (creating if absent) a wallet store rooted at `dir`.
    ///
    /// There is deliberately no way to open one without keys. A pure-bearer
    /// note is redeemable from its container bytes alone, so a plaintext store
    /// *is* the money sitting readable on disk. Making
    /// the credentials a parameter rather than an option means that state
    /// cannot be reached by forgetting to opt in.
    ///
    /// Opening never imports plaintext records. Sealing any `*.json` it found
    /// under the id the file claimed would be an unauthenticated write into
    /// the sealed store: anyone able to write the directory, holding no key,
    /// could replace a note's record at the next open. A plaintext file is
    /// only ever reported (`all`).
    pub fn open(dir: impl AsRef<Path>, creds: StoreCredentials) -> Result<Self> {
        let root = dir.as_ref();
        let tokens_dir = root.join(TOKENS_DIR);
        let pending_dir = root.join(PENDING_DIR);
        for d in [&tokens_dir, &pending_dir] {
            std::fs::create_dir_all(d)
                .map_err(|e| WalletError::Store(format!("creating {}: {e}", d.display())))?;
        }
        let store = FileStore {
            tokens_dir,
            pending_dir,
            state_path: root.join(STATE_FILE),
            lock_path: root.join(LOCK_FILE),
            state_lock_path: root.join(STATE_LOCK_FILE),
            creds,
        };
        store.sweep_stale_temps(root);
        Ok(store)
    }

    /// Take the wallet directory's write lock, waiting if another holder
    /// has it.
    ///
    /// # Why this exists
    ///
    /// Several wallet operations are read-modify-write: `reconcile` binds a
    /// note to its mint, `sync` writes back a reconciled snapshot,
    /// `bind_owner`, `verify_ownership`, `forget` and the mark-spent paths
    /// all read then write. Without a lock nothing serializes them. The
    /// desktop GUI opens **eleven** separate stores across its job threads,
    /// and the CLI's `backup restore` is a `get`-then-`put` loop; the two
    /// share a directory by design.
    ///
    /// # Why one mechanism and not two
    ///
    /// The obvious design is an in-process mutex for the GUI racing itself
    /// plus a file lock for the two clients racing each other. One
    /// advisory lock does both, because `flock` and `LockFileEx` are
    /// per-open-**handle**: two handles conflict whether or not they belong
    /// to the same process. `fcntl` locks would *not* — they are
    /// per-process, so two threads of one process would both succeed and
    /// the GUI's own race would be left wide open while looking closed.
    /// That distinction is why this uses [`std::fs::File::lock`], which
    /// documents the `flock`/`LockFileEx` behaviour, rather than `fcntl`.
    /// It is asserted by `two_handles_in_one_process_exclude_each_other`
    /// rather than taken on trust, because the whole in-process half of
    /// the guarantee rests on it.
    ///
    /// No dependency: `File::lock` is in std as of Rust 1.89.
    ///
    /// # Staleness
    ///
    /// There is none to handle. The OS drops the lock when the holding
    /// process exits, crashes or is killed, so a wallet cannot be bricked
    /// by a stale lock and no holder is ever asked to delete a file they
    /// do not understand. A pid-bearing lock file would have needed that
    /// story.
    ///
    /// # Blocking
    ///
    /// Waits rather than failing: a failure would surface as an error about
    /// something the holder cannot act on.
    ///
    /// Every critical section is a handful of local file operations. Callers
    /// must never hold this lock across an RPC round trip or a card
    /// derivation, or a slow ledger stalls every other writer: `reconcile`,
    /// `sync`, `complete_receive`, `import` and `verify_ownership` read
    /// first and take it only to re-read and write
    /// (`TokenWallet::commit_if_unchanged`). The state file has its own lock
    /// (`update_state`).
    fn lock_inner(&self) -> Result<StoreGuard> {
        Ok(StoreGuard {
            file: Some(lock_file(&self.lock_path)?),
        })
    }

    /// Delete temp files a crashed write left behind.
    ///
    /// Each write has its own temp name (`write_atomic`), so one stranded
    /// between write and rename is never overwritten by the next. Only files
    /// over an hour old go: a younger one may belong to a write in progress
    /// in another process, and removing it would fail that write's rename.
    /// Best effort -- a file that will not go is left for next time, since
    /// nothing reads `.tmp` files and opening a wallet must not fail on one.
    fn sweep_stale_temps(&self, root: &Path) {
        let cutoff = std::time::Duration::from_secs(60 * 60);
        for dir in [root, &self.tokens_dir, &self.pending_dir] {
            let Ok(entries) = std::fs::read_dir(dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("tmp") {
                    continue;
                }
                let stale = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > cutoff);
                if stale {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    /// Read `state.json`, change it, write it back, under the state lock.
    ///
    /// Every write of the state file goes through here. It holds both the
    /// owner-index counter and the last-backup record, and its callers
    /// (`begin_receive`, `start_receive`, the GUI's direct allocations,
    /// `record_backup`, restore) mostly do not hold the wallet lock. Without
    /// this lock two handles can each read the counter and each write it back
    /// one higher, handing the same index to two payers, and an unlocked
    /// `record_backup` can write back a stale counter. Locking here covers
    /// every caller, present and future, instead of trusting each to
    /// remember.
    ///
    /// `f` returns `None` to leave the file untouched.
    fn update_state<T>(
        &self,
        f: impl FnOnce(&mut WalletState) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        let _held = lock_file(&self.state_lock_path)?;
        let mut state = self.read_state()?;
        let out = f(&mut state)?;
        if out.is_some() {
            self.write_state(&state)?;
        }
        Ok(out)
    }

    /// Where a record lives: an opaque, keyed name, so a directory listing is
    /// not a statement about which notes are held (`sealed.rs`).
    fn sealed_path(&self, dir: &Path, kind: &str, id: &str) -> PathBuf {
        dir.join(format!("{}.{RECORD_EXT}", record_name(&self.creds, kind, id)))
    }

    fn read_state(&self) -> Result<WalletState> {
        match std::fs::read(&self.state_path) {
            Ok(raw) => {
                let plain = unseal(&self.creds, &raw)?;
                serde_json::from_slice(&plain).map_err(|e| {
                    WalletError::Store(format!("parsing {}: {e}", self.state_path.display()))
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(WalletState::default()),
            Err(e) => Err(WalletError::Store(format!(
                "reading {}: {e}",
                self.state_path.display()
            ))),
        }
    }

    fn write_state(&self, state: &WalletState) -> Result<()> {
        let json = serde_json::to_vec_pretty(state)
            .map_err(|e| WalletError::Store(format!("encoding wallet state: {e}")))?;
        write_atomic(&self.state_path, &seal(&self.creds, &json)?)
    }

    fn pending_path(&self, index: u32) -> PathBuf {
        self.sealed_path(&self.pending_dir, "pending", &index.to_string())
    }

    /// The directory holding token records. Only the tests need to reach in;
    /// the CLI reports the wallet root instead.
    #[cfg(test)]
    pub fn tokens_dir(&self) -> &Path {
        &self.tokens_dir
    }

    /// The path for a token id.
    ///
    /// Ids are derived from attacker-supplied container bytes, but no
    /// validation is needed: the filename is a keyed hash of the id, so no id
    /// can reach outside the directory (`..`, separators, drive letters)
    /// however it is spelled.
    fn path_for(&self, id: &str) -> PathBuf {
        self.sealed_path(&self.tokens_dir, "token", id)
    }

    async fn read_record(&self, path: &Path) -> Result<HeldToken> {
        let raw = tokio::fs::read(path)
            .await
            .map_err(|e| WalletError::Store(format!("reading {}: {e}", path.display())))?;
        let plain = unseal(&self.creds, &raw)?;
        let stored: StoredToken = serde_json::from_slice(&plain)
            .map_err(|e| WalletError::Store(format!("parsing {}: {e}", path.display())))?;

        // The name is derived from the id, so a record that does not hash back
        // to the file it was found in has been moved or swapped. Cheap to
        // check and the only way to notice.
        let expected = self.sealed_path(&self.tokens_dir, "token", &stored.id);
        if expected != path {
            return Err(WalletError::Store(format!(
                "record in {} does not belong there",
                path.display()
            )));
        }
        stored.into_held(path)
    }
}

impl StoredToken {
    fn from_held(t: &HeldToken) -> Self {
        StoredToken {
            id: t.id.clone(),
            slot_id: t.slot_id,
            ephemeral_public_key: hex::encode(t.ephemeral_public_key),
            event_id: hex::encode(t.event_id),
            amount: t.amount,
            imported_at: t.imported_at,
            mint: t.mint.clone(),
            label: t.label.clone(),
            owner_index: t.owner_index,
            owner_commitment: t.owner_commitment.map(hex::encode),
            spent_away: t.spent_away,
            exports: t.exports,
            marked_spent: t.marked_spent,
            blob: hex::encode(&t.blob),
        }
    }

    fn into_held(self, path: &Path) -> Result<HeldToken> {
        let bad = |what: &str| WalletError::Store(format!("{}: bad {what}", path.display()));
        let ephemeral_public_key: [u8; 32] = hex::decode(&self.ephemeral_public_key)
            .map_err(|_| bad("ephemeral_public_key"))?
            .try_into()
            .map_err(|_| bad("ephemeral_public_key length"))?;
        let event_id: [u8; 32] = hex::decode(&self.event_id)
            .map_err(|_| bad("event_id"))?
            .try_into()
            .map_err(|_| bad("event_id length"))?;
        let blob = hex::decode(&self.blob).map_err(|_| bad("blob"))?;
        Ok(HeldToken {
            id: self.id,
            slot_id: self.slot_id,
            ephemeral_public_key,
            event_id,
            amount: self.amount,
            blob,
            imported_at: self.imported_at,
            mint: self.mint.clone(),
            label: self.label,
            owner_index: self.owner_index,
            owner_commitment: match self.owner_commitment {
                None => None,
                Some(h) => Some(
                    hex::decode(&h)
                        .map_err(|_| bad("owner_commitment"))?
                        .try_into()
                        .map_err(|_| bad("owner_commitment length"))?,
                ),
            },
            spent_away: self.spent_away,
            exports: self.exports,
            marked_spent: self.marked_spent,
        })
    }
}

impl Store for FileStore {
    fn lock(&self) -> Result<StoreGuard> {
        self.lock_inner()
    }

    async fn put(&mut self, token: HeldToken) -> Result<()> {
        let path = self.path_for(&token.id);
        let json = serde_json::to_vec_pretty(&StoredToken::from_held(&token))
            .map_err(|e| WalletError::Store(format!("encoding {}: {e}", token.id)))?;

        write_atomic(&path, &seal(&self.creds, &json)?)
    }

    async fn get(&self, id: &str) -> Result<Option<HeldToken>> {
        let path = self.path_for(id);
        match tokio::fs::metadata(&path).await {
            Ok(_) => Ok(Some(self.read_record(&path).await?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(WalletError::Store(format!("stat {}: {e}", path.display()))),
        }
    }

    async fn all(&self) -> Result<Vec<HeldToken>> {
        let mut dir = tokio::fs::read_dir(&self.tokens_dir).await.map_err(|e| {
            WalletError::Store(format!("listing {}: {e}", self.tokens_dir.display()))
        })?;

        let mut out = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|e| WalletError::Store(format!("listing tokens: {e}")))?
        {
            let path = entry.path();
            match path.extension().and_then(|s| s.to_str()) {
                Some(RECORD_EXT) => {}
                // The wallet only writes sealed records, so this was put
                // here by something else. It is never read -- trusting it
                // would let anyone with write access to the directory forge
                // a record without the key -- but it is reported, not
                // skipped: a token file that is
                // silently not listed reads as value that vanished.
                Some("json") => {
                    return Err(WalletError::Store(format!(
                        "{} is an unsealed record this wallet did not write; it was not \
                         read. Move it out of the wallet directory to continue",
                        path.display()
                    )))
                }
                _ => continue, // leftover .tmp files
            }
            // A record that won't parse is surfaced, never skipped: silently
            // omitting a token would read to the holder as value that vanished.
            out.push(self.read_record(&path).await?);
        }
        out.sort_by(|a, b| a.imported_at.cmp(&b.imported_at).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    async fn remove(&mut self, id: &str) -> Result<()> {
        let path = self.path_for(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Store(format!("removing {}: {e}", path.display()))),
        }
    }

    async fn allocate_owner_index(&mut self) -> Result<u32> {
        // Persist the advance *before* returning, so a crash can only ever burn
        // an index, never hand the same one out twice. A gap costs nothing; a
        // duplicate would link two payments to one commitment.
        let index = self.update_state(|state| {
            let index = state.next_owner_index.unwrap_or(FIRST_FRESH_INDEX);
            state.next_owner_index = Some(index.checked_add(1).ok_or_else(|| {
                WalletError::Store("owner index space exhausted".into())
            })?);
            Ok(Some(index))
        })?;
        Ok(index.expect("allocation always writes"))
    }

    async fn advance_owner_index(&mut self, to: u32) -> Result<u32> {
        let mut current = FIRST_FRESH_INDEX;
        let moved = self.update_state(|state| {
            current = state.next_owner_index.unwrap_or(FIRST_FRESH_INDEX);
            if to <= current {
                // Already covered. Nothing to persist, and a read (`to = 0`)
                // must not rewrite the state file on every billfold paint.
                return Ok(None);
            }
            state.next_owner_index = Some(to);
            Ok(Some(to))
        })?;
        Ok(moved.unwrap_or(current))
    }

    async fn last_backup(&self) -> Result<Option<BackupRecord>> {
        Ok(self.read_state()?.last_backup)
    }

    async fn record_backup(&mut self, record: BackupRecord) -> Result<()> {
        self.update_state(|state| {
            state.last_backup = Some(record);
            Ok(Some(()))
        })?;
        Ok(())
    }

    async fn put_pending(&mut self, pending: PendingReceive) -> Result<()> {
        let json = serde_json::to_vec_pretty(&pending).map_err(|e| {
            WalletError::Store(format!("encoding pending {}: {e}", pending.index))
        })?;
        write_atomic(&self.pending_path(pending.index), &seal(&self.creds, &json)?)
    }

    async fn pending(&self) -> Result<Vec<PendingReceive>> {
        let mut dir = tokio::fs::read_dir(&self.pending_dir).await.map_err(|e| {
            WalletError::Store(format!("listing {}: {e}", self.pending_dir.display()))
        })?;
        let mut out = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|e| WalletError::Store(format!("listing pending: {e}")))?
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some(RECORD_EXT) {
                continue;
            }
            let raw = tokio::fs::read(&path)
                .await
                .map_err(|e| WalletError::Store(format!("reading {}: {e}", path.display())))?;
            let plain = unseal(&self.creds, &raw)?;
            // Like a token record, an unreadable pending entry is surfaced: it
            // names an index a payer may already have been told to pay.
            out.push(serde_json::from_slice(&plain).map_err(|e| {
                WalletError::Store(format!("parsing {}: {e}", path.display()))
            })?);
        }
        out.sort_by_key(|p: &PendingReceive| p.index);
        Ok(out)
    }

    async fn remove_pending(&mut self, index: u32) -> Result<()> {
        let path = self.pending_path(index);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Store(format!("removing {}: {e}", path.display()))),
        }
    }
}

/// Open `path` and take its advisory lock, waiting for any other holder.
fn lock_file(path: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| WalletError::Store(format!("opening {}: {e}", path.display())))?;
    file.lock()
        .map_err(|e| WalletError::Store(format!("locking {}: {e}", path.display())))?;
    Ok(file)
}

/// Write via a `.tmp` sibling and rename over the target, so a reader never
/// observes a half-written file. `fs::rename` replaces an existing file on both
/// Windows and Unix.
///
/// The sibling's name is unique to this write. A shared temp name would let
/// two writers of one file collide: one renames the other's bytes into place
/// and the second rename finds nothing ("finalizing state.json: file not
/// found"). Locks serialize the writers that matter, and this keeps a writer
/// that is not locked from failing someone else's write.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    // Flushed before the rename, so a crash cannot leave the target
    // replaced by a file whose contents never reached the disk.
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| WalletError::Store(format!("writing {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| WalletError::Store(format!("writing {}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| WalletError::Store(format!("finalizing {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed keys, so a store reopened inside a test reads what it wrote.
    fn test_creds() -> StoreCredentials {
        StoreCredentials {
            aead: zeroize::Zeroizing::new([7u8; 32]),
            name: zeroize::Zeroizing::new([9u8; 32]),
        }
    }

    fn tmp_root(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kenter-filestore-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn sample(id: &str, imported_at: i64) -> HeldToken {
        HeldToken {
            slot_id: 1,
            id: id.to_string(),
            ephemeral_public_key: [7u8; 32],
            event_id: [9u8; 32],
            amount: 1234,
            blob: vec![0xde, 0xad, 0xbe, 0xef],
            imported_at,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        }
    }

    #[tokio::test]
    async fn roundtrip_persists_across_instances() {
        let root = tmp_root("roundtrip");
        let t = sample("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 100);

        {
            let mut s = FileStore::open(&root, test_creds()).unwrap();
            s.put(t.clone()).await.unwrap();
        }
        // A fresh instance sees it — the whole point of the store.
        let s = FileStore::open(&root, test_creds()).unwrap();
        assert_eq!(s.get(&t.id).await.unwrap().as_ref(), Some(&t));
        assert_eq!(s.all().await.unwrap(), vec![t]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn get_missing_is_none_and_remove_is_idempotent() {
        let root = tmp_root("missing");
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        let id = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert!(s.get(id).await.unwrap().is_none());
        s.remove(id).await.unwrap();
        s.remove(id).await.unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn all_is_ordered_and_remove_drops_one() {
        let root = tmp_root("ordered");
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        let a = sample("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 300);
        let b = sample("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 100);
        s.put(a.clone()).await.unwrap();
        s.put(b.clone()).await.unwrap();

        let ids: Vec<_> = s.all().await.unwrap().into_iter().map(|t| t.id).collect();
        assert_eq!(ids, vec![b.id.clone(), a.id.clone()], "oldest import first");

        s.remove(&b.id).await.unwrap();
        assert_eq!(s.all().await.unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn put_overwrites_in_place() {
        let root = tmp_root("overwrite");
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        let mut t = sample("GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 1);
        s.put(t.clone()).await.unwrap();
        t.label = Some("rent".into());
        s.put(t.clone()).await.unwrap();

        let all = s.all().await.unwrap();
        assert_eq!(all.len(), 1, "same id must not create a second record");
        assert_eq!(all[0].label.as_deref(), Some("rent"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Ids come from parsed container bytes, so they are untrusted. The name
    /// is a keyed hash of the id, so there is nothing to reject - a hostile id
    /// produces hex like any other. The property worth asserting is the one
    /// that actually matters, and it is unconditional rather than depending
    /// on a validator somebody could weaken.
    #[tokio::test]
    async fn no_id_can_escape_the_store_directory() {
        let root = tmp_root("traversal");
        let s = FileStore::open(&root, test_creds()).unwrap();
        for id in [
            "../escape",
            "a/b",
            "..",
            r"C:\windows\system32\x",
            "",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let path = s.path_for(id);
            assert_eq!(
                path.parent(),
                Some(s.tokens_dir()),
                "{id:?} landed outside the store"
            );
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".rec").expect("sealed extension");
            assert!(
                stem.len() == 32 && stem.chars().all(|c| c.is_ascii_hexdigit()),
                "{id:?} produced {name:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Handles that take no wallet lock -- `begin_receive`,
    /// the GUI's direct allocations -- allocating at once from many
    /// threads never hand out one index twice, and no write fails on
    /// another's temp file.
    #[test]
    fn concurrent_allocations_never_share_an_index() {
        let root = tmp_root("alloc-race");
        let _ = FileStore::open(&root, test_creds()).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let mut s = FileStore::open(&root, test_creds()).unwrap();
                    (0..25)
                        .map(|_| pollster::block_on(s.allocate_owner_index()).unwrap())
                        .collect::<Vec<u32>>()
                })
            })
            .collect();
        let mut all: Vec<u32> = threads.into_iter().flat_map(|t| t.join().unwrap()).collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "an owner index was handed out twice");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A temp file stranded by a crash is swept at open once it is old; a
    /// fresh one, possibly another process's write in flight, is left.
    #[test]
    fn open_sweeps_only_stale_temp_files() {
        let root = tmp_root("sweep");
        let s = FileStore::open(&root, test_creds()).unwrap();
        let old = s.tokens_dir().join("x.1-1.tmp");
        let fresh = s.tokens_dir().join("x.1-2.tmp");
        std::fs::write(&old, b"").unwrap();
        std::fs::write(&fresh, b"").unwrap();
        let f = std::fs::File::options().write(true).open(&old).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600))
            .unwrap();
        drop(f);
        drop(s);

        let _ = FileStore::open(&root, test_creds()).unwrap();
        assert!(!old.exists(), "a stale temp file survived open");
        assert!(fresh.exists(), "a fresh temp file was removed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn owner_index_round_trips() {
        let root = tmp_root("ownerindex");
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        let mut t = sample("GFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 1);
        t.owner_index = Some(42);
        s.put(t.clone()).await.unwrap();

        let s = FileStore::open(&root, test_creds()).unwrap();
        assert_eq!(s.get(&t.id).await.unwrap().unwrap().owner_index, Some(42));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Indices must be monotonic and survive a restart. A duplicate would link
    /// two payments to one commitment; a gap costs nothing.
    #[tokio::test]
    async fn owner_indices_are_monotonic_and_persist() {
        let root = tmp_root("alloc");
        let first = {
            let mut s = FileStore::open(&root, test_creds()).unwrap();
            let a = s.allocate_owner_index().await.unwrap();
            let b = s.allocate_owner_index().await.unwrap();
            assert_eq!(a, FIRST_FRESH_INDEX);
            assert_eq!(b, a + 1);
            b
        };
        // A fresh instance must not hand out an index it already gave away.
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        let c = s.allocate_owner_index().await.unwrap();
        assert_eq!(c, first + 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The setter restore depends on: it must persist, and it must refuse to
    /// go backwards even when asked, because the thing asking is an old backup
    /// file and the indices behind it are already spent.
    #[tokio::test]
    async fn advancing_the_index_persists_and_only_goes_forward() {
        let root = tmp_root("advance");
        {
            let mut s = FileStore::open(&root, test_creds()).unwrap();
            // A read on a never-touched store, which must not create one.
            assert_eq!(s.advance_owner_index(0).await.unwrap(), FIRST_FRESH_INDEX);
            assert_eq!(s.advance_owner_index(40).await.unwrap(), 40);
            // Backwards, and level, are both no-ops that report the truth.
            assert_eq!(s.advance_owner_index(7).await.unwrap(), 40);
            assert_eq!(s.advance_owner_index(40).await.unwrap(), 40);
            assert_eq!(s.advance_owner_index(0).await.unwrap(), 40);
        }
        // Across a restart, since a counter that only lives in memory is the
        // same bug with a longer fuse.
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        assert_eq!(s.advance_owner_index(0).await.unwrap(), 40);
        assert_eq!(s.allocate_owner_index().await.unwrap(), 40);
        assert_eq!(s.advance_owner_index(0).await.unwrap(), 41);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Index 0 is the static receive address and is never handed out as a fresh
    /// per-receipt index.
    #[tokio::test]
    async fn allocation_never_yields_the_static_index() {
        let root = tmp_root("alloc-static");
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        for _ in 0..5 {
            assert_ne!(
                s.allocate_owner_index().await.unwrap(),
                crate::models::STATIC_RECEIVE_INDEX
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn pending_receives_round_trip() {
        let root = tmp_root("pending");
        let p1 = PendingReceive { index: 1, commitment: [1u8; 32], created_at: 10 };
        let p2 = PendingReceive { index: 9, commitment: [2u8; 32], created_at: 20 };
        {
            let mut s = FileStore::open(&root, test_creds()).unwrap();
            s.put_pending(p2.clone()).await.unwrap();
            s.put_pending(p1.clone()).await.unwrap();
        }
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        assert_eq!(s.pending().await.unwrap(), vec![p1.clone(), p2.clone()], "sorted by index");

        s.remove_pending(1).await.unwrap();
        assert_eq!(s.pending().await.unwrap(), vec![p2]);
        // Removing twice is fine - consuming an already-consumed receive is not
        // an error worth failing a receive over.
        s.remove_pending(1).await.unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Pending records must not be mistaken for token records or vice versa.
    #[tokio::test]
    async fn pending_and_tokens_do_not_collide() {
        let root = tmp_root("nocollide");
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        s.put(sample("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", 1))
            .await
            .unwrap();
        s.put_pending(PendingReceive { index: 1, commitment: [7u8; 32], created_at: 1 })
            .await
            .unwrap();
        assert_eq!(s.all().await.unwrap().len(), 1);
        assert_eq!(s.pending().await.unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn corrupt_record_is_reported_not_skipped() {
        let root = tmp_root("corrupt");
        let mut s = FileStore::open(&root, test_creds()).unwrap();
        s.put(sample("GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", 1))
            .await
            .unwrap();
        std::fs::write(s.tokens_dir().join("deadbeef.rec"), b"not sealed at all").unwrap();

        let err = s.all().await.unwrap_err();
        assert!(matches!(err, WalletError::Store(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A plaintext record is never read, and never silently skipped either:
    /// omitting it reads to the holder as value that vanished.
    #[tokio::test]
    async fn a_stray_plaintext_record_is_reported_rather_than_ignored() {
        let root = tmp_root("stray");
        let s = FileStore::open(&root, test_creds()).unwrap();
        std::fs::write(s.tokens_dir().join("GEEEE.json"), b"{}").unwrap();

        let err = s.all().await.unwrap_err();
        assert!(err.to_string().contains("did not write"), "got {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A plaintext file planted under a held note's id is not
    /// sealed into the store at open, and the note's record is untouched.
    #[tokio::test]
    async fn a_planted_plaintext_record_never_replaces_a_sealed_one() {
        let root = tmp_root("plant");
        let held = sample("GFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 42);
        {
            let mut s = FileStore::open(&root, test_creds()).unwrap();
            s.put(held.clone()).await.unwrap();
        }
        let mut forged = held.clone();
        forged.marked_spent = true;
        forged.blob = vec![0];
        let json = serde_json::to_vec_pretty(&StoredToken::from_held(&forged)).unwrap();
        std::fs::write(root.join(TOKENS_DIR).join("x.json"), &json).unwrap();

        let s = FileStore::open(&root, test_creds()).unwrap();
        assert_eq!(s.get(&held.id).await.unwrap(), Some(held));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── The lock ──────────────────────────────────────────────────────

    /// The claim the whole in-process half of the guarantee rests on:
    /// two handles in **one process** exclude each other.
    ///
    /// This is asserted rather than assumed because the wrong primitive
    /// looks identical and fails silently. `fcntl` byte-range locks are
    /// held *per process*, so a second thread of the same process takes
    /// one happily and both proceed — the GUI, which opens eleven stores
    /// across its job threads, would be raced as if there were no lock while
    /// every test passed. `flock` and `LockFileEx`, which
    /// `std::fs::File::lock` documents using, are held per open handle.
    ///
    /// Verified on Windows. Linux and macOS are expected to behave the
    /// same way via `flock` and are **unverified**, the same caveat the
    /// camera path carries.
    #[test]
    fn two_handles_in_one_process_exclude_each_other() {
        let root = tmp_root("lock-intra");
        let a = FileStore::open(&root, test_creds()).unwrap();
        let b = FileStore::open(&root, test_creds()).unwrap();

        let held = a.lock().unwrap();

        // A second holder must not get in while the first has it. Proved
        // by a thread that tries and reports whether it got through
        // before the first lock is dropped.
        let got_in = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = got_in.clone();
        let worker = std::thread::spawn(move || {
            let _second = b.lock().unwrap();
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // Give the thread every chance to succeed wrongly. Spinning on a
        // yield rather than sleeping keeps this honest without a timer:
        // if the lock were per-process the store would be true almost at
        // once.
        for _ in 0..10_000 {
            std::thread::yield_now();
            if got_in.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
        }
        assert!(
            !got_in.load(std::sync::atomic::Ordering::SeqCst),
            "a second handle in the same process took the lock -- this is              the per-process `fcntl` behaviour, and it leaves the GUI's own              race open"
        );

        // And it is a lock, not a deadlock: dropping it lets the waiter in.
        drop(held);
        worker.join().expect("the waiting thread panicked");
        assert!(
            got_in.load(std::sync::atomic::Ordering::SeqCst),
            "the waiter never acquired the lock after it was released"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The lock file is an artefact of locking, not a record, so it must
    /// never be mistaken for one.
    #[tokio::test]
    async fn the_lock_file_is_not_mistaken_for_a_token() {
        let root = tmp_root("lock-artifact");
        let store = FileStore::open(&root, test_creds()).unwrap();
        let guard = store.lock().unwrap();
        assert!(root.join(LOCK_FILE).exists(), "locking creates its file");
        drop(guard);

        // It lives in the wallet root, not in `tokens/`, so a listing
        // cannot pick it up -- but assert it rather than trusting the
        // layout, since `all()` is what a balance is built from.
        assert!(
            store.all().await.unwrap().is_empty(),
            "the lock file is not a token"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
