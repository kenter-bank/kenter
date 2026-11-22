//! In-memory [`Store`] — for tests and ephemeral sessions. Real shells provide a
//! filesystem (desktop) or IndexedDB (PWA) implementation of the same trait.

use std::collections::HashMap;

use crate::error::Result;
use crate::models::{BackupRecord, HeldToken, PendingReceive, FIRST_FRESH_INDEX};
use crate::ports::Store;

/// A non-persistent token store backed by a `HashMap`.
#[derive(Debug, Default)]
pub struct MemoryStore {
    tokens: HashMap<String, HeldToken>,
    pending: HashMap<u32, PendingReceive>,
    next_owner_index: Option<u32>,
    last_backup: Option<BackupRecord>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of tokens currently held.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl Store for MemoryStore {
    async fn put(&mut self, token: HeldToken) -> Result<()> {
        self.tokens.insert(token.id.clone(), token);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<HeldToken>> {
        Ok(self.tokens.get(id).cloned())
    }

    async fn all(&self) -> Result<Vec<HeldToken>> {
        Ok(self.tokens.values().cloned().collect())
    }

    async fn remove(&mut self, id: &str) -> Result<()> {
        self.tokens.remove(id);
        Ok(())
    }

    async fn allocate_owner_index(&mut self) -> Result<u32> {
        let next = self.next_owner_index.unwrap_or(FIRST_FRESH_INDEX);
        self.next_owner_index = Some(next + 1);
        Ok(next)
    }

    async fn advance_owner_index(&mut self, to: u32) -> Result<u32> {
        let current = self.next_owner_index.unwrap_or(FIRST_FRESH_INDEX);
        let next = current.max(to);
        self.next_owner_index = Some(next);
        Ok(next)
    }

    async fn put_pending(&mut self, pending: PendingReceive) -> Result<()> {
        self.pending.insert(pending.index, pending);
        Ok(())
    }

    async fn pending(&self) -> Result<Vec<PendingReceive>> {
        let mut out: Vec<PendingReceive> = self.pending.values().cloned().collect();
        out.sort_by_key(|p| p.index);
        Ok(out)
    }

    async fn remove_pending(&mut self, index: u32) -> Result<()> {
        self.pending.remove(&index);
        Ok(())
    }

    async fn last_backup(&self) -> Result<Option<BackupRecord>> {
        Ok(self.last_backup.clone())
    }

    async fn record_backup(&mut self, record: BackupRecord) -> Result<()> {
        self.last_backup = Some(record);
        Ok(())
    }
}
