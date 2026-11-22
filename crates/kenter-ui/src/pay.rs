//! Handing a note over.
//!
//! Two different verbs, not two flavours of one, because the client can do
//! completely different amounts of work for each.
//!
//! **Bearer: Export.** There is no bearer "pay" to perform. Handing one over
//! happens in the world, not in the software, which cannot confirm it,
//! reverse it, or know it happened. So the client writes the file and gets
//! out of the way, and records that a copy left — by *kind*, because a backup
//! is a copy the holder keeps and a handover is one they gave away.
//!
//! **Spend mode: Pay.** Two deliveries, not one. Moving the pointer does not
//! give the payee the note: `complete_receive` needs the container bytes
//! *and* the ledger agreement. A screen that does only the on-chain half has
//! not paid anybody.
//!
//! ## The order is decided by the contract
//!
//! File first, transaction second, because the failure modes are not
//! symmetric:
//!
//! - *Pointer moved, file never delivered.* The payer can no longer satisfy
//!   `enforce_owner` — the live commitment is the payee's now — and the payee
//!   cannot call `redeem_by_chain_owned` without the chain data. **Nobody can
//!   redeem it.**
//! - *File delivered, pointer never moved.* Benign. `enforce_owner` returns
//!   `SpendModeRequiresOwner` for a spend-mode token presented without an
//!   owner signature, so the bytes alone do nothing and the payer still owns
//!   it.
//!
//! The payee's inbox watch already covers the gap, since G3 is retryable.

use std::path::{Path, PathBuf};

use kenter_client::MintClient;
use kenter_wallet::{ExportKind, FileStore, HeldToken, WalletError};

use crate::GuiWallet;

/// Where the save dialog starts.
///
/// Not a destination and not a send mechanism — there is no network send for
/// notes, and a transfer is a file the holder hands over themselves. This is
/// only somewhere sensible for the dialog to open.
pub fn outbox_dir(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join("outbox")
}

/// Write the bytes beside their destination, without claiming to be it.
///
/// For a spend-mode payment the bytes must exist on disk **before** the
/// owner pointer moves: once it has moved, this holder's key no longer
/// matches the live commitment, and a payee with no file has nothing to
/// redeem with — the note is stranded with nobody able to act on it.
///
/// But a file sitting at the chosen path after a payment that then failed
/// is its own trap: it looks exactly like a payment that worked. So the
/// bytes go to a `.partial` beside the target, and [`promote`] renames it
/// only once the ledger has agreed. Same directory, so the rename is a
/// move within one volume rather than a copy that can half-finish.
pub fn stage(dest: &Path, held: &HeldToken) -> Result<PathBuf, String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let partial = dest.with_extension("partial");
    std::fs::write(&partial, &held.blob)
        .map_err(|e| format!("writing {}: {e}", partial.display()))?;
    Ok(partial)
}

/// Put a staged file at its destination and record that a copy left.
pub async fn promote(
    wallet: &mut GuiWallet,
    partial: &Path,
    dest: &Path,
    held: &HeldToken,
    kind: ExportKind,
) -> Result<PathBuf, String> {
    std::fs::rename(partial, dest).map_err(|e| format!("moving to {}: {e}", dest.display()))?;
    wallet
        .record_export(&held.id, kind)
        .await
        .map_err(|e: WalletError| e.to_string())?;
    Ok(dest.to_path_buf())
}

/// Write a note's container bytes out, and record that a copy left.
///
/// The recorded kind is what makes the count mean anything later: only a
/// handover implies someone else may hold a redeemable copy.
pub async fn export(
    wallet: &mut GuiWallet,
    dest: &Path,
    held: &HeldToken,
    kind: ExportKind,
) -> Result<PathBuf, String> {
    // The holder picked the path, so the directory is theirs too — but a
    // chosen path whose parent has since gone is a write that fails after
    // the dialog has already closed, which reads as the export silently
    // not happening.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let path = dest.to_path_buf();
    // The blob is the note exactly as received or minted. Nothing local is
    // added to it - in particular not the export log, which would become a
    // fingerprint linking copies of the same note to each other.
    std::fs::write(&path, &held.blob).map_err(|e| format!("writing {}: {e}", path.display()))?;
    wallet
        .record_export(&held.id, kind)
        .await
        .map_err(|e: WalletError| e.to_string())?;
    Ok(path)
}

/// Can this note be handed over at all, and by which verb?
pub fn is_spend_mode(held: &HeldToken) -> bool {
    held.owner_index.is_some()
}

/// A note the holder could pay with, as the picker shows it.
#[derive(Debug, Clone)]
pub struct Payable {
    pub id: String,
    pub short_id: String,
    pub amount: u64,
    pub spend_mode: bool,
    /// How many other parties may already hold a copy (`ExportLog::exposure`).
    pub exposure: u32,
}

/// Notes that can still be paid away.
///
/// Excludes anything already redeemed, paid away, or that the holder has
/// marked spent. Offering one of those would be offering to pay with money
/// that is gone.
pub async fn payable(wallet: &GuiWallet) -> Result<Vec<Payable>, String> {
    let held = wallet.held().await.map_err(|e| e.to_string())?;
    Ok(held
        .into_iter()
        .filter(|t| !t.spent_away && !t.marked_spent)
        .map(|t| Payable {
            short_id: crate::wallet::short(&t.id),
            exposure: t.exports.exposure(),
            spend_mode: is_spend_mode(&t),
            amount: t.amount,
            id: t.id,
        })
        .collect())
}

/// Move a spend-mode note's owner pointer to `new_commitment`.
///
/// Called **after** the file has been written, never before — see the module
/// docs for why that order is not a preference.
pub async fn repoint(
    wallet: &mut GuiWallet,
    mint: &mut MintClient,
    held: &HeldToken,
    credential: &[u8],
    new_commitment: [u8; 32],
) -> Result<(), String> {
    let index = held.owner_index.ok_or_else(|| {
        "this note is bearer: hand over the file, there is nothing to sign".to_string()
    })?;
    // Derived when it was not recorded, rather than refused. The
    // commitment is a deterministic function of the owner index and the
    // seed, so a missing one is a bookkeeping gap and not lost information
    // — and telling the holder to run a sync would not fix it, because
    // `sync` only fills this in for notes received from someone else.
    let live = match held.owner_commitment {
        Some(c) => c,
        None => wallet
            .owner_commitment_for(index, credential)
            .map_err(|e| format!("deriving the owner commitment: {e}"))?,
    };

    let auth = wallet
        .authorize_spend(
            index,
            held.slot_id,
            &held.ephemeral_public_key,
            &live,
            &new_commitment,
            credential,
        )
        .await
        .map_err(|e| e.to_string())?;

    // A failed submission is not the same as nothing having happened.
    //
    // The authorisation is already built and, once the transaction has
    // been broadcast, published — and it stays valid until the note's
    // spend nonce moves. A holder who reads "spend failed" and pays the
    // same payee with a different note can then be relayed the first
    // authorisation as well, and pays twice.
    //
    // So the message says what is outstanding and what closes it. The
    // self-spend remedy is self-verifying: if the original did land, a
    // `current → current` spend at the old commitment fails on its own
    // (`OwnerCommitmentMismatch`), and if it did not, it lands and
    // advances the nonce, which kills the stranded authorisation.
    mint.spend(
        held.slot_id,
        auth.current_owner_pubkey,
        auth.new_owner_commitment,
        auth.signature,
    )
    .await
    .map_err(|e| {
        format!(
            "spend: {e}\n\nThis payment may still be live. The authorisation you \
             just signed stays valid until this note is spent on, so do not pay \
             the same person with another note yet \u{2014} retry this one first. If it \
             keeps failing, pay the note to yourself to cancel the outstanding \
             authorisation."
        )
    })
}

/// Load a token record by id.
pub async fn held_token(store: &FileStore, id: &str) -> Result<HeldToken, String> {
    use kenter_wallet::Store;
    store
        .get(id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{id} is not held"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(id: &str, spend: bool, handovers: u32, marked: bool) -> HeldToken {
        HeldToken {
            slot_id: 1,
            id: id.into(),
            ephemeral_public_key: [1; 32],
            event_id: [0; 32],
            amount: 10_000_000,
            blob: vec![1, 2, 3],
            imported_at: 0,
            mint: None,
            label: None,
            owner_index: spend.then_some(3),
            owner_commitment: spend.then_some([7; 32]),
            spent_away: false,
            exports: kenter_wallet::ExportLog {
                backup: 2,
                to_card: 0,
                handover: handovers,
            },
            marked_spent: marked,
        }
    }

    #[test]
    fn mode_decides_the_verb() {
        assert!(is_spend_mode(&note("a", true, 0, false)));
        assert!(!is_spend_mode(&note("b", false, 0, false)));
    }

    /// Backups are not exposure. A holder with two backups and no handovers
    /// has given nothing away, and the picker must not imply otherwise.
    #[test]
    fn exposure_ignores_the_holders_own_backups() {
        let n = note("a", false, 0, false);
        assert_eq!(n.exports.backup, 2);
        assert_eq!(n.exports.exposure(), 0);
        assert_eq!(note("a", false, 1, false).exports.exposure(), 1);
    }
}
