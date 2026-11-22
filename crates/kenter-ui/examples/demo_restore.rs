//! Build a wallet and a backup to restore *from*, so the restore flow can be
//! walked by hand.
//!
//! Every step under the restore screens is tested, including on a card,
//! but the tests exercise the flow through its functions. Driving it by
//! hand needs two things a fresh machine does
//! not have — a backup file, and the words that open it — and making those
//! by hand means a deposit, a network and several minutes.
//!
//! ```text
//! cargo run -p kenter-ui --example demo_restore -- [card|software]
//! ```
//!
//! It prints the phrase, the file and the two environment variables to
//! launch the client with. The wallet it builds is then **deleted**: what is
//! left is the position a holder is in after losing a machine.
//!
//! The notes are cryptographically real — they have to be, because restore
//! verifies the container and refuses anything else — but **no mint printed
//! them and no escrow backs them**. A local process can play every node in
//! a print; what it cannot fake is the on-chain registration. So the
//! billfold will mark them stalled once it reaches the ledger, and that is
//! the ledger check working rather than a defect.
//!
//! What this fixture therefore cannot show is a *healthy* restored
//! billfold. That needs the real print path: tunnler, node, mint, deposit.

use std::path::PathBuf;

use kenter_vault::SoftVault;
use kenter_wallet::backup::{SeedOrigin, SeedSource};
use kenter_wallet::{FileStore, HeldToken, Store};

/// Fixed, so a second run restores into the same wallet rather than making
/// a stranger. Published BIP-39 test words; never use them for anything.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal \
                      winner thank year wave sausage worth useful legal will";

/// Genuine notes, from the shared fixture. `backup::restore` verifies the
/// container now, so fabricated records are refused rather than restored —
/// which would have left this demo with nothing to show.
fn note(seed: u8, spend: bool) -> HeldToken {
    let amount = 2_500_000 * seed as u64;
    if spend {
        kenter_wallet::testing::spend_note(seed, amount, seed as u32)
    } else {
        kenter_wallet::testing::note(seed, amount)
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let card = match std::env::args().nth(1).as_deref() {
        None | Some("card") => true,
        Some("software") => false,
        Some(other) => return Err(format!("unknown kind {other:?} - use card or software")),
    };

    let root = std::env::temp_dir().join("kenter-demo-restore");
    let _ = std::fs::remove_dir_all(&root);
    let build = root.join("build");
    let fresh = root.join("fresh");
    let drawer = root.join("drawer");
    for d in [&build, &fresh, &drawer] {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }

    // The wallet as it was, before the machine was lost. A card wallet is
    // built in software: the derivations are checked against a real card by
    // `stellar-keycard`'s `on_metal.rs`, so this is the same bytes.
    let mut vault = SoftVault::open(&build.join("vault.json")).map_err(|e| e.to_string())?;
    vault
        .set_seed_from_mnemonic(PHRASE, "", b"the old passphrase")
        .map_err(|e| e.to_string())?;
    let (creds, backup) = if card {
        kenter_vault::vault_bound_credentials(&mut vault, b"the old passphrase")
            .map_err(|e| e.to_string())?
    } else {
        (
            vault.store_credentials(b"the old passphrase").map_err(|e| e.to_string())?,
            vault.backup_credentials(b"the old passphrase").map_err(|e| e.to_string())?,
        )
    };

    let mut store = FileStore::open(&build.join("wallet"), creds).map_err(|e| e.to_string())?;
    for (i, spend) in [(1u8, false), (2, true), (3, true), (4, false)] {
        store.put(note(i, spend)).await.map_err(|e| e.to_string())?;
    }
    store.advance_owner_index(17).await.map_err(|e| e.to_string())?;
    store
        .put_pending(kenter_wallet::PendingReceive {
            index: 0,
            commitment: [0xAB; 32],
            created_at: 1_700_000_500,
        })
        .await
        .map_err(|e| e.to_string())?;

    let file: PathBuf = drawer.join(kenter_ui::backup::file_name(&backup.fingerprint));
    kenter_ui::backup::save(
        &mut store,
        &backup.key,
        &SeedSource {
            fingerprint: backup.fingerprint.clone(),
            origin: if card {
                SeedOrigin::Card
            } else {
                SeedOrigin::Software
            },
            bip85: None,
        },
        &file,
        kenter_ui::backup::now() - 3 * 24 * 60 * 60,
    )
    .await?;

    // The machine is gone. Only the drawer survives.
    drop(store);
    std::fs::remove_dir_all(&build).map_err(|e| e.to_string())?;

    println!("\n  a {} wallet, backed up and lost", if card { "card" } else { "software" });
    println!("  ---------------------------------------------");
    println!("  phrase   {PHRASE}");
    println!("  backup   {}", file.display());
    println!("  holds    4 notes and a standing pay tag, saved 3 days ago");
    println!("           (real containers, but no mint printed them - the");
    println!("            billfold will call them stalled, correctly)");
    if card {
        println!("\n  Restore offers both ways back. A card needs a blank one on");
        println!("  the reader; the software route needs nothing.");
    }
    println!("\n  Launch a fresh client against it:\n");
    println!("    KENTER_VAULT={} \\", fresh.join("vault.json").display());
    println!("    KENTER_WALLET_DIR={} \\", fresh.join("wallet").display());
    println!("      cargo run -p kenter-ui --bin kenter-ui\n");
    Ok(())
}
