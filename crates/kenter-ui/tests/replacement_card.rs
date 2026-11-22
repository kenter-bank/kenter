//! Restoring a card wallet onto a replacement card, against a real card.
//!
//! `backup_recovery.rs` covers the software route — card gone, phrase only.
//! This is the other one a holder takes: they buy another card and put the
//! wallet back on it. Everything between the phrase and a working wallet is
//! exercised here except the screens: `INIT`, `LOAD KEY`, the account vault,
//! the working copy, and the notes going back in.
//!
//! Destructive, and doubly gated, because it wipes whatever is on the reader:
//!
//! ```text
//! KENTER_CARD_DESTRUCTIVE=1 KENTER_CARD_PIN=<current pin> \
//!   cargo test -p kenter-ui --test replacement_card -- --ignored --test-threads=1
//! ```
//!
//! It leaves the card holding SEP-0005 test vector 1 with the PIN below, so
//! `stellar-keycard`'s `on_metal.rs` keeps working afterwards.

use kenter_vault::SoftVault;
use kenter_wallet::{backup::SeedSource, FileStore, HeldToken, Store};

/// What the card is given. Not the PIN it is *found* with — that comes from
/// `KENTER_CARD_PIN`, because a card that has been through the ceremony has
/// whatever its owner chose and a wrong guess costs one of five attempts.
const PIN: &[u8] = b"123456";
const PUK: &[u8] = b"012345678901";
const DURESS: &[u8] = b"098765";

/// SEP-0005 test vector 1. Published, so it is not a secret, and it is what
/// the other on-metal tests expect to find afterwards.
const PHRASE: &str = "illness spike retreat truth genius clock brain pass fit cave bargain toe";

/// A genuine note, from the shared fixture: real chain, real signature,
/// and an id derived from its own container.
///
/// `backup::restore` verifies all three now, so a hand-built record with a
/// blob of repeated bytes is refused rather than stored — which is the
/// point, and which means a test fixture has to be the real thing.
fn note(seed: u8, spend: bool) -> HeldToken {
    let amount = 2_500_000 * seed as u64;
    if spend {
        kenter_wallet::testing::spend_note(seed, amount, seed as u32)
    } else {
        kenter_wallet::testing::note(seed, amount)
    }
}

#[tokio::test]
#[ignore = "destructive; needs a fork Keycard and KENTER_CARD_DESTRUCTIVE=1"]
async fn a_card_wallet_goes_back_onto_a_replacement_card() {
    if std::env::var("KENTER_CARD_DESTRUCTIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set KENTER_CARD_DESTRUCTIVE=1 to wipe the card on the reader");
        return;
    }
    let found_pin = std::env::var("KENTER_CARD_PIN").unwrap_or_else(|_| "000000".into());

    let root = std::env::temp_dir().join(format!(
        "kenter-replacement-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let drawer = root.join("drawer");
    std::fs::create_dir_all(&drawer).unwrap();
    let file = drawer.join("kenter.kbk");

    // ── The wallet as it was, on the card that is now gone ──────────────
    //
    // Built in software from the same phrase. That is not a shortcut: the
    // card and software BIP85 derivations are checked against each other on
    // metal by `on_metal.rs`, so this produces byte-for-byte what the lost
    // card produced, and lets the test own a *second* card it does not have.
    let before = root.join("before");
    std::fs::create_dir_all(&before).unwrap();
    let mut old_vault = SoftVault::open(&before.join("vault.json")).unwrap();
    old_vault.set_seed_from_mnemonic(PHRASE, "", b"the old passphrase").unwrap();
    let (old_creds, old_backup) =
        kenter_vault::vault_bound_credentials(&mut old_vault, b"the old passphrase").unwrap();

    let held = [note(1, false), note(2, true), note(3, true)];
    let mut old_store = FileStore::open(&before.join("wallet"), old_creds).unwrap();
    for t in &held {
        old_store.put(t.clone()).await.unwrap();
    }
    old_store.advance_owner_index(31).await.unwrap();
    kenter_ui::backup::save(
        &mut old_store,
        &old_backup.key,
        &SeedSource {
            fingerprint: old_backup.fingerprint.clone(),
            origin: kenter_wallet::backup::SeedOrigin::Card,
            bip85: None,
        },
        &file,
        1_700_000_900,
    )
    .await
    .unwrap();
    std::fs::remove_dir_all(&before).unwrap();

    // ── A new machine. First run reads the file before asking anything. ─
    let after = root.join("after");
    std::fs::create_dir_all(&after).unwrap();
    std::env::set_var("KENTER_VAULT", after.join("vault.json"));
    std::env::set_var("KENTER_WALLET_DIR", after.join("wallet"));

    let source = kenter_ui::setup::inspect_backup(&file).expect("read the header");
    assert!(source.card_rooted, "the header must say this was a card wallet");
    assert!(
        kenter_ui::setup::phrase_matches(PHRASE, &source).unwrap(),
        "the phrase must be checked against the file before the card is touched"
    );
    // Read now, as first run does, so nothing written below can disturb it.
    let bytes = std::fs::read(&file).unwrap();

    // ── A blank replacement card ────────────────────────────────────────
    kenter_ui::card_setup::erase(found_pin.as_bytes()).expect("FACTORY RESET");
    let pubkey = kenter_ui::card_setup::restore_to_card(PHRASE, PIN, PUK, DURESS)
        .expect("INIT + LOAD KEY");

    // The card now holds the lost card's key. Same wallet, different silicon.
    let (card_creds, card_backup) =
        kenter_ui::card_setup::unlock(PIN).expect("unlock the replacement");
    assert_eq!(
        card_backup.fingerprint, source.fingerprint,
        "the replacement card is not the wallet the backup belongs to"
    );
    assert_eq!(*card_backup.key, *old_backup.key);

    // ── The account vault, the custody record, the working copy ─────────
    let wallet = kenter_ui::card_setup::provision(PIN).expect("provision");
    assert!(wallet.address.starts_with('G'));

    let vault = SoftVault::open(&after.join("vault.json")).unwrap();
    match vault.custody() {
        Some(kenter_vault::Custody::Card {
            seed_fingerprint,
            card_identity,
        }) => {
            assert_eq!(seed_fingerprint, &source.fingerprint);
            assert!(!card_identity.is_empty(), "the new card's identity is recorded");
        }
        other => panic!("expected card custody, got {other:?}"),
    }

    // ── The notes go back ───────────────────────────────────────────────
    let mut store = FileStore::open(&after.join("wallet"), card_creds).unwrap();
    assert!(store.all().await.unwrap().is_empty());

    let contents =
        kenter_ui::backup::open(&card_backup.key, &card_backup.fingerprint, &bytes).unwrap();
    let report = kenter_wallet::backup::restore(&mut store, &contents)
        .await
        .unwrap();
    assert_eq!(report.tokens_added, 3);

    // What first run does next, and the reason it does it: a wallet that
    // has just restored is backed up, and greeting its owner with "3 notes
    // in no backup" on the first screen after a recovery is both false and
    // the worst possible moment to be wrong.
    assert_eq!(
        kenter_ui::backup::coverage(&store).await.unwrap(),
        kenter_wallet::backup::Coverage::Missing,
        "nothing has been adopted yet"
    );
    kenter_ui::backup::adopt(&mut store, &contents, Some(file.display().to_string()))
        .await
        .unwrap();
    let covered = kenter_ui::backup::coverage(&store).await.unwrap();
    assert!(covered.is_covered(), "{covered:?}");
    assert_eq!(
        covered,
        kenter_wallet::backup::Coverage::Covered {
            // The file's date, not now, so "saved 3 days ago" stays true.
            created_at: 1_700_000_900,
            notes: 3
        }
    );
    // Per note, which is what the icon on each card reads.
    let record = store.last_backup().await.unwrap().unwrap();
    for t in &held {
        assert!(record.covers(&t.id), "{} reads as unbacked", t.id);
    }

    let mut back = store.all().await.unwrap();
    back.sort_by(|a, b| a.id.cmp(&b.id));
    let mut want = held.to_vec();
    want.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(back, want, "every field of every note");
    assert_eq!(
        store.allocate_owner_index().await.unwrap(),
        31,
        "the counter must not restart onto indices the restored notes stand on"
    );

    // Spendable, not just visible: the owner key for a restored spend note
    // has to come off the new card.
    let spend_index = held[1].owner_index.unwrap();
    let custody = vault.custody().cloned();
    let mut card =
        kenter_ui::vault::GuiVault::open(custody.as_ref(), vault).expect("open as card");
    let owner = kenter_vault::DerivingVault::derive_public(&mut card, spend_index, PIN)
        .expect("owner key from the replacement card");
    drop(card);

    let mut check = SoftVault::open(&root.join("check.json")).unwrap();
    check.set_seed_from_mnemonic(PHRASE, "", b"anything").unwrap();
    let want_owner =
        kenter_vault::DerivingVault::derive_public(&mut check, spend_index, b"anything").unwrap();
    assert_eq!(owner, want_owner, "the replacement card derives different owner keys");
    assert_eq!(
        hex::encode(pubkey),
        hex::encode(
            kenter_vault::DerivingVault::derive_public(&mut check, 0, b"anything").unwrap()
        ),
        "LOAD KEY reported an account-0 key that is not this phrase's"
    );

    let _ = std::fs::remove_dir_all(&root);
}
