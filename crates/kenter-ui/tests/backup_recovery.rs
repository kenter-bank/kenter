//! The disaster, rehearsed: the computer is gone, and all that survived is
//! twenty-four words and a file.
//!
//! Everything else about backups is tested a layer down — the format in
//! `kenter_wallet::backup`, the file handling in `kenter_ui::backup`. This
//! tests the only claim that matters to a holder, and it is the one no unit
//! test can make, because it spans the vault, the store and the backup file
//! and depends on all three deriving from the same seed.
//!
//! The passphrase is **deliberately different** on the new machine. That is
//! not incidental: a backup sealed under the vault passphrase would make the
//! vault file a third thing you must not lose, which is exactly the thing a
//! backup is supposed to survive. If
//! this test ever has to use the same passphrase twice to pass, that promise
//! has been broken.

use std::path::{Path, PathBuf};

use kenter_vault::{SoftVault, StoreCredentials};
use kenter_wallet::backup::{content_digest, SeedSource};
use kenter_wallet::{FileStore, HeldToken, Store};

/// A phrase, fixed so the test is deterministic. Never used anywhere real.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal \
                      winner thank year wave sausage worth useful legal will";

fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "kenter-recovery-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

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

/// Build a vault at `vault_path` from `PHRASE`, and derive what a session
/// would hold. This is `setup::create` plus the unlock, which is what first
/// run does on a replacement machine.
fn install(vault_path: &Path, passphrase: &[u8]) -> (StoreCredentials, [u8; 32], String) {
    let mut vault = SoftVault::open(vault_path).unwrap();
    vault
        .set_seed_from_mnemonic(PHRASE, "", passphrase)
        .unwrap();
    vault.set_custody(kenter_vault::Custody::Software, passphrase).unwrap();

    let store = vault.store_credentials(passphrase).unwrap();
    let backup = vault.backup_credentials(passphrase).unwrap();
    (store, *backup.key, backup.fingerprint)
}

#[tokio::test]
async fn a_phrase_and_a_file_bring_the_notes_back_to_a_different_computer() {
    let old = scratch("old");
    let new = scratch("new");
    // Somewhere that survives both: the stick in the drawer.
    let drawer = scratch("drawer");
    let file = drawer.join("kenter.kbk");

    // ── The machine that is about to be lost ────────────────────────────
    let (creds, key, fingerprint) = install(&old.join("vault.json"), b"the old passphrase");
    let seed = SeedSource::software(&fingerprint);

    let mut store = FileStore::open(&old.join("wallet"), creds).unwrap();
    let held = [note(1, false), note(2, true), note(3, true)];
    for t in &held {
        store.put(t.clone()).await.unwrap();
    }
    // Spend mode reserves indices, so the counter is somewhere past them.
    store.advance_owner_index(12).await.unwrap();
    // A standing pay tag, which lives in `pending` and would silently retire
    // a published address if it did not travel.
    store
        .put_pending(kenter_wallet::PendingReceive {
            index: 0,
            commitment: [0xAB; 32],
            created_at: 1_700_000_500,
        })
        .await
        .unwrap();

    kenter_ui::backup::save(&mut store, &key, &seed, &file, 1_700_000_900)
        .await
        .unwrap();
    assert!(kenter_ui::backup::coverage(&store).await.unwrap().is_covered());

    // ── The machine is gone ─────────────────────────────────────────────
    std::fs::remove_dir_all(&old).unwrap();

    // ── A new one, the same twenty-four words, a different passphrase ───
    let (new_creds, new_key, new_fingerprint) =
        install(&new.join("vault.json"), b"a completely different passphrase");

    // The seed is the same, so the wallet is the same, whatever was typed
    // to guard it locally.
    assert_eq!(new_fingerprint, fingerprint, "the phrase must fix the wallet");
    assert_eq!(new_key, key, "the backup key must come from the seed alone");

    let mut fresh = FileStore::open(&new.join("wallet"), new_creds).unwrap();
    assert!(fresh.all().await.unwrap().is_empty());

    let report = kenter_ui::backup::restore_file(&mut fresh, &new_key, &new_fingerprint, &file)
        .await
        .unwrap();

    // ── Everything is back ──────────────────────────────────────────────
    assert_eq!(report.tokens_added, 3);
    assert_eq!(report.pending_added, 1);

    let mut back = fresh.all().await.unwrap();
    back.sort_by(|a, b| a.id.cmp(&b.id));
    let mut want = held.to_vec();
    want.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(back, want, "every field of every note, not just the ids");
    assert_eq!(content_digest(&back), content_digest(&held));

    // The standing tag survived, so the published address still works.
    let pending = fresh.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].index, 0);
    assert_eq!(pending[0].commitment, [0xAB; 32]);

    // And the counter did not reset, so the restored wallet cannot hand out
    // an index one of its own restored notes already stands on.
    assert_eq!(fresh.allocate_owner_index().await.unwrap(), 12);

    for d in [new, drawer] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A card wallet, recovered with no card.
///
/// This is the case the whole design turns on and the one most likely to be
/// wrong, because a card wallet does **not** derive its keys the way a
/// software wallet does: its store and backup keys are BIP85 children
/// (`m/83696968'/128169'/32'/{0,1}'`), while a software wallet hashes the
/// seed under a domain tag. Same phrase, different keys.
///
/// So "phrase + file" only holds for a card wallet if the BIP85 derivation
/// can be reproduced off-card. `SoftVault` implements `Bip85` for exactly
/// that reason, and this is the test that it is true all the way up: a
/// backup written by a card wallet opens on a machine that never saw a card.
///
/// The software derivation is pinned to the card's by the published BIP85
/// vectors in `kenter_vault::bip85` and by the on-metal tests, so proving it
/// here against `SoftVault` proves it for the card.
#[tokio::test]
async fn a_card_wallet_is_recoverable_with_no_card_at_all() {
    let old = scratch("card-old");
    let new = scratch("card-new");
    let drawer = scratch("card-drawer");
    let file = drawer.join("kenter.kbk");

    // ── The card wallet. `vault_bound_credentials` is what the card runs;
    // the vault here stands in for the seed the card holds. ─────────────
    let mut card_side = SoftVault::open(&old.join("vault.json")).unwrap();
    card_side
        .set_seed_from_mnemonic(PHRASE, "", b"the PIN stands in here")
        .unwrap();
    let (creds, backup) =
        kenter_vault::vault_bound_credentials(&mut card_side, b"the PIN stands in here").unwrap();

    // Card origin: the phrase *is* the card's seed, so a restorer needs the
    // words and nothing else - which is the claim under test.
    let seed = kenter_ui::backup::seed_source(
        Some(&kenter_vault::Custody::Card {
            seed_fingerprint: backup.fingerprint.clone(),
            card_identity: "03c7a53f".into(),
        }),
        &backup.fingerprint,
    );

    let mut store = FileStore::open(&old.join("wallet"), creds).unwrap();
    let held = [note(4, true), note(5, false)];
    for t in &held {
        store.put(t.clone()).await.unwrap();
    }
    store.advance_owner_index(21).await.unwrap();
    kenter_ui::backup::save(&mut store, &backup.key, &seed, &file, 1_700_000_900)
        .await
        .unwrap();

    // The header says what a restorer has to be asked for.
    let header = kenter_wallet::backup::inspect(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(header.origin(), kenter_wallet::backup::SeedOrigin::Card);

    // ── The card is destroyed and the computer with it ────────────────
    std::fs::remove_dir_all(&old).unwrap();

    // ── A new machine, no reader, no card: just the words ────────────
    let mut rebuilt = SoftVault::open(&new.join("vault.json")).unwrap();
    rebuilt
        .set_seed_from_mnemonic(PHRASE, "", b"whatever they choose now")
        .unwrap();
    let (new_creds, new_backup) =
        kenter_vault::vault_bound_credentials(&mut rebuilt, b"whatever they choose now").unwrap();

    assert_eq!(
        new_backup.fingerprint, backup.fingerprint,
        "the BIP85 children must come from the seed alone, not from the credential \
         that unwraps it - otherwise a card wallet's backup dies with its card"
    );
    assert_eq!(*new_backup.key, *backup.key);

    let mut fresh = FileStore::open(&new.join("wallet"), new_creds).unwrap();
    let report =
        kenter_ui::backup::restore_file(&mut fresh, &new_backup.key, &new_backup.fingerprint, &file)
            .await
            .unwrap();
    assert_eq!(report.tokens_added, 2);

    let mut back = fresh.all().await.unwrap();
    back.sort_by(|a, b| a.id.cmp(&b.id));
    let mut want = held.to_vec();
    want.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(back, want);
    assert_eq!(fresh.allocate_owner_index().await.unwrap(), 21);

    // Seeing the notes is not recovery; they have to be spendable. A spend
    // signs with the owner key at the note's index, and the card derives
    // those at SLIP-0010 `m/44'/148'/n'` - the same path this vault uses.
    let spend_index = held[0].owner_index.unwrap();
    let recovered = kenter_vault::DerivingVault::derive_public(
        &mut rebuilt,
        spend_index,
        b"whatever they choose now",
    )
    .unwrap();
    let on_card =
        kenter_vault::DerivingVault::derive_public(&mut card_side, spend_index, b"the PIN stands in here")
            .unwrap();
    assert_eq!(
        recovered, on_card,
        "owner keys must survive the card too, or the notes come back unspendable"
    );

    for d in [new, drawer] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Recovery is not a one-way door.
///
/// A wallet recovered from a lost card goes on deriving the card's way, so
/// the backups it writes *afterwards* have to say `Card` too — the origin
/// names the derivation, not where the seed is kept. Marking them `Software`
/// would be invisible until the next disaster, and then the holder would
/// have done everything right and still lost the notes.
#[tokio::test]
async fn a_recovered_wallet_writes_backups_that_restore_again() {
    let first = scratch("again-1");
    let second = scratch("again-2");
    let third = scratch("again-3");
    let drawer = scratch("again-drawer");

    // ── A card wallet, backed up, then lost ───────────────────────
    let mut card_side = SoftVault::open(&first.join("vault.json")).unwrap();
    card_side.set_seed_from_mnemonic(PHRASE, "", b"pin").unwrap();
    let (creds, backup) = kenter_vault::vault_bound_credentials(&mut card_side, b"pin").unwrap();

    let custody = kenter_vault::Custody::Card {
        seed_fingerprint: backup.fingerprint.clone(),
        card_identity: "03c7a53f".into(),
    };
    let mut store = FileStore::open(&first.join("wallet"), creds).unwrap();
    store.put(note(1, false)).await.unwrap();
    kenter_ui::backup::save(
        &mut store,
        &backup.key,
        &kenter_ui::backup::seed_source(Some(&custody), &backup.fingerprint),
        &drawer.join("first.kbk"),
        10,
    )
    .await
    .unwrap();
    std::fs::remove_dir_all(&first).unwrap();

    // ── Recovered in software. This is what first run now records. ─────
    let source = kenter_ui::setup::inspect_backup(&drawer.join("first.kbk")).unwrap();
    assert!(source.card_rooted, "the header has to survive the first hop");
    let recovered_custody = kenter_vault::Custody::RecoveredCard {
        seed_fingerprint: source.fingerprint.clone(),
    };

    let mut rebuilt = SoftVault::open(&second.join("vault.json")).unwrap();
    rebuilt.set_seed_from_mnemonic(PHRASE, "", b"new pass").unwrap();
    rebuilt.set_custody(recovered_custody.clone(), b"new pass").unwrap();
    let (creds2, backup2) =
        kenter_ui::vault::session_credentials(&mut rebuilt, Some(&recovered_custody), b"new pass")
            .unwrap();
    assert_eq!(backup2.fingerprint, source.fingerprint);

    let mut store2 = FileStore::open(&second.join("wallet"), creds2).unwrap();
    kenter_ui::backup::restore_file(
        &mut store2,
        &backup2.key,
        &backup2.fingerprint,
        &drawer.join("first.kbk"),
    )
    .await
    .unwrap();
    // ...and it keeps being used: another note arrives.
    store2.put(note(2, false)).await.unwrap();

    // ── It backs itself up, and is lost again ────────────────────
    kenter_ui::backup::save(
        &mut store2,
        &backup2.key,
        &kenter_ui::backup::seed_source(Some(&recovered_custody), &backup2.fingerprint),
        &drawer.join("second.kbk"),
        20,
    )
    .await
    .unwrap();
    std::fs::remove_dir_all(&second).unwrap();

    // ── The second file has to work exactly like the first ──────────
    let again = kenter_ui::setup::inspect_backup(&drawer.join("second.kbk")).unwrap();
    assert!(
        again.card_rooted,
        "a recovered wallet wrote a backup that claims the wrong derivation - \
         restoring it would pick software keys and fail as another wallet"
    );
    assert_eq!(again.fingerprint, source.fingerprint, "still the same wallet");
    assert!(kenter_ui::setup::phrase_matches(PHRASE, &again).unwrap());

    let mut rebuilt2 = SoftVault::open(&third.join("vault.json")).unwrap();
    rebuilt2.set_seed_from_mnemonic(PHRASE, "", b"third pass").unwrap();
    let custody3 = kenter_vault::Custody::RecoveredCard {
        seed_fingerprint: again.fingerprint.clone(),
    };
    let (creds3, backup3) =
        kenter_ui::vault::session_credentials(&mut rebuilt2, Some(&custody3), b"third pass")
            .unwrap();
    let mut store3 = FileStore::open(&third.join("wallet"), creds3).unwrap();
    let report = kenter_ui::backup::restore_file(
        &mut store3,
        &backup3.key,
        &backup3.fingerprint,
        &drawer.join("second.kbk"),
    )
    .await
    .unwrap();

    assert_eq!(report.tokens_added, 2, "both notes, across two recoveries");

    for d in [third, drawer] {
        let _ = std::fs::remove_dir_all(d);
    }
}

// ---------------------------------------------------------------------------
// First run reads the file before it asks for anything
// ---------------------------------------------------------------------------

/// A different valid phrase, for the wrong-words case.
const OTHER_PHRASE: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Write a backup for `origin` and read its header back the way first run
/// does — with no key, and before the holder has typed anything.
async fn source_for(dir: &Path, card_rooted: bool) -> kenter_ui::RestoreSource {
    let mut vault = SoftVault::open(&dir.join("vault.json")).unwrap();
    vault.set_seed_from_mnemonic(PHRASE, "", b"pass").unwrap();

    let (creds, backup) = if card_rooted {
        let (c, b) = kenter_vault::vault_bound_credentials(&mut vault, b"pass").unwrap();
        (c, b)
    } else {
        (
            vault.store_credentials(b"pass").unwrap(),
            vault.backup_credentials(b"pass").unwrap(),
        )
    };
    let custody = if card_rooted {
        kenter_vault::Custody::Card {
            seed_fingerprint: backup.fingerprint.clone(),
            card_identity: "03ab".into(),
        }
    } else {
        kenter_vault::Custody::Software
    };

    let file = dir.join("b.kbk");
    let mut store = FileStore::open(&dir.join("wallet"), creds).unwrap();
    store.put(note(1, false)).await.unwrap();
    store.put(note(2, false)).await.unwrap();
    kenter_ui::backup::save(
        &mut store,
        &backup.key,
        &kenter_ui::backup::seed_source(Some(&custody), &backup.fingerprint),
        &file,
        kenter_ui::backup::now() - 3 * 24 * 60 * 60,
    )
    .await
    .unwrap();

    kenter_ui::setup::inspect_backup(&file).unwrap()
}

/// The header says which kind of wallet the words are for. The holder has
/// no way to know this, and picking wrong is silent.
#[tokio::test]
async fn the_header_says_what_the_phrase_is_for() {
    let dir = scratch("hdr-card");
    let card = source_for(&dir, true).await;
    assert!(card.card_rooted);
    assert!(card.summary.starts_with("a card wallet - 2 notes"), "{}", card.summary);
    assert!(card.summary.contains("3 days ago"), "{}", card.summary);
    // The reassurance that matters: no card is needed to use this.
    assert!(card.needs.contains("the card itself is not needed"), "{}", card.needs);
    let _ = std::fs::remove_dir_all(&dir);

    let dir = scratch("hdr-soft");
    let soft = source_for(&dir, false).await;
    assert!(!soft.card_rooted);
    assert!(soft.summary.starts_with("a software wallet - 2 notes"), "{}", soft.summary);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The trap `phrase_matches` exists to avoid: one seed, two wallets.
///
/// If the check used the wrong derivation it would reject the right phrase,
/// and a holder with a correct backup and correct words would be told their
/// words were wrong — the single most discouraging failure this flow has.
#[tokio::test]
async fn one_seed_gives_two_different_fingerprints() {
    let dir = scratch("two-fp");
    let card = source_for(&dir, true).await;
    let _ = std::fs::remove_dir_all(&dir);

    let dir = scratch("two-fp2");
    let soft = source_for(&dir, false).await;
    let _ = std::fs::remove_dir_all(&dir);

    assert_ne!(
        card.fingerprint, soft.fingerprint,
        "the same phrase must name two different wallets, or the header could \
         not tell a restore which derivation to use"
    );
    // Each is matched by the right derivation, and only by it.
    assert!(kenter_ui::setup::phrase_matches(PHRASE, &card).unwrap());
    assert!(kenter_ui::setup::phrase_matches(PHRASE, &soft).unwrap());

    let crossed = kenter_ui::RestoreSource {
        card_rooted: false,
        ..card.clone()
    };
    assert!(
        !kenter_ui::setup::phrase_matches(PHRASE, &crossed).unwrap(),
        "reading a card file with the software derivation must not appear to match"
    );
}

/// Wrong words, caught before a vault is built on them.
#[tokio::test]
async fn the_wrong_phrase_is_caught_before_anything_is_written() {
    let dir = scratch("wrong-words");
    let source = source_for(&dir, true).await;

    assert!(kenter_ui::setup::phrase_matches(PHRASE, &source).unwrap());
    assert!(!kenter_ui::setup::phrase_matches(OTHER_PHRASE, &source).unwrap());
    // Nonsense is an error, not a silent "no" - the holder mistyped rather
    // than brought the wrong words.
    assert!(kenter_ui::setup::phrase_matches("not a phrase at all", &source).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Provisioning a replacement card must not destroy the backup it is being
/// restored from.
///
/// The working copy provisioning writes is **empty**, and it goes to exactly
/// the filename the save dialog suggests. A holder restoring onto a new card,
/// who copied their backup next to the vault, would have had it replaced by
/// that empty file moments before the notes were read out of it — losing the
/// notes and the only copy of them in one step, while doing nothing wrong.
#[tokio::test]
async fn provisioning_never_writes_over_a_backup_that_is_already_there() {
    let home = scratch("clobber");
    std::env::set_var("KENTER_VAULT", home.join("vault.json"));

    // A real backup, sitting at the path provisioning wants to use.
    let mut vault = SoftVault::open(&home.join("source.json")).unwrap();
    vault.set_seed_from_mnemonic(PHRASE, "", b"pass").unwrap();
    let (creds, backup) = kenter_vault::vault_bound_credentials(&mut vault, b"pass").unwrap();
    let target = kenter_ui::backup::working_copy_path(&backup.fingerprint).unwrap();

    let mut store = FileStore::open(&home.join("wallet"), creds).unwrap();
    store.put(note(1, false)).await.unwrap();
    store.put(note(2, false)).await.unwrap();
    kenter_ui::backup::save(
        &mut store,
        &backup.key,
        &kenter_ui::backup::seed_source(
            Some(&kenter_vault::Custody::RecoveredCard {
                seed_fingerprint: backup.fingerprint.clone(),
            }),
            &backup.fingerprint,
        ),
        &target,
        10,
    )
    .await
    .unwrap();
    let before = std::fs::read(&target).unwrap();
    assert_eq!(
        kenter_wallet::backup::inspect(&before).unwrap().token_count,
        2
    );

    // What provisioning does to it. Nothing: the notes are still in there.
    kenter_ui::card_setup::write_working_copy(&backup).unwrap();
    let after = std::fs::read(&target).unwrap();
    assert_eq!(
        kenter_wallet::backup::inspect(&after).unwrap().token_count,
        2,
        "provisioning replaced a backup holding notes with an empty one"
    );
    assert_eq!(before, after);

    // With nothing there, it writes the empty header as it always did -
    // that file records the origin and fingerprint, which is its job.
    std::fs::remove_file(&target).unwrap();
    kenter_ui::card_setup::write_working_copy(&backup).unwrap();
    let fresh = kenter_wallet::backup::inspect(&std::fs::read(&target).unwrap()).unwrap();
    assert_eq!(fresh.token_count, 0);
    assert_eq!(fresh.origin(), kenter_wallet::backup::SeedOrigin::Card);

    let _ = std::fs::remove_dir_all(&home);
}

/// The account a redemption pays into has to come back from the words too.
///
/// A random account (`StellarKeypair::random()`) stored in the vault and
/// nowhere else would be recoverable from *phrase plus vault file*, never
/// from the phrase alone, and the vault file would quietly be a third
/// thing a holder must not lose.
///
/// The loss is not subtle: a restore would bring back every note and
/// leave the account's balance at an address the restored wallet cannot
/// sign for. Redemption pays *into* this account, so the shape of the loss
/// is "your notes survived and the proceeds of the ones you had already
/// spent did not".
#[tokio::test]
async fn the_fee_paying_account_comes_back_from_the_phrase() {
    let first = scratch("acct-1");
    let second = scratch("acct-2");

    // Two installs of the same wallet, with nothing shared but the words:
    // different directories, different passphrases, no file copied.
    let a = kenter_ui::setup::create_at(
        &first.join("vault.json"),
        b"the first passphrase",
        PHRASE,
        kenter_vault::Custody::Software,
    )
    .expect("first install");
    let b = kenter_ui::setup::create_at(
        &second.join("vault.json"),
        b"a completely different passphrase",
        PHRASE,
        kenter_vault::Custody::Software,
    )
    .expect("second install");

    assert_eq!(
        a, b,
        "the same phrase produced two different fee-paying accounts - \
         anything redeemed into the first is unreachable from the second"
    );
    assert!(a.starts_with('G'));

    // A different phrase must still be a different account, or the
    // derivation is ignoring its input.
    let third = scratch("acct-3");
    let c = kenter_ui::setup::create_at(
        &third.join("vault.json"),
        b"pass",
        OTHER_PHRASE,
        kenter_vault::Custody::Software,
    )
    .expect("third install");
    assert_ne!(a, c);

    // And a wallet recovered from a lost card lands on the same account as
    // the card did: the derivation is the seed's, not the custody's.
    let fourth = scratch("acct-4");
    let d = kenter_ui::setup::create_at(
        &fourth.join("vault.json"),
        b"pass",
        PHRASE,
        kenter_vault::Custody::RecoveredCard {
            seed_fingerprint: "irrelevant".into(),
        },
    )
    .expect("fourth install");
    assert_eq!(a, d, "custody changed which account the words name");

    for dir in [first, second, third, fourth] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The other half of the promise: the file alone is worth nothing.
///
/// Someone who steals the backup and not the phrase has a file they cannot
/// open — which is what makes it safe to keep one on a stick in a drawer.
#[tokio::test]
async fn the_file_alone_opens_nothing() {
    let home = scratch("thief-home");
    let drawer = scratch("thief-drawer");
    let file = drawer.join("kenter.kbk");

    let (creds, key, fingerprint) = install(&home.join("vault.json"), b"the passphrase");
    let mut store = FileStore::open(&home.join("wallet"), creds).unwrap();
    store.put(note(1, false)).await.unwrap();
    kenter_ui::backup::save(
        &mut store,
        &key,
        &SeedSource::software(&fingerprint),
        &file,
        10,
    )
    .await
    .unwrap();

    let bytes = std::fs::read(&file).unwrap();

    // The header is readable — that is deliberate, so a holder can tell two
    // files apart without unlocking either.
    let header = kenter_wallet::backup::inspect(&bytes).unwrap();
    assert_eq!(header.token_count, 1);
    assert_eq!(header.seed_fingerprint, fingerprint);

    // The notes are not.
    assert!(!String::from_utf8_lossy(&bytes).contains(&hex::encode(vec![1u8; 96])));
    let wrong = [0x99u8; 32];
    assert!(kenter_ui::backup::open(&wrong, &fingerprint, &bytes).is_err());

    for d in [home, drawer] {
        let _ = std::fs::remove_dir_all(d);
    }
}
