//! The whole card ceremony against a real card, without the screens.
//!
//! In order: wipe, set the PINs, take a phrase off
//! the card, load it, derive the wallet's keys, make the account, write the
//! backup. The screens collect the same values and call the same three
//! functions, so this is the half that can fail against hardware — and
//! failing here is much easier to read than failing behind a GUI.
//!
//! Gated twice — `#[ignore]` and an environment variable — because it
//! **destroys whatever is on the card**:
//!
//! ```text
//! KENTER_CARD_DESTRUCTIVE=1 cargo test -p kenter-ui --test card_ceremony \
//!   -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! It leaves the card **blank**, which is what first run needs to see, so a
//! GUI run can follow it directly.

use stellar_keycard::{StellarKeycard, Transport};

const PIN: &[u8] = b"000000";
const PUK: &[u8] = b"012345678901";
const DURESS: &[u8] = b"024680";

fn card() -> StellarKeycard<Transport> {
    let t = Transport::connect().expect("no card on a PC/SC reader - hold it steady on it");
    StellarKeycard::connect(t).expect("SELECT failed")
}

/// Wipe to a blank card, whatever state it is in.
fn wipe() {
    let mut c = card();
    if c.application_info().expect("SELECT").initialized {
        c.factory_reset(Some(PIN))
            .expect("could not wipe - is the PIN still 000000?");
    } else {
        let _ = c.factory_reset(None);
    }
    assert!(
        !card().application_info().expect("SELECT").initialized,
        "the card is still initialized after a wipe"
    );
}

#[test]
#[ignore = "destructive; needs a fork Keycard and KENTER_CARD_DESTRUCTIVE=1"]
fn the_whole_ceremony_runs_against_a_card() {
    if std::env::var("KENTER_CARD_DESTRUCTIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set KENTER_CARD_DESTRUCTIVE=1 to wipe the card on the reader");
        return;
    }

    // A scratch vault. `provision` writes to KENTER_VAULT, and a test that
    // wrote to the real one would quietly replace a wallet.
    let dir = std::env::temp_dir().join(format!("kenter-ceremony-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("vault.json");
    unsafe { std::env::set_var("KENTER_VAULT", &vault) };

    println!("\n-- wiping the card --");
    wipe();

    // The PIN, duress and PUK steps only collect. Generating the phrase is
    // the first card contact.
    println!("-- INIT + GENERATE MNEMONIC --");
    let phrase = kenter_ui::card_setup::generate_phrase(PIN, PUK, DURESS, 24)
        .expect("the card would not produce a phrase");
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    println!(
        "   {} words, first/last: {} ... {}",
        words.len(),
        words[0],
        words[23]
    );

    // Five, from us. Passing nothing silently gets the applet's three.
    let info = card().application_info().expect("SELECT");
    assert!(info.initialized, "INIT did not take");
    assert_eq!(
        info.pin_retries,
        Some(5),
        "the PIN retry limit was not set to 5"
    );
    // The ordering the whole ceremony is built around: the words are
    // confirmed before any key exists, so abandoning costs nothing.
    assert!(
        !info.key_initialized,
        "a key exists before LOAD KEY - the confirm-before-write ordering is broken"
    );

    println!("-- LOAD KEY --");
    let pk = kenter_ui::card_setup::load_phrase(&phrase, PIN).expect("the card refused the key");
    assert!(
        card().application_info().expect("SELECT").key_initialized,
        "the card reports no key after LOAD KEY"
    );
    println!("   owner key 0: {}", hex::encode(pk));

    println!("-- derive, account, backup --");
    let w = kenter_ui::card_setup::provision(PIN).expect("provisioning failed");
    println!("   account : {}", w.address);
    println!("   backup  : {}", w.backup_path);

    assert!(
        w.address.starts_with('G') && w.address.len() == 56,
        "{}",
        w.address
    );
    assert!(vault.exists(), "no vault was written");
    let v = std::fs::read_to_string(&vault).unwrap();
    assert!(
        !v.contains("\"seed\""),
        "the account vault holds a seed - a card wallet's seed belongs on the card"
    );

    // The record that makes the wallet findable on the next launch. Both
    // identifiers, and the identity key must be *this* card's.
    {
        let v = kenter_vault::SoftVault::open(&vault).unwrap();
        let want_id = hex::encode(card().identity_pubkey());
        match v.custody() {
            Some(kenter_vault::Custody::Card {
                seed_fingerprint,
                card_identity,
            }) => {
                assert_eq!(card_identity, &want_id, "recorded the wrong card");
                assert!(!seed_fingerprint.is_empty(), "no seed fingerprint recorded");
                println!(
                    "   custody : card {} / wallet {}",
                    &card_identity[..16],
                    seed_fingerprint
                );
            }
            other => panic!("expected a card custody record, got {other:?}"),
        }
    }

    // The header is why this file is written before there are any notes.
    let bytes = std::fs::read(&w.backup_path).expect("backup file");
    let file = kenter_wallet::backup::inspect(&bytes).expect("backup header");
    assert_eq!(
        file.origin(),
        kenter_wallet::backup::SeedOrigin::Card,
        "the backup does not say the phrase is the card's seed"
    );

    // The claim the whole recovery story rests on: those 24 words, restored
    // into software, reproduce every key the card derives.
    println!("-- the phrase reproduces the card's keys --");
    let seed = kenter_vault::mnemonic::to_seed(&phrase, "").unwrap();
    let soft_path = dir.join("restored.json");
    let mut soft = kenter_vault::SoftVault::open(&soft_path).unwrap();
    soft.set_seed(&*seed, b"restore-pass").unwrap();

    let (s_store, s_backup) =
        kenter_vault::vault_bound_credentials(&mut soft, b"restore-pass").unwrap();
    let (c_store, c_backup) = kenter_vault::vault_bound_credentials(&mut card(), PIN).unwrap();
    assert_eq!(
        c_store.aead.as_slice(),
        s_store.aead.as_slice(),
        "store key"
    );
    assert_eq!(
        c_backup.key.as_slice(),
        s_backup.key.as_slice(),
        "backup key"
    );
    assert_eq!(
        kenter_vault::account_vault_credential(&mut card(), PIN)
            .unwrap()
            .as_slice(),
        kenter_vault::account_vault_credential(&mut soft, b"restore-pass")
            .unwrap()
            .as_slice(),
        "account-vault credential - the restored wallet could not open its own account"
    );

    // The guard that was missing. Running setup again against the vault we
    // just wrote must refuse rather than add a second account to it.
    println!("-- a second provision over the same vault is refused --");
    let err = kenter_ui::card_setup::provision(PIN)
        .expect_err("provisioning twice into one vault was allowed");
    assert!(
        err.contains("already holds an account"),
        "wrong refusal: {err}"
    );

    // Step 3's claim: with the record written, the app can find this
    // wallet. The old test - has_seed() - is false here and would have
    // sent its owner to first run with the card on the reader.
    println!("-- the wallet is findable on a relaunch --");
    {
        let v = kenter_vault::SoftVault::open(&vault).unwrap();
        assert!(!v.has_seed(), "a card wallet's vault must hold no seed");
        let Some(kenter_vault::Custody::Card { card_identity, .. }) = v.custody() else {
            panic!("no card custody recorded");
        };
        // And the gate would find the card, without a PIN.
        let p = kenter_ui::card::presence(card_identity);
        assert_eq!(p, kenter_ui::card::Presence::Ready, "{p:?}");
        assert!(p.can_try());

        // A card for another wallet is Different, not Ready - which is what
        // keeps a stranger's card from looking like yours at the gate.
        let other = kenter_ui::card::presence(&"00".repeat(33));
        assert_eq!(other, kenter_ui::card::Presence::Different);
        println!("   gate finds the card without a PIN");
    }

    println!("-- leaving the card blank for the GUI run --");
    wipe();
    let _ = std::fs::remove_dir_all(&dir);
    println!("   done\n");
}

/// Card setup must refuse a vault that already holds a software wallet.
///
/// No card needed: the refusal happens before anything is sent to one,
/// which is the point - `setup::create` has always guarded this and
/// `provision` did not, so card setup over an existing wallet quietly
/// produced a vault with a software seed and a card-derived account key.
#[test]
fn card_setup_refuses_a_vault_that_holds_a_software_wallet() {
    let dir = std::env::temp_dir().join(format!("kenter-mixed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("vault.json");

    // A software wallet, made the way first run makes one.
    let mut v = kenter_vault::SoftVault::open(&vault).unwrap();
    let seed = kenter_vault::mnemonic::to_seed(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .unwrap();
    v.set_seed(&*seed, b"a passphrase").unwrap();
    drop(v);

    unsafe { std::env::set_var("KENTER_VAULT", &vault) };
    let err = kenter_ui::card_setup::provision(PIN)
        .expect_err("card setup over a software wallet was allowed");
    assert!(
        err.contains("already holds a software wallet"),
        "wrong refusal: {err}"
    );

    // And the wallet it refused to touch is untouched.
    let after = kenter_vault::SoftVault::open(&vault).unwrap();
    assert!(after.has_seed(), "the software wallet's seed was disturbed");
    let _ = std::fs::remove_dir_all(&dir);
}
