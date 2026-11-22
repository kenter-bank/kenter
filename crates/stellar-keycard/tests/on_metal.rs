//! The same claims as `owner_keys.rs`, against a real card over PC/SC.
//!
//! The hardware run is a gate rather than a formality: protocol code can pass
//! review and the simulator and still fail on a card (a card signing with a
//! high `s` fails about half of all secure-channel opens if the client does
//! not normalise it). The simulator is the applet's own code, but it is not
//! the card's chip, its RNG, or its NFC framing.
//!
//! Everything here needs:
//!
//! - a Keycard with the Ed25519 fork on a PC/SC reader (contactless, and it
//!   wants a steady position — a card at the edge of range drops the channel
//!   mid-command and the failure reads like a protocol bug);
//! - that card seeded with **SEP-0005 test vector 1**, which is what the
//!   applet suite leaves behind, and which `tests/vectors/owner_key_vectors.json`
//!   is generated from;
//! - PIN `000000` — the applet suite's value.
//!
//! ```text
//! cargo test -p stellar-keycard --test on_metal -- --ignored --test-threads=1
//! ```
//!
//! **Only the main PIN is ever sent.** The duress pin verifies with `9000`
//! and switches to a decoy tree: empty notes, unrelated keys, its own index
//! counter. A test that fell back to it would not fail, it would report that
//! the card derives the wrong keys.

use kenter_vault::{DerivingVault, SoftVault, vault_bound_credentials};
use serde_json::Value;
use stellar_keycard::{StellarKeycard, Transport};

/// The PIN these tests send, defaulting to the applet suite's value.
///
/// Overridable because a card that has been through the Kenter ceremony has
/// whatever PIN its owner chose, and **a wrong PIN costs one of five
/// attempts**. A hardcoded default is a trap on any card but the one the
/// suite left behind:
///
/// ```text
/// KENTER_CARD_PIN=123456 cargo test -p stellar-keycard --test on_metal -- --ignored
/// ```
fn card_pin() -> Vec<u8> {
    std::env::var("KENTER_CARD_PIN")
        .unwrap_or_else(|_| "000000".into())
        .into_bytes()
}
const VECTORS: &str = "../../tests/vectors/owner_key_vectors.json";

fn vectors() -> Value {
    let raw = std::fs::read_to_string(VECTORS).unwrap_or_else(|e| panic!("{VECTORS}: {e}"));
    serde_json::from_str(&raw).expect("vectors are not JSON")
}

fn card() -> StellarKeycard<Transport> {
    let t = Transport::connect()
        .expect("no card on a PC/SC reader - place the Keycard on the reader and hold it still");
    StellarKeycard::connect(t).expect("SELECT failed - is this a Keycard?")
}

/// The whole owner-key model rests on this: a token records an *index*, and
/// the key is re-derived when needed. A card that derives
/// differently cannot open the commitments a software wallet wrote, and the
/// notes behind them hold escrow nobody can then spend or redeem.
#[test]
#[ignore = "needs a seeded fork Keycard on a PC/SC reader"]
fn the_card_derives_the_published_owner_keys_on_metal() {
    let pin = card_pin();
    let v = vectors();
    let mut card = card();

    for case in v["cases"].as_array().expect("cases") {
        let index = case["index"].as_u64().expect("index") as u32;
        let want = case["raw_public_hex"].as_str().expect("raw_public_hex");
        let got = card
            .derive_public(index, &pin)
            .unwrap_or_else(|e| panic!("index {index}: {e}"));
        assert_eq!(
            hex::encode(got),
            want,
            "index {index} ({}): the card and the software wallet derive different owner \
             keys, so neither can open the other's commitments",
            case["path"].as_str().unwrap_or("?")
        );
    }
}

/// A card and a software vault holding the same seed must derive the **same**
/// store and backup keys, or a holder whose card dies has the paper phrase,
/// the backup file, and no way to open it.
///
/// Implied by the test above — same seed, same BIP85 — but implied is not
/// verified, and that distinction is the whole reason this file exists.
#[test]
#[ignore = "needs a seeded fork Keycard on a PC/SC reader"]
fn card_and_software_agree_on_vault_bound_keys_on_metal() {
    let pin = card_pin();
    const PASS: &[u8] = b"correct horse battery staple";

    let v = vectors();
    let seed: [u8; 64] = hex::decode(v["seed"]["bip39_seed_hex"].as_str().unwrap())
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();

    let mut card = card();
    let (card_store, card_backup) =
        vault_bound_credentials(&mut card, &pin).expect("card credentials");

    // The same seed in software: the path a holder takes when the card dies.
    let path = std::env::temp_dir().join(format!("kenter-metal-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut soft = SoftVault::open(&path).unwrap();
    soft.set_seed(&seed, PASS).unwrap();
    let (soft_store, soft_backup) =
        vault_bound_credentials(&mut soft, PASS).expect("software credentials");
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        hex::encode(card_store.aead.as_slice()),
        hex::encode(soft_store.aead.as_slice()),
        "card and software disagree on the store key - a restored wallet could not read its notes"
    );
    assert_eq!(
        hex::encode(card_backup.key.as_slice()),
        hex::encode(soft_backup.key.as_slice()),
        "card and software disagree on the backup key - a lost card would mean an unopenable backup"
    );
    assert_eq!(card_backup.fingerprint, soft_backup.fingerprint);
}

/// A 31-byte message where a digest belongs is a caller bug. The card can
/// only refuse; the backend should say which it got.
#[test]
#[ignore = "needs a seeded fork Keycard on a PC/SC reader"]
fn signing_a_non_digest_says_so_on_metal() {
    let pin = card_pin();
    let mut card = card();
    let err = card
        .sign_derived(1, b"this is a message, not a digest", &pin)
        .expect_err("a 31-byte message must be refused");
    assert!(
        err.to_string().contains("32-byte digest"),
        "unhelpful: {err}"
    );
}

/// The card's own phrase has to survive the trip into words and back.
///
/// `GENERATE MNEMONIC` returns 11-bit word indexes with a checksum already
/// packed in; `mnemonic::from_indexes` unpacks them and re-verifies it. A
/// disagreement between the card's packing and ours would hand a holder
/// twenty-four words that restore a *different* wallet than the card holds
/// — the one failure in this flow nobody notices until the card is gone.
///
/// Non-destructive: the card derives nothing, stores nothing and leaves its
/// existing key alone.
#[test]
#[ignore = "needs a fork Keycard on a PC/SC reader"]
fn the_cards_generated_phrase_is_a_real_bip39_phrase() {
    // No PIN: GENERATE MNEMONIC needs none, which is the point of it.
    let mut card = card();

    for words in [12u8, 24] {
        let indexes = card
            .generate_mnemonic(words)
            .unwrap_or_else(|e| panic!("GENERATE MNEMONIC {words}: {e}"));
        assert_eq!(indexes.len(), words as usize);

        let phrase = kenter_vault::mnemonic::from_indexes(&indexes)
            .unwrap_or_else(|e| panic!("{words} words from the card did not assemble: {e}"));
        assert_eq!(phrase.split_whitespace().count(), words as usize);
        // A seed it can actually be used as.
        kenter_vault::mnemonic::to_seed(&phrase, "").expect("seed");
    }

    // Two calls differ: the card's RNG, and the cheapest possible check that
    // we are not reading a fixed buffer back.
    let a = card.generate_mnemonic(24).unwrap();
    let b = card.generate_mnemonic(24).unwrap();
    assert_ne!(a, b, "two generated phrases came back identical");
}

/// The claim the whole backup design rests on, against real silicon: a
/// holder who has lost the card can get back in with the words they wrote
/// down.
///
/// `card_and_software_agree_on_vault_bound_keys_on_metal` above checks the
/// same equality from a **raw seed**. This one starts where a holder starts
/// — from the phrase, loaded onto a card the way the ceremony loads it — and
/// is destructive for that reason: it has to put the phrase on the card
/// itself rather than assume a card already holds it.
///
/// What it settles that the published BIP85 vectors cannot: that the card
/// in hand agrees with them. The vectors prove the software is right about
/// BIP85; only a card proves the card is.
///
/// ```text
/// KENTER_CARD_DESTRUCTIVE=1 cargo test -p stellar-keycard --test on_metal \
///   -- --ignored --test-threads=1 a_lost_card_is_recoverable
/// ```
#[test]
#[ignore = "destructive; needs a fork Keycard and KENTER_CARD_DESTRUCTIVE=1"]
fn a_lost_card_is_recoverable_from_its_phrase_on_metal() {
    let pin = card_pin();
    use stellar_keycard::{DuressPin, InitParams};

    if std::env::var("KENTER_CARD_DESTRUCTIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set KENTER_CARD_DESTRUCTIVE=1 to wipe the card on the reader");
        return;
    }

    const PUK: &[u8] = b"012345678901";
    const DURESS: &[u8] = b"024680";
    const PASS: &[u8] = b"a different passphrase on the new machine";
    let v = vectors();
    // The words a holder would have written down. Read from the vectors
    // rather than spelled here, so the phrase and the seed it has to
    // produce cannot drift apart across two files.
    let phrase = v["seed"]["bip39_mnemonic"].as_str().expect("bip39_mnemonic");
    let published: [u8; 64] = hex::decode(v["seed"]["bip39_seed_hex"].as_str().unwrap())
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    // Checked before anything is sent, so a mismatch fails on this machine
    // rather than putting an unintended key on a card.
    let from_phrase = kenter_vault::mnemonic::to_seed(phrase, "").expect("phrase -> seed");
    assert_eq!(
        hex::encode(from_phrase.as_slice()),
        hex::encode(published),
        "the vectors' phrase and seed disagree - refusing to touch the card"
    );

    // ── The card, seeded from the words a holder would have written ───
    let mut card = card();
    card.factory_reset(Some(&pin)).expect("FACTORY RESET");
    card.init(&InitParams::new(&pin, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT after reset");
    card.load_bip39_seed(&published, &pin).expect("LOAD KEY");

    let (card_store, card_backup) =
        vault_bound_credentials(&mut card, &pin).expect("card credentials");
    let card_owner = card.derive_public(3, &pin).expect("card owner key");

    // ── The card is destroyed. All that is left is the phrase. ───────
    let path = std::env::temp_dir().join(format!("kenter-recover-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut soft = SoftVault::open(&path).unwrap();
    soft.set_seed_from_mnemonic(phrase, "", PASS)
        .expect("rebuild from the phrase");
    let (soft_store, soft_backup) =
        vault_bound_credentials(&mut soft, PASS).expect("software credentials");
    let soft_owner = soft.derive_public(3, PASS).expect("software owner key");
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        hex::encode(card_store.aead.as_slice()),
        hex::encode(soft_store.aead.as_slice()),
        "the recovered wallet cannot read the notes the card wrote"
    );
    assert_eq!(
        hex::encode(card_backup.key.as_slice()),
        hex::encode(soft_backup.key.as_slice()),
        "the recovered wallet cannot open the backup the card wrote"
    );
    assert_eq!(
        card_backup.fingerprint, soft_backup.fingerprint,
        "the recovered wallet is not recognised as the same wallet"
    );
    // Seeing the notes is not recovery. They have to be spendable, which
    // means the owner keys have to come back too.
    assert_eq!(
        hex::encode(card_owner),
        hex::encode(soft_owner),
        "the notes come back unspendable - owner keys diverged"
    );

    // Left as found: same seed, same pin, so the tests above keep working.
    let pk = card.derive_public(0, &pin).expect("derive after reseed");
    assert_eq!(
        hex::encode(pk),
        v["cases"][0]["raw_public_hex"].as_str().unwrap(),
        "the card was not left on the published vector"
    );
}

/// Wipe the card, re-provision it, and put the seed back.
///
/// Gated twice — `#[ignore]` and an environment variable — because it
/// destroys whatever is on the card, and a destructive test that runs on
/// `--ignored` alone is one somebody else runs by accident:
///
/// ```text
/// KENTER_CARD_DESTRUCTIVE=1 cargo test -p stellar-keycard --test on_metal \
///   -- --ignored --test-threads=1 wipes_and_reprovisions
/// ```
///
/// Three things it proves that the simulator cannot settle on its own:
///
/// 1. **`factory_reset` reaches the applet.** It is sent in plain, outside
///    the secure channel; wrapped, it silently never arrives and every
///    refusal reads as a successful wipe.
/// 2. **`init`'s 26-byte form works on a card**, so a duress PIN can be
///    chosen rather than inherited from the PUK prefix.
/// 3. **The owner-index counter survives the wipe.** The wallet's restore
///    margin is built on that, and a counter that silently restarted at 1
///    would relink a holder's history.
///
/// It leaves the card seeded with the same SEP-0005 vector it started with,
/// so the tests above keep working afterwards.
#[test]
#[ignore = "destructive; needs a fork Keycard and KENTER_CARD_DESTRUCTIVE=1"]
fn wipes_and_reprovisions_while_the_owner_index_survives() {
    let pin = card_pin();
    use stellar_keycard::{DuressPin, InitParams};

    if std::env::var("KENTER_CARD_DESTRUCTIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set KENTER_CARD_DESTRUCTIVE=1 to wipe the card on the reader");
        return;
    }

    const PUK: &[u8] = b"012345678901";
    const DURESS: &[u8] = b"024680";
    let v = vectors();
    let seed: [u8; 64] = hex::decode(v["seed"]["bip39_seed_hex"].as_str().unwrap())
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();

    let mut card = card();
    let before = card.owner_index(&pin).expect("read owner index");
    assert!(
        before > 0,
        "expected a used counter to test survival against"
    );

    card.factory_reset(Some(&pin)).expect("FACTORY RESET");
    let blank = card.application_info().expect("SELECT after reset");
    assert!(
        !blank.initialized,
        "the card is still initialized after a wipe"
    );
    assert!(!blank.key_initialized, "the seed survived a wipe");

    card.init(&InitParams::new(&pin, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT (26-byte form) after reset");
    let live = card.application_info().expect("SELECT after INIT");
    assert!(live.initialized, "INIT did not take");
    assert_eq!(live.pin_retries, Some(3), "default PIN retries");

    // D7: deliberate. A re-seeded card restarting at 1 would hand out owner
    // indices a holder has already used, relinking their history.
    let after = card.owner_index(&pin).expect("read owner index after reset");
    assert_eq!(
        after, before,
        "the owner-index counter changed across FACTORY RESET ({before} -> {after}); \
         the wallet's restore margin assumes it survives"
    );

    // Put the card back the way it was found.
    card.load_bip39_seed(&seed, &pin).expect("LOAD KEY");
    let pk = card.derive_public(0, &pin).expect("derive after reseed");
    let want = v["cases"][0]["raw_public_hex"].as_str().unwrap();
    assert_eq!(hex::encode(pk), want, "reseeded card derives the wrong key");
}
