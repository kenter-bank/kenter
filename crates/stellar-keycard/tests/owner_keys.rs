//! The card's owner keys must be the software wallet's owner keys.
//!
//! This is the property the whole owner-key model rests on: a token records
//! only a derivation *index*, and the key is re-derived when needed (see
//! `docs/architecture/custody.md`). A card that derives differently cannot
//! open the commitments a software wallet wrote, and the notes behind them hold real
//! escrow with nobody able to spend or redeem them.
//!
//! So the two tests here check the two halves of that agreement:
//!
//! - `the_card_is_asked_for_the_path_the_vectors_pin` runs anywhere, with no
//!   card and no simulator. It checks the **path this client sends**.
//! - `the_card_derives_the_published_owner_keys` is `#[ignore]`d and needs the
//!   applet's jcardsim server. It checks the **keys that come back**.
//!
//! Both read `tests/vectors/owner_key_vectors.json`, which is generated from
//! `kenter-vault` itself, so neither can drift from the software wallet
//! without a failure here or in `kenter-vault`'s own vector test.
//!
//! Running the integration half, from the applet repo (JDK 11):
//!
//! ```text
//! ./gradlew simServer          # listens on 127.0.0.1:21345
//! ```
//!
//! then here:
//!
//! ```text
//! cargo test -p stellar-keycard --test owner_keys -- --ignored
//! ```

use kenter_vault::DerivingVault;
use serde_json::Value;
use stellar_keycard::{DuressPin, InitParams};

/// The vectors, relative to this crate.
const VECTORS: &str = "../../tests/vectors/owner_key_vectors.json";

fn vectors() -> Value {
    let raw = std::fs::read_to_string(VECTORS)
        .unwrap_or_else(|e| panic!("{VECTORS}: {e} — generate it with KENTER_BLESS_VECTORS=1"));
    serde_json::from_str(&raw).expect("vectors are not JSON")
}

/// `m/44'/148'/n'` as the applet wants it: three hardened 4-byte big-endian
/// elements. Written out here rather than imported, so the test is an
/// independent statement of the path and not a restatement of the code's.
fn expected_path(index: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(12);
    for element in [44u32, 148, index] {
        p.extend_from_slice(&(0x8000_0000u32 | element).to_be_bytes());
    }
    p
}

/// The client must ask the card for the path the vectors declare.
///
/// Cheap, and it catches the failure that would otherwise only appear on
/// hardware: this client deriving at a path the software vault and the applet
/// did not agree to. The vectors carry the path as a *string*, so this parses
/// what a human would read and compares it to what goes on the wire.
#[test]
fn the_card_is_asked_for_the_path_the_vectors_pin() {
    let v = vectors();
    let declared = v["derivation"]["path"].as_str().expect("derivation.path");
    assert_eq!(declared, "m/44'/148'/n'", "the pinned path changed");

    let cases = v["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());

    for case in cases {
        let index = case["index"].as_u64().expect("index") as u32;
        let path = case["path"].as_str().expect("path");
        assert_eq!(
            path,
            format!("m/44'/148'/{index}'"),
            "vector {index} does not describe the pinned path"
        );
        assert_eq!(
            stellar_keycard::stellar::stellar_path(index),
            expected_path(index)[..],
            "the client would ask the card for a different path at index {index}"
        );
    }
}

/// End to end against the applet: load the published seed, derive the owner
/// keys, and require them to equal the ones `kenter-vault` produces.
///
/// Needs `./gradlew simServer` in the `kenter-keycard` repo. Ignored by
/// default so the suite stays runnable with nothing else alive.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn the_card_derives_the_published_owner_keys() {
    use stellar_keycard::sim::SimTransport;
    use stellar_keycard::stellar::StellarKeycard;

    const PIN: &[u8] = b"123456";
    // Must not start with the PIN: with no explicit duress PIN the card uses
    // the PUK's first six digits as one, and INIT refuses a duress PIN equal
    // to the main PIN (6A80). `123456789012` is exactly that collision.
    const PUK: &[u8] = b"987654321098";
    // Chosen, not inherited, so these runs exercise INIT's 26-byte form
    // — the one the wallet will send.
    const DURESS: &[u8] = b"654321";

    let v = vectors();
    let seed_hex = v["seed"]["bip39_seed_hex"].as_str().expect("seed hex");
    let seed_bytes = hex::decode(seed_hex).expect("seed is not hex");
    let seed: [u8; 64] = seed_bytes
        .as_slice()
        .try_into()
        .expect("seed is not 64 bytes");

    let t = SimTransport::connect(stellar_keycard::DEFAULT_SIM_ADDR).expect(
        "no SimServer on 127.0.0.1:21345 — run ./gradlew simServer in the kenter-keycard repo",
    );
    let mut card = StellarKeycard::connect(t).expect("SELECT failed");
    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT failed");
    card.load_bip39_seed(&seed, PIN).expect("LOAD KEY failed");

    for case in v["cases"].as_array().expect("cases") {
        let index = case["index"].as_u64().unwrap() as u32;
        let want = case["raw_public_hex"].as_str().unwrap();

        let got = card
            .derive_public(index, PIN)
            .unwrap_or_else(|e| panic!("derive_public({index}): {e}"));

        assert_eq!(
            hex::encode(got),
            want,
            "index {index}: the card and the software wallet derive different owner keys, \
             so neither can open the other's commitments"
        );
    }
}

/// A preimage passed where a digest belongs is a caller bug, and the card
/// cannot tell us so — it just refuses. The backend should say which it got.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn signing_something_that_is_not_a_digest_says_so() {
    use stellar_keycard::sim::SimTransport;
    use stellar_keycard::stellar::StellarKeycard;

    let t = SimTransport::connect(stellar_keycard::DEFAULT_SIM_ADDR).expect("no SimServer");
    let mut card = StellarKeycard::connect(t).expect("SELECT failed");

    let err = card
        .sign_derived(1, b"this is a message, not a digest", b"123456")
        .expect_err("a 31-byte message must be refused");
    let msg = err.to_string();
    assert!(msg.contains("32-byte digest"), "unhelpful error: {msg}");
}

/// A card and a software vault holding the same seed must derive the **same**
/// store and backup keys.
///
/// This is what makes a card-only wallet recoverable: the credential is the
/// signature by owner key `STORE_KEY_INDEX` over a fixed challenge, Ed25519 is
/// deterministic, so a phrase restored into software reproduces it. If this
/// ever diverges, a holder whose card dies has the paper phrase, the backup
/// file, and no way to open it.
///
/// Implied by `the_card_derives_the_published_owner_keys` — same key, so same
/// signature — but implied is not verified, which is the lesson the V2
/// secure-channel bug taught at some cost.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn card_and_software_derive_the_same_vault_bound_keys() {
    use kenter_vault::{SoftVault, vault_bound_credentials};
    use stellar_keycard::sim::SimTransport;
    use stellar_keycard::stellar::StellarKeycard;

    const PIN: &[u8] = b"123456";
    // Must not start with the PIN: with no explicit duress PIN the card uses
    // the PUK's first six digits as one, and INIT refuses a duress PIN equal
    // to the main PIN (6A80). `123456789012` is exactly that collision.
    const PUK: &[u8] = b"987654321098";
    // Chosen, not inherited, so these runs exercise INIT's 26-byte form
    // — the one the wallet will send.
    const DURESS: &[u8] = b"654321";
    const PASS: &[u8] = b"correct horse battery staple";

    let v = vectors();
    let seed_hex = v["seed"]["bip39_seed_hex"].as_str().unwrap();
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let seed: [u8; 64] = seed_bytes.as_slice().try_into().unwrap();

    // The card.
    let t = SimTransport::connect(stellar_keycard::DEFAULT_SIM_ADDR).expect("no SimServer");
    let mut card = StellarKeycard::connect(t).expect("SELECT");
    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT");
    card.load_bip39_seed(&seed, PIN).expect("LOAD KEY");
    let (card_store, card_backup) =
        vault_bound_credentials(&mut card, PIN).expect("card credentials");

    // The same seed in software — the path a holder takes when the card dies.
    let path = std::env::temp_dir().join("kenter-card-vs-soft.json");
    let _ = std::fs::remove_file(&path);
    let mut soft = SoftVault::open(&path).unwrap();
    soft.set_seed(&seed, PASS).unwrap();
    let (soft_store, soft_backup) =
        vault_bound_credentials(&mut soft, PASS).expect("software credentials");
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        hex::encode(card_store.aead.as_slice()),
        hex::encode(soft_store.aead.as_slice()),
        "card and software disagree on the store key — a restored wallet could not read its notes"
    );
    assert_eq!(
        hex::encode(card_backup.key.as_slice()),
        hex::encode(soft_backup.key.as_slice()),
        "card and software disagree on the backup key — a lost card would mean an unopenable backup"
    );
    assert_eq!(card_backup.fingerprint, soft_backup.fingerprint);
}
