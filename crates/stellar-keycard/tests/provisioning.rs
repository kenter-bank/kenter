//! The provisioning commands, against the applet.
//!
//! These are the calls the wallet's card-provisioning ceremony is built
//! out of. They are
//! `#[ignore]`d because they need the applet's jcardsim server, and because
//! several of them are destructive — `factory_reset` wipes the card it runs
//! against, which is correct behaviour and a poor default for `cargo test`.
//!
//! From the `kenter-keycard` repo (the applet, a fork of Status's keycard):
//!
//! ```text
//! ./gradlew simServer          # listens on 127.0.0.1:21345
//! ```
//!
//! then here:
//!
//! ```text
//! cargo test -p stellar-keycard --test provisioning -- --ignored
//! ```
//!
//! Each test factory-resets on the way in rather than on the way out, so a
//! run that fails half way leaves the card inspectable and the *next* run
//! still starts clean. Cleaning up afterwards would destroy the evidence at
//! exactly the moment it was worth having.

use stellar_keycard::{DEFAULT_SIM_ADDR, DuressPin, InitParams, SimTransport, StellarKeycard};

const PIN: &[u8] = b"123456";
const PUK: &[u8] = b"987654321098";
const DURESS: &[u8] = b"654321";

/// Every PIN any test in this file leaves behind.
///
/// `fresh` has to be able to wipe a card whose PIN it does not know, and the
/// only way in is a PIN that verifies. Missing one means the next test runs
/// against a card in an unknown state, which is how the first run of this
/// file produced two failures that had nothing to do with the code under
/// test. Add to this list when a test sets a new PIN.
const PINS_IN_PLAY: &[&[u8]] = &[PIN, b"111111", b"222222"];

/// A blank card, whatever state the last test left behind.
///
/// `FACTORY RESET` needs one of three things (`factoryResetAllowed`): an
/// uninitialized card, a verified PIN, or a PIN *and* PUK both exhausted. So
/// recovery walks them in that order, and the blocked-PIN case is the one
/// worth spelling out: a blocked PIN with a healthy PUK satisfies none of the
/// three, so it has to be unblocked before it can be wiped.
fn fresh() -> StellarKeycard<SimTransport> {
    let t = SimTransport::connect(DEFAULT_SIM_ADDR).expect(
        "no SimServer on 127.0.0.1:21345 - run ./gradlew simServer in the kenter-keycard repo",
    );
    let mut card = StellarKeycard::connect(t).expect("SELECT failed");

    if !card.application_info().expect("SELECT").initialized {
        return card;
    }

    // A PIN we know, if one of them still verifies.
    for pin in PINS_IN_PLAY {
        if card.factory_reset(Some(pin)).is_ok() {
            return assert_blank(card);
        }
    }

    // Nothing verified, so the PIN is blocked by those very attempts. The PUK
    // is never changed to an unknown value by this suite, so it still opens.
    card.unblock_pin(PUK, PIN)
        .expect("could not unblock the card - restart simServer for a blank one");
    card.factory_reset(Some(PIN))
        .expect("could not wipe the card after unblocking it");
    assert_blank(card)
}

/// Refuse to run a test against a card that is not actually blank.
///
/// Without this the suite reports failures of whatever it was pointed at,
/// which is strictly worse than not running: a passing assertion about an
/// unknown card state means nothing, and a failing one sends you to read the
/// wrong code.
fn assert_blank(mut card: StellarKeycard<SimTransport>) -> StellarKeycard<SimTransport> {
    assert!(
        !card.application_info().expect("SELECT").initialized,
        "the card is still initialized after a reset - the suite cannot start from here"
    );
    card
}

/// The 26-byte INIT, which is the whole reason this file exists: it is the
/// only form that sets a duress PIN the holder chose.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn a_card_takes_a_chosen_duress_pin() {
    let mut card = fresh();
    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT with a chosen duress PIN");

    // Both PINs open the card. That is the point of a duress PIN — a refusal
    // would tell a coercer they had been given the wrong one.
    card.generate_mnemonic(24)
        .expect("channel works after INIT");
}

/// `GENERATE MNEMONIC` returns word indexes and stores nothing.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn the_card_invents_a_phrase_and_forgets_it() {
    let mut card = fresh();
    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT");

    let a = card.generate_mnemonic(24).expect("GENERATE MNEMONIC");
    assert_eq!(a.len(), 24);
    assert!(a.iter().all(|i| *i <= 2047), "index outside the word list");

    // Two calls differ, which is the card's RNG doing its job and also the
    // cheapest possible check that we are not reading a fixed buffer back.
    let b = card.generate_mnemonic(24).expect("GENERATE MNEMONIC again");
    assert_ne!(a, b, "two phrases came back identical");

    // 12 words is the other end of the range the applet accepts.
    assert_eq!(card.generate_mnemonic(12).expect("12 words").len(), 12);
}

/// PIN change needs the current PIN, and the old one stops working.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn changing_the_pin_takes_effect() {
    let mut card = fresh();
    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT");

    card.change_pin(PIN, b"111111").expect("CHANGE PIN");
    card.change_puk(b"111111", b"222222222222")
        .expect("CHANGE PUK with the new PIN");
    assert!(
        card.change_puk(PIN, b"333333333333").is_err(),
        "the old PIN still worked after a change"
    );
}

/// Unblocking only applies to a blocked card, and says so otherwise.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn unblocking_an_unblocked_card_says_which_call_was_wanted() {
    let mut card = fresh();
    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT");

    let err = card.unblock_pin(PUK, b"111111").unwrap_err().to_string();
    assert!(err.contains("not blocked"), "{err}");
    assert!(
        err.contains("change_pin"),
        "the error should name the right call: {err}"
    );
}

/// Factory reset wipes, and the card comes back as a blank one.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn a_reset_card_can_be_provisioned_again() {
    let mut card = fresh();
    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT");

    card.factory_reset(Some(PIN)).expect("FACTORY RESET");

    // A blank card takes a *different* PIN, which an un-wiped one would
    // refuse — INIT on an initialized card is a no-op here.
    card.init(&InitParams::new(b"111111", PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT after reset");
    card.change_pin(b"111111", b"222222")
        .expect("the new PIN is the live one, so the wipe took");
}

/// A blank card swallows every secured command but INIT as an empty 9000,
/// so a client that just sends them reads success from a card that did
/// nothing. The refusal has to come from this side.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn a_blank_card_refuses_the_commands_it_would_otherwise_swallow() {
    let mut card = fresh();

    for (what, result) in [
        ("GENERATE MNEMONIC", card.generate_mnemonic(24).map(|_| ())),
        ("CHANGE PIN", card.change_pin(PIN, b"111111")),
        ("CHANGE PUK", card.change_puk(PIN, b"222222222222")),
        ("UNBLOCK PIN", card.unblock_pin(PUK, PIN)),
    ] {
        let err = result.expect_err(&format!("{what} reported success on a blank card"));
        assert!(err.to_string().contains("not been set up"), "{what}: {err}");
    }
}

/// The status byte's low nibble is only meaningful once there is a PIN.
#[test]
#[ignore = "needs the applet's jcardsim SimServer on 127.0.0.1:21345"]
fn attempts_remaining_are_reported_only_once_there_is_a_pin() {
    let mut card = fresh();
    let blank = card.application_info().expect("SELECT");
    assert!(!blank.initialized);
    assert_eq!(
        blank.pin_retries, None,
        "a blank card reported attempts left, which reads as 'blocked'"
    );

    card.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .expect("INIT");
    let live = card.application_info().expect("SELECT");
    assert!(live.initialized);
    assert_eq!(
        live.pin_retries,
        Some(3),
        "the applet's default PIN retries"
    );
}
