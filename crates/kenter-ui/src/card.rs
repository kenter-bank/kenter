//! Is there a card, and can a wallet be put on it?
//!
//! Everything here runs **before a PIN is asked for**, which is what makes it
//! worth a module of its own: a holder choosing card custody at first run
//! should be told "there is no reader" or "this card has no seed" *then*, not
//! after typing a PIN into something that was never going to work. The same
//! reasoning as `receive::readiness` — a page that offers a button leading
//! only to an error is a worse way to learn you have no card than being told
//! on arrival.
//!
//! What it deliberately cannot answer is whether the card was seeded by
//! `LOAD KEY P1=SEED`, which decides whether the wallet is recoverable at all.
//! That check needs the ed25519 tree, which needs a
//! verified PIN, so it belongs to the step after this one — see
//! [`Readiness::Usable`].

use stellar_keycard::transport::Transport;

/// What a look at the reader found. Each variant carries the sentence a
/// holder can act on, because "card error" is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// No reader attached, or the PC/SC service is not running.
    NoReader(String),
    /// A reader, but nothing in it.
    NoCard(String),
    /// Something is there, but it does not answer as a Keycard applet.
    NotAKeycard(String),
    /// A Keycard that has never been INIT'd. Usable, but it needs
    /// provisioning first — PIN, PUK, and a seed.
    Blank,
    /// An initialized Keycard. Whether it carries a *seed* is still unknown
    /// and needs the PIN; see the module docs.
    Usable { version: (u8, u8) },
}

impl Readiness {
    /// Can first run proceed down the card path at all?
    pub fn can_continue(&self) -> bool {
        matches!(self, Readiness::Blank | Readiness::Usable { .. })
    }

    /// One line for the screen.
    pub fn message(&self) -> String {
        match self {
            Readiness::NoReader(detail) => {
                format!("no card reader found - plug one in and try again ({detail})")
            }
            Readiness::NoCard(detail) => {
                format!("a reader, but no card in it - place your card on it ({detail})")
            }
            Readiness::NotAKeycard(detail) => format!(
                "the card in the reader is not a Kenter card - it does not answer as one ({detail})"
            ),
            Readiness::Blank => {
                "a new card, not set up yet - this will give it a PIN and a key".into()
            }
            Readiness::Usable { version } => {
                let (major, minor) = version;
                format!("a card is ready - applet {major}.{minor}")
            }
        }
    }
}

/// Look at the reader. Local, quick, and asks for nothing.
pub fn readiness() -> Readiness {
    let mut t = match Transport::connect() {
        Ok(t) => t,
        Err(e) => return classify_connect(&e.to_string()),
    };
    match t.select_keycard() {
        Ok(info) if info.initialized => Readiness::Usable {
            version: info.app_version,
        },
        // SELECT answered, but the applet has not been INIT'd: it returns only
        // its secure-channel key and nothing else is meaningful yet.
        Ok(_) => Readiness::Blank,
        Err(e) => Readiness::NotAKeycard(e.to_string()),
    }
}

/// Split a transport error into "no reader" and "no card", which lead to
/// different actions by the holder and so must not share a message.
///
/// Matched on text because the error type flattens PC/SC's own distinction;
/// a wrong guess here costs a misleading sentence, never correctness, and the
/// fallback names the raw error rather than inventing one.
fn classify_connect(detail: &str) -> Readiness {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("no card reader") || lower.contains("no reader") {
        Readiness::NoReader(detail.to_string())
    } else if lower.contains("no card") || lower.contains("no smart card") {
        Readiness::NoCard(detail.to_string())
    } else {
        Readiness::NoReader(detail.to_string())
    }
}

// ---------------------------------------------------------------------------
// The three secrets first run has to produce or check before the card is
// touched. Pure functions, so the rules are
// testable without a reader.
// ---------------------------------------------------------------------------

/// The CA keys whose signature makes a card a Kenter card.
///
/// A set, not one key, so a CA can be retired without stranding the cards
/// it certified: production pins the active key and a sealed spare.
/// Today it holds only the development CA, whose private key is public,
/// so this proves a card came from this workbench and nothing more.
pub const PINNED_CAS: &[stellar_keycard::CaPublicKey] = &[stellar_keycard::DEV_CA_PUBLIC_KEY];

use zeroize::Zeroizing;

/// Exactly, as the applet counts them.
pub const PIN_LEN: usize = 6;
pub const PUK_LEN: usize = 12;

/// Wrong PINs before the card blocks.
///
/// Five, not the applet's default of three. At six
/// digits the security difference is 3-in-a-million against 5-in-a-million;
/// the usability difference is a working card against a search for the backup
/// sheet. **Passing nothing silently gets three**, so this has to be handed
/// to `InitParams` explicitly.
pub const PIN_RETRIES: u8 = 5;

/// Why a PIN or PUK was refused, in words a holder can act on.
///
/// Refused here rather than by the card: the applet answers `6A80` for every
/// one of these, which is the same answer it gives for a malformed APDU.
pub fn check_pin(label: &str, v: &str, want: usize) -> Result<(), String> {
    let n = v.chars().count();
    if n != want {
        return Err(format!(
            "a {label} is exactly {want} digits - this one is {n}"
        ));
    }
    if !v.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("a {label} is digits only"));
    }
    Ok(())
}

/// The duress PIN may not equal the PIN.
///
/// The card checks duress **first**, so an identical pair would send every
/// unlock down the duress path and show the decoy wallet every time. `INIT`
/// refuses it; this refuses it earlier, with a reason.
pub fn check_duress(pin: &str, duress: &str) -> Result<(), String> {
    check_pin("duress PIN", duress, PIN_LEN)?;
    if duress == pin {
        return Err(
            "your duress PIN must be different from your PIN - the card checks \
                    the duress one first, so the same digits would open the decoy wallet \
                    every time"
                .into(),
        );
    }
    Ok(())
}

/// A fresh PUK: twelve digits that do not begin with the PIN.
///
/// **Generated, not chosen**. Twelve digits is past
/// what anyone invents well, and the one constraint is a rule we can satisfy
/// silently and a holder cannot be asked to hold in their head.
///
/// The constraint: with no explicit duress PIN the card takes the PUK's first
/// six digits as one, and refuses a duress PIN equal to the PIN. First run
/// always sends an explicit duress PIN, so the applet does not force this —
/// the check stays because it costs one comparison and keeps the shorter
/// `INIT` form safe if anything ever falls back to it.
///
/// Rejection-sampled rather than patched: nudging a colliding prefix would
/// bias those digits, and a retry here costs nothing because the collision
/// has probability 1e-6.
/// Twelve digits in threes, for copying onto paper.
///
/// This screen exists so a PUK is written down *correctly* - it is confirmed
/// by re-entry for exactly that reason - and an unbroken twelve-digit run is
/// the shape people miscopy. Display only: [`puk_matches`] is what decides
/// whether the holder got it right.
pub fn group_puk(puk: &str) -> String {
    puk.chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Did the holder type the PUK back correctly?
///
/// Whitespace is ignored, because the screen shows the PUK in groups and
/// typing it back the way it was shown is the obvious thing to do. Refusing
/// a correct PUK over spaces we introduced ourselves would be our bug
/// presented as theirs.
pub fn puk_matches(shown: &str, typed: &str) -> bool {
    let strip = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    !shown.is_empty() && strip(shown) == strip(typed)
}

pub fn generate_puk(pin: &str, rng: &mut impl rand::Rng) -> Zeroizing<String> {
    loop {
        let puk: String = (0..PUK_LEN)
            .map(|_| char::from(b'0' + rng.gen_range(0..10u8)))
            .collect();
        if !puk.starts_with(pin) {
            return Zeroizing::new(puk);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the two states that can be provisioned may continue. A holder
    /// must not reach a PIN prompt on a card that cannot hold a wallet.
    #[test]
    fn only_a_real_card_lets_first_run_continue() {
        assert!(Readiness::Blank.can_continue());
        assert!(Readiness::Usable { version: (3, 1) }.can_continue());
        assert!(!Readiness::NoReader("x".into()).can_continue());
        assert!(!Readiness::NoCard("x".into()).can_continue());
        assert!(!Readiness::NotAKeycard("x".into()).can_continue());
    }

    /// Every message names the next action, which is the standard this
    /// codebase holds itself to. "Card error" is not a
    /// sentence anyone can act on.
    #[test]
    fn every_message_says_what_to_do_about_it() {
        for r in [
            Readiness::NoReader("detail".into()),
            Readiness::NoCard("detail".into()),
            Readiness::NotAKeycard("detail".into()),
        ] {
            let m = r.message();
            assert!(
                m.contains("try again")
                    || m.contains("place your card")
                    || m.contains("not a Kenter card"),
                "unactionable: {m}"
            );
            assert!(m.contains("detail"), "the raw cause is dropped: {m}");
        }
    }

    /// No reader and no card lead to different actions, so they must not
    /// collapse into one message.
    #[test]
    fn a_missing_reader_and_a_missing_card_read_differently() {
        let no_reader = classify_connect("no card reader found");
        let no_card = classify_connect("no card present in reader");
        assert!(matches!(no_reader, Readiness::NoReader(_)));
        assert!(matches!(no_card, Readiness::NoCard(_)));
        assert_ne!(no_reader.message(), no_card.message());
    }

    /// An unrecognised failure must still produce something, and must carry
    /// the original text rather than replacing it with a guess.
    #[test]
    fn an_unknown_failure_still_names_itself() {
        let r = classify_connect("PCSC service unavailable (0x8010001D)");
        assert!(r.message().contains("0x8010001D"));
        assert!(!r.can_continue());
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn a_pin_is_six_digits_and_says_which_rule_it_broke() {
        assert!(check_pin("PIN", "123456", PIN_LEN).is_ok());
        let short = check_pin("PIN", "12345", PIN_LEN).unwrap_err();
        assert!(short.contains("is 5"), "{short}");
        let alpha = check_pin("PIN", "12345a", PIN_LEN).unwrap_err();
        assert!(alpha.contains("digits only"), "{alpha}");
    }

    /// The card checks duress first, so an identical pair sends every unlock
    /// down the decoy path. INIT answers 6A80, which reads like a channel
    /// fault; this has to be caught before the card sees it.
    #[test]
    fn a_duress_pin_equal_to_the_pin_is_refused_with_a_reason() {
        assert!(check_duress("123456", "654321").is_ok());
        let err = check_duress("123456", "123456").unwrap_err();
        assert!(err.contains("different from your PIN"), "{err}");
        assert!(
            err.contains("decoy"),
            "the reason should be in the message: {err}"
        );
    }

    #[test]
    fn a_generated_puk_is_twelve_digits() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        for _ in 0..200 {
            let puk = generate_puk("000000", &mut rng);
            assert_eq!(puk.chars().count(), PUK_LEN);
            assert!(puk.chars().all(|c| c.is_ascii_digit()), "{}", &*puk);
        }
    }

    /// The rule that exists so the shorter INIT form stays safe: with no
    /// explicit duress PIN the card takes PUK[0..6] as one, and refuses it
    /// when it equals the PIN.
    #[test]
    fn a_generated_puk_never_begins_with_the_pin() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for pin in ["000000", "123456", "999999"] {
            for _ in 0..500 {
                let puk = generate_puk(pin, &mut rng);
                assert!(!puk.starts_with(pin), "{} starts with {pin}", &*puk);
            }
        }
    }

    /// Rejection sampling must not bias the digits it keeps. With the
    /// forbidden prefix removed, every digit should still appear in every
    /// position at roughly 10%.
    #[test]
    fn rejection_sampling_does_not_skew_the_digits() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let n = 4000;
        let mut counts = [[0u32; 10]; PUK_LEN];
        for _ in 0..n {
            let puk = generate_puk("000000", &mut rng);
            for (i, c) in puk.chars().enumerate() {
                counts[i][c as usize - '0' as usize] += 1;
            }
        }
        let expect = n as f64 / 10.0;
        for (pos, row) in counts.iter().enumerate() {
            for (d, &got) in row.iter().enumerate() {
                let off = (got as f64 - expect).abs() / expect;
                assert!(
                    off < 0.30,
                    "position {pos} digit {d}: {got} of {n}, {off:.2} off"
                );
            }
        }
    }
}

#[cfg(test)]
mod puk_display_tests {
    use super::*;

    #[test]
    fn a_puk_is_shown_in_threes_of_four() {
        assert_eq!(group_puk("482073915064"), "4820 7391 5064");
    }

    /// The screen shows groups, so people type groups. Refusing a correct
    /// PUK over spacing we introduced would be our bug reported as theirs.
    #[test]
    fn typing_the_puk_back_with_the_spaces_shown_is_accepted() {
        let shown = "482073915064";
        assert!(puk_matches(shown, "482073915064"));
        assert!(puk_matches(shown, "4820 7391 5064"));
        assert!(puk_matches(shown, " 4820  7391 5064 "));
        assert!(!puk_matches(shown, "482073915065"));
        assert!(!puk_matches(shown, ""));
    }

    /// An empty shown value must never match, or a bug that lost the PUK
    /// would present as the holder having typed it correctly.
    #[test]
    fn an_empty_puk_matches_nothing() {
        assert!(!puk_matches("", ""));
        assert!(!puk_matches("", "   "));
    }
}

// ---------------------------------------------------------------------------
// Opening a wallet that lives on a card.
// ---------------------------------------------------------------------------

/// Is the card this wallet needs on the reader?
///
/// Answered **before a PIN is asked for**, and without one: the card's
/// identity key comes from its SELECT certificate, so "is this the right
/// card" is free. The seed fingerprint would be the stronger answer but is
/// PIN-gated, which is the wrong order — a holder should learn they have
/// the wrong card before typing into it, not after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// The card this wallet was set up with.
    Ready,
    /// A card, but a different one. Possibly a replacement restored from
    /// the phrase, which the fingerprint would confirm — and which this
    /// cannot, because that needs the PIN.
    Different,
    /// No card, no reader, or not a Keycard. Carries the reason.
    Missing(String),
}

impl Presence {
    pub fn message(&self, expected: &str) -> String {
        match self {
            Presence::Ready => "your card is on the reader".into(),
            Presence::Different => format!(
                "this is a different card from the one this wallet was set up with \
                 ({}…). If it is a replacement you restored from your phrase, unlocking \
                 will check that.",
                &expected[..8.min(expected.len())]
            ),
            Presence::Missing(why) => why.clone(),
        }
    }
    /// Can an unlock be attempted at all?
    ///
    /// `Different` counts: a replacement card restored from the phrase has
    /// a new identity key and the right seed, and refusing it here would
    /// lock a holder out of their own wallet on the day their card died.
    pub fn can_try(&self) -> bool {
        matches!(self, Presence::Ready | Presence::Different)
    }
}

/// Look for the card a wallet was recorded against.
///
/// **A hint for the screen, not an authorisation.** This opens its own
/// PC/SC connection, so what it learns is true of *that* conversation
/// and nothing else: a device is free to answer honestly here and as
/// itself when the wallet later connects to sign. Relied on alone, that
/// would be a time-of-check/time-of-use gap.
///
/// It is not the only check. `GuiVault::open` connects with
/// `connect_expecting`, and `open_verified` re-checks on the same
/// connection before every PIN, so the check that matters is made
/// where the PIN goes. This stays because "is the right card on the
/// reader?" is a useful thing to show someone before they try.
pub fn presence(expected_identity: &str) -> Presence {
    let mut t = match Transport::connect() {
        Ok(t) => t,
        Err(e) => return Presence::Missing(classify_connect(&e.to_string()).message()),
    };
    let resp = match t.transmit(SELECT_AID) {
        Ok(r) => r,
        Err(e) => return Presence::Missing(format!("the card did not answer ({e})")),
    };
    match stellar_keycard::card_identity_pubkey(&resp) {
        Ok(id) if hex::encode(&id) == expected_identity => Presence::Ready,
        Ok(_) => Presence::Different,
        Err(e) => Presence::Missing(format!("not a Kenter card ({e})")),
    }
}

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];
