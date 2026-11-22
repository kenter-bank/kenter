//! BIP-39 mnemonics — the human-holdable form of the wallet seed.
//!
//! The owner-key model rests on "back up the seed once, it covers every owner
//! key you will ever derive." That only works if the seed is something a person can
//! actually write down and re-enter, so the wallet seed is a **BIP-39 mnemonic**
//! and the bytes [`slip10`](crate::slip10) derives from are its 64-byte PBKDF2
//! output.
//!
//! # Why BIP-39 specifically
//!
//! The Keycard applet is loaded with a BIP-39 seed (`loadSeed`, reached from
//! GENERATE KEY / LOAD KEY), and computes its SLIP-0010 master from those same
//! 64 bytes. Using any other seed format would mean a card and a software wallet
//! restored from "the same" backup derive different owner keys — and in spend
//! mode that means tokens one of them cannot redeem.
//!
//! # What the mnemonic does and does not recover
//!
//! It recovers **authorization**, not value. Tokens cannot
//! be enumerated from the chain, so a phrase with no token blobs redeems nothing.
//! Callers surfacing a backup flow must say so; this module cannot.
//!
//! # Passphrase
//!
//! BIP-39's optional passphrase is a *different* secret from the vault
//! passphrase that encrypts the file. It changes which seed the words produce,
//! so a forgotten one is unrecoverable and silently yields a different wallet
//! rather than an error. Default to empty unless the user asks.

use bip39::{Language, Mnemonic, WordCount};
use zeroize::Zeroizing;

use crate::{Result, VaultError};

/// Words in the phrase we generate. 24 words = 256 bits of entropy, and matches
/// what the Keycard generates on-card.
pub const DEFAULT_WORD_COUNT: WordCount = WordCount::Words24;

/// Generate a fresh English mnemonic.
///
/// The phrase is the **only** copy of the wallet's authorization: it is returned
/// in a [`Zeroizing`] wrapper so it does not linger in memory, but once shown to
/// the user it is their responsibility. Nothing can regenerate it.
pub fn generate() -> Result<Zeroizing<String>> {
    let m = Mnemonic::generate(DEFAULT_WORD_COUNT)
        .map_err(|e| VaultError::Crypto2(format!("generating mnemonic: {e}")))?;
    Ok(Zeroizing::new(m.to_string()))
}

/// Parse and checksum-validate a phrase.
///
/// BIP-39's checksum is what catches a mistyped or misremembered word. Rejecting
/// here, loudly, is far better than accepting a near-miss phrase that silently
/// derives a different wallet full of keys that open nothing.
pub fn validate(phrase: &str) -> Result<()> {
    parse(phrase).map(|_| ())
}

/// Is this a BIP-39 word at all?
///
/// Lets a restore screen point at *which* word is wrong, which is the error
/// people actually make. The checksum catches the rest, but only mostly: at
/// 24 words it is 8 bits, so roughly one substitution in 256 validates and
/// silently derives a different wallet. Naming a non-word first removes the
/// larger part of the error space before the checksum has to.
pub fn wordlist_contains(word: &str) -> bool {
    let w = word.to_lowercase();
    Language::English.word_list().contains(&w.as_str())
}

/// Build a phrase from BIP-39 **word indexes**.
///
/// This is what a Keycard hands back from `GENERATE MNEMONIC`: the card
/// draws entropy from its own RNG, converts it to 11-bit indexes, returns
/// them and keeps nothing. The host turns them into words, shows them, and
/// only then derives a seed and loads it back.
///
/// **The checksum is re-verified here, not assumed.** The indexes already
/// encode one — the card appended it before packing — so parsing the
/// assembled phrase proves the whole round trip: the card's packing, this
/// unpacking, and the wordlist agreeing at both ends. A silent disagreement
/// would hand a holder twenty-four words that restore a different wallet
/// than the card holds, which is the one failure in this flow that cannot
/// be noticed until the card is gone.
pub fn from_indexes(indexes: &[u16]) -> Result<Zeroizing<String>> {
    if !matches!(indexes.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(VaultError::Crypto2(format!(
            "a recovery phrase is 12, 15, 18, 21 or 24 words, not {}",
            indexes.len()
        )));
    }
    let list = Language::English.word_list();
    let mut phrase = String::new();
    for (i, &idx) in indexes.iter().enumerate() {
        let word = list.get(idx as usize).ok_or_else(|| {
            VaultError::Crypto2(format!(
                "word {} is index {idx}, outside the 2048-word list",
                i + 1
            ))
        })?;
        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(word);
    }
    let phrase = Zeroizing::new(phrase);
    // Rejects a bad checksum, so a mis-packed index set fails here rather
    // than becoming a wallet nobody can restore.
    validate(&phrase)?;
    Ok(phrase)
}

/// Convert a phrase to the 64-byte BIP-39 seed `slip10` derives from.
///
/// `passphrase` is BIP-39's optional 25th-word secret, **not** the vault
/// passphrase; pass `""` unless the user set one.
pub fn to_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    Ok(Zeroizing::new(parse(phrase)?.to_seed(passphrase)))
}

/// Number of words in a phrase, without validating it — for UI hints only.
pub fn word_count(phrase: &str) -> usize {
    phrase.split_whitespace().count()
}

fn parse(phrase: &str) -> Result<Mnemonic> {
    // English only: the card's wordlist is English, and offering others would
    // invite a phrase a card cannot restore.
    Mnemonic::parse_in(Language::English, phrase.trim())
        .map_err(|e| VaultError::BadMnemonic(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slip10;
    use kenter_crypto::keypair::StellarKeypair;

    /// SEP-0005 test vector 1 — the same mnemonic the applet fork's
    /// `StellarM4Test` loads on-card.
    const SEP5_V1: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    const SEP5_V1_ACCOUNT_0: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    /// The whole point: phrase → seed → owner key must land on the published
    /// address, because that is what the card does with the same words.
    #[test]
    fn sep0005_vector_1_end_to_end() {
        let seed = to_seed(SEP5_V1, "").unwrap();
        let secret = slip10::stellar_account_secret(&*seed, 0).unwrap();
        assert_eq!(
            StellarKeypair::from_raw_secret(&secret).stellar_address(),
            SEP5_V1_ACCOUNT_0
        );
    }

    #[test]
    fn generated_phrases_are_valid_and_distinct() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_eq!(word_count(&a), 24);
        validate(&a).unwrap();
        validate(&b).unwrap();
        assert_ne!(*a, *b, "two generated phrases must not collide");
    }

    #[test]
    fn a_generated_phrase_round_trips_to_a_usable_seed() {
        let phrase = generate().unwrap();
        let seed = to_seed(&phrase, "").unwrap();
        assert_eq!(seed.len(), 64);
        // And it derives — the seed is in SLIP-0010's accepted range.
        slip10::stellar_account_secret(&*seed, 1).unwrap();
    }

    /// The deterministic rejections: off-wordlist words, and wrong word counts.
    #[test]
    fn malformed_phrases_are_rejected() {
        for bad in [
            "not even words at all",
            "",
            "illness spike retreat", // right words, wrong count
            "illness spike retreat truth genius clock brain pass fit cave bargain zzzz",
        ] {
            assert!(
                matches!(validate(bad), Err(VaultError::BadMnemonic(_))),
                "should have rejected {bad:?}"
            );
        }
    }

    /// **A single mistyped word is not reliably caught.** BIP-39's checksum is
    /// only 4 bits for a 12-word phrase, so about 1 substitution in 16 still
    /// validates — and then derives a completely different wallet, silently.
    ///
    /// This test measures it rather than asserting a hand-picked example,
    /// because the first draft of it picked `illness -> island`, which happens
    /// to be one of the ~1/16 that passes. That near-miss is the whole hazard.
    ///
    /// It is also the argument for generating 24 words (8 checksum bits, ~1 in
    /// 256) and for never treating "the phrase parsed" as "the phrase is right":
    /// the real confirmation is that a known address derives from it.
    #[test]
    fn a_single_wrong_word_slips_past_the_checksum_about_one_time_in_sixteen() {
        let words = Language::English.word_list();
        let tail: Vec<&str> = SEP5_V1.split_whitespace().skip(1).collect();

        let accepted = words
            .iter()
            .filter(|w| {
                let candidate = format!("{} {}", w, tail.join(" "));
                validate(&candidate).is_ok()
            })
            .count();

        // 2048 candidates, 4 checksum bits -> expect ~128 (one of which is the
        // original word). Generous bounds: this pins the order of magnitude,
        // not an exact count.
        assert!(
            (64..=256).contains(&accepted),
            "expected roughly 2048/16 = 128 single-word substitutions to pass \
             the 12-word checksum, got {accepted}"
        );
        assert!(
            accepted > 1,
            "the original phrase must at least be accepted"
        );
    }

    #[test]
    fn whitespace_is_forgiven() {
        validate(&format!("  {SEP5_V1}  ")).unwrap();
        assert_eq!(
            *to_seed(&format!(" {SEP5_V1} "), "").unwrap(),
            *to_seed(SEP5_V1, "").unwrap()
        );
    }

    /// A BIP-39 passphrase yields a different wallet entirely. Worth pinning:
    /// it is the failure mode where a user "has their words" and still cannot
    /// reach their tokens.
    #[test]
    fn a_passphrase_changes_the_seed() {
        let plain = to_seed(SEP5_V1, "").unwrap();
        let salted = to_seed(SEP5_V1, "extra").unwrap();
        assert_ne!(*plain, *salted);

        let a = slip10::stellar_account_secret(&*plain, 0).unwrap();
        let b = slip10::stellar_account_secret(&*salted, 0).unwrap();
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod index_tests {
    use super::*;

    /// SEP-0005 test vector 1, the same phrase the other tests use.
    const SEP5_V1: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";

    /// A round trip through indexes must give back the same phrase, or the
    /// words shown to a holder are not the words the card's seed came from.
    #[test]
    fn indexes_round_trip_through_the_wordlist() {
        let list = Language::English.word_list();
        let phrase = generate().unwrap();
        let indexes: Vec<u16> = phrase
            .split_whitespace()
            .map(|w| list.iter().position(|x| *x == w).unwrap() as u16)
            .collect();
        assert_eq!(indexes.len(), 24);
        assert_eq!(*from_indexes(&indexes).unwrap(), *phrase);
    }

    /// The published vector, by index: proof the mapping is the standard
    /// one and not merely self-consistent.
    #[test]
    fn the_published_vector_rebuilds_from_its_indexes() {
        let list = Language::English.word_list();
        let indexes: Vec<u16> = SEP5_V1
            .split_whitespace()
            .map(|w| list.iter().position(|x| *x == w).unwrap() as u16)
            .collect();
        assert_eq!(*from_indexes(&indexes).unwrap(), SEP5_V1);
    }

    /// A corrupted index set must fail here. The alternative is twenty-four
    /// words that restore a different wallet than the card holds - which
    /// nothing notices until the card is gone.
    #[test]
    fn a_broken_checksum_is_refused() {
        let list = Language::English.word_list();
        let mut indexes: Vec<u16> = SEP5_V1
            .split_whitespace()
            .map(|w| list.iter().position(|x| *x == w).unwrap() as u16)
            .collect();
        indexes[0] ^= 1; // a real word, wrong checksum
        assert!(
            from_indexes(&indexes).is_err(),
            "a bad checksum was accepted"
        );
    }

    #[test]
    fn an_out_of_range_index_names_its_position() {
        let mut indexes = vec![0u16; 24];
        indexes[5] = 2048;
        let err = from_indexes(&indexes).unwrap_err().to_string();
        assert!(err.contains("word 6"), "{err}");
    }

    #[test]
    fn a_wrong_word_count_is_refused() {
        assert!(from_indexes(&[0u16; 13]).is_err());
        assert!(from_indexes(&[]).is_err());
    }
}
