//! First run: a passphrase, a seed, a store, an account.
//!
//! The store is encrypted, which makes this a gate rather than a convenience — there is
//! no holding a note without a seed, so nothing else in the client works until
//! this has run once.
//!
//! ## Nothing is persisted until the phrase is confirmed
//!
//! `SoftVault::set_seed` refuses to overwrite, which is right (replacing a seed
//! orphans every note owned by a key derived from the old one) and which turns
//! into a trap if the seed is written before the holder has copied it down:
//! close the window at the wrong moment and the vault is unrecoverable *and*
//! cannot be redone. So the phrase is generated in memory, shown, confirmed,
//! and only then written. An interrupted first run loses nothing.

use kenter_vault::{mnemonic, KeyVault, SoftVault};
use zeroize::Zeroizing;

use crate::receive::default_vault_path;

/// A fresh recovery phrase, held only in memory.
pub fn new_phrase() -> Result<Zeroizing<String>, String> {
    mnemonic::generate().map_err(|e| e.to_string())
}

/// Which words to ask back, by 1-based position.
///
/// Three, chosen across the phrase. Worth being honest about what this
/// achieves: it proves the screen is still open, not that anything was written
/// down, and anyone determined to skip the step will photograph the phrase —
/// which is worse than not asking. Its value is forcing a pause at the one
/// irreversible moment, so the wording asks for that and claims nothing more.
pub fn challenge(word_count: usize) -> Vec<usize> {
    // Deterministic spread rather than random: the point is a pause, and
    // three positions a holder cannot predict in advance adds nothing when
    // the phrase is in front of them either way.
    let n = word_count.max(3);
    vec![2, n / 2, n - 1]
}

/// Does the answer match the phrase at the challenged positions?
pub fn check(phrase: &str, positions: &[usize], answer: &str) -> bool {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let given: Vec<&str> = answer.split_whitespace().collect();
    if given.len() != positions.len() {
        return false;
    }
    positions
        .iter()
        .zip(given)
        .all(|(&i, g)| words.get(i).is_some_and(|w| w.eq_ignore_ascii_case(g)))
}

/// Check a phrase the holder typed, naming the word that is wrong.
///
/// Most of the value of wordlist-constrained entry without the entry widget:
/// a word that is not in the list is reported by position, which is the error
/// people actually make. The checksum catches the rest — not all of it, since
/// at 24 words it is 8 bits, so roughly one substitution in 256 still
/// validates and silently derives a different wallet. Per-word completion is
/// the remaining mitigation and is not built yet.
pub fn validate_phrase(phrase: &str) -> Result<(), String> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.is_empty() {
        return Err("enter your recovery phrase".into());
    }
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(format!(
            "a recovery phrase is 12 or 24 words; this is {}",
            words.len()
        ));
    }
    for (i, w) in words.iter().enumerate() {
        if !mnemonic::wordlist_contains(w) {
            return Err(format!("word {} ({w:?}) is not a recovery word", i + 1));
        }
    }
    mnemonic::validate(phrase).map_err(|_| {
        "the phrase does not check out — a word is in the wrong place, or mistyped".to_string()
    })
}

/// Write the vault: seed, then a Stellar account to submit with.
///
/// Called only after the phrase is confirmed (or supplied, when restoring).
/// Slow — the vault KDF is Argon2id — so it belongs on a worker.
pub fn create(passphrase: &[u8], phrase: &str) -> Result<String, String> {
    create_as(passphrase, phrase, kenter_vault::Custody::Software)
}

/// Same, for a wallet that is not a plain software one.
///
/// `custody` decides how every later session derives its store and backup
/// keys, so getting it wrong is silent and total: a card wallet rebuilt as
/// `Software` hashes the seed where it should run BIP85, and reads its own
/// notes as unopenable and its own backup as another wallet's
/// (see `docs/architecture/custody.md`). It is taken from the backup file's
/// header rather than asked, because the file knows and the holder does not.
pub fn create_as(
    passphrase: &[u8],
    phrase: &str,
    custody: kenter_vault::Custody,
) -> Result<String, String> {
    let path = default_vault_path().ok_or("set KENTER_VAULT to choose where the vault lives")?;
    create_at(&path, passphrase, phrase, custody)
}

/// Same, at a path given rather than resolved from the environment.
///
/// Exists so a test can stand up two installs of one wallet in a single
/// process. `KENTER_VAULT` is global, so the environment-driven form cannot
/// — and "two installs of one wallet agree" is exactly the property worth
/// testing, because it fails silently.
pub fn create_at(
    path: &std::path::Path,
    passphrase: &[u8],
    phrase: &str,
    custody: kenter_vault::Custody,
) -> Result<String, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let mut vault = SoftVault::open(&path).map_err(|e| e.to_string())?;
    if vault.has_seed() {
        return Err(format!(
            "{} already holds a seed — replacing it would orphan every note \
             owned by a key derived from the old one",
            path.display()
        ));
    }
    vault
        .set_seed_from_mnemonic(phrase, "", passphrase)
        .map_err(|e| e.to_string())?;

    // Said out loud, so the card path is not the only one that declares
    // itself. A vault with a record is unambiguous; a vault without one
    // leaves the reader guessing.
    // The credential, because the record lives inside the vault's
    // authenticated header, so it cannot be edited without the passphrase.
    vault
        .set_custody(custody, passphrase)
        .map_err(|e| e.to_string())?;

    // An account to pay fees with. Free to make, and making it here means the
    // only thing left needing the outside world is funding it.
    //
    // **Derived from the seed, not generated.** A random account would
    // exist only in this file: restoring from the phrase would produce a
    // different, empty account, and anything a redemption had already paid
    // into the old one would be unreachable. The words name the account
    // (`kenter_vault::ACCOUNT_KEY_INDEX`).
    let account_secret =
        kenter_vault::account_key(&mut vault, passphrase).map_err(|e| e.to_string())?;
    let slot = vault
        .import_seed(&account_secret, "submitting account", passphrase)
        .map_err(|e| e.to_string())?;
    vault.stellar_address(slot).map_err(|e| e.to_string())
}

/// Does this phrase open that backup?
///
/// Answered before a vault exists. The seed is derived
/// in memory and thrown away: nothing is written, so a wrong answer costs the
/// holder a sentence rather than a wallet they then have to unpick.
///
/// Which derivation to use comes from the file, not from a guess — a card
/// wallet's fingerprint is a hash of a BIP85 child and a software wallet's is
/// a hash of the seed, so the wrong one says "no" to a phrase that is right.
pub fn phrase_matches(phrase: &str, source: &crate::RestoreSource) -> Result<bool, String> {
    let (soft, card) = fingerprints(phrase)?;
    Ok(source.fingerprint == if source.card_rooted { card } else { soft })
}

/// Does this phrase open those paper sheets, and as which kind of wallet?
///
/// The paper counterpart of [`phrase_matches`], with one difference that
/// makes it answer more. A sheet carries the seed fingerprint in clear but
/// not the origin a `.kbk` header names, so there is no telling in advance
/// which derivation to try. Both are tried, and the one that matches *is*
/// the answer: `Some(true)` for a card wallet's words, `Some(false)` for a
/// software wallet's, `None` for words that open neither.
///
/// The two cannot both match. One is a hash of the seed and the other a
/// hash of a BIP85 child of it, so agreement would be a hash collision.
pub fn phrase_opens_paper(phrase: &str, fingerprint: &str) -> Result<Option<bool>, String> {
    let (soft, card) = fingerprints(phrase)?;
    Ok(if fingerprint == card {
        Some(true)
    } else if fingerprint == soft {
        Some(false)
    } else {
        None
    })
}

/// The backup fingerprint these words would have as a software wallet, and
/// as a card wallet. Derived in memory and dropped; nothing is written.
fn fingerprints(phrase: &str) -> Result<(String, String), String> {
    let seed = kenter_vault::mnemonic::to_seed(phrase, "").map_err(|e| e.to_string())?;
    let soft = kenter_vault::soft_backup_fingerprint(seed.as_slice());
    let key = kenter_vault::bip85::hex_key(seed.as_slice(), kenter_vault::bip85::BACKUP_KEY_INDEX)
        .map_err(|e| e.to_string())?;
    Ok((soft, kenter_vault::bip85::backup_fingerprint(&key)))
}

/// Read a backup file's header into something first run can show.
///
/// Nothing here needs a key: that is the whole point of the cleartext
/// header, and it is why this can run before the holder has typed
/// anything at all.
pub fn inspect_backup(path: &std::path::Path) -> Result<crate::RestoreSource, String> {
    use kenter_wallet::backup::SeedOrigin;

    let header = crate::backup::inspect_file(path)?;
    let card_rooted = matches!(header.origin(), SeedOrigin::Card);
    if header.origin() == SeedOrigin::Bip85Child {
        // Honest refusal rather than a wrong wallet: this build writes
        // `Card` for a card-rooted vault, and has no flow that produces a
        // BIP85-child backup to restore.
        return Err(
            "this backup names a BIP85 child, which this version cannot rebuild from a phrase"
                .into(),
        );
    }

    let notes = header.token_count;
    Ok(crate::RestoreSource {
        path: path.display().to_string(),
        summary: format!(
            "{} - {notes} note{}, saved {}",
            if card_rooted {
                "a card wallet"
            } else {
                "a software wallet"
            },
            if notes == 1 { "" } else { "s" },
            crate::backup::when(header.created_at)
        ),
        needs: if card_rooted {
            "the card's recovery phrase - the card itself is not needed".into()
        } else {
            "the wallet's recovery phrase".into()
        },
        fingerprint: header.seed_fingerprint,
        card_rooted,
    })
}

/// Whether a freshly made account can actually be used yet.
///
/// Both answers come from the ledger rather than from anything this client
/// remembers, because the funding happens outside it — someone sends XLM, or
/// a faucet does — and a cached "no" would strand the holder on a screen
/// that is wrong.
#[derive(Debug, Clone, Default)]
pub struct Activation {
    pub funded: bool,
    /// `Some(code)` when this mint's asset needs a trustline and there is
    /// none. `None` when one exists, or the mint escrows native XLM.
    pub trustline_needed: Option<String>,
    /// Set when the ledger could not be reached — distinct from a confident
    /// "not funded", which is a step to take rather than a problem to retry.
    pub unreachable: Option<String>,
}

impl Activation {
    /// Can this client do anything beyond accepting notes?
    pub fn ready(&self) -> bool {
        self.funded && self.trustline_needed.is_none()
    }
}

/// Ask the ledger what still stands between this account and a working
/// client.
pub async fn activation(net: crate::wallet::Network, address: &str) -> Activation {
    use kenter_client::{AssetClient, MintClient, TxBuilder};

    let rpc = net.rpc_client();
    if rpc.get_account_sequence(address).await.is_err() {
        // Unfunded and unreachable look the same from here, and the
        // difference does not change what to do next: both mean "not yet".
        return Activation::default();
    }

    // Read as this account: these go through `simulate_invoke`, which needs
    // a source with a sequence number. A throwaway key would fail every time
    // and make a needed trustline look like one that is not needed.
    let build = || TxBuilder::read_only(net.rpc_client(), address);
    let asset = match MintClient::new(build(), net.contract).pay_token().await {
        Ok(token) => AssetClient::new(build(), &token).describe().await,
        Err(e) => Err(e),
    };
    let asset = match asset {
        Ok(a) => a,
        Err(e) => {
            return Activation {
                funded: true,
                trustline_needed: None,
                unreachable: Some(format!("could not read the mint: {e}")),
            };
        }
    };
    let Some(issuer) = asset.issuer.clone() else {
        return Activation {
            funded: true,
            trustline_needed: None,
            unreachable: None,
        };
    };
    match build().has_trustline(&asset.code, &issuer).await {
        Ok(true) => Activation {
            funded: true,
            trustline_needed: None,
            unreachable: None,
        },
        Ok(false) => Activation {
            funded: true,
            trustline_needed: Some(asset.code),
            unreachable: None,
        },
        Err(e) => Activation {
            funded: true,
            trustline_needed: None,
            unreachable: Some(format!("could not read the trustline: {e}")),
        },
    }
}

/// Copying the recovery phrase is always offered.
///
/// The case against: a clipboard is readable by every other process, and
/// clipboard managers keep history. All of that is true.
///
/// It is offered anyway, because that compares against the wrong
/// alternative. The alternative is not "no copy"; it is **transcribing
/// twenty-four words by hand**, and a single wrong word loses the wallet
/// completely, silently, and only ever at the moment it is needed. A
/// clipboard exposure needs an attacker already running code on the
/// machine; a typo needs nobody. The confirm step catches a mistyped
/// *entry*, and catches nothing about a mistyped copy on paper.
///
/// The phrase is still never cached in the raster and is zeroized on drop;
/// the only question here is whether the button exists.

#[cfg(test)]
mod activation_tests {
    use super::*;

    /// Both gates have to be open. A funded account with no trustline can
    /// deposit and then find it cannot be paid out, which is the worse of
    /// the two failures because it shows up after the money has moved.
    #[test]
    fn ready_needs_funding_and_a_trustline() {
        let a = |funded, trustline: Option<&str>| Activation {
            funded,
            trustline_needed: trustline.map(String::from),
            unreachable: None,
        };
        assert!(!a(false, None).ready());
        assert!(!a(false, Some("USDC")).ready());
        assert!(!a(true, Some("USDC")).ready());
        assert!(a(true, None).ready());
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon abandon art";

    /// A sheet names no origin, so the match itself has to say which kind
    /// of wallet the words are - and say it right both ways round, because
    /// rebuilding a card wallet as a software one is silently the wrong
    /// wallet.
    #[test]
    fn paper_tells_a_card_phrase_from_a_software_one() {
        let (soft, card) = fingerprints(WORDS).unwrap();
        assert_ne!(soft, card);
        assert_eq!(phrase_opens_paper(WORDS, &soft).unwrap(), Some(false));
        assert_eq!(phrase_opens_paper(WORDS, &card).unwrap(), Some(true));
    }

    #[test]
    fn paper_refuses_words_that_open_neither() {
        assert_eq!(phrase_opens_paper(WORDS, "5e1f0c2a9d4b7368").unwrap(), None);
    }

    /// What the scan screen holds is the fingerprint the symbols carry, so
    /// it has to be the same value the `.kbk` header check uses.
    #[test]
    fn paper_and_file_agree_on_the_fingerprint() {
        let (soft, card) = fingerprints(WORDS).unwrap();
        for (fingerprint, card_rooted) in [(soft, false), (card, true)] {
            let source = crate::RestoreSource {
                path: String::new(),
                summary: String::new(),
                needs: String::new(),
                fingerprint: fingerprint.clone(),
                card_rooted,
            };
            assert!(phrase_matches(WORDS, &source).unwrap());
            assert_eq!(
                phrase_opens_paper(WORDS, &fingerprint).unwrap(),
                Some(card_rooted)
            );
        }
    }

    #[test]
    fn the_challenge_asks_for_words_inside_the_phrase() {
        let positions = challenge(24);
        assert_eq!(positions.len(), 3);
        assert!(positions.iter().all(|&i| i < 24));
    }

    #[test]
    fn the_right_words_pass_and_wrong_ones_do_not() {
        let phrase = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima";
        let positions = challenge(12);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let answer = positions
            .iter()
            .map(|&i| words[i])
            .collect::<Vec<_>>()
            .join(" ");
        assert!(check(phrase, &positions, &answer));
        assert!(check(phrase, &positions, &answer.to_uppercase()));
        assert!(!check(phrase, &positions, "alpha bravo charlie"));
        // A short answer must not pass by matching a prefix.
        assert!(!check(phrase, &positions, words[positions[0]]));
    }

    #[test]
    fn a_generated_phrase_validates_and_its_own_challenge_passes() {
        let phrase = new_phrase().unwrap();
        validate_phrase(&phrase).unwrap();
        let n = phrase.split_whitespace().count();
        let positions = challenge(n);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let answer = positions
            .iter()
            .map(|&i| words[i])
            .collect::<Vec<_>>()
            .join(" ");
        assert!(check(&phrase, &positions, &answer));
    }

    #[test]
    fn a_bad_word_is_named_by_position() {
        let phrase = new_phrase().unwrap();
        let mut words: Vec<String> = phrase.split_whitespace().map(String::from).collect();
        words[3] = "notaword".into();
        let err = validate_phrase(&words.join(" ")).unwrap_err();
        assert!(err.contains("word 4"), "{err}");
    }

    #[test]
    fn the_wrong_length_is_rejected_before_anything_else() {
        let err = validate_phrase("alpha bravo charlie").unwrap_err();
        assert!(err.contains("12 or 24"), "{err}");
        assert!(validate_phrase("").is_err());
    }

    /// A phrase of real words in the wrong order fails the checksum. Not
    /// always — 8 bits at 24 words — but the common case must be caught.
    #[test]
    fn a_reordered_phrase_is_rejected() {
        // Over many phrases, not one: a single random phrase passed its own
        // reordering about once in 256 runs (an 8-bit checksum), which
        // would make this test fail at random. Nearly all must be caught.
        let caught = (0..64)
            .filter(|_| {
                let phrase = new_phrase().unwrap();
                let mut words: Vec<String> =
                    phrase.split_whitespace().map(String::from).collect();
                if words[0] == words[1] {
                    return true; // swapping identical words changes nothing
                }
                words.swap(0, 1);
                validate_phrase(&words.join(" ")).is_err()
            })
            .count();
        assert!(caught >= 60, "only {caught} of 64 reordered phrases were rejected");
    }
}
