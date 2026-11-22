//! Putting a wallet on a card: the two steps that touch it.
//!
//! Everything before this collects; this writes.
//!
//! ## Why the phrase is asked for before anything is written
//!
//! `GENERATE MNEMONIC` **stores nothing**. The card draws entropy, returns
//! BIP-39 word indexes and forgets them; the host assembles the words, shows
//! them, derives the 64-byte seed and sends it back with `LOAD KEY`. So the
//! card is untouched until that second call, and a holder who walks away
//! mid-ceremony leaves nothing behind — no half-provisioned state to detect,
//! no card that holds a wallet whose phrase nobody can read.
//!
//! That property is free, and it is the reason the confirm step sits where
//! it does. Writing early to save a screen would spend it.

use kenter_vault::mnemonic;
use stellar_keycard::{DuressPin, InitParams, StellarKeycard, Transport};
use zeroize::Zeroizing;

/// Ask the card to invent a phrase. Nothing is written.
///
/// Needs an initialized card for the secure channel to carry the command, so
/// a blank card is `INIT`ed first with the credentials first run collected —
/// which is the one ordering wrinkle here: `INIT` *is* a write, but it writes
/// only the PINs, and a card with PINs and no key is not a wallet anybody can
/// be misled about. The key is what makes it one, and that still waits for
/// the confirm.
/// Give a blank card its PINs.
///
/// Split out because **two paths need it and only one of them wants a new
/// phrase**: setting up a fresh wallet generates words on the card, while
/// restoring brings its own. `INIT` is what creates the PIN, and the PIN is
/// what opens the secure channel `LOAD KEY` needs — so a restore that
/// skipped this would meet a card with no PIN to verify and fail in a way
/// that reads like a broken reader.
pub fn init_card(pin: &[u8], puk: &[u8], duress: &[u8]) -> Result<(), String> {
    let mut card = connect()?;
    // Five, not the applet's default of three. Passing
    // nothing silently gets three, which is the whole reason this is spelled
    // out rather than left to `InitParams::new`.
    let params = InitParams {
        pin,
        puk,
        duress: DuressPin::Chosen(duress),
        pin_retries: Some(crate::card::PIN_RETRIES),
        puk_retries: None,
    };
    card.init(&params)
        .map_err(|e| format!("could not set the card's PIN: {e}"))
}

pub fn generate_phrase(
    pin: &[u8],
    puk: &[u8],
    duress: &[u8],
    words: u8,
) -> Result<Zeroizing<String>, String> {
    init_card(pin, puk, duress)?;
    let mut card = connect()?;

    let indexes = card
        .generate_mnemonic(words)
        .map_err(|e| format!("the card could not generate a phrase: {e}"))?;
    mnemonic::from_indexes(&indexes).map_err(|e| {
        // A checksum failure here means the card's packing and ours
        // disagree, which would hand the holder words that restore a
        // different wallet. Say that, rather than "invalid mnemonic".
        format!("the card's phrase did not assemble - nothing was written to it: {e}")
    })
}

/// Write the seed. **This is the irreversible step.**
///
/// After it the card holds a key, and the only way back to an empty one is
/// `FACTORY RESET`. Returns the account-0 public key so the caller can show
/// the holder what they now own.
pub fn load_phrase(phrase: &str, pin: &[u8]) -> Result<[u8; 32], String> {
    let seed = mnemonic::to_seed(phrase, "").map_err(|e| e.to_string())?;
    let mut card = connect()?;
    card.load_bip39_seed(&seed, pin)
        .map_err(|e| format!("the card refused the key: {e}"))?;
    use kenter_vault::DerivingVault;
    card.derive_public(0, pin)
        .map_err(|e| format!("the card took the key but would not read it back: {e}"))
}

/// Put a phrase the holder already has onto a blank card.
///
/// The restore counterpart of [`generate_phrase`] plus [`load_phrase`]: same
/// two card operations, in the same order, with the words coming from the
/// holder instead of from the card's RNG.
///
/// It is one function rather than two calls at the call site because the
/// pair is not separable here — between them the card has PINs and no key,
/// which on the *creation* path is a real resting state (the holder is
/// reading their words) and on this path is nothing but a window to fail in.
pub fn restore_to_card(
    phrase: &str,
    pin: &[u8],
    puk: &[u8],
    duress: &[u8],
) -> Result<[u8; 32], String> {
    init_card(pin, puk, duress)?;
    load_phrase(phrase, pin)
}

/// Everything a finished card wallet needs the shell to know.
pub struct CardWallet {
    /// The Stellar account that pays fees. Software, by design.
    pub address: String,
    /// Where the backup file was written, so the screen can name it.
    pub backup_path: String,
    /// What opens the vault holding that account — BIP85 child 2.
    ///
    /// Returned rather than re-derived because the caller needs it at a
    /// moment when the PIN is already gone: the trustline is signed by the
    /// submitting account, so **the activation gate needs this and not the
    /// PIN**. A card wallet still has one secret; this is a value computed
    /// from it, not a second thing to remember.
    pub account_credential: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for CardWallet {
    /// Hand-written so the credential cannot be printed by a `{:?}` that
    /// someone adds later.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardWallet")
            .field("address", &self.address)
            .field("backup_path", &self.backup_path)
            .finish_non_exhaustive()
    }
}

/// Finish provisioning: the vault, the account, and the backup file.
///
/// Runs after [`load_phrase`], so the card already holds the key. Every
/// secret here is derived *from* that key rather than stored, which is what
/// makes the paper phrase a complete recovery: a holder who restores it onto
/// a replacement card derives the same store key, the same backup key and
/// the same account-vault credential, and opens everything again.
///
/// **The account vault has no seed.** A card-custody wallet keeps the seed
/// on the card; this vault holds exactly one thing, the fee-paying Stellar
/// key that is deliberately left in software (see
/// `docs/architecture/custody.md`). Its
/// credential is BIP85 child 2, so the card is still the single unlock.
pub fn provision(pin: &[u8]) -> Result<CardWallet, String> {
    use kenter_vault::{account_vault_credential, vault_bound_credentials, KeyVault, SoftVault};

    // The account vault. Seedless on purpose: the seed is the card's.
    let path = crate::receive::default_vault_path()
        .ok_or("set KENTER_VAULT to choose where the account vault lives")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let mut vault = SoftVault::open(&path).map_err(|e| e.to_string())?;

    // **Checked before the card is touched.** These are local and free, and
    // they are about a mistake the card cannot see; asking the card first
    // would give a holder with a wallet already here a hardware error
    // instead of the real reason. Same argument `card::readiness` makes
    // about saying there is no reader before someone types a PIN at it.
    //
    // The same guard `setup::create` has. Without it, running card setup
    // against an existing wallet would open that wallet's vault and add a
    // key to it - leaving a vault holding a software seed *and* a
    // card-derived account key, with nothing to detect the mixture.
    //
    // Two refusals, because the two states are different mistakes. A seed
    // means a software wallet lives here. Keys without a seed mean a card
    // wallet does, and a second account would be a second identity paying
    // fees from the same vault.
    if vault.has_seed() {
        return Err(format!(
            "{} already holds a software wallet. Setting a card up here would leave              two wallets in one vault - move or remove it first.",
            path.display()
        ));
    }
    if !vault.list_keys().map_err(|e| e.to_string())?.is_empty() {
        return Err(format!(
            "{} already holds an account. If this is the same card's wallet, unlock it              rather than setting it up again.",
            path.display()
        ));
    }

    let mut card = connect()?;
    let (_store, backup) =
        vault_bound_credentials(&mut card, pin).map_err(|e| format!("deriving keys: {e}"))?;
    let account_cred =
        account_vault_credential(&mut card, pin).map_err(|e| format!("deriving keys: {e}"))?;

    // Derived, never generated. A random account key would live only in
    // this file, so a holder with their phrase and their backup would
    // recover every note and none of the money their redemptions had
    // already paid out (`ACCOUNT_KEY_INDEX`).
    let account_secret = kenter_vault::account_key(&mut card, pin)
        .map_err(|e| format!("deriving the submitting account: {e}"))?;
    let slot = vault
        .import_seed(&account_secret, "submitting account", &account_cred[..])
        .map_err(|e| format!("creating the submitting account: {e}"))?;
    let address = vault.stellar_address(slot).map_err(|e| e.to_string())?;

    // What opens this wallet, recorded rather than left to be inferred
    // Both identifiers, because they answer
    // different questions: the identity key says whether this is the same
    // *card* and costs no PIN, while the fingerprint says whether it is
    // the same *wallet* and survives the card being replaced.
    vault
        .set_custody(
            kenter_vault::Custody::Card {
                seed_fingerprint: backup.fingerprint.clone(),
                card_identity: hex::encode(card.identity_pubkey()),
            },
            // The same card-derived credential the account key was
            // sealed with: the record is inside the authenticated
            // header, so writing it means re-tagging the file. That is
            // the point — `card_identity` decides which physical card a
            // launch check accepts.
            &account_cred[..],
        )
        .map_err(|e| format!("recording custody: {e}"))?;

    let backup_path = write_working_copy(&backup)?;
    Ok(CardWallet {
        address,
        backup_path,
        account_credential: Zeroizing::new(account_cred.to_vec()),
    })
}

/// Write the working copy for a card that holds no notes yet.
///
/// It carries none, and that is not the point of writing it now. The header
/// is: `SeedOrigin::Card`, which tells a restorer the twenty-four words are
/// the **card's** seed rather than a software vault's, and the fingerprint,
/// which says which card opens this file. A holder with two cards and two
/// files has no other way to tell them apart.
///
/// This is the copy beside the vault, which is not a backup — see
/// `crate::backup`. It is not recorded as one, so a holder who has just set
/// up a card is still told they have no backup, which is true.
///
/// The notes come later, every time the billfold writes a fresh one.
pub fn write_working_copy(
    backup: &kenter_vault::BackupCredentials,
) -> Result<String, String> {
    use kenter_wallet::backup::encode;

    // One convention for the path and the header, shared with every later
    // write: a provisioning file the refresh path did not recognise would be
    // left to rot beside a second one.
    let source = crate::backup::seed_source(
        Some(&kenter_vault::Custody::Card {
            seed_fingerprint: backup.fingerprint.clone(),
            card_identity: String::new(),
        }),
        &backup.fingerprint,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let bytes = encode(&backup.key, &source, &[], &[], None, now)
        .map_err(|e| format!("encoding the backup: {e}"))?;

    let path = crate::backup::working_copy_path(&backup.fingerprint).ok_or("set KENTER_VAULT")?;

    // **Never over an existing file.** This one is empty, and the path is
    // the exact name the save dialog suggests — so a holder restoring onto
    // a replacement card, who copied their backup next to the vault, would
    // have it replaced by an empty file moments before the notes were read
    // out of it. A file already here is at worst stale, and stale beats
    // destroyed; the refresh path brings it up to date as soon as the
    // wallet opens.
    if path.exists() {
        return Ok(path.display().to_string());
    }
    std::fs::write(&path, bytes).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path.display().to_string())
}

/// Erase the card so it can be set up again.
///
/// Needs the PIN: `factoryResetAllowed` wants an uninitialized card, a
/// verified PIN, or a PIN **and** PUK both exhausted. So a card whose PIN
/// nobody has cannot be erased from here, which is the PIN doing its job
/// and not a gap.
///
/// Keys, PINs, PUK and any notes on the card go. The owner-index counter
/// does **not** — it survives by design, because a
/// re-seeded card restarting at 1 would hand out indices a holder has
/// already used and relink their history.
pub fn erase(pin: &[u8]) -> Result<(), String> {
    let mut card = connect()?;
    card.factory_reset(Some(pin))
        .map_err(|e| format!("the card refused to erase: {e}"))?;
    if card
        .application_info()
        .map_err(|e| e.to_string())?
        .initialized
    {
        return Err("the card still reports itself set up after erasing".into());
    }
    Ok(())
}

/// A card on a reader, or a sentence about why not.
fn connect() -> Result<StellarKeycard<Transport>, String> {
    // Re-read rather than holding a handle across screens: a contactless
    // card leaves the field between steps, and a stale handle fails in a way
    // that reads as a protocol error rather than as "put the card back".
    let t = Transport::connect()
        .map_err(|e| format!("{} ({e})", crate::card::readiness().message()))?;
    // Certified, not merely asked.
    //
    // There is no recorded identity to pin against yet — this is the
    // call that produces one. That makes the CA signature the only
    // check available, and the most consequential: the key read here is
    // written into the vault record and every later session is pinned
    // to it, so a substitute card accepted now is a substitution that
    // becomes permanent and invisible.
    StellarKeycard::connect_certified(t, crate::card::PINNED_CAS)
        .map_err(|e| format!("this is not a Kenter card: {e}"))
}

/// Open a wallet whose seed is on a card.
///
/// The card analogue of `SoftVault::store_credentials`: PIN to the card,
/// BIP85 to the store key. Returns the store credentials the billfold needs
/// and the fingerprint, so a caller can check that this card is the wallet
/// it expected — which is the check the identity key cannot make, and the
/// one that lets a replacement card be recognised.
pub fn unlock(
    pin: &[u8],
) -> kenter_vault::Result<(kenter_vault::StoreCredentials, kenter_vault::BackupCredentials)> {
    // `VaultError`, not a string, so a wrong PIN stays `BadCredential` and
    // the retry loops that branch on it keep working. Flattening it to a
    // message would turn "ask again" into "give up".
    let mut card = connect().map_err(kenter_vault::VaultError::Hardware)?;
    // Both halves of the one derivation. Keeping only the fingerprint would
    // mean a card wallet could only write a backup by asking for the PIN
    // and tapping again - for a value it had already computed.
    let (store, backup) = kenter_vault::vault_bound_credentials(&mut card, pin)?;
    Ok((store, backup))
}

/// The credential that opens a card wallet's account vault.
///
/// BIP85 child 2. Derived on
/// demand from the PIN rather than kept, so the value exists only while
/// something needs it.
pub fn account_credential(pin: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut card = connect()?;
    let k = kenter_vault::account_vault_credential(&mut card, pin)
        .map_err(|e| format!("deriving the account credential: {e}"))?;
    Ok(Zeroizing::new(k.to_vec()))
}
