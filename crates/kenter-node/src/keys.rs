//! The pair's two keys, and the phrase they come from.
//!
//! **Both keys derive from one node-only BIP-39 phrase**, so a single
//! written-down backup restores the pair, and with it the stake: the roster
//! pays a withdrawal only to the address that staked (`withdraw_stake`), so
//! losing the keys loses the bond for good.
//!
//! **The phrase is the node's, never the wallet's.** A node's keys sign
//! unattended, all day, for anyone on the network; a wallet's guard notes.
//! The node generates its own phrase at `init`. As a second line, the keys
//! sit at SLIP-10 accounts [`NODE_ACCOUNT`] and `NODE_ACCOUNT + 1`, far from
//! the low indexes wallets use, so a wallet phrase pasted in by mistake
//! still does not yield the wallet's own accounts.
//!
//! **At rest, one of two places** (`config::KeyStore`):
//! - **File**: `pair.phrase` in the home, owner-only on unix (`0600`, and
//!   a looser file is refused at load, as ssh does). A headless node must
//!   restart unattended after a power cut, so nothing unlocks it; the
//!   machine is the trust boundary. On Windows the file must sit under the
//!   user's profile, whose ACL is what keeps other users out; a home
//!   elsewhere is refused for a phrase file.
//! - **OS keystore** (feature `keystore`; Windows Credential Manager, macOS
//!   Keychain): protected by the user's login, and no phrase on disk in
//!   the home. The desktop default. On Windows the `keyring` crate writes
//!   `CRED_PERSIST_ENTERPRISE`, which roams with a domain roaming profile;
//!   on a home machine it stays local. A managed-machine install would want
//!   local persistence.
//!
//! [`move_to_os`] moves an existing file into the keystore: write, read
//! back and compare, record in `node.json`, then overwrite the file with
//! zeros and delete it. [`move_to_file`] is the reverse, for taking a pair
//! to a headless machine.

use kenter_crypto::keypair::StellarKeypair;
use kenter_vault::{mnemonic, slip10};
use zeroize::Zeroizing;

use crate::config::{KeyStore, NodeConfig};
use crate::home::{Home, write_atomic};

/// SLIP-10 account of the node's own key (`m/44'/148'/27502'`); the partner
/// is the next one. 27502 is "kn" read as two bytes.
pub const NODE_ACCOUNT: u32 = 27_502;

pub struct PairKeys {
    /// The key the tunnel authenticates with and `confirm_link` signs with.
    pub own: StellarKeypair,
    /// The other half of the pair: co-signs every link this node builds.
    pub partner: StellarKeypair,
}

impl PairKeys {
    pub fn from_phrase(phrase: &str) -> Result<Self, String> {
        let seed = mnemonic::to_seed(phrase, "").map_err(|e| format!("recovery phrase: {e}"))?;
        let derive = |account: u32| -> Result<StellarKeypair, String> {
            let secret = Zeroizing::new(
                slip10::stellar_account_secret(&seed[..], account)
                    .map_err(|e| format!("deriving node key: {e}"))?,
            );
            Ok(StellarKeypair::from_raw_secret(&secret))
        };
        Ok(Self { own: derive(NODE_ACCOUNT)?, partner: derive(NODE_ACCOUNT + 1)? })
    }

    pub fn addresses(&self) -> [String; 2] {
        [self.own.stellar_address(), self.partner.stellar_address()]
    }

    /// Load the pair from the home's phrase file.
    pub fn load(home: &Home) -> Result<Self, String> {
        Self::from_phrase(&load_phrase(home)?)
    }
}

/// A fresh 24-word phrase.
pub fn new_phrase() -> Result<Zeroizing<String>, String> {
    mnemonic::generate().map_err(|e| e.to_string())
}

/// Does this home hold a pair, in either store?
pub fn has_pair(home: &Home) -> Result<bool, String> {
    // An unreadable node.json is an error, never "no pair": it may be the
    // only pointer to a keystore pair (SC-1).
    Ok(home.phrase().exists()
        || NodeConfig::load_if_present(home)?
            .is_some_and(|c| c.key_store == KeyStore::Os && c.key_id.is_some()))
}

/// A `pair.phrase` left on disk although `node.json` says the phrase is in
/// the OS keystore: a move into the keystore that was interrupted, or
/// whose wipe failed. Surfaced by `status`, the tray
/// and Settings until it is destroyed.
pub fn leftover_file(home: &Home) -> bool {
    home.phrase().exists()
        && NodeConfig::load_if_present(home).is_ok_and(|c| c.is_some_and(|c| c.key_store == KeyStore::Os))
}

/// Destroy a leftover phrase file, but only if it holds the very phrase
/// the keystore holds: a file with some other phrase may be another pair's
/// only copy, and is refused. The caller must hold the daemon lock.
pub fn wipe_leftover(home: &Home) -> Result<(), String> {
    if !leftover_file(home) {
        return Err("there is no leftover phrase file".into());
    }
    let in_store = load_phrase(home)?;
    let on_disk = load_phrase_file(home)?;
    if on_disk.trim() != in_store.trim() {
        return Err(format!(
            "{} holds a different phrase from the OS keystore; it may be another pair's \
             only copy, so it is left alone",
            home.phrase().display()
        ));
    }
    wipe(&home.phrase())
}

/// The keystore entry's name: one per network and pair.
fn account(net: &str, own_address: &str) -> String {
    format!("{net}:{own_address}")
}

/// Save the phrase to the OS keystore and record that in `cfg` (which the
/// caller saves). Read back and compared before it counts as stored.
pub fn store_phrase_os(cfg: &mut NodeConfig, phrase: &str) -> Result<(), String> {
    let pair = PairKeys::from_phrase(phrase)?;
    let net = cfg.network()?.profile.name;
    let id = pair.own.stellar_address();
    let acct = account(net, &id);
    os::set(&acct, phrase)?;
    let back = os::get(&acct)?;
    if back.trim() != phrase.trim() {
        let _ = os::delete(&acct);
        return Err("the OS keystore did not return the phrase it was given".into());
    }
    cfg.key_store = KeyStore::Os;
    cfg.key_id = Some(id);
    Ok(())
}

/// Move the phrase from `pair.phrase` into the OS keystore, then destroy
/// the file. The caller must hold the daemon lock.
///
/// Order, so that no failure loses the phrase: (1) read the file; (2)
/// write the keystore and read it back; (3) save `node.json` saying
/// `os` (on failure, delete the keystore entry and stop, file intact);
/// (4) overwrite the file with zeros, sync, delete. A failure at (4)
/// leaves a phrase file the config no longer uses, and is reported so the
/// operator can delete it. Overwriting does not guarantee erasure on an
/// SSD or a journaling filesystem; the written-down phrase was always the
/// backup, and this removes the copy from the home.
pub fn move_to_os(home: &Home) -> Result<(), String> {
    let mut cfg = NodeConfig::load(home)?;
    if cfg.key_store == KeyStore::Os {
        return Err("the phrase is already in the OS keystore".into());
    }
    let phrase = load_phrase_file(home)?;
    store_phrase_os(&mut cfg, &phrase)?;
    if let Err(e) = cfg.save(home) {
        let net = cfg.network().map(|n| n.profile.name).unwrap_or("?");
        let _ = os::delete(&account(net, cfg.key_id.as_deref().unwrap_or("")));
        return Err(format!("{e}; the phrase stays in its file"));
    }
    wipe(&home.phrase())
}

/// Move the phrase out of the OS keystore into `pair.phrase` (for a pair
/// going to a headless machine), then delete the keystore entry. The
/// caller must hold the daemon lock.
pub fn move_to_file(home: &Home) -> Result<(), String> {
    let mut cfg = NodeConfig::load(home)?;
    if cfg.key_store == KeyStore::File {
        return Err("the phrase is already in a file".into());
    }
    let phrase = load_phrase(home)?;
    if home.phrase().exists() {
        // A retry after a move that wrote the file and then failed (SC-2):
        // carry on if the file is this very phrase, refuse otherwise.
        if load_phrase_file(home)?.trim() != phrase.trim() {
            return Err(format!(
                "{} already exists with a different phrase; it may be another pair's only copy",
                home.phrase().display()
            ));
        }
    } else {
        store_phrase(home, &phrase)?;
    }
    let acct = account(cfg.network()?.profile.name, cfg.key_id.as_deref().unwrap_or(""));
    cfg.key_store = KeyStore::File;
    cfg.key_id = None;
    cfg.save(home)?;
    os::delete(&acct)
}

/// Overwrite with zeros, sync, delete.
fn wipe(path: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) as usize;
    let result = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|mut f| {
            f.write_all(&vec![0u8; len])?;
            f.sync_all()
        })
        .and_then(|_| std::fs::remove_file(path));
    result.map_err(|e| {
        format!(
            "the phrase is in the OS keystore, but {} could not be destroyed ({e}); delete it by hand",
            path.display()
        )
    })
}

/// On Windows a phrase file must sit under the user's profile: the
/// profile's ACL is what keeps other users out, and a home elsewhere
/// (another drive, a shared folder) may be readable by them.
#[cfg(windows)]
fn check_private_location(home: &Home) -> Result<(), String> {
    let lower = |p: &std::path::Path| std::path::PathBuf::from(p.to_string_lossy().to_lowercase());
    let profile = std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .ok_or("USERPROFILE is not set")?;
    let root = std::path::absolute(home.root()).map_err(|e| e.to_string())?;
    if lower(&root).starts_with(lower(std::path::Path::new(&profile))) {
        Ok(())
    } else {
        Err(format!(
            "{} is outside your user profile, where other users may be able to read it. \
             Keep the phrase in the OS keystore (`--keystore`), or use a home under {}.",
            home.root().display(),
            std::path::Path::new(&profile).display()
        ))
    }
}

#[cfg(not(windows))]
fn check_private_location(_home: &Home) -> Result<(), String> {
    Ok(())
}

/// Save the phrase to `pair.phrase`. Refuses to replace an existing one:
/// that file is the only thing between an operator and their stake.
pub fn store_phrase(home: &Home, phrase: &str) -> Result<(), String> {
    mnemonic::validate(phrase).map_err(|e| format!("recovery phrase: {e}"))?;
    check_private_location(home)?;
    home.ensure()?;
    let path = home.phrase();
    if path.exists() {
        return Err(format!(
            "{} already exists; this install already has a pair. \
             Move it away first if you really mean to replace it.",
            path.display()
        ));
    }
    let normalised = Zeroizing::new(
        phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase() + "\n",
    );
    write_atomic(&path, normalised.as_bytes(), true)
}

/// The phrase, from wherever `node.json` says it is.
pub fn load_phrase(home: &Home) -> Result<Zeroizing<String>, String> {
    // An unreadable node.json is reported, never read as "file" (SC-1):
    // the message would otherwise send the operator to `init`.
    match NodeConfig::load_if_present(home)? {
        Some(cfg) if cfg.key_store == KeyStore::Os => {
            let id = cfg.key_id.as_deref().ok_or("node.json says os keystore but names no key")?;
            let phrase = os::get(&account(cfg.network()?.profile.name, id))?;
            let phrase = Zeroizing::new(phrase.trim().to_string());
            mnemonic::validate(&phrase).map_err(|e| format!("OS keystore entry: {e}"))?;
            // The entry must be the pair the config names, not a stale one.
            if PairKeys::from_phrase(&phrase)?.own.stellar_address() != id {
                return Err("the OS keystore entry is for a different pair".into());
            }
            Ok(phrase)
        }
        _ => load_phrase_file(home),
    }
}

fn load_phrase_file(home: &Home) -> Result<Zeroizing<String>, String> {
    let path = home.phrase();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!(
                    "{} is readable by other users (mode {:o}); run `chmod 600` on it",
                    path.display(),
                    mode & 0o777
                ));
            }
        }
    }
    let text = Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("this install has no keys yet (run `kenter-node init`)")
        } else {
            format!("reading {}: {e}", path.display())
        }
    })?);
    let phrase = Zeroizing::new(text.trim().to_string());
    mnemonic::validate(&phrase).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(phrase)
}

/// The OS credential store. One entry per pair, service `kenter-node`.
#[cfg(all(feature = "keystore", any(windows, target_os = "macos")))]
pub mod os {
    use zeroize::Zeroizing;

    const SERVICE: &str = "kenter-node";

    pub fn supported() -> bool {
        true
    }

    fn entry(account: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(SERVICE, account).map_err(|e| format!("OS keystore: {e}"))
    }

    pub fn set(account: &str, phrase: &str) -> Result<(), String> {
        entry(account)?
            .set_password(phrase)
            .map_err(|e| format!("writing to the OS keystore: {e}"))
    }

    pub fn get(account: &str) -> Result<Zeroizing<String>, String> {
        entry(account)?
            .get_password()
            .map(Zeroizing::new)
            .map_err(|e| format!("reading the OS keystore: {e}"))
    }

    pub fn delete(account: &str) -> Result<(), String> {
        match entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("deleting from the OS keystore: {e}")),
        }
    }
}

/// A build without the OS keystore (headless): every call says so.
#[cfg(not(all(feature = "keystore", any(windows, target_os = "macos"))))]
pub mod os {
    use zeroize::Zeroizing;

    const NONE: &str = "this build has no OS keystore; the phrase stays in its file";

    pub fn supported() -> bool {
        false
    }
    pub fn set(_account: &str, _phrase: &str) -> Result<(), String> {
        Err(NONE.into())
    }
    pub fn get(_account: &str) -> Result<Zeroizing<String>, String> {
        Err(NONE.into())
    }
    pub fn delete(_account: &str) -> Result<(), String> {
        Err(NONE.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    #[test]
    fn a_phrase_gives_two_distinct_stable_keys() {
        let a = PairKeys::from_phrase(PHRASE).unwrap();
        let b = PairKeys::from_phrase(PHRASE).unwrap();
        assert_eq!(a.addresses(), b.addresses());
        let [own, partner] = a.addresses();
        assert_ne!(own, partner, "a pair is two keys");
    }

    /// A wallet phrase pasted in by mistake must not yield the wallet's own
    /// low-index accounts.
    #[test]
    fn node_keys_are_not_the_low_wallet_accounts() {
        let pair = PairKeys::from_phrase(PHRASE).unwrap();
        let seed = mnemonic::to_seed(PHRASE, "").unwrap();
        for account in 0..1000 {
            let s = slip10::stellar_account_secret(&seed[..], account).unwrap();
            let addr = StellarKeypair::from_raw_secret(&s).stellar_address();
            assert!(!pair.addresses().contains(&addr), "collides with account {account}");
        }
    }

    #[test]
    fn the_phrase_is_stored_once_and_reloads() {
        let home = Home::at(crate::testing::tempdir("keys"));
        let phrase = new_phrase().unwrap();
        store_phrase(&home, &phrase).unwrap();
        assert_eq!(&*load_phrase(&home).unwrap(), phrase.trim());
        let e = store_phrase(&home, &phrase).unwrap_err();
        assert!(e.contains("already exists"), "{e}");
        assert_eq!(
            PairKeys::load(&home).unwrap().addresses(),
            PairKeys::from_phrase(&phrase).unwrap().addresses()
        );
    }

    #[test]
    fn a_bad_phrase_is_refused_before_it_is_written() {
        let home = Home::at(crate::testing::tempdir("badkeys"));
        assert!(store_phrase(&home, "abandon abandon abandon").is_err());
        assert!(!home.phrase().exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_phrase_file_is_owner_only_and_a_loose_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let home = Home::at(crate::testing::tempdir("perm"));
        store_phrase(&home, PHRASE).unwrap();
        let mode = std::fs::metadata(home.phrase()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::set_permissions(home.phrase(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_phrase(&home).unwrap_err().contains("chmod 600"));
    }

    /// SA-4: a stale, looser temp file is not reused for the phrase.
    #[cfg(unix)]
    #[test]
    fn a_stale_loose_temp_file_is_not_reused() {
        use std::os::unix::fs::PermissionsExt;
        let home = Home::at(crate::testing::tempdir("staletmp"));
        home.ensure().unwrap();
        let tmp = home.phrase().with_extension("tmp");
        std::fs::write(&tmp, b"old").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        store_phrase(&home, PHRASE).unwrap();
        let mode = std::fs::metadata(home.phrase()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Windows: a phrase file outside the user's profile is refused before
    /// anything is written.
    #[cfg(windows)]
    #[test]
    fn a_phrase_file_outside_the_profile_is_refused() {
        let home = Home::at(r"Z:\kenter-node-outside-profile-test");
        let e = store_phrase(&home, PHRASE).unwrap_err();
        assert!(e.contains("outside your user profile"), "{e}");
        assert!(!home.root().exists());
    }

    /// The whole move, against the real OS keystore: file to keystore (file
    /// destroyed, phrase loads from the keystore) and back again (entry
    /// deleted).
    #[cfg(all(feature = "keystore", any(windows, target_os = "macos")))]
    #[test]
    fn the_phrase_moves_into_the_os_keystore_and_back() {
        let home = Home::at(crate::testing::tempdir("keystore"));
        let phrase = new_phrase().unwrap();
        let mut cfg = NodeConfig::new("ks-test");
        cfg.save(&home).unwrap();
        store_phrase(&home, &phrase).unwrap();
        let want = PairKeys::from_phrase(&phrase).unwrap().addresses();

        move_to_os(&home).unwrap();
        assert!(!home.phrase().exists(), "the file is destroyed");
        cfg = NodeConfig::load(&home).unwrap();
        assert_eq!(cfg.key_store, KeyStore::Os);
        assert_eq!(cfg.key_id.as_deref(), Some(want[0].as_str()));
        assert!(has_pair(&home).unwrap());
        assert_eq!(PairKeys::load(&home).unwrap().addresses(), want);
        assert!(move_to_os(&home).is_err(), "only once");

        move_to_file(&home).unwrap();
        assert!(home.phrase().exists());
        assert_eq!(NodeConfig::load(&home).unwrap().key_store, KeyStore::File);
        assert_eq!(PairKeys::load(&home).unwrap().addresses(), want);
        let acct = account(cfg.network().unwrap().profile.name, &want[0]);
        assert!(os::get(&acct).is_err(), "the keystore entry is deleted");
    }

    /// A keystore entry that holds some other pair is refused, not used.
    #[cfg(all(feature = "keystore", any(windows, target_os = "macos")))]
    #[test]
    fn a_keystore_entry_for_another_pair_is_refused() {
        let home = Home::at(crate::testing::tempdir("keystore-wrong"));
        let mut cfg = NodeConfig::new("ks-wrong");
        let a = new_phrase().unwrap();
        store_phrase_os(&mut cfg, &a).unwrap();
        cfg.save(&home).unwrap();
        let acct = account(cfg.network().unwrap().profile.name, cfg.key_id.as_deref().unwrap());
        // Overwrite the entry with a different pair's phrase.
        os::set(&acct, &new_phrase().unwrap()).unwrap();
        let e = load_phrase(&home).unwrap_err();
        assert!(e.contains("different pair"), "{e}");
        os::delete(&acct).unwrap();
    }

    /// SC-1: an unreadable node.json is an error everywhere, never "no
    /// pair", since it may be the only pointer to a keystore pair.
    #[test]
    fn an_unreadable_config_is_never_read_as_no_pair() {
        let home = Home::at(crate::testing::tempdir("badconfig"));
        home.ensure().unwrap();
        std::fs::write(home.config(), b"{ this is not json").unwrap();
        let e = has_pair(&home).unwrap_err();
        assert!(e.contains("fix or restore it"), "{e}");
        let e = load_phrase(&home).unwrap_err();
        assert!(!e.contains("kenter-node init"), "must not send the operator to init: {e}");
    }

    /// SC-2: a phrase file left beside a keystore pair is noticed, and
    /// destroyed only if it is the same phrase; move_to_file can resume.
    #[cfg(all(feature = "keystore", any(windows, target_os = "macos")))]
    #[test]
    fn a_leftover_file_is_noticed_and_only_a_matching_one_wiped() {
        let home = Home::at(crate::testing::tempdir("leftover"));
        let phrase = new_phrase().unwrap();
        let mut cfg = NodeConfig::new("leftover");
        store_phrase_os(&mut cfg, &phrase).unwrap();
        cfg.save(&home).unwrap();
        let acct = account(cfg.network().unwrap().profile.name, cfg.key_id.as_deref().unwrap());
        assert!(!leftover_file(&home));

        // A different phrase on disk: noticed, and refused.
        write_atomic(&home.phrase(), format!("{}
", &*new_phrase().unwrap()).as_bytes(), true).unwrap();
        assert!(leftover_file(&home));
        assert!(wipe_leftover(&home).unwrap_err().contains("different phrase"));
        assert!(move_to_file(&home).unwrap_err().contains("different phrase"));

        // The same phrase: move_to_file resumes over it...
        write_atomic(&home.phrase(), format!("{}
", &*phrase).as_bytes(), true).unwrap();
        move_to_file(&home).unwrap();
        assert_eq!(NodeConfig::load(&home).unwrap().key_store, KeyStore::File);
        assert!(os::get(&acct).is_err());

        // ...and after moving back in, a matching leftover is wiped.
        move_to_os(&home).unwrap();
        write_atomic(&home.phrase(), format!("{}
", &*phrase).as_bytes(), true).unwrap();
        assert!(leftover_file(&home));
        wipe_leftover(&home).unwrap();
        assert!(!home.phrase().exists());
        let acct = account(cfg.network().unwrap().profile.name, NodeConfig::load(&home).unwrap().key_id.as_deref().unwrap());
        os::delete(&acct).unwrap();
    }
}
