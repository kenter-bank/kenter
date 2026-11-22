//! What this client is, where it keeps things, and whether it can act.
//!
//! A status page rather than a preferences page. Nothing here is a setting yet
//! — every path is resolved from the environment, and the network is pinned to
//! testnet — so the job is to answer the questions a holder actually has when
//! something does not work: which wallet am I looking at, is there a seed, can
//! this thing submit a transaction, and where do I put a token someone sends
//! me.
//!
//! Each answer is a row and most are read off the filesystem, so the page
//! renders instantly and then fills in the one fact that needs the network:
//! whether the submitting account exists on testnet. An account that does not
//! exist cannot pay a fee, which means no spend and no redemption, and that is
//! worth saying plainly rather than letting it surface later as a failed
//! transaction.

use kenter_client::{AssetClient, MintClient, TxBuilder};
use kenter_vault::{KeyVault, SoftVault};
use kenter_wallet::Store;

use crate::receive::{default_vault_path, inbox_dir};
use crate::wallet::{default_wallet_dir, Network};
use crate::SettingsView;

/// Everything readable without touching the network.
/// `account` is the verified submitting address from this session's unlock,
/// `None` while locked.
pub fn local(net: Network, account: Option<&str>) -> SettingsView {
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut note = None;

    match default_wallet_dir() {
        Some(dir) => {
            rows.push((
                "wallet".into(),
                format!("{}{}", dir.display(), missing_if(!dir.exists())),
            ));
            rows.push(("inbox".into(), inbox_dir(&dir).display().to_string()));
        }
        None => {
            rows.push(("wallet".into(), "unresolved".into()));
            note = Some("set KENTER_WALLET_DIR".into());
        }
    }

    match default_vault_path() {
        Some(path) if path.exists() => {
            rows.push(("vault".into(), path.display().to_string()));
            match SoftVault::open(&path) {
                Ok(vault) => {
                    let (custody, seed) = custody_lines(&vault);
                    rows.push(("custody".into(), custody));
                    rows.push(("recovery seed".into(), seed));
                    rows.push(("submitting account".into(), account_line(&vault, account)));
                }
                Err(e) => rows.push(("vault".into(), format!("unreadable: {e}"))),
            }
        }
        Some(path) => {
            rows.push((
                "vault".into(),
                format!("{} (does not exist yet)", path.display()),
            ));
            rows.push(("custody".into(), "none - no wallet here yet".into()));
            rows.push(("recovery seed".into(), "none".into()));
            rows.push(("submitting account".into(), "none".into()));
        }
        None => rows.push(("vault".into(), "unresolved - set KENTER_VAULT".into())),
    }

    rows.push(("network".into(), net.name.into()));
    // Host only: a provider's API key often rides in the url's path.
    let host = kenter_client::SorobanRpcClient::new(net.rpc, net.passphrase).host_only();
    rows.push((
        "rpc".into(),
        if net.rpc_is_custom {
            format!("{host} (yours)")
        } else {
            format!("{host} (default)")
        },
    ));
    rows.push(("mint contract".into(), net.contract.into()));

    // Account reads do not go to the RPC above, and the difference is
    // worth showing. Soroban RPC has no `getAccount`, so sequence
    // numbers and balances come from Horizon — by default SDF's,
    // whoever the user chose for everything else, which means SDF
    // learns every address this wallet touches.
    rows.push((
        "account reads".into(),
        if net.horizon == kenter_client::network::built().horizon {
            format!("{} (public - set KENTER_HORIZON)", net.horizon)
        } else {
            net.horizon.to_string()
        },
    ));

    // How a deposit's nodes are found: nobody configures them.
    rows.push((
        "print network".into(),
        "nodes chosen by a public draw, reached through each node's own relay".into(),
    ));
    // Filled in by `with_account_status`: what this mint escrows cannot be
    // known without asking it.
    rows.push(("escrow asset".into(), "reading…".into()));

    SettingsView {
        rows,
        note,
        trustline_needed: None,
        // Needs the store keys, so it is filled in by `with_backup` once the
        // session has them. Absent reads as "not known", not as "fine".
        backup: None,
        rpc_edit: None,
    }
}

/// Add what the wallet can say about its backup.
///
/// Separate from [`local`] because it needs the store keys, and the status
/// page is deliberately readable while locked — a holder debugging a wallet
/// they cannot open is exactly who the page is for.
pub async fn with_backup(
    mut view: SettingsView,
    store: &kenter_wallet::FileStore,
) -> SettingsView {
    use kenter_wallet::backup::Coverage;

    let coverage = match crate::backup::coverage(store).await {
        Ok(c) => c,
        Err(e) => {
            view.rows
                .push(("backup".into(), format!("cannot tell: {e}")));
            // Not known is not fine. A wallet that cannot answer should
            // offer the button, not hide it.
            view.backup = Some(("cannot tell".into(), true));
            return view;
        }
    };

    let (line, at_risk) = match &coverage {
        Coverage::Covered { created_at, notes } => (
            format!(
                "{notes} note{} - saved {}",
                if *notes == 1 { "" } else { "s" },
                crate::backup::when(*created_at)
            ),
            false,
        ),
        Coverage::Stale {
            created_at,
            in_file,
            held,
        } => (
            format!(
                "{in_file} of {held} notes - last saved {}",
                crate::backup::when(*created_at)
            ),
            true,
        ),
        // The other variants describe a *file*, and this reads a record.
        _ => ("never saved".into(), true),
    };
    view.rows.push(("backup".into(), line.clone()));
    if let Some(whence) = store
        .last_backup()
        .await
        .ok()
        .flatten()
        .and_then(|r| r.whence)
    {
        view.rows.push(("last written to".into(), whence));
    }
    view.backup = Some((line, at_risk));
    view
}

/// What opens this wallet, and where its seed is.
///
/// Two rows, because they are two questions and a card wallet answers them
/// differently. `has_seed()` alone answers neither: a card wallet's vault
/// holds no seed by design, so the page would tell its owner "none -
/// receiving needs one", which is false and is the one sentence on a status page that
/// would send someone looking for a problem that is not there.
///
/// It is an easy mistake to repeat. The question is never where the seed
/// sits; it is what opens the wallet, and the vault records that.
fn custody_lines(vault: &SoftVault) -> (String, String) {
    match vault.custody() {
        Some(kenter_vault::Custody::Card { card_identity, .. }) => (
            format!("a card - {}", short_identity(card_identity)),
            "on the card. This file holds only the fee-paying account".into(),
        ),
        Some(kenter_vault::Custody::RecoveredCard { .. }) => (
            "this computer, recovered from a card".into(),
            "present - keys still derive the card's way, so your old backups open"
                .into(),
        ),
        Some(kenter_vault::Custody::Software) => (
            "this computer, behind your passphrase".into(),
            if vault.has_seed() {
                "present - owner keys derive from it".into()
            } else {
                // A software wallet with no seed is a broken one, not an
                // empty machine: the custody record says a wallet lives
                // here. Worth saying plainly rather than reading as "not
                // set up yet".
                "missing - this vault says it is a software wallet but holds no seed"
                    .into()
            },
        ),
        // Written before custody was recorded, so it can only be software
        // Said as an inference, not a fact.
        None if vault.has_seed() => (
            "this computer (assumed - set up before custody was recorded)".into(),
            "present - owner keys derive from it".into(),
        ),
        None => ("none - no wallet here yet".into(), "none".into()),
    }
}

/// Enough of a card's identity key to tell two cards apart, which is all a
/// holder ever needs it for.
fn short_identity(hex: &str) -> String {
    match hex.len() {
        0 => "identity not recorded".into(),
        n if n <= 12 => hex.to_string(),
        _ => format!("{}\u{2026}", &hex[..12]),
    }
}

/// The first Stellar key in the vault — the account that would pay fees.
///
/// "First" rather than a chosen one because nothing chooses yet; when spending
/// exists this becomes a selection, and saying "slot 0" now is honest about
/// which key is actually going to be used.
///
/// The address shown is `verified`, the one derived from the unwrapped key
/// at unlock, never the vault's plaintext list. Locked,
/// there is nothing trustworthy to show, and the row says so.
fn account_line(vault: &SoftVault, verified: Option<&str>) -> String {
    match vault.list_keys() {
        Ok(keys) if keys.is_empty() => "none - spending and redeeming need one".into(),
        Ok(keys) => match verified {
            Some(address) => format!("slot {} - {address}", keys[0].slot),
            None => format!("slot {} - unlock to show its address", keys[0].slot),
        },
        Err(e) => format!("unreadable: {e}"),
    }
}

/// The vault's **plaintext** record of its first account address.
///
/// Unauthenticated: the vault file's key list can be rewritten by anyone who
/// can write the file, without the passphrase, and the header MAC that would
/// catch it is only checked with a credential. So this is never shown as the
/// holder's account and never chosen as somewhere to pay: either would let
/// a swapped entry redirect deposits and payouts. Its one
/// use is as the source account of a read-only simulation, where any
/// existing account answers the same.
fn listed_address() -> Option<String> {
    let path = default_vault_path()?;
    let vault = SoftVault::open(path).ok()?;
    vault
        .list_keys()
        .ok()?
        .first()
        .map(|k| k.stellar_address.clone())
}

/// The submitting account's address, derived from its key.
///
/// Run at unlock with the account credential: the vault unwraps the first
/// key, checking the header MAC on the way, and the address is computed from
/// that key. `Ok(None)` is a vault with no account yet.
pub fn verified_address(account_credential: &[u8]) -> Result<Option<String>, String> {
    let path = default_vault_path().ok_or("set KENTER_VAULT")?;
    verified_address_in(&path, account_credential)
}

fn verified_address_in(
    path: &std::path::Path,
    account_credential: &[u8],
) -> Result<Option<String>, String> {
    let vault = SoftVault::open(path).map_err(|e| e.to_string())?;
    let Some(slot) = vault
        .list_keys()
        .map_err(|e| e.to_string())?
        .first()
        .map(|k| k.slot)
    else {
        return Ok(None);
    };
    vault
        .verified_stellar_address(slot, account_credential)
        .map(Some)
        .map_err(|e| format!("the vault's account key does not verify: {e}"))
}

/// Ask the ledger whether that account exists, and append the answer.
///
/// Split from [`local`] because it is the only part that can hang. An account
/// with no sequence number has never been funded: on testnet that is the
/// normal state of a freshly generated key, and it is the difference between a
/// client that can act and one that can only look.
pub async fn with_account_status(
    mut view: SettingsView,
    net: Network,
    address: Option<String>,
) -> SettingsView {
    let Some(address) = address else {
        return view;
    };
    let rpc = net.rpc_client();
    let funded = rpc.get_account_sequence(&address).await;
    let line = match &funded {
        Ok(_) => "funded - this client can submit transactions".to_string(),
        // Distinguish "not funded" from "could not ask": one is a setup step,
        // the other is a network problem, and telling someone to fund an
        // account that is already funded wastes their time.
        Err(e) if is_missing_account(e) => {
            "not funded - no transaction can be submitted until it is".into()
        }
        Err(e) => format!("unknown - could not reach the ledger ({e})"),
    };
    view.rows.push(("account status".into(), line));

    // Reading the mint's config needs a funded source account, because it
    // goes through `simulate_invoke` and that needs a sequence number. So
    // this follows the funded check rather than running beside it.
    if funded.is_err() {
        set_row(
            &mut view,
            "escrow asset",
            "unknown until the account is funded",
        );
        return view;
    }
    // Read as *this* account. `pay_token` and the asset reads go through
    // `simulate_invoke`, which needs a source with a sequence number — and
    // this client's account is the one we have just confirmed has one. A
    // throwaway keypair would be an address that has never existed, so every
    // read below would fail and the trustline row would never appear at all.
    let build = || TxBuilder::read_only(net.rpc_client(), &address);
    let mut mint = MintClient::new(build(), net.contract);
    let asset = match mint.pay_token().await {
        Ok(token) => AssetClient::new(build(), &token).describe().await,
        Err(e) => Err(e),
    };
    let Ok(asset) = asset else {
        set_row(&mut view, "escrow asset", "could not read it from the mint");
        return view;
    };
    set_row(
        &mut view,
        "escrow asset",
        &format!("{} - notes are a claim on this", asset.code),
    );

    // The line that decides whether this client can be *paid*. A payout
    // cannot reach an account with no trustline, so without one a holder can
    // end up with good notes they cannot redeem - which is worse than being
    // unable to deposit, and far less obvious.
    let Some(issuer) = asset.issuer.clone() else {
        view.rows.push((
            "trustline".into(),
            "not needed - this mint escrows native XLM".into(),
        ));
        return view;
    };
    let line = match build().has_trustline(&asset.code, &issuer).await {
        Ok(true) => format!("{} - this client can be paid out", asset.code),
        Ok(false) => {
            view.trustline_needed = Some(asset.code.clone());
            format!(
                "missing - add one for {}, or a redemption cannot pay you",
                asset.code
            )
        }
        // Not offered on an unknown: adding one that already exists is
        // harmless but confusing, and the holder can retry the read.
        Err(e) => format!("unknown - could not reach the ledger ({e})"),
    };
    view.rows.push(("trustline".into(), line));
    view
}

/// The asset this mint escrows, for a client that needs to act on it.
pub async fn escrow_asset(net: Network) -> Result<kenter_client::Asset, String> {
    // Same trap as `with_account_status`: these are `simulate_invoke` reads,
    // which need a source account that exists. A throwaway keypair has no
    // sequence number and fails before the read is sent.
    // The plaintext address is fine here and only here: it is the source of
    // a simulation, not anyone's money.
    let address = listed_address()
        .ok_or_else(|| "no account in the vault to read the mint with".to_string())?;
    let build = || TxBuilder::read_only(net.rpc_client(), &address);
    let token = MintClient::new(build(), net.contract)
        .pay_token()
        .await
        .map_err(|e| e.to_string())?;
    AssetClient::new(build(), &token)
        .describe()
        .await
        .map_err(|e| e.to_string())
}

/// Replace a placeholder row in place, so the order on screen stays fixed
/// however the network reads resolve.
fn set_row(view: &mut SettingsView, key: &str, value: &str) {
    if let Some(row) = view.rows.iter_mut().find(|(k, _)| k == key) {
        row.1 = value.to_string();
    }
}

/// Horizon and the RPC both report an unfunded account as "not found"; the
/// shapes differ by version, so this matches on the common substrings rather
/// than on one error variant.
fn is_missing_account(e: &kenter_client::ClientError) -> bool {
    let s = e.to_string().to_lowercase();
    s.contains("not found") || s.contains("notfound") || s.contains("404")
}

fn missing_if(missing: bool) -> &'static str {
    if missing {
        " (not created yet)"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::{custody_lines, verified_address_in};
    use kenter_vault::KeyVault;

    /// The address the holder is shown and paid to comes from
    /// the key. A vault file whose plaintext entry was swapped yields an
    /// error, never the attacker's address.
    #[test]
    fn a_swapped_vault_entry_is_never_the_shown_address() {
        let path = std::env::temp_dir().join(format!(
            "kenter-settings-ws4-3-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut v = SoftVault::open(&path).unwrap();
        let slot = v.generate_key("acct", b"pw").unwrap();
        let honest = v.stellar_address(slot).unwrap();
        drop(v);

        assert_eq!(verified_address_in(&path, b"pw").unwrap(), Some(honest));

        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["entries"][0]["public_key"] = serde_json::json!(hex::encode([0xEE; 32]));
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        assert!(verified_address_in(&path, b"pw").is_err());
        let _ = std::fs::remove_file(&path);
    }
    use kenter_vault::{Custody, SoftVault};

    fn vault(tag: &str, seed: bool, custody: Option<Custody>) -> SoftVault {
        let path = std::env::temp_dir().join(format!(
            "kenter-settings-{tag}-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut v = SoftVault::open(&path).unwrap();
        if seed {
            v.set_seed_from_mnemonic(
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "",
                b"pass",
            )
            .unwrap();
        }
        if let Some(c) = custody {
            v.set_custody(c, b"pass").unwrap();
        }
        let _ = std::fs::remove_file(&path);
        v
    }

    /// A card wallet's vault holds no seed by design, and the page must not
    /// tell its owner "none - receiving needs one" - sending them to look for a problem that is not there.
    #[test]
    fn a_card_wallet_is_not_reported_as_having_no_seed() {
        let v = vault(
            "card",
            false,
            Some(Custody::Card {
                seed_fingerprint: "abcdef0123456789".into(),
                card_identity: "03c7a53f1122334455".into(),
            }),
        );
        let (custody, seed) = custody_lines(&v);
        assert!(custody.starts_with("a card - 03c7a53f1122"), "{custody}");
        assert!(seed.starts_with("on the card"), "{seed}");
        assert!(!seed.contains("none"), "{seed}");
        assert!(!seed.contains("needs one"), "{seed}");
    }

    /// A recovered wallet says so, including the part a holder needs: their
    /// old backups still open.
    #[test]
    fn a_recovered_card_wallet_says_which_it_is() {
        let v = vault(
            "recovered",
            true,
            Some(Custody::RecoveredCard {
                seed_fingerprint: "abcdef0123456789".into(),
            }),
        );
        let (custody, seed) = custody_lines(&v);
        assert!(custody.contains("recovered from a card"), "{custody}");
        assert!(seed.contains("old backups open"), "{seed}");
    }

    #[test]
    fn a_software_wallet_says_so() {
        let v = vault("soft", true, Some(Custody::Software));
        let (custody, seed) = custody_lines(&v);
        assert!(custody.contains("this computer"), "{custody}");
        assert!(seed.starts_with("present"), "{seed}");
    }

    /// A software wallet with no seed is broken, not empty. Reading it as
    /// "not set up yet" would hide the one state worth acting on.
    #[test]
    fn a_software_wallet_with_no_seed_is_called_broken() {
        let v = vault("soft-empty", false, Some(Custody::Software));
        let (_, seed) = custody_lines(&v);
        assert!(seed.starts_with("missing"), "{seed}");
        assert!(seed.contains("holds no seed"), "{seed}");
    }

    /// No record at all: software is the only thing it can be, and the page
    /// says so as an inference rather than as a fact.
    #[test]
    fn an_old_vault_without_a_record_is_an_assumption() {
        let v = vault("legacy", true, None);
        let (custody, seed) = custody_lines(&v);
        assert!(custody.contains("assumed"), "{custody}");
        assert!(seed.starts_with("present"), "{seed}");
    }

    #[test]
    fn an_empty_vault_is_empty() {
        let v = vault("empty", false, None);
        assert_eq!(custody_lines(&v), ("none - no wallet here yet".into(), "none".into()));
    }

    /// Identity keys are 33 bytes of hex. The row exists to tell two cards
    /// apart, which the first few bytes do.
    #[test]
    fn the_card_identity_is_shortened_but_never_invented() {
        use super::short_identity;
        assert_eq!(short_identity(""), "identity not recorded");
        assert_eq!(short_identity("03c7a53f"), "03c7a53f");
        assert_eq!(
            short_identity("03c7a53f1122334455667788"),
            "03c7a53f1122\u{2026}"
        );
    }
}
