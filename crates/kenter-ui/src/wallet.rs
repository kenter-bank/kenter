//! Loading a real [`WalletView`] from the wallet on disk.
//!
//! This is the seam between the GUI and the core: the GUI is a shell over
//! `kenter-wallet`, reaching the chain through `kenter-client`'s `WalletChain`
//! and the disk through `FileStore` — the same two engines the CLI uses, so the
//! two desktop surfaces cannot drift about what the wallet contains.
//!
//! All the IO lives here. `Ui::build_with` takes a plain [`WalletView`] and does
//! no IO at all, which is what keeps the PNG mock renderable with no chain,
//! vault or store present.
//!
//! No vault is involved: showing a balance needs neither the seed nor a
//! passphrase, and prompting for one just to look at the screen would be a bad
//! trade. Signing operations will need it, and will ask then.

use kenter_client::{MintClient, SorobanRpcClient, TxBuilder, WalletChain};
use kenter_crypto::keypair::StellarKeypair;
use kenter_wallet::{
    fmt_stroops, Balance, FileStore, ReconciledToken, Store, StoreCredentials, TokenStatus,
    TokenWallet,
};

use crate::{DenomTab, NoteCard, NoteState, WalletView};

/// Which chain and mint the window talks to.
///
/// One value passed around rather than three loose strings: an RPC url paired
/// with the wrong network passphrase fails in a way that reads like a network
/// problem, and a mint id from another network reads like an empty wallet.
///
/// Built from [`kenter_client::network`]: the network itself (testnet or
/// mainnet) is fixed when the binary is built, and only where it is reached
/// can change at runtime ([`Network::set_rpc`]).
#[derive(Debug, Clone, Copy)]
pub struct Network {
    /// `"testnet"` or `"mainnet"`.
    pub name: &'static str,
    pub rpc: &'static str,
    pub passphrase: &'static str,
    pub contract: &'static str,
    /// The node roster the mint checks print requests against.
    pub roster: &'static str,
    /// Where account reads go. Soroban RPC has no `getAccount`, so
    /// sequence numbers and balances come from Horizon.
    pub horizon: &'static str,
    /// Whether `rpc` is the build's default or the holder's own choice.
    pub rpc_is_custom: bool,
}

/// The process's current network. Starts unset; [`Network::init`] fills it.
static CURRENT: std::sync::RwLock<Option<Network>> = std::sync::RwLock::new(None);

/// Leak a string for the process lifetime. Network settings change at most
/// a handful of times per run, and every consumer wants `&'static str`.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

impl Network {
    fn from_config(c: kenter_client::NetworkConfig, rpc_is_custom: bool) -> Network {
        Network {
            name: c.profile.name,
            passphrase: c.profile.passphrase,
            rpc: leak(c.rpc),
            horizon: leak(c.horizon),
            contract: leak(c.mint),
            roster: leak(c.roster),
            rpc_is_custom,
        }
    }

    /// Resolve the network once, at startup: the build's profile, then the
    /// saved Settings RPC, then the environment, which wins.
    ///
    /// An error here is a build or configuration that cannot be used -- a
    /// mainnet build without its contract ids, or a contract override a
    /// mainnet build does not allow -- and the app should stop and say so
    /// rather than open on a guess.
    pub fn init() -> Result<Network, String> {
        let saved = saved_rpc();
        let env = kenter_client::Overrides::from_env();
        let rpc_is_custom = env.rpc.is_some() || saved.is_some();
        let overrides = env.or(kenter_client::Overrides { rpc: saved, ..Default::default() });
        let net = Network::from_config(
            kenter_client::NetworkConfig::resolve(kenter_client::network::built(), overrides)?,
            rpc_is_custom,
        );
        *CURRENT.write().unwrap_or_else(|e| e.into_inner()) = Some(net);
        Ok(net)
    }

    /// The network as it stands now.
    ///
    /// Read fresh at each use rather than captured once, so a new RPC
    /// endpoint from Settings applies to the next request without a
    /// restart.
    pub fn current() -> Network {
        if let Some(net) = *CURRENT.read().unwrap_or_else(|e| e.into_inner()) {
            return net;
        }
        // Not initialised: a test, or a tool that skipped `init`. Resolve
        // without the saved setting, and fail loudly on a build that
        // cannot resolve at all, since `main` refuses to start on one.
        Network::init().expect("network configuration")
    }

    /// Use `url` as the RPC endpoint, or the build's default for `None`.
    ///
    /// A custom endpoint is asked which network it serves first and
    /// refused unless it is this build's ([`kenter_client::network::check_endpoint`]).
    /// The choice is saved beside the wallet and applies at once.
    pub async fn set_rpc(url: Option<&str>) -> Result<Network, String> {
        let profile = kenter_client::network::built();
        let url = url.map(str::trim).filter(|u| !u.is_empty());
        if let Some(u) = url {
            if !(u.starts_with("https://") || u.starts_with("http://127.") || u.starts_with("http://localhost")) {
                return Err("the RPC address has to start with https://".into());
            }
            kenter_client::network::check_endpoint(profile, u).await?;
        }
        save_rpc(url)?;
        let mut net = Network::current();
        if std::env::var("KENTER_RPC").map(|v| !v.trim().is_empty()).unwrap_or(false) {
            return Err("KENTER_RPC is set in the environment and overrides this setting; \
                        it was saved, and applies once KENTER_RPC is unset"
                .into());
        }
        net.rpc = match url {
            Some(u) => leak(u.to_string()),
            None => profile.rpc,
        };
        net.rpc_is_custom = url.is_some();
        *CURRENT.write().unwrap_or_else(|e| e.into_inner()) = Some(net);
        Ok(net)
    }

    /// An RPC client configured the way this build says.
    ///
    /// One constructor rather than fifteen `SorobanRpcClient::new(..)`
    /// calls, so that a setting like the Horizon endpoint is applied
    /// everywhere by being set once.
    pub fn rpc_client(&self) -> kenter_client::SorobanRpcClient {
        kenter_client::SorobanRpcClient::new(self.rpc, self.passphrase).with_horizon(self.horizon)
    }
}

/// Settings the holder chose, saved beside the wallet as `settings.json`.
///
/// Plain JSON: nothing in it is secret. It does hold the RPC url, which can
/// carry a provider's API key in its path, so the screens show only its
/// host ([`kenter_client::SorobanRpcClient::host_only`]).
fn settings_path() -> Option<std::path::PathBuf> {
    default_wallet_dir().map(|d| d.join("settings.json"))
}

fn saved_rpc() -> Option<String> {
    let raw = std::fs::read(settings_path()?).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get("rpc").and_then(|r| r.as_str()).map(str::to_string).filter(|r| !r.is_empty())
}

fn save_rpc(url: Option<&str>) -> Result<(), String> {
    let path = settings_path().ok_or("no wallet directory to save settings in")?;
    let mut v: serde_json::Value = std::fs::read(&path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    match url {
        Some(u) => v["rpc"] = serde_json::Value::String(u.to_string()),
        None => {
            if let Some(o) = v.as_object_mut() {
                o.remove("rpc");
            }
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap_or_default())
        .map_err(|e| format!("saving {}: {e}", path.display()))
}

/// The user's home directory, however this platform spells it.
pub fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()
        .map(std::path::PathBuf::from)
}

/// Where the CLI keeps its wallet, so the GUI opens the same one by default.
/// Mirrors `kenter-desktop`'s resolution order.
pub fn default_wallet_dir() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("KENTER_WALLET_DIR") {
        if !p.is_empty() {
            return Some(std::path::PathBuf::from(p));
        }
    }
    home_dir().map(|h| h.join(".kenter").join("wallet"))
}

/// Abbreviate a note id for display: `GD7MDB…CLHR-3`.
pub fn short(id: &str) -> String {
    kenter_wallet::short_note_id(id)
}

/// How many denomination tabs before the rest go in `Other`.
///
/// The compartments are meant to be the holder's *saved
/// denominations*, which is what stops them multiplying: free-form amounts
/// mean an unbounded number of distinct ones, and one tab per note is worse
/// than no tabs. There is no preset store yet, so the tabs are derived from
/// what is actually held and capped here — the same shape a populated preset
/// list would produce for most holders, and it degrades the same way.
const MAX_TABS: usize = 5;

fn card(
    r: &ReconciledToken,
    redeems_for: String,
    backup: Option<&kenter_wallet::models::BackupRecord>,
) -> NoteCard {
    let state = if r.held.marked_spent {
        NoteState::MarkedSpent
    } else if r.held.spent_away {
        NoteState::Spent("paid away")
    } else if r.claim_disputed() {
        // Ahead of the on-chain status, including `Active`. A disputed
        // note usually *is* Active - that is what makes it dangerous, and
        // showing it as `live` is the thing being fixed.
        NoteState::Disputed
    } else {
        match r.status {
            TokenStatus::Active => NoteState::Live,
            TokenStatus::Redeemed => NoteState::Spent("redeemed"),
            // A note the ledger has never heard of is either a deposit that
            // did not finish registering, or one that never will. The client
            // cannot tell them apart from here, and "stalled" is the reading
            // that prompts someone to look.
            TokenStatus::NotFound => NoteState::Stalled,
            TokenStatus::Unknown => NoteState::Unverified,
            // The ledger has a live record for this slot and it does
            // not describe these bytes. Disputed rather than live:
            // shown as live, a counterfeit reaching the store through
            // `import` would display at the ledger's amount, which is
            // the one number an attacker controls.
            TokenStatus::Counterfeit => NoteState::Disputed,
            // Bound to a mint this wallet is not pointed at. Very
            // likely still live where it belongs, so it is not spent
            // and it is certainly not stalled -- the one thing it must
            // not read as is anything that invites deleting it.
            TokenStatus::OtherMint => NoteState::Unverified,
            // No mint has confirmed these bytes, so nothing the ledger
            // said is about this note.
            TokenStatus::Unbound => NoteState::Unverified,
            // The ledger names another owner.
            TokenStatus::NotOurs => NoteState::Spent("owned by someone else"),
        }
    };
    NoteCard {
        short_id: short(&r.held.id),
        // The ledger's figure. `r.held.amount` is a local claim and is the
        // one number someone handing over a loaded wallet would edit.
        amount: fmt_stroops(r.trusted_amount()),
        claimed: r
            .claim_disputed()
            .then(|| fmt_stroops(r.held.amount)),
        redeems_for,
        spend_mode: r.held.owner_index.is_some(),
        state,
        // The backup icon, answered from the wallet's record of its last
        // backup rather than by reading the file — which is usually not
        // here, being the whole point of a backup. No record means no, which
        // is both the safe reading and the true one.
        backed_up: backup.is_some_and(|b| b.covers(&r.held.id)),
        exposure: r.held.exports.exposure(),
        id: r.held.id.clone(),
    }
}

/// Group cards into compartments: denominations largest first, then `Other`,
/// then `Spent`.
fn compartments(cards: Vec<NoteCard>) -> Vec<DenomTab> {
    let (done, live): (Vec<_>, Vec<_>) = cards.into_iter().partition(|c| c.state.is_done());

    // Order denominations by how many are held, so the compartment a holder
    // uses most is the one that survives the cap.
    let mut by_denom: Vec<(String, Vec<NoteCard>)> = Vec::new();
    for c in live {
        match by_denom.iter_mut().find(|(d, _)| *d == c.amount) {
            Some((_, v)) => v.push(c),
            None => by_denom.push((c.amount.clone(), vec![c])),
        }
    }
    by_denom.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(b.0.cmp(&a.0)));

    let mut tabs: Vec<DenomTab> = Vec::new();
    let mut other: Vec<NoteCard> = Vec::new();
    for (label, notes) in by_denom {
        if tabs.len() < MAX_TABS {
            tabs.push(DenomTab { label, notes });
        } else {
            other.extend(notes);
        }
    }
    // Back in denomination order for display, now that the cap has been
    // applied by frequency.
    tabs.sort_by(|a, b| b.label.cmp(&a.label));
    if !other.is_empty() {
        tabs.push(DenomTab {
            label: "Other".into(),
            notes: other,
        });
    }
    // Spent is a compartment, not a deletion: a billfold that silently
    // shrinks reads as loss.
    if !done.is_empty() {
        tabs.push(DenomTab {
            label: "Spent".into(),
            notes: done,
        });
    }
    tabs
}

/// Read the wallet and reconcile it against the ledger.
///
/// A chain read can fail — no network, RPC down — and that must not leave the
/// screen blank or lying. On failure the held tokens are still shown, with the
/// status line saying the ledger could not be reached, because "here is what
/// you hold, unverified" is honest and useful while "$0.0000000" would be a
/// false statement about someone's money.
pub async fn load(
    dir: &std::path::Path,
    rpc_url: &str,
    network_passphrase: &str,
    contract_id: &str,
    creds: Option<StoreCredentials>,
) -> WalletView {
    // Q8: the store is encrypted, so there is no reading it without the seed.
    // Locked is a state, not a failure - the notes are there and intact, the
    // client simply cannot see them yet, and saying "0.0000000 KEN" instead
    // would be a false statement about someone's money.
    let Some(creds) = creds else {
        return WalletView::locked();
    };
    let store = match FileStore::open(dir, creds) {
        Ok(s) => s,
        Err(e) => {
            return WalletView {
                empty_hint: format!("{e}"),
                ..WalletView::bare("—", "billfold unavailable", "")
            }
        }
    };

    let rpc = SorobanRpcClient::new(rpc_url, network_passphrase);
    let mint = MintClient::new(TxBuilder::new(rpc, StellarKeypair::random()), contract_id);
    let mut wallet = TokenWallet::new(WalletChain::new(mint), store);

    // Reconcile ownership before counting anything. A token paid away is still
    // Active on the ledger, so without this the balance keeps counting money
    // the holder no longer controls - the single worst thing a wallet can get
    // wrong. `sync` also binds a receive that crashed after the payer's spend
    // landed but before the token was recorded.
    //
    // It costs a second chain read per token, on top of the one `reconcile`
    // does. Worth it: the alternative is a figure that is confidently wrong,
    // and the sweep is a handful of round trips for a wallet of any size a
    // person actually holds. A failure here is not fatal - it means the
    // picture may be stale, not that the tokens are gone - so it is noted and
    // the read continues.
    let stale = wallet.sync().await.err().map(|e| e.to_string());

    // Read before `held`, so the early returns below do not have to carry
    // it. A failure here is not worth a banner of its own: it means the
    // wallet cannot say whether it is backed up, and the honest rendering of
    // that is the same warning as not being backed up.
    let last_backup = wallet.store().last_backup().await.ok().flatten();

    let held = match wallet.held().await {
        Ok(h) => h,
        Err(e) => {
            return WalletView {
                empty_hint: format!("{e}"),
                ..WalletView::bare("—", "billfold unreadable", "")
            }
        }
    };
    if held.is_empty() {
        return WalletView::empty("run `kenter import <file.symtoken>` to add one");
    }

    match wallet.reconcile().await {
        Ok(reconciled) => {
            let balance = Balance::from_reconciled(&reconciled);
            let cards: Vec<NoteCard> = reconciled
                .iter()
                .map(|r| {
                    // Redemption value is not derivable from the record: the
                    // fee depends on the pair count, which lives on the
                    // ledger entry rather than the local one. Until that is
                    // read, the honest answer is the face value with a note
                    // that fees come off it.
                    card(
                        r,
                        format!("{} less fees", fmt_stroops(r.held.amount)),
                        last_backup.as_ref(),
                    )
                })
                .collect();
            let count = cards.iter().filter(|c| !c.state.is_done()).count();
            let stalled = cards
                .iter()
                .filter(|c| c.state == NoteState::Stalled)
                .count();

            let mut subtitle = format!("{count} note{} held", if count == 1 { "" } else { "s" });
            // What left, said out loud. The headline does not carry it, so
            // without this a redeemed note would vanish from the screen
            // with nothing to show it had ever been there.
            if balance.gone() > 0 {
                subtitle.push_str(&format!(
                    " · {} redeemed or paid away",
                    fmt_stroops(balance.gone())
                ));
            }
            if stale.is_some() {
                subtitle.push_str(" · ownership unchecked");
            }
            WalletView {
                // What is still held — not `total_held`, which counts every
                // record the store has ever had and so kept including notes
                // after they were redeemed. Still not a claim that the sum
                // is payable: most of it cannot be combined, and that is what
                // the compartments below are for.
                balance: fmt_stroops(balance.still_held()),
                subtitle,
                tabs: compartments(cards),
                selected_tab: 0,
                expanded: None,
                empty_hint: String::new(),
                locked: false,
                loading: false,
                stalled: (stalled > 0).then(|| {
                    format!(
                        "{stalled} deposit{} did not finish - the escrow is still in its slot",
                        if stalled == 1 { "" } else { "s" }
                    )
                }),
                backup: backup_line(last_backup.as_ref(), &held),
                disputed: disputed_line(&reconciled),
            }
        }
        Err(e) => {
            // Offline: show what is held, and say the figure is unverified.
            //
            // `spent_away` and `marked_spent` are local facts — the holder
            // told us, or a previous sync did — so they still apply with no
            // ledger. Summing them here would reproduce the bug the online
            // path just had: redeem a note, lose the network, and the
            // money reappears.
            local_view(&held, last_backup.as_ref(), &format!("{e}"), true)
        }
    }
}

/// A billfold built from the store alone, with no ledger.
///
/// Two callers, for two reasons that look different and are the same one:
/// the ledger is slow, and sometimes it is not there at all.
///
/// - **Offline**, where it is the only thing that can be shown.
/// - **Immediately after unlocking**, where it is shown *first* and then
///   replaced by the reconciled view. A sweep is a round trip per note and
///   takes seconds; the notes are on disk and take none. Waiting for the
///   ledger before painting anything made a restored wallet look empty for
///   five seconds, which is the one moment a holder is least willing to
///   believe their notes are there.
///
/// Everything is `Unverified` because that is true: nothing here has been
/// checked against the ledger. What *is* known locally still applies — a
/// note the holder paid away does not come back looking live just because
/// the ledger has not been asked yet.
pub fn local_view(
    held: &[kenter_wallet::HeldToken],
    last_backup: Option<&kenter_wallet::models::BackupRecord>,
    hint: &str,
    offline: bool,
) -> WalletView {
    let gone = |t: &kenter_wallet::HeldToken| t.spent_away || t.marked_spent;
    let total: u64 = held.iter().filter(|t| !gone(t)).map(|t| t.amount).sum();
    let cards: Vec<NoteCard> = held
        .iter()
        .map(|t| NoteCard {
            short_id: short(&t.id),
            amount: fmt_stroops(t.amount),
            redeems_for: "unknown offline".into(),
            spend_mode: t.owner_index.is_some(),
            state: if t.marked_spent {
                NoteState::MarkedSpent
            } else if t.spent_away {
                NoteState::Spent("paid away")
            } else {
                NoteState::Unverified
            },
            backed_up: last_backup.is_some_and(|b| b.covers(&t.id)),
            // Nothing to dispute with: there is no ledger figure here to
            // contradict the record.
            claimed: None,
            exposure: t.exports.exposure(),
            id: t.id.clone(),
        })
        .collect();
    WalletView {
        balance: fmt_stroops(total),
        subtitle: if offline {
            "unverified \u{2014} could not reach the ledger".into()
        } else {
            "checking against the ledger\u{2026}".into()
        },
        tabs: compartments(cards),
        selected_tab: 0,
        expanded: None,
        empty_hint: hint.to_string(),
        locked: false,
        // Not `loading` when offline: there is nothing still coming.
        loading: !offline,
        stalled: None,
        backup: backup_line(last_backup, held),
        disputed: None,
    }
}

/// [`local_view`] read straight off the disk, for the moment after an
/// unlock and before the ledger has been asked anything.
pub fn load_local(dir: &std::path::Path, creds: StoreCredentials) -> Option<WalletView> {
    let store = FileStore::open(dir, creds).ok()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .ok()?;
    rt.block_on(async {
        let held = store.all().await.ok()?;
        let last_backup = store.last_backup().await.ok().flatten();
        Some(local_view(&held, last_backup.as_ref(), "", false))
    })
}

/// The billfold's red line: records that contradict the ledger.
///
/// Counted, not summed. The quantity that matters is "something here is
/// lying to you"; adding up the lie would put a fictional figure on screen
/// to describe fiction.
fn disputed_line(reconciled: &[ReconciledToken]) -> Option<String> {
    let n = reconciled
        .iter()
        .filter(|r| !r.held.spent_away && !r.held.marked_spent)
        .filter(|r| r.claim_disputed())
        .count();
    if n == 0 {
        return None;
    }
    Some(format!(
        "{n} note{} claim{} an amount the mint does not back - open {} to see the real value",
        if n == 1 { "" } else { "s" },
        if n == 1 { "s" } else { "" },
        if n == 1 { "it" } else { "them" }
    ))
}

/// The billfold's backup sentence, or silence when there is nothing to say.
///
/// Counts the notes *at risk* rather than reporting the coverage verdict,
/// because "4 notes" is the number a holder can act on and "stale" is not.
/// Notes already spent or paid away are excluded: their bytes are worth
/// nothing to anybody, so warning about them would be crying wolf on every
/// billfold that has ever been used.
fn backup_line(
    record: Option<&kenter_wallet::models::BackupRecord>,
    held: &[kenter_wallet::HeldToken],
) -> Option<String> {
    let at_risk = held
        .iter()
        .filter(|t| !t.spent_away && !t.marked_spent)
        .filter(|t| !record.is_some_and(|b| b.covers(&t.id)))
        .count();
    if at_risk == 0 {
        return None;
    }
    Some(match record {
        None => format!(
            "{at_risk} note{} in no backup - if this computer is lost, so are they",
            if at_risk == 1 { "" } else { "s" }
        ),
        Some(_) => format!(
            "{at_risk} note{} arrived since your last backup and {} in it",
            if at_risk == 1 { "" } else { "s" },
            if at_risk == 1 { "is not" } else { "are not" }
        ),
    })
}

#[cfg(test)]
mod backup_line_tests {
    use super::backup_line;
    use kenter_wallet::backup::record_for;
    use kenter_wallet::HeldToken;

    fn note(seed: u8, spent: bool) -> HeldToken {
        HeldToken {
            slot_id: 1,
            id: format!("G{seed:0>55}"),
            ephemeral_public_key: [seed; 32],
            event_id: [seed; 32],
            amount: 1_000,
            blob: vec![seed; 8],
            imported_at: 1,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: spent,
            exports: Default::default(),
            marked_spent: false,
        }
    }

    /// Silence is the reward for being backed up. A tick nobody reads is
    /// noise, and noise is what makes the warning get ignored.
    #[test]
    fn a_covered_wallet_says_nothing() {
        let held = [note(1, false), note(2, false)];
        let record = record_for(&held, 10, None);
        assert_eq!(backup_line(Some(&record), &held), None);
    }

    #[test]
    fn no_backup_at_all_names_the_stakes() {
        let held = [note(1, false), note(2, false)];
        let line = backup_line(None, &held).unwrap();
        assert!(line.starts_with("2 notes in no backup"), "{line}");
        assert!(line.contains("if this computer is lost"), "{line}");
    }

    #[test]
    fn a_single_note_reads_as_one() {
        let held = [note(1, false)];
        let line = backup_line(None, &held).unwrap();
        assert!(line.starts_with("1 note in no backup"), "{line}");
    }

    /// The count is of notes at risk, not of notes held — that is the
    /// number a holder can do something about.
    #[test]
    fn only_the_notes_that_arrived_since_are_counted() {
        let old = [note(1, false)];
        let record = record_for(&old, 10, None);
        let held = [note(1, false), note(2, false), note(3, false)];

        let line = backup_line(Some(&record), &held).unwrap();
        assert!(line.starts_with("2 notes arrived since"), "{line}");
        assert!(line.ends_with("are not in it"), "{line}");
    }

    #[test]
    fn one_note_since_reads_as_one() {
        let record = record_for(&[note(1, false)], 10, None);
        let held = [note(1, false), note(2, false)];
        let line = backup_line(Some(&record), &held).unwrap();
        assert!(line.starts_with("1 note arrived since"), "{line}");
        assert!(line.ends_with("is not in it"), "{line}");
    }

    /// A spent note's bytes are worth nothing to anybody, so warning about
    /// them would cry wolf on every billfold that has ever been used.
    #[test]
    fn spent_notes_are_not_at_risk() {
        let held = [note(1, true), note(2, true)];
        assert_eq!(backup_line(None, &held), None);

        let mut mixed = vec![note(1, true), note(2, false)];
        mixed[1].marked_spent = false;
        let line = backup_line(None, &mixed).unwrap();
        assert!(line.starts_with("1 note in no backup"), "{line}");
    }

    #[test]
    fn a_note_the_holder_marked_spent_is_not_at_risk() {
        let mut n = note(1, false);
        n.marked_spent = true;
        assert_eq!(backup_line(None, &[n]), None);
    }

    #[test]
    fn an_empty_wallet_has_nothing_to_warn_about() {
        assert_eq!(backup_line(None, &[]), None);
    }
}

