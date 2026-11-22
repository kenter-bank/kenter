//! Running a receive, off the event loop.
//!
//! The flow is: reserve an owner index, get the holder's authorization, derive
//! that index's commitment, record the pending receive, show the address. All
//! of it off the UI thread — deriving reads an encrypted vault and the store
//! writes to disk, and neither belongs on the thread that paints.
//!
//! ## Why not `TokenWallet::start_receive`
//!
//! That method does reserve-derive-record in one call, which is right for the
//! CLI, where the passphrase was collected before the command ran. Here the
//! prompt has to *name the index it is authorizing*, so the index must exist
//! before the holder is asked. The same ordering guarantee is kept by hand:
//! the pending record is written before the address is ever shown, so a crash
//! between the two cannot leave a payment inbound to an index the wallet has
//! forgotten it promised. Cancelling burns an index, which costs nothing —
//! reusing one would link two payments to the same commitment.
//!
//! ## Finishing: the inbox
//!
//! An address is only half of getting paid. The payer sends a `.symtoken`, and
//! until it passes gates G1–G3 the holder is **not** paid — holding the bytes
//! is not owning the token. The window has no file dialog, so the handover is
//! a watched directory, `<wallet>/inbox/`: drop the file in and the watch
//! completes the receive against the pending record this screen created.
//!
//! A directory is not a worse answer than a file picker here, it is a better
//! one. The file usually arrives from a chat client or a download, which is to
//! say it arrives *somewhere* and then has to be found; a fixed place to put it
//! is one step, and it also lets a payment land while the holder is looking at
//! something else.
//!
//! ## The prompt crosses a thread boundary
//!
//! [`GuiPrompter`] is the shell's half of `kenter_wallet::Prompter`. It posts
//! the request to the event loop and blocks this worker until an answer comes
//! back. Blocking is correct here rather than lazy: the worker's runtime has
//! exactly one task on it, there is nothing else for it to do while a person
//! decides, and the alternative — a channel future — would add machinery to
//! wait in a fancier way.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use kenter_client::{MintClient, TxBuilder, WalletChain};
use kenter_crypto::keypair::StellarKeypair;
use kenter_vault::DerivingVault;
use kenter_vault::SoftVault;
use kenter_wallet::{
    fmt_stroops, receive_uri, AuthAction, Authorizer, ChainRead, FileStore, Gate, HeldToken, PendingReceive,
    Policy, Prompter, SessionAuthorizer, StoreCredentials, TokenWallet, WalletError, Why,
    STATIC_RECEIVE_INDEX,
};
use winit::event_loop::EventLoopProxy;
use zeroize::Zeroizing;

use crate::wallet::{default_wallet_dir, home_dir, Network};
use crate::{PromptView, ReceiveState, WalletView};

/// What a worker thread sends back to the event loop.
pub enum UiEvent {
    /// A wallet read finished.
    Wallet(WalletView),
    /// A worker needs the holder to authorize something.
    Ask(Ask),
    /// The receive flow reached a new state.
    Receive(ReceiveState),
    /// The settings page finished gathering its facts.
    Settings(crate::SettingsView),
    /// A new RPC server was checked and saved, or refused. `Ok` carries the
    /// host now in use.
    RpcSaved(Result<String, String>),
    /// The paper flow moved on.
    Paper(crate::PaperState),
    /// The camera said something. Frames come this way too, a dozen a
    /// second, so the arm handling it must stay cheap.
    Camera(crate::camera::Event),
    /// A wallet backup was written, or could not be. `Ok` carries where.
    BackupDone(Result<String, String>),
    /// A backup was merged in, or could not be. `Ok` carries what changed.
    Restored(Result<String, String>),
    /// First run put the notes back, or could not. `Ok` carries how many.
    RestoredAtSetup(Result<usize, String>),
    /// A restore's spend notes were checked against the vault.
    OwnershipChecked(Result<kenter_wallet::OwnershipReport, String>),
    /// The holder unlocked. Carries what the session needs to act without
    /// asking again: the store keys, and the credential the vault wants for
    /// signing (`Policy::Session`).
    Unlocked {
        creds: StoreCredentials,
        /// Authorises **owner-key** operations: the passphrase, or the PIN.
        credential: Zeroizing<Vec<u8>>,
        /// Opens the vault holding the **submitting account**.
        ///
        /// The same value as `credential` for a software wallet, and BIP85
        /// child 2 for a card one. Two fields because a card wallet signs
        /// owner keys on the card and fee-paying transactions from a
        /// software vault, and those want different secrets — a
        /// distinction that does not exist on the software path and is
        /// invisible until something tries to pay a fee.
        account: Zeroizing<Vec<u8>>,
        /// Seals the wallet backup, and names which wallet it is.
        ///
        /// Carried from the unlock rather than derived when a backup is
        /// wanted, because on a card wallet deriving it is a tap and a PIN -
        /// and a backup nobody can make without ceremony is a backup nobody
        /// makes. The same derivation already produced the store keys.
        backup: kenter_vault::BackupCredentials,
        /// The submitting account's address, derived from its unwrapped key
        /// with `account` ([`crate::settings::verified_address`]). The one
        /// address the screens show as the holder's own or pay out to, since
        /// the vault's plaintext key list can be edited without the
        /// passphrase. An error is kept, not swallowed: an account key that
        /// will not verify under a credential that just opened the store is
        /// a vault file that has been altered.
        address: Result<Option<String>, String>,
    },
    /// Unlocking did not happen — declined, or no seed to unlock.
    NotUnlocked(String),
    /// First run moved on.
    Setup(crate::SetupState),
    /// The card produced a phrase, or could not. Nothing is written to the
    /// card either way - `GENERATE MNEMONIC` stores nothing.
    CardPhrase(Result<Zeroizing<String>, String>),
    /// The card took the key, or refused it. **This one is not reversible.**
    CardSeeded(Result<[u8; 32], String>),
    /// A card was erased, or refused to be.
    CardErased(Result<(), String>),
    /// The account vault and the backup file are written; the wallet exists.
    CardReady(Result<crate::card_setup::CardWallet, String>),
    /// A deposit moved on.
    Deposit(crate::DepositState),
    /// A payment moved on.
    Pay(crate::PayState),
    /// A redemption moved on.
    Redeem(crate::RedeemState),
    /// The account page finished reading the ledger.
    Account(crate::AccountView),
    /// Re-run whatever screen is showing. Used where a worker has changed
    /// the ledger and the page should ask again rather than guess at what
    /// its own write did.
    Reopen,
}

/// Where a worker's state updates go.
///
/// The event loop in the real shell, a `Vec` in a test. The watch loop is the
/// part of the receive flow most worth testing — stability checks, what gets
/// moved aside, when it gives up — and none of that should need a window to
/// exercise.
pub trait Report {
    fn report(&self, state: ReceiveState);
}

impl Report for EventLoopProxy<UiEvent> {
    fn report(&self, state: ReceiveState) {
        // The loop may already have exited; nothing to do about it here.
        let _ = self.send_event(UiEvent::Receive(state));
    }
}

/// An authorization request waiting on an answer.
pub struct Ask {
    /// What to put on screen. Carries no credential — see [`PromptView`].
    pub view: PromptView,
    /// `None` means the holder declined. Dropping the sender without replying
    /// is read as "the window went away", not as consent.
    pub reply: mpsc::Sender<Option<Zeroizing<Vec<u8>>>>,
}

/// Where the GUI looks for the vault holding the HD seed.
///
/// The CLI takes `--vault <file>` on every command; a window has nowhere to put
/// that, so it resolves a default and says plainly when nothing is there.
pub fn default_vault_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KENTER_VAULT") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    home_dir().map(|h| h.join(".kenter").join("vault.json"))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The shell's half of the authorization port: show a prompt, wait for a person.
struct GuiPrompter {
    proxy: EventLoopProxy<UiEvent>,
}

impl Prompter for GuiPrompter {
    async fn prompt(
        &mut self,
        action: &AuthAction,
        why: Why,
    ) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        let (tx, rx) = mpsc::channel();
        let view = PromptView {
            title: action.summary(),
            why: match why {
                Why::Unlock => "unlock your wallet to derive the key".into(),
                Why::PerAction => "confirm this action".into(),
                Why::Retry => "try again".into(),
            },
            rows: action
                .rows()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            entered: 0,
            error: match why {
                Why::Retry => Some("that passphrase was not accepted".into()),
                _ => None,
            },
        };
        self.proxy
            .send_event(UiEvent::Ask(Ask { view, reply: tx }))
            .map_err(|_| WalletError::PromptFailed("the window is gone".into()))?;

        match rx.recv() {
            Ok(Some(credential)) => Ok(credential),
            Ok(None) => Err(WalletError::Declined),
            // The loop exited, or the prompt was dropped without an answer.
            // Silence is not consent.
            Err(_) => Err(WalletError::PromptFailed(
                "the prompt was dismissed without an answer".into(),
            )),
        }
    }
}

/// Can this machine create a pay tag at all?
///
/// Checked when the page opens, not when the button is pressed. Everything it
/// looks at is local and cheap - a vault file and a directory - and finding out
/// afterwards turns "New pay tag" into a button whose only outcome is an error,
/// which is a worse way to learn you have no seed than being told on arrival.
///
/// `Ok` carries a line for the idle hint; `Err` carries the reason and the
/// command that fixes it.
pub fn readiness() -> Result<String, String> {
    let dir = default_wallet_dir()
        .ok_or_else(|| "set KENTER_WALLET_DIR, or create ~/.kenter/wallet".to_string())?;
    let vault_path =
        default_vault_path().ok_or_else(|| "set KENTER_VAULT to your vault file".to_string())?;

    if !vault_path.exists() {
        return Err(format!(
            "no vault at {} - create one with: kenter seed generate --vault {}",
            vault_path.display(),
            vault_path.display()
        ));
    }
    let vault =
        SoftVault::open(&vault_path).map_err(|e| format!("{}: {e}", vault_path.display()))?;
    // A card wallet's vault holds no seed - the card does - so asking about
    // the seed refused the very wallets this client now supports.
    if vault.custody().is_none() && !vault.has_seed() {
        return Err(format!(
            "no wallet at {} - set one up first",
            vault_path.display()
        ));
    }
    // Opening the store creates its directories, so this both checks the path
    // is usable and makes sure the first thing to touch it is not a receive
    // that has already shown someone an address.
    // Only that the directory is usable; opening the sealed store needs the
    // seed, which needs a prompt, and readiness must not prompt.
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(format!("ready - vault {}", vault_path.display()))
}

/// Answers from the session if it is unlocked, and asks if it is not.
///
/// A thin `Prompter` rather than a branch at each call site: the flows should
/// not have to know whether a prompt will appear.
struct SessionPrompter {
    session: Option<Zeroizing<Vec<u8>>>,
    fallback: GuiPrompter,
}

impl Prompter for SessionPrompter {
    async fn prompt(
        &mut self,
        action: &AuthAction,
        why: Why,
    ) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        // A retry means the session credential was rejected, so it is wrong
        // and asking is the only way forward.
        if why != Why::Retry {
            if let Some(c) = &self.session {
                return Ok(c.clone());
            }
        }
        self.session = None;
        self.fallback.prompt(action, why).await
    }
}

/// Ask for the passphrase and hand the session its keys.
///
/// The one place a prompt happens for its own sake rather than on the way to
/// something else. Everything that touches the store needs it, so paying it
/// once up front beats each flow discovering it separately.
/// Open a card wallet: PIN to the card, BIP85 to the store key.
///
/// The card path's `spawn_unlock_with`. Off the event loop for the same
/// reason — a secure-channel open plus two BIP85 derivations over NFC is
/// seconds, not milliseconds.
///
/// `expected` is the wallet's seed fingerprint from the vault. A card that
/// derives a different one is a card for **another wallet**, which the
/// identity-key check at the gate cannot tell from a replacement — only
/// this can, and only after the PIN.
pub fn spawn_card_unlock(proxy: EventLoopProxy<UiEvent>, pin: Zeroizing<String>, expected: String) {
    std::thread::spawn(move || {
        let event = match crate::card_setup::unlock(pin.as_bytes()) {
            Err(e) => UiEvent::NotUnlocked(e.to_string()),
            Ok((_, backup)) if backup.fingerprint != expected => UiEvent::NotUnlocked(format!(
                "this card holds a different wallet ({}), not this one ({expected}).                  Nothing was changed.",
                backup.fingerprint
            )),
            Ok((creds, backup)) => match crate::card_setup::account_credential(pin.as_bytes()) {
                Err(e) => UiEvent::NotUnlocked(e),
                Ok(account) => UiEvent::Unlocked {
                    address: crate::settings::verified_address(&account),
                    creds,
                    // The PIN is this wallet's owner-key credential, the way
                    // a passphrase is a software wallet's.
                    credential: Zeroizing::new(pin.as_bytes().to_vec()),
                    account,
                    backup,
                },
            },
        };
        let _ = proxy.send_event(event);
    });
}

/// Open the store with a credential already in hand, with no prompt.
///
/// First run has just had the passphrase typed twice and confirmed against
/// the vault it created. Asking for it a third time to establish a session
/// proves nothing that the previous two did not, and the cost of not doing
/// this was a billfold that appeared locked the moment someone finished
/// setting it up.
///
/// Still off the event loop, because deriving store credentials runs
/// Argon2id and that is deliberately slow.
pub fn spawn_unlock_with(proxy: EventLoopProxy<UiEvent>, credential: Zeroizing<Vec<u8>>) {
    std::thread::spawn(move || {
        let event = match default_vault_path() {
            None => UiEvent::NotUnlocked("set KENTER_VAULT".into()),
            Some(path) => match SoftVault::open(&path) {
                Err(e) => UiEvent::NotUnlocked(e.to_string()),
                Ok(mut vault) => {
                    // Which derivation, from the vault's own record. A
                    // wallet recovered from a lost card keeps deriving the
                    // card's way, because that is what its notes and its
                    // backup are sealed under.
                    let custody = vault.custody().cloned();
                    match crate::vault::session_credentials(
                        &mut vault,
                        custody.as_ref(),
                        &credential,
                    ) {
                        // One secret, used for both: a software wallet's
                        // passphrase opens the store and the account vault
                        // alike.
                        Ok((creds, backup)) => UiEvent::Unlocked {
                            address: crate::settings::verified_address(&credential),
                            creds,
                            account: credential.clone(),
                            credential,
                            backup,
                        },
                        Err(e) => UiEvent::NotUnlocked(e.to_string()),
                    }
                }
            },
        };
        let _ = proxy.send_event(event);
    });
}

/// Is there a vault with a seed to unlock at all?
///
/// Lets the shell tell "locked" from "nothing set up yet", which want
/// different words and different next steps.
pub fn can_unlock() -> bool {
    default_vault_path()
        .and_then(|p| SoftVault::open(p).ok())
        .is_some_and(|v| v.has_seed())
}

/// Run a receive on a worker thread; states arrive as [`UiEvent::Receive`].
///
/// The thread outlives the tag: after showing one it watches the inbox until
/// a token completes the receive or `cancel` is set. The caller sets `cancel`
/// when the holder leaves the page — otherwise a thread goes on reading the
/// wallet behind a screen nobody is looking at.
///
/// `fresh` is the **Different tag** button. Left false, the page shows the
/// pay tag that is already outstanding; a tag is reserved only when there is
/// none, because the tag rotates when a note binds to it and at no other time
/// (two payers on one tag land on one commitment the ledger links).
/// Reserving one on every arrival at the page would leave orphaned codes
/// behind.
pub fn spawn(
    proxy: EventLoopProxy<UiEvent>,
    net: Network,
    cancel: Arc<AtomicBool>,
    session: Option<Zeroizing<Vec<u8>>>,
    fresh: bool,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = proxy.send_event(UiEvent::Receive(ReceiveState::Failed {
                    message: format!("runtime: {e}"),
                }));
                return;
            }
        };
        rt.block_on(run(&proxy, net, cancel, session, fresh));
    });
}

async fn run(
    proxy: &EventLoopProxy<UiEvent>,
    net: Network,
    cancel: Arc<AtomicBool>,
    session: Option<Zeroizing<Vec<u8>>>,
    fresh: bool,
) {
    let dir = match default_wallet_dir() {
        Some(d) => d,
        None => {
            let _ = proxy.send_event(UiEvent::Receive(ReceiveState::Failed {
                message: "set KENTER_WALLET_DIR, or create ~/.kenter/wallet".into(),
            }));
            return;
        }
    };
    // One unlock covers the session, so a flow that starts
    // after the holder has already unlocked must not ask again — that is what
    // "session" means, and a client that re-prompts anyway has the setting in
    // name only. PerAction is the maximum-security tier and waits on card
    // custody, where the proof is a tap.
    let mut authz = SessionAuthorizer::new(
        SessionPrompter {
            session,
            fallback: GuiPrompter {
                proxy: proxy.clone(),
            },
        },
        Policy::Session,
    );

    // Unlock before opening anything. The store is sealed under a seed-derived
    // key, so the passphrase is needed to read a record, not only to sign -
    // the prompt cannot wait for the first signature.
    let creds = match unlock(&mut authz).await {
        Ok(c) => c,
        Err(WalletError::Declined) => {
            proxy.report(ReceiveState::Idle {
                hint: "cancelled - the wallet stayed locked".into(),
            });
            return;
        }
        Err(e) => {
            proxy.report(ReceiveState::Failed {
                message: e.to_string(),
            });
            return;
        }
    };
    let mut wallet = match open_wallet(net, creds) {
        Ok(w) => w,
        Err(e) => {
            proxy.report(ReceiveState::Failed {
                message: e.to_string(),
            });
            return;
        }
    };

    // The outstanding tag, if there is one. A pay tag is good for one
    // payment and is consumed when a note binds to it, so the newest
    // unconsumed record *is* the live tag; older ones are abandoned by the
    // Different tag button and stay watched through the known-owner rule
    // rather than through this screen.
    let live = match wallet.pending().await {
        Ok(p) => p.into_iter().max_by_key(|p| p.index),
        Err(e) => {
            proxy.report(ReceiveState::Failed {
                message: e.to_string(),
            });
            return;
        }
    };
    let state = match live {
        Some(p) if !fresh => ready_for(&p, &dir, wallet.chain().ledger_source()),
        _ => reserve_and_derive(&mut wallet, &mut authz, &dir).await,
    };
    proxy.report(state.clone());

    // A tag on its own is half of getting paid. Keep going.
    if let ReceiveState::Ready { .. } = &state {
        watch(proxy, &mut wallet, &dir, state, cancel, POLL).await;
    }
}

/// What a press on the standing-tag screen is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Read whether it is published, and show it if so.
    Show,
    /// Derive index 0's commitment and start watching it.
    Publish,
    /// Stop watching it. Nothing on the ledger changes, and notes already
    /// paid to it stay recognisable through the commitments on them.
    Retire,
}

/// Run one standing-tag operation off the event loop.
///
/// Publishing derives index 0, which needs the seed, so it runs where every
/// other derivation does. Showing and retiring only touch the sealed store,
/// but they go the same way rather than being special cases on the UI thread.
pub fn spawn_standing(
    proxy: EventLoopProxy<UiEvent>,
    net: Network,
    session: Option<Zeroizing<Vec<u8>>>,
    op: Standing,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = proxy.send_event(UiEvent::Receive(ReceiveState::Failed {
                    message: format!("runtime: {e}"),
                }));
                return;
            }
        };
        rt.block_on(async {
            match standing(&proxy, net, session, op).await {
                Ok(state) => proxy.report(state),
                // Not Standing { hex: None }: that reads as "off", and
                // declining says nothing about whether it is on. The screen
                // that cannot be read is better than a screen that guesses.
                Err(WalletError::Declined) => proxy.report(ReceiveState::Failed {
                    message: "cancelled - the standing tag was not changed".into(),
                }),
                Err(e) => proxy.report(ReceiveState::Failed {
                    message: e.to_string(),
                }),
            }
        });
    });
}

async fn standing(
    proxy: &EventLoopProxy<UiEvent>,
    net: Network,
    session: Option<Zeroizing<Vec<u8>>>,
    op: Standing,
) -> Result<ReceiveState, WalletError> {
    let mut authz = SessionAuthorizer::new(
        SessionPrompter {
            session,
            fallback: GuiPrompter {
                proxy: proxy.clone(),
            },
        },
        Policy::Session,
    );
    let creds = unlock(&mut authz).await?;
    let mut wallet = open_wallet(net, creds)?;

    match op {
        Standing::Retire => {
            // Only the watching stops. The contract will still accept a
            // payment to this commitment, and one that arrives is still
            // recognised by the commitment stored on a note already bound —
            // so this is reversible, and publishing again derives the same
            // code.
            wallet.forget_pending(STATIC_RECEIVE_INDEX).await?;
        }
        Standing::Publish => {
            let action = AuthAction::Receive {
                index: STATIC_RECEIVE_INDEX,
            };
            let commitment = loop {
                let auth = authz.authorize(&action).await?;
                match wallet.owner_commitment_for(STATIC_RECEIVE_INDEX, auth.credential()) {
                    Ok(c) => break c,
                    Err(WalletError::BadCredential) => authz.rejected(),
                    Err(e) => return Err(e),
                }
            };
            wallet
                .record_pending(PendingReceive {
                    index: STATIC_RECEIVE_INDEX,
                    commitment,
                    created_at: unix_now(),
                })
                .await?;
        }
        Standing::Show => {}
    }

    // Read back rather than report what was just written: the record is the
    // only thing that says whether the tag is live, so the screen should
    // show what the store says and not what the worker intended.
    let hex = wallet
        .pending()
        .await?
        .into_iter()
        .find(|p| p.index == STATIC_RECEIVE_INDEX)
        .map(|p| hex::encode(p.commitment));
    Ok(ReceiveState::Standing { hex, busy: None })
}

/// Obtain the store keys, prompting if the session is not unlocked.
/// Obtain the store keys, prompting if the session is not unlocked.
///
/// Retries on a wrong passphrase rather than failing, the same loop the owner
/// key derivation uses: `BadCredential` is the one vault error where asking
/// again is the right answer.
pub async fn unlock<P: Prompter>(
    authz: &mut SessionAuthorizer<P>,
) -> Result<StoreCredentials, WalletError> {
    let vault_path = default_vault_path()
        .ok_or_else(|| WalletError::Vault("set KENTER_VAULT to your vault file".into()))?;
    let vault = SoftVault::open(&vault_path).map_err(|e| WalletError::Vault(e.to_string()))?;
    if vault.custody().is_none() && !vault.has_seed() {
        return Err(WalletError::Vault(format!(
            "no wallet at {} - set one up first",
            vault_path.display()
        )));
    }
    // Unlocking is not itself a value-moving act, so it reads as a plain
    // unlock under either policy.
    let action = AuthAction::Receive { index: 0 };
    // Where the store key comes from depends on custody. A software
    // wallet's is hashed from the seed in this file; a card wallet's is
    // BIP85 on the card, and this vault has no seed to hash - which is
    // exactly the "vault holds no HD seed" the Accept screen reported.
    let on_card = matches!(vault.custody(), Some(kenter_vault::Custody::Card { .. }));
    loop {
        let auth = authz.authorize(&action).await?;
        let got = if on_card {
            crate::card_setup::unlock(auth.credential()).map(|(c, _)| c)
        } else {
            vault.store_credentials(auth.credential())
        };
        match got {
            Ok(c) => return Ok(c),
            // Still the one error worth asking again about, on either path.
            Err(kenter_vault::VaultError::BadCredential) => authz.rejected(),
            Err(e) => return Err(WalletError::Vault(e.to_string())),
        }
    }
}

/// How often the inbox is read. Slow enough to be free, fast enough that
/// dropping a file in feels like it did something.
const POLL: Duration = Duration::from_millis(1500);

/// Watch the inbox until a token completes the receive, or the holder leaves.
///
/// Cancellation is checked between every step rather than only between polls,
/// so leaving the page does not leave a thread reading someone's wallet for
/// another second and a half.
pub async fn watch<C, R, V: DerivingVault>(
    report: &R,
    wallet: &mut TokenWallet<C, FileStore, V>,
    wallet_dir: &Path,
    ready: ReceiveState,
    cancel: Arc<AtomicBool>,
    poll: Duration,
) where
    C: kenter_wallet::ChainRead,
    R: Report,
{
    let inbox = inbox_dir(wallet_dir);
    let mut stable: HashMap<PathBuf, (u64, Option<SystemTime>)> = HashMap::new();
    let mut note: Option<String> = None;
    let mut polls: u32 = 0;
    let started = std::time::Instant::now();

    while !cancel.load(Ordering::Relaxed) {
        polls += 1;
        let mut waiting = 0usize;
        // Why the last retryable failure was retryable. Reset each pass so
        // a reason that has stopped applying stops being shown.
        let mut why: Option<String> = None;

        for path in candidates(&inbox) {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            // Only touch a file that looked the same last time round. A file
            // still being copied in parses as malformed, and malformed is a
            // permanent rejection — so without this, a slow copy gets the
            // payer's token thrown into `rejected/` for no reason.
            let Some(stamp) = stamp(&path) else { continue };
            if stable.insert(path.clone(), stamp) != Some(stamp) {
                waiting += 1;
                continue;
            }

            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };

            // One call, one answer. Which of this wallet's tags was paid is
            // the ledger's business, not this loop's: the core matches the
            // live owner commitment against every index it can open
            // including tags a previous note already
            // consumed.
            match wallet.complete_receive(bytes.clone(), unix_now()).await {
                Ok(held) => {
                    file_away(&inbox, &path, "accepted");
                    report.report(received(&held));
                    return;
                }
                // A bearer note is not a refusal. It has no owner pointer and
                // never will (see `docs/architecture/spend-mode.md`), so it
                // fails G3 for good — but G1 and G2 just passed, which is
                // every gate a bearer note can pass. Filing it under
                // `rejected/` would tell the holder their money bounced when
                // a payment had in fact arrived.
                Err(WalletError::ReceiveGate {
                    retryable: false,
                    gate,
                    detail,
                }) if detail.contains("not in spend mode") => {
                    match wallet.import(bytes, unix_now()).await {
                        Ok(held) => {
                            file_away(&inbox, &path, "accepted");
                            report.report(ReceiveState::Held {
                                id: crate::wallet::short(&held.id),
                                amount: fmt_stroops(held.amount),
                            });
                            return;
                        }
                        // Already in the billfold: still not a refusal, and
                        // leaving it in the inbox would re-judge it forever.
                        Err(WalletError::Duplicate(_)) => {
                            file_away(&inbox, &path, "accepted");
                            note = Some(format!(
                                "{} is a bearer note already in your billfold",
                                name_of(&path)
                            ));
                        }
                        Err(e) => {
                            file_away(&inbox, &path, "rejected");
                            note = Some(rejection(&path, gate, &format!("{detail}: {e}")));
                        }
                    }
                }
                // Permanent. Move it aside with the reason, so the same file
                // is not re-judged every poll and the holder can see what was
                // wrong with it.
                Err(WalletError::ReceiveGate {
                    retryable: false,
                    gate,
                    detail,
                }) => {
                    file_away(&inbox, &path, "rejected");
                    note = Some(rejection(&path, gate, &detail));
                }
                // The payer's spend may simply not have landed, or the
                // ledger is unreachable. Leave the file where it is and look
                // again — but keep the reason, because "waiting" with no
                // object is indistinguishable from stuck.
                Err(e) => {
                    waiting += 1;
                    why = Some(e.to_string());
                }
            }
        }

        // Elapsed, not just a spinner word. A receive waits on the
        // *payer* finishing, which may never happen — their payment can
        // fail after writing the file — and a line that never changes
        // cannot tell that apart from a hung client.
        let secs = started.elapsed().as_secs();
        let status = match waiting {
            0 => format!("watching for a token file ({polls})"),
            1 => format!("a file is waiting on the ledger - {secs}s"),
            n => format!("{n} files waiting on the ledger - {secs}s"),
        };
        // Said once it has gone on long enough to be worth doubting.
        let stalling = (waiting > 0 && secs >= 45).then(|| {
            let detail = why.clone().unwrap_or_else(|| "no reason given".into());
            format!(
                "still waiting after {secs}s. The ledger has to show the payer moved \
                 ownership to you; until they finish, this cannot complete. Last \
                 check said: {detail}"
            )
        });
        let note = note.clone().or(stalling);
        report.report(with_status(&ready, status, note));

        // Sleep in slices so Back is not followed by a pause.
        for _ in 0..6 {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(poll / 6).await;
        }
    }
}

fn received(held: &HeldToken) -> ReceiveState {
    ReceiveState::Received {
        id: crate::wallet::short(&held.id),
        amount: fmt_stroops(held.amount),
        // Bound by the core to whichever index the ledger said owns it, so
        // this is read off the token rather than assumed by the caller.
        index: held.owner_index.unwrap_or_default(),
    }
}

/// The same Ready screen with a fresh status line.
fn with_status(ready: &ReceiveState, status: String, note: Option<String>) -> ReceiveState {
    match ready {
        ReceiveState::Ready {
            uri,
            hex,
            index,
            inbox,
            ledger,
            ..
        } => ReceiveState::Ready {
            uri: uri.clone(),
            hex: hex.clone(),
            index: *index,
            status,
            inbox: inbox.clone(),
            ledger: ledger.clone(),
            note,
        },
        other => other.clone(),
    }
}

fn rejection(path: &Path, gate: Gate, detail: &str) -> String {
    format!("refused {} - {gate}: {detail}", name_of(path))
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Token files in the inbox, oldest first, ignoring the subdirectories we
/// move things into.
fn candidates(inbox: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(inbox) else {
        return Vec::new();
    };
    let mut out: Vec<(Option<SystemTime>, PathBuf)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "symtoken"))
        .map(|p| (p.metadata().ok().and_then(|m| m.modified().ok()), p))
        .collect();
    out.sort();
    out.into_iter().map(|(_, p)| p).collect()
}

/// Size and mtime — enough to tell "finished copying" from "still copying".
fn stamp(path: &Path) -> Option<(u64, Option<SystemTime>)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.len(), m.modified().ok()))
}

/// Move a handled file into `inbox/<bucket>/`, out of the way of the next poll.
///
/// Moved rather than deleted. An accepted token's bytes are already stored in
/// the wallet verbatim, so deleting would be safe — but these are files
/// somebody else put there, and a wallet that silently removes them is a
/// wallet nobody trusts with the one that mattered.
fn file_away(inbox: &Path, path: &Path, bucket: &str) {
    let dir = inbox.join(bucket);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let Some(name) = path.file_name() else { return };
    let mut target = dir.join(name);
    // Never overwrite: two tokens can arrive under one name.
    let mut n = 1;
    while target.exists() {
        target = dir.join(format!("{}.{n}", name.to_string_lossy()));
        n += 1;
    }
    let _ = std::fs::rename(path, target);
}

/// Copy a token file into the inbox, where the watch will find it.
///
/// A copy rather than a move: the file belongs to whoever handed it over,
/// and for a bearer note it may be their only copy until they decide
/// otherwise. Silently relocating somebody else's money off their desktop
/// is not a thing a wallet should do.
///
/// Never overwrites, for the reason `file_away` does not — two notes can
/// arrive under one name, and the second must not erase the first.
pub fn copy_into_inbox(inbox: &Path, src: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(inbox).map_err(|e| format!("creating {}: {e}", inbox.display()))?;
    let name = src
        .file_name()
        .ok_or_else(|| format!("{} has no file name", src.display()))?;
    let mut target = inbox.join(name);
    let mut n = 1;
    while target.exists() {
        target = inbox.join(format!("{}.{n}", name.to_string_lossy()));
        n += 1;
    }
    std::fs::copy(src, &target).map_err(|e| format!("copying to {}: {e}", target.display()))?;
    Ok(target)
}

/// Open the same wallet, store and vault the CLI uses.
///
/// Takes the store credentials because the store is sealed (Q8) and they can
/// only come from an unlocked vault — which means a prompt, which means this
/// cannot derive them itself without prompting from inside a constructor.
fn open_wallet(net: Network, creds: StoreCredentials) -> Result<GuiWallet, WalletError> {
    let dir = default_wallet_dir().ok_or_else(|| {
        WalletError::Store("set KENTER_WALLET_DIR, or create ~/.kenter/wallet".into())
    })?;
    let vault_path = default_vault_path()
        .ok_or_else(|| WalletError::Vault("set KENTER_VAULT to your vault file".into()))?;

    let soft = SoftVault::open(&vault_path).map_err(|e| WalletError::Vault(e.to_string()))?;
    let custody = soft.custody().cloned();

    // Not gated on `has_seed()` alone, which would refuse a card wallet: its
    // seed is on the card and its vault holds only the fee-paying account
    // key. The question is what opens this wallet, not where the seed sits.
    if custody.is_none() && !soft.has_seed() {
        return Err(WalletError::Vault(format!(
            "no wallet at {} - set one up first",
            vault_path.display()
        )));
    }
    let vault = crate::vault::GuiVault::open(custody.as_ref(), soft)
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    let store = FileStore::open(&dir, creds).map_err(|e| WalletError::Store(e.to_string()))?;

    let rpc = net.rpc_client();
    let mint = MintClient::new(TxBuilder::new(rpc, StellarKeypair::random()), net.contract);
    Ok(TokenWallet::with_vault(
        WalletChain::new(mint),
        store,
        vault,
    ))
}

pub use crate::GuiWallet;

/// The flow itself: reserve, authorize, derive, record, show.
///
/// Generic over the chain and the prompter so it can be exercised without a
/// window or a ledger — the part worth testing is the ordering and the retry,
/// and neither involves either.
pub async fn reserve_and_derive<C, P, V: DerivingVault>(
    wallet: &mut TokenWallet<C, FileStore, V>,
    authz: &mut SessionAuthorizer<P>,
    wallet_dir: &Path,
) -> ReceiveState
where
    C: kenter_wallet::ChainRead,
    P: Prompter,
{
    match try_reserve_and_derive(wallet, authz, wallet_dir).await {
        Ok(state) => state,
        // Declining is a decision, not a failure: back to where we started,
        // with no error dialog and nothing promised to anybody.
        Err(WalletError::Declined) => ReceiveState::Idle {
            hint: "cancelled - no address was created".into(),
        },
        Err(e) => ReceiveState::Failed {
            message: e.to_string(),
        },
    }
}

async fn try_reserve_and_derive<C, P, V: DerivingVault>(
    wallet: &mut TokenWallet<C, FileStore, V>,
    authz: &mut SessionAuthorizer<P>,
    wallet_dir: &Path,
) -> Result<ReceiveState, WalletError>
where
    C: kenter_wallet::ChainRead,
    P: Prompter,
{
    // The index must exist before the holder is asked, because the prompt names
    // it. Reserving persists the counter advance first, so a crash can only
    // burn an index, never hand the same one out twice.
    let index = wallet.reserve_owner_index().await?;
    let action = AuthAction::Receive { index };

    let commitment = loop {
        let auth = authz.authorize(&action).await?;
        match wallet.owner_commitment_for(index, auth.credential()) {
            Ok(c) => break c,
            // The only vault failure worth asking again about.
            Err(WalletError::BadCredential) => authz.rejected(),
            Err(e) => return Err(e),
        }
    };

    // Recorded before the address can be shown. The reverse order would let a
    // crash leave a payment inbound to an index the wallet no longer knows it
    // promised.
    let pending = PendingReceive {
        index,
        commitment,
        created_at: unix_now(),
    };
    wallet.record_pending(pending.clone()).await?;
    // The payer needs somewhere to put the file, and an inbox that only
    // appears once someone has already been handed an address is a directory
    // nobody can be told about in advance.
    let _ = std::fs::create_dir_all(inbox_dir(wallet_dir));

    let ledger = wallet.chain().ledger_source();
    Ok(ready_for(&pending, wallet_dir, ledger))
}

/// The pay tag screen for one pending receive.
///
/// Built from the stored record, not re-derived: the record carries the
/// commitment, which is the whole of what the payer needs. Showing a tag
/// again therefore costs a store read and no vault work — no passphrase for
/// the key, no prompt naming an index the holder never asked to reserve. A
/// tag the holder has seen before and one just reserved are the same screen,
/// because they are the same object.
fn ready_for(pending: &PendingReceive, wallet_dir: &Path, ledger: String) -> ReceiveState {
    ReceiveState::Ready {
        uri: receive_uri(&pending.commitment),
        hex: hex::encode(pending.commitment),
        index: pending.index,
        status: "waiting for the payer - you are not paid until their token verifies".into(),
        inbox: inbox_dir(wallet_dir).display().to_string(),
        ledger,
        note: None,
    }
}

/// Where the payer's token file goes.
pub fn inbox_dir(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join("inbox")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed store keys. The fixture vault has a seed, but deriving from it
    /// would mean unwrapping it on every open for no gain in what is tested.
    fn test_creds() -> StoreCredentials {
        StoreCredentials {
            aead: Zeroizing::new([11u8; 32]),
            name: Zeroizing::new([13u8; 32]),
        }
    }
    use kenter_wallet::{OnChainToken, Store, TokenStatus};
    use zeroize::Zeroizing;

    /// The flow never reads the chain, so this exists only to satisfy the type.
    struct NoChain;
    impl kenter_wallet::ChainRead for NoChain {
        // A test double answers for one notional deployment; the
        // gates only need slot answers to be attributable to it.
        fn mint_id(&self) -> String {
            "CTESTMINT".into()
        }

        async fn token_status(&self, _slot: u32) -> Result<OnChainToken, WalletError> {
            Ok(OnChainToken {
                status: TokenStatus::Unknown,
                amount: None,
                chain_hash: None,
                // G2 reads these to refuse a note whose chain the
                // contract would never accept.
                event_id: None,
                participants_len: None,
                owner_commitment: None,
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: None,
            })
        }
    

        fn mint_contract_xdr(&self) -> Vec<u8> {
            b"test-mint".to_vec()
        }

        fn ledger_source(&self) -> String {
            "a test ledger".into()
        }
    }

    /// Hands back scripted answers and records what it was asked.
    struct Script {
        answers: Vec<Option<&'static str>>,
        seen: Vec<(String, Why)>,
    }
    impl Prompter for Script {
        async fn prompt(
            &mut self,
            action: &AuthAction,
            why: Why,
        ) -> Result<Zeroizing<Vec<u8>>, WalletError> {
            self.seen.push((action.summary(), why));
            match self.answers.remove(0) {
                Some(p) => Ok(Zeroizing::new(p.as_bytes().to_vec())),
                None => Err(WalletError::Declined),
            }
        }
    }

    const PASS: &str = "correct horse battery staple";

    /// `FileStore` reads through `tokio::fs`, which needs a reactor — a bare
    /// `block_on` panics inside it. Each test gets its own current-thread
    /// runtime, which is also what the worker thread does in the app.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn fixture(dir: &std::path::Path) -> (FileStore, SoftVault) {
        let mut vault = SoftVault::open(dir.join("vault.json")).unwrap();
        let phrase = kenter_vault::mnemonic::generate().unwrap();
        vault
            .set_seed_from_mnemonic(&phrase, "", PASS.as_bytes())
            .unwrap();
        (FileStore::open(dir, test_creds()).unwrap(), vault)
    }

    fn run_with(answers: Vec<Option<&'static str>>) -> (ReceiveState, Script, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (store, vault) = fixture(dir.path());
        let mut wallet = TokenWallet::with_vault(NoChain, store, vault);
        let mut authz = SessionAuthorizer::new(
            Script {
                answers,
                seen: Vec::new(),
            },
            Policy::Session,
        );
        let state = block_on(reserve_and_derive(&mut wallet, &mut authz, dir.path()));
        let script = authz.into_prompter();
        (state, script, dir)
    }

    #[test]
    fn an_authorized_receive_yields_an_address_and_records_it() {
        let (state, script, dir) = run_with(vec![Some(PASS)]);
        let ReceiveState::Ready {
            uri,
            hex: hexed,
            index,
            ..
        } = state
        else {
            panic!("expected Ready, got {state:?}");
        };
        assert_eq!(script.seen.len(), 1);
        assert_eq!(script.seen[0].1, Why::Unlock);

        // The address shown is the commitment that was recorded. If these ever
        // diverge the payer pays into a key the wallet cannot re-derive.
        let shown = kenter_wallet::parse_receive_uri(&uri).unwrap();
        assert_eq!(hex::encode(shown), hexed);
        let store = FileStore::open(dir.path(), test_creds()).unwrap();
        let pending = block_on(store.pending()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].index, index);
        assert_eq!(pending[0].commitment, shown);
    }

    #[test]
    fn a_wrong_passphrase_asks_again_instead_of_failing() {
        let (state, script, _dir) = run_with(vec![Some("not it"), Some(PASS)]);
        assert!(matches!(state, ReceiveState::Ready { .. }), "{state:?}");
        let whys: Vec<Why> = script.seen.iter().map(|(_, w)| *w).collect();
        assert_eq!(whys, vec![Why::Unlock, Why::Retry]);
    }

    /// Declining must leave nothing behind. The index is burned, which is the
    /// cheap half of the trade; a pending record would be the expensive half —
    /// the wallet would be waiting on a payment nobody was ever asked to make.
    #[test]
    fn declining_records_nothing() {
        let (state, _script, dir) = run_with(vec![None]);
        assert!(matches!(state, ReceiveState::Idle { .. }), "{state:?}");
        let store = FileStore::open(dir.path(), test_creds()).unwrap();
        assert!(block_on(store.pending()).unwrap().is_empty());
    }

    /// The prompt has to name what it is authorizing, or it is a password box.
    #[test]
    fn the_prompt_is_told_which_index_it_authorizes() {
        let (_state, script, _dir) = run_with(vec![Some(PASS)]);
        assert_eq!(script.seen[0].0, "Create a pay tag");
    }

    /// Two receives in a row must not reuse an index — that would point two
    /// payers at one commitment and link the payments to each other.
    #[test]
    fn consecutive_receives_get_distinct_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, vault) = fixture(dir.path());
        let mut wallet = TokenWallet::with_vault(NoChain, store, vault);
        let mut authz = SessionAuthorizer::new(
            Script {
                answers: vec![Some(PASS)],
                seen: Vec::new(),
            },
            Policy::Session,
        );
        let a = block_on(reserve_and_derive(&mut wallet, &mut authz, dir.path()));
        // Session policy: the second one must not need a second answer.
        let b = block_on(reserve_and_derive(&mut wallet, &mut authz, dir.path()));
        let (
            ReceiveState::Ready {
                index: i, hex: ha, ..
            },
            ReceiveState::Ready {
                index: j, hex: hb, ..
            },
        ) = (a, b)
        else {
            panic!("expected two addresses");
        };
        assert_ne!(i, j);
        assert_ne!(ha, hb);
    }

    // ── the inbox watch ──

    use kenter_crypto::container::serialize_bearer_token;
    use kenter_crypto::token::{assemble_bearer_token, PartialToken};
    use std::cell::RefCell;

    /// Collects what the flow would have put on screen, and stops the watch
    /// once it has seen enough.
    ///
    /// Counting reports rather than waiting a wall-clock budget is what makes
    /// these tests deterministic. The watch sleeps between passes, so a
    /// budget of `poll × n` only holds while the machine is idle: under a
    /// loaded `cargo test --workspace` the scheduler stretches those sleeps,
    /// fewer passes fit, and a file never gets judged. Such a test fails
    /// under load and passes in isolation, which is the worst shape a test
    /// can have. The watch reports exactly once per pass, so the count *is*
    /// the thing a time budget would only approximate.
    #[derive(Default)]
    struct Screenplay {
        states: RefCell<Vec<ReceiveState>>,
        /// Flip this once `stop_after` reports have arrived.
        stop: RefCell<Option<(usize, Arc<AtomicBool>)>>,
    }
    impl Report for Screenplay {
        fn report(&self, state: ReceiveState) {
            self.states.borrow_mut().push(state);
            if let Some((n, cancel)) = self.stop.borrow().as_ref() {
                if self.states.borrow().len() >= *n {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    impl Screenplay {
        /// Stop the watch after `n` reported states.
        fn stopping_after(n: usize, cancel: Arc<AtomicBool>) -> Self {
            Screenplay {
                states: RefCell::new(Vec::new()),
                stop: RefCell::new(Some((n, cancel))),
            }
        }
        fn last(&self) -> ReceiveState {
            self.states
                .borrow()
                .last()
                .cloned()
                .expect("nothing was reported")
        }
        fn paid(&self) -> Option<(String, String)> {
            self.states.borrow().iter().find_map(|s| match s {
                ReceiveState::Received { id, amount, .. } => Some((id.clone(), amount.clone())),
                _ => None,
            })
        }
    }

    /// A ledger that says the token is Active and has no owner at all —
    /// which is what a pure-bearer note looks like, in either mode.
    #[derive(Clone, Copy)]
    struct Bearer {
        amount: i128,
        event_id: [u8; 32],
        participants_len: u32,
        /// What the mint recorded for this note. G2 compares it against
        /// the chain in the container, so a fixture that wants a receive
        /// to succeed has to agree with itself.
        chain_hash: [u8; 32],
        ephemeral_key: [u8; 32],
        claim_pubkey: [u8; 32],
    }
    impl kenter_wallet::ChainRead for Bearer {
        // A test double answers for one notional deployment; the
        // gates only need slot answers to be attributable to it.
        fn mint_id(&self) -> String {
            "CTESTMINT".into()
        }

        async fn token_status(&self, _slot: u32) -> Result<OnChainToken, WalletError> {
            Ok(OnChainToken {
                status: TokenStatus::Active,
                amount: Some(self.amount),
                chain_hash: Some(self.chain_hash),
                // G2 reads these to refuse a note whose chain the
                // contract would never accept.
                event_id: Some(self.event_id),
                participants_len: Some(self.participants_len),
                owner_commitment: None,
                spend_nonce: Some(0),
                // What `register_token` records for a pure-bearer note,
                // and what G2 compares.
                claim_pubkey: Some(self.claim_pubkey),
                ephemeral_key: Some(self.ephemeral_key),
            })
        }
    

        fn mint_contract_xdr(&self) -> Vec<u8> {
            b"test-mint".to_vec()
        }

        fn ledger_source(&self) -> String {
            "a test ledger".into()
        }
    }

    /// A ledger that says one token is Active and owned by `commitment`.
    #[derive(Clone, Copy)]
    struct Paid {
        commitment: [u8; 32],
        amount: i128,
        event_id: [u8; 32],
        participants_len: u32,
        chain_hash: [u8; 32],
        ephemeral_key: [u8; 32],
    }
    impl kenter_wallet::ChainRead for Paid {
        // A test double answers for one notional deployment; the
        // gates only need slot answers to be attributable to it.
        fn mint_id(&self) -> String {
            "CTESTMINT".into()
        }

        async fn token_status(&self, _slot: u32) -> Result<OnChainToken, WalletError> {
            Ok(OnChainToken {
                status: TokenStatus::Active,
                amount: Some(self.amount),
                chain_hash: Some(self.chain_hash),
                // G2 reads these to refuse a note whose chain the
                // contract would never accept.
                event_id: Some(self.event_id),
                participants_len: Some(self.participants_len),
                owner_commitment: Some(self.commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(self.ephemeral_key),
            })
        }
    

        fn mint_contract_xdr(&self) -> Vec<u8> {
            b"test-mint".to_vec()
        }

        fn ledger_source(&self) -> String {
            "a test ledger".into()
        }
    }

    /// The commitment the mint would hold for this container.
    /// The ephemeral key a container carries, which a record claiming
    /// to be its record has to name.
    fn claim_of(bytes: &[u8]) -> [u8; 32] {
        kenter_crypto::container::deserialize_bearer_token(bytes)
            .unwrap()
            .claim_public_key()
    }

    fn key_of(bytes: &[u8]) -> [u8; 32] {
        kenter_crypto::container::deserialize_bearer_token(bytes)
            .unwrap()
            .ephemeral_public_key
    }

    /// What the mint would have recorded at `register_token`.
    ///
    /// G2 refuses a note whose ledger record names a different event or
    /// a different number of participants, because the contract would
    /// refuse that chain at redemption. A fixture that
    /// wants a receive to succeed has to agree with the note it built,
    /// so these are derived from the container rather than invented.
    fn event_id_of(bytes: &[u8]) -> [u8; 32] {
        kenter_crypto::container::deserialize_bearer_token(bytes)
            .expect("fixture container")
            .header
            .event_id
    }

    /// Two participants per pair, which is what the contract stores.
    fn participants_of(bytes: &[u8]) -> u32 {
        let t = kenter_crypto::container::deserialize_bearer_token(bytes)
            .expect("fixture container");
        (t.chain.links.len() * 2) as u32
    }

    fn chain_hash_of(bytes: &[u8]) -> [u8; 32] {
        let t = kenter_crypto::container::deserialize_bearer_token(bytes)
            .expect("fixture container");
        kenter_crypto::chain_data::token_chain_hash(&t).expect("fixture chain hash")
    }

    /// A real container, built the way `kenter print` builds one, so G1 has
    /// something genuine to verify rather than bytes shaped like a token.
    fn a_token(denom: u64) -> Vec<u8> {
        use kenter_crypto::keypair::StellarKeypair;
        let requestor = StellarKeypair::random();
        let (n0a, n0b) = (StellarKeypair::random(), StellarKeypair::random());
        let (partial, _shard) =
            PartialToken::initiate([9u8; 32], 1_700_000_000, Some(denom), 2, &n0a, &n0b, vec![])
                .unwrap();
        let partner = StellarKeypair::random();
        let token = assemble_bearer_token(&partial, &requestor, &partner, 7, None).unwrap();
        serialize_bearer_token(&token, &requestor).unwrap()
    }

    /// Reserve an address, then hand back everything the watch needs.
    fn addressed(dir: &std::path::Path) -> (PendingReceive, ReceiveState) {
        let (store, vault) = fixture(dir);
        let mut wallet = TokenWallet::with_vault(NoChain, store, vault);
        let mut authz = SessionAuthorizer::new(
            Script {
                answers: vec![Some(PASS)],
                seen: Vec::new(),
            },
            Policy::Session,
        );
        let ready = block_on(reserve_and_derive(&mut wallet, &mut authz, dir));
        let pending = block_on(wallet.pending()).unwrap().pop().unwrap();
        (pending, ready)
    }

    /// Fast enough that a test is not a coffee break; the watch needs two
    /// polls to touch a file at all, by design.
    const FAST: Duration = Duration::from_millis(60);

    fn run_watch<C: kenter_wallet::ChainRead>(
        dir: &std::path::Path,
        chain: C,
        ready: ReceiveState,
        polls: u64,
    ) -> Screenplay {
        let store = FileStore::open(dir, test_creds()).unwrap();
        let vault = SoftVault::open(dir.join("vault.json")).unwrap();
        let mut wallet = TokenWallet::with_vault(chain, store, vault);
        let cancel = Arc::new(AtomicBool::new(false));
        let play = Screenplay::stopping_after(polls as usize, cancel.clone());
        let stop = cancel.clone();
        block_on(async {
            // The counted stop above is what ends this. The deadline is only
            // a backstop against a watch that hangs without ever reporting,
            // which the count cannot catch — so it is generous enough that
            // scheduling noise never reaches it.
            tokio::select! {
                _ = watch(&play, &mut wallet, dir, ready, cancel.clone(), FAST) => {}
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    stop.store(true, Ordering::Relaxed);
                    panic!("the watch reported nothing for 30s — it is stuck, not slow");
                }
            }
        });
        play
    }

    #[test]
    fn a_token_dropped_in_the_inbox_completes_the_receive() {
        let dir = tempfile::tempdir().unwrap();
        let (pending, ready) = addressed(dir.path());
        let inbox = inbox_dir(dir.path());
        let note = a_token(25_000_000);
        std::fs::write(inbox.join("payment.symtoken"), &note).unwrap();

        let play = run_watch(
            dir.path(),
            Paid {
                commitment: pending.commitment,
                amount: 25_000_000,
                chain_hash: chain_hash_of(&note),
                event_id: event_id_of(&note),
                participants_len: participants_of(&note),
                ephemeral_key: key_of(&note),
            },
            ready,
            12,
        );

        let (_, amount) = play.paid().expect("expected a Received state");
        assert_eq!(amount, "$2.5000000");
        // The file is moved out of the way, not left to be re-judged.
        assert!(!inbox.join("payment.symtoken").exists());
        assert!(inbox.join("accepted").join("payment.symtoken").exists());
        // And the token is actually in the wallet, bound to our index.
        let store = FileStore::open(dir.path(), test_creds()).unwrap();
        let held = block_on(store.all()).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].owner_index, Some(pending.index));
        assert!(block_on(store.pending()).unwrap().is_empty());
    }

    /// A pay tag is consumed when a note binds to it, so a second payer using
    /// the same tag arrives with nothing pending to match. The core matches
    /// against every index it can open; this checks the watch actually gets
    /// that answer and files the token as accepted rather than refused.
    #[test]
    fn a_payment_to_a_tag_already_used_is_still_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (pending, ready) = addressed(dir.path());
        let inbox = inbox_dir(dir.path());
        // A record per note: a ledger record names the chain it was
        // registered with, so one cannot describe two different notes.
        let record = |bytes: &[u8]| Paid {
            event_id: event_id_of(bytes),
            participants_len: participants_of(bytes),
            commitment: pending.commitment,
            amount: 25_000_000,
            chain_hash: chain_hash_of(bytes),
            ephemeral_key: key_of(bytes),
        };

        // Use the tag up, exactly as a first payer would.
        let first = a_token(25_000_000);
        std::fs::write(inbox.join("first.symtoken"), &first).unwrap();
        run_watch(dir.path(), record(&first), ready.clone(), 12)
            .paid()
            .expect("the first payment should land");
        let store = FileStore::open(dir.path(), test_creds()).unwrap();
        assert!(
            block_on(store.pending()).unwrap().is_empty(),
            "the tag was used up"
        );

        // The second payer had the same tag.
        let second = a_token(25_000_000);
        std::fs::write(inbox.join("second.symtoken"), &second).unwrap();
        let play = run_watch(dir.path(), record(&second), ready, 12);

        play.paid().expect("a payment to a spent tag was refused");
        assert!(
            !inbox.join("rejected").exists(),
            "a paid token was filed as rejected"
        );
        let store = FileStore::open(dir.path(), test_creds()).unwrap();
        let held = block_on(store.all()).unwrap();
        assert_eq!(held.len(), 2);
        assert!(held.iter().all(|h| h.owner_index == Some(pending.index)));
    }

    /// Showing a tag again comes from the stored record alone. If this ever
    /// needed the commitment re-derived, coming back to the page would mean a
    /// prompt naming an index the holder never asked to reserve.
    #[test]
    fn a_stored_record_reproduces_the_address_it_was_shown_as() {
        let dir = tempfile::tempdir().unwrap();
        let (pending, fresh) = addressed(dir.path());
        let again = ready_for(&pending, dir.path(), "a test ledger".into());
        let (
            ReceiveState::Ready {
                uri,
                hex,
                index,
                inbox,
                ..
            },
            ReceiveState::Ready {
                uri: u2,
                hex: h2,
                index: i2,
                inbox: b2,
                ..
            },
        ) = (fresh, again)
        else {
            panic!("expected two tags");
        };
        assert_eq!((uri, hex, index, inbox), (u2, h2, i2, b2));
    }

    /// A bearer note has no owner pointer and never will, so it fails G3 for
    /// good — but G1 and G2 just passed, which is every gate a bearer note
    /// can pass. Filing it under `rejected/` told the holder their money had
    /// bounced when a payment had in fact arrived.
    #[test]
    fn a_bearer_note_is_taken_into_the_billfold_not_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_pending, ready) = addressed(dir.path());
        let inbox = inbox_dir(dir.path());
        let note = a_token(25_000_000);
        std::fs::write(inbox.join("bearer.symtoken"), &note).unwrap();

        let play = run_watch(
            dir.path(),
            Bearer {
                event_id: event_id_of(&note),
                participants_len: participants_of(&note),
                amount: 25_000_000,
                chain_hash: chain_hash_of(&note),
                ephemeral_key: key_of(&note),
                claim_pubkey: claim_of(&note),
            },
            ready,
            12,
        );

        let ReceiveState::Held { amount, .. } = play.last() else {
            panic!("expected Held, got {:?}", play.last());
        };
        assert_eq!(amount, "$2.5000000");
        assert!(
            !inbox.join("rejected").exists(),
            "a bearer note was called a refusal"
        );
        assert!(inbox.join("accepted").join("bearer.symtoken").exists());
        // And it is actually in the billfold, unbound - there is no index to
        // bind it to, which is the whole difference from a settled receive.
        let store = FileStore::open(dir.path(), test_creds()).unwrap();
        let held = block_on(store.all()).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].owner_index, None);
    }

    /// A file still being copied in parses as malformed, and malformed is a
    /// permanent rejection. Without the stability check the payer's token gets
    /// thrown into `rejected/` for the crime of being large.
    #[test]
    fn a_file_is_never_judged_the_first_time_it_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let (pending, ready) = addressed(dir.path());
        let inbox = inbox_dir(dir.path());
        std::fs::write(inbox.join("half.symtoken"), b"not a token yet").unwrap();

        // Exactly one poll: the file is seen, stamped, and left alone.
        let _pending = pending;
        let play = run_watch(dir.path(), NoChain, ready, 1);
        assert!(!inbox.join("rejected").exists(), "judged on first sight");
        assert!(inbox.join("half.symtoken").exists());
        assert!(
            matches!(play.last(), ReceiveState::Ready { .. }),
            "expected to still be waiting"
        );
    }

    #[test]
    fn a_permanently_bad_file_is_moved_aside_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let (pending, ready) = addressed(dir.path());
        let inbox = inbox_dir(dir.path());
        std::fs::write(inbox.join("junk.symtoken"), b"definitely not a token").unwrap();

        let _pending = pending;
        let play = run_watch(dir.path(), NoChain, ready, 8);
        assert!(inbox.join("rejected").join("junk.symtoken").exists());
        let ReceiveState::Ready { note, .. } = play.last() else {
            panic!("expected to still be waiting");
        };
        let note = note.expect("the holder should be told what was refused");
        assert!(note.contains("junk.symtoken"), "{note}");
    }

    /// Anything that is not a token file is none of our business.
    #[test]
    fn other_files_in_the_inbox_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (pending, ready) = addressed(dir.path());
        let inbox = inbox_dir(dir.path());
        std::fs::write(inbox.join("notes.txt"), b"shopping list").unwrap();

        let _pending = pending;
        run_watch(dir.path(), NoChain, ready, 8);
        assert!(inbox.join("notes.txt").exists());
        assert!(!inbox.join("rejected").exists());
    }

    #[test]
    fn cancelling_stops_the_watch() {
        let dir = tempfile::tempdir().unwrap();
        let (pending, ready) = addressed(dir.path());
        let store = FileStore::open(dir.path(), test_creds()).unwrap();
        let vault = SoftVault::open(dir.path().join("vault.json")).unwrap();
        let mut wallet = TokenWallet::with_vault(NoChain, store, vault);
        let play = Screenplay::default();
        let cancel = Arc::new(AtomicBool::new(true)); // already cancelled
        let _pending = pending;
        block_on(watch(&play, &mut wallet, dir.path(), ready, cancel, FAST));
        assert!(
            play.states.borrow().is_empty(),
            "a cancelled watch reported anyway"
        );
    }

    /// Two tokens can arrive under one name; the second must not silently
    /// replace the first in `accepted/`.
    #[test]
    fn filing_a_second_file_of_the_same_name_does_not_overwrite_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = inbox_dir(dir.path());
        std::fs::create_dir_all(&inbox).unwrap();
        for body in ["first", "second"] {
            let p = inbox.join("same.symtoken");
            std::fs::write(&p, body).unwrap();
            file_away(&inbox, &p, "accepted");
        }
        let kept = std::fs::read_to_string(inbox.join("accepted").join("same.symtoken")).unwrap();
        let also = std::fs::read_to_string(inbox.join("accepted").join("same.symtoken.1")).unwrap();
        assert_eq!(kept, "first");
        assert_eq!(also, "second");
    }
}
