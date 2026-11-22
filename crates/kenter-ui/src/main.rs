//! Kenter Desktop UI — interactive window.
//!
//! A winit window that presents the CPU-composited pelt canvas via softbuffer.
//! We own and clear the framebuffer every frame (no transparent-compositing
//! ghosting), and re-render only when something changes:
//!
//! - move the cursor    → hover feedback on buttons and nav items
//! - press the mouse    → button press state
//! - click a nav item   → selects that page (active state moves)
//! - click a button     → acts on its [`Action`]
//! - scroll the wheel  → moves a long list inside its panel
//! - press R            → re-read the wallet and reconcile
//!
//! Everything slow runs on a worker thread and arrives as a user event: the
//! wallet read (one RPC round trip per held token) and the receive flow (an
//! encrypted vault read, a store write, and a human). The window opens at once
//! and a slow ledger never freezes it.
//!
//! ## The event loop owns the passphrase
//!
//! Keystrokes land here, so the buffer lives here, in a `Zeroizing<String>`
//! that is cleared the moment it is handed to the worker. The view model that
//! gets cloned into the layout tree carries only a character count. There is
//! no path by which the passphrase reaches a `Debug` print, a PNG, or the
//! layout tree.
//!
//! Run: `cargo run -p kenter-ui --bin kenter-ui`.
//! GPU (Vello) rendering + tweened transitions are a later milestone.

use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kenter_ui::receive::{self, UiEvent};
use kenter_ui::wallet::{default_wallet_dir, load, Network};
use kenter_ui::{
    account, canvas_to_argb, deposit, pay, redemption, settings, setup, AccountView, Action,
    DepositPreview, DepositState, DepositView, Interaction, LockedView, NoteCard, PayState,
    PayView, PayableRow, ReceiveState, ReceiveView, RedeemQuote, RedeemState, RedeemView, Screen,
    SetupState, SetupView, Ui, WalletView, H, W,
};
use kenter_wallet::StoreCredentials;

use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::KeyEvent;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{Key, NamedKey};
use winit::window::{Window, WindowId};
use zeroize::Zeroizing;

/// Read the wallet and reconcile it, off the event loop.
///
/// Each call owns its own runtime: this runs at most once every few seconds on
/// a user's keypress, so a persistent runtime would be ceremony for no gain.
fn load_view(creds: Option<StoreCredentials>) -> WalletView {
    let Some(dir) = default_wallet_dir() else {
        return WalletView::empty("set KENTER_WALLET_DIR or pass a wallet directory");
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return WalletView::empty(&format!("runtime: {e}")),
    };
    let net = Network::current();
    rt.block_on(load(&dir, net.rpc, net.passphrase, net.contract, creds))
}

/// Keep the copy beside the vault current.
///
/// Not a backup and never recorded as one (`kenter_ui::backup`), so this
/// cannot move the "last backed up" date and cannot make the billfold stop
/// warning. It exists so that the file card provisioning writes does not sit
/// there going stale: a `kenter-backup-*.kbk` next to the vault that is empty
/// from the day the card was set up is worse than no file, because somebody
/// will eventually find it and believe it.
///
/// Failure is logged and dropped. The copy is a convenience, and a client
/// that refused to show a billfold because it could not rewrite a spare file
/// would have its priorities backwards.
fn refresh_working_copy(
    creds: Option<StoreCredentials>,
    backup: kenter_vault::BackupCredentials,
    seed: kenter_wallet::backup::SeedSource,
) {
    let (Some(creds), Some(dir)) = (creds, default_wallet_dir()) else {
        return;
    };
    let Ok(rt) = tokio::runtime::Runtime::new() else {
        return;
    };
    let outcome = rt.block_on(async {
        let mut store =
            kenter_wallet::FileStore::open(&dir, creds).map_err(|e| e.to_string())?;
        kenter_ui::backup::refresh_working_copy(
            &mut store,
            &backup.key,
            &seed,
            kenter_ui::backup::now(),
        )
        .await
    });
    if let Err(e) = outcome {
        eprintln!("kenter: could not refresh the working copy: {e}");
    }
}

/// Everything the store holds, cut into paper symbols.
///
/// Returns the note count too, because the offer screen says it and
/// counting chunks does not give it — the wallet record is an item as
/// well.
fn paper_chunks(
    creds: kenter_wallet::StoreCredentials,
    backup: &kenter_vault::BackupCredentials,
) -> Result<(Vec<kenter_wallet::paper::Chunk>, usize), String> {
    use kenter_wallet::Store;

    let dir = kenter_ui::wallet::default_wallet_dir().ok_or("set KENTER_WALLET_DIR")?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let mut store =
            kenter_wallet::FileStore::open(&dir, creds).map_err(|e| e.to_string())?;
        let tokens = store.all().await.map_err(|e| e.to_string())?;
        let pending = store.pending().await.map_err(|e| e.to_string())?;
        let next = store.advance_owner_index(0).await.map_err(|e| e.to_string())?;
        // An empty wallet is not an error here. It is the wallet a holder
        // restoring from paper is sitting in front of, and the paper
        // screen is where they reach the scanner. Printing is the thing
        // that cannot proceed, and `write_paper` is where that is said.
        if tokens.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let chunks = kenter_wallet::paper::encode(
            &backup.fingerprint,
            &tokens,
            &pending,
            Some(next),
            |plain| kenter_wallet::backup::seal_item(&backup.key, plain),
        )
        .map_err(|e| e.to_string())?;
        Ok((chunks, tokens.len()))
    })
}

/// Draw the sheets and write them.
///
/// PDF is one file; SVG is one file per page, because a vector page is
/// headed for a laser cutter one at a time.
fn write_paper(
    creds: kenter_wallet::StoreCredentials,
    backup: &kenter_vault::BackupCredentials,
    dest: &std::path::Path,
    svg: bool,
) -> Result<(String, usize), String> {
    let (chunks, _) = paper_chunks(creds, backup)?;
    if chunks.is_empty() {
        return Err("there are no notes to put on paper yet".to_string());
    }
    let created = {
        let days = kenter_ui::backup::now() / 86_400;
        // Days to a date, inline rather than taking a crate for one line.
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        format!("{:04}-{m:02}-{d:02}", if m <= 2 { y + 1 } else { y })
    };

    let pages = kenter_ui::sheet::pages(&chunks, &backup.fingerprint, &created)?;
    if svg {
        for (i, page) in pages.iter().enumerate() {
            let path = if pages.len() == 1 {
                dest.to_path_buf()
            } else {
                dest.with_file_name(format!(
                    "{}-page-{}.svg",
                    dest.file_stem().unwrap_or_default().to_string_lossy(),
                    i + 1
                ))
            };
            std::fs::write(&path, page)
                .map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
    } else {
        let pdf = kenter_ui::pdf::render(&chunks, &backup.fingerprint, &created)?;
        std::fs::write(dest, &pdf).map_err(|e| format!("writing {}: {e}", dest.display()))?;
    }
    Ok((dest.display().to_string(), pages.len()))
}

/// Open what was scanned and merge it into the store.
///
/// Runs the same `backup::restore` the file path runs, so everything it
/// guarantees holds here too: additive, never overwriting a note already
/// held, and every note checked against its own container first.
fn restore_from_sheet(
    creds: kenter_wallet::StoreCredentials,
    backup: &kenter_vault::BackupCredentials,
    sheet: &kenter_wallet::paper::Sheet,
) -> Result<kenter_ui::PaperState, String> {
    if let Some(w) = sheet.wallet() {
        if w != backup.fingerprint {
            return Err(format!(
                "those sheets belong to a different wallet ({w}), not this one ({})",
                backup.fingerprint
            ));
        }
    }
    let progress = sheet.progress();
    let name = |i: u16| {
        if i == 0 {
            "wallet record".to_string()
        } else {
            format!("note {i}")
        }
    };

    let recovered = sheet
        .finish(|sealed| kenter_wallet::backup::open_item(&backup.key, sealed))
        .map_err(|e| e.to_string())?;

    let dir = kenter_ui::wallet::default_wallet_dir().ok_or("set KENTER_WALLET_DIR")?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let (added, kept, failed, rejected) = rt.block_on(async {
        let mut store =
            kenter_wallet::FileStore::open(&dir, creds).map_err(|e| e.to_string())?;
        let failed: Vec<(u16, String)> = recovered.failed.clone();
        let contents = recovered.into_contents(kenter_ui::backup::now());
        let report = kenter_wallet::backup::restore(&mut store, &contents)
            .await
            .map_err(|e| e.to_string())?;
        // Paper is a backup like any other, so a wallet restored from it
        // is backed up and must not be warned at.
        kenter_ui::backup::adopt(&mut store, &contents, Some("a paper backup".into())).await?;
        Ok::<_, String>((report.tokens_added, report.tokens_kept, failed, report.rejected))
    })?;

    Ok(kenter_ui::PaperState::Restored {
        added,
        kept,
        missed: failed.iter().map(|(i, _)| name(*i)).collect(),
        absent: progress.absent.iter().map(|i| name(*i)).collect(),
        partial: progress.partial.iter().map(|(i, gone)| (name(*i), gone.len())).collect(),
        rejected: rejected
            .into_iter()
            .map(|(id, why)| (format!("note {}", kenter_ui::wallet::short(&id)), why))
            .collect(),
    })
}

/// `to` is the account the escrow would be paid into: the session's
/// verified address ([`App::verified_account`]), never the vault's plaintext
/// list, which can be edited without the passphrase.
async fn redeem_quotes(
    creds: kenter_wallet::StoreCredentials,
    to: String,
) -> Result<Vec<RedeemQuote>, String> {
    let (_, wallet) = open_for_pay(creds)?;
    let mut out = Vec::new();
    for held in redemption::redeemable(&wallet).await? {
        // A note whose fees exceed its face cannot be redeemed, and the
        // picker leaves it out rather than offering a row that errors.
        if let Ok(q) = redemption::quote(&held, deposit::ASSUMED_NODE_FEE, &to) {
            out.push(RedeemQuote {
                id: q.id,
                short_id: q.short_id,
                face: kenter_wallet::fmt_stroops(q.face),
                payout: kenter_wallet::fmt_stroops(q.payout),
                fee: kenter_wallet::fmt_stroops(q.fee),
                spend_mode: q.spend_mode,
                to_account: q.to_account,
                own_account: q.own_account,
            });
        }
    }
    Ok(out)
}

async fn redeem_job(
    creds: kenter_wallet::StoreCredentials,
    session: kenter_ui::SessionCreds,
    id: &str,
    recipient: &str,
) -> Result<i128, String> {
    let net = Network::current();
    let (_, mut wallet) = open_for_pay(creds)?;
    let held = pay::held_token(wallet.store(), id).await?;

    let vault_path = receive::default_vault_path().ok_or("set KENTER_VAULT")?;
    let vault = kenter_vault::SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    let (slot, listed) = kenter_vault::KeyVault::list_keys(&vault)
        .map_err(|e| e.to_string())?
        .first()
        .map(|k| (k.slot, k.stellar_address.clone()))
        .ok_or("no account in the vault to submit with")?;
    // The submitting account authorises the redemption; where the escrow
    // goes is a separate question now, answered by `recipient`.
    let kp = vault
        .keypair(slot, &session.account)
        .map_err(|e| e.to_string())?;
    // The address the screens showed, and offered as the payout account,
    // is the vault's plaintext key list, readable and writable without the
    // passphrase. Only the decrypted key is authenticated. If they differ
    // the file was altered, and redeeming would pay wherever the edit
    // pointed. Checked here because this is the moment
    // the address moves money.
    if listed != kp.stellar_address() {
        return Err(format!(
            "the vault lists account {listed} but its key is {} - the vault file \
             has been altered, so nothing was redeemed",
            kp.stellar_address()
        ));
    }
    let mut mint = kenter_client::MintClient::new(
        kenter_client::TxBuilder::new(
            net.rpc_client(),
            kp,
        ),
        net.contract,
    );
    redemption::redeem(&mut wallet, &mut mint, &held, recipient, &session.owner).await
}

/// Add a trustline for whatever this mint escrows, signed by the vault key.
///
/// Shared by first run and Settings: the step is the same wherever it is
/// reached from, and two copies of a signing path is one too many.
async fn submit_trustline(net: Network, credential: &[u8]) -> Result<(), String> {
    let asset = settings::escrow_asset(net).await?;
    let issuer = asset
        .issuer
        .clone()
        .ok_or_else(|| "this mint escrows native XLM; no trustline needed".to_string())?;
    let vault_path = receive::default_vault_path().ok_or_else(|| "set KENTER_VAULT".to_string())?;
    let vault = kenter_vault::SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    let slot = kenter_vault::KeyVault::list_keys(&vault)
        .map_err(|e| e.to_string())?
        .first()
        .map(|k| k.slot)
        .ok_or_else(|| "no account in the vault".to_string())?;
    let kp = vault.keypair(slot, credential).map_err(|e| e.to_string())?;
    let mut tx = kenter_client::TxBuilder::new(
        net.rpc_client(),
        kp,
    );
    // No limit. A trust limit caps exposure to an issuer, and a holder who
    // cannot receive their own redemption has been capped by accident.
    tx.change_trust(&asset.code, &issuer, i64::MAX)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Open the store with the session keys. Every Pay job starts here.
fn open_for_pay(
    creds: kenter_wallet::StoreCredentials,
) -> Result<(std::path::PathBuf, kenter_ui::GuiWallet), String> {
    let net = Network::current();
    let dir = kenter_ui::wallet::default_wallet_dir().ok_or("set KENTER_WALLET_DIR")?;
    let vault_path = receive::default_vault_path().ok_or("set KENTER_VAULT")?;
    let soft = kenter_vault::SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    // Whichever custody this installation records. Paying from a card
    // wallet signs on the card, so the vault has to be the card.
    let custody = soft.custody().cloned();
    let vault =
        kenter_ui::vault::GuiVault::open(custody.as_ref(), soft).map_err(|e| e.to_string())?;
    let store = kenter_wallet::FileStore::open(&dir, creds).map_err(|e| e.to_string())?;
    let chain = kenter_client::WalletChain::new(kenter_client::MintClient::new(
        kenter_client::TxBuilder::new(
            net.rpc_client(),
            kenter_crypto::keypair::StellarKeypair::random(),
        ),
        net.contract,
    ));
    Ok((
        dir,
        kenter_wallet::TokenWallet::with_vault(chain, store, vault),
    ))
}

async fn export_job(
    creds: kenter_wallet::StoreCredentials,
    id: &str,
    dest: &std::path::Path,
    kind: kenter_wallet::ExportKind,
) -> Result<String, String> {
    let (_, mut wallet) = open_for_pay(creds)?;
    let held = pay::held_token(wallet.store(), id).await?;
    let path = pay::export(&mut wallet, dest, &held, kind).await?;
    Ok(path.display().to_string())
}

async fn mark_spent_job(creds: kenter_wallet::StoreCredentials, id: &str) -> Result<(), String> {
    let (_, mut wallet) = open_for_pay(creds)?;
    wallet
        .mark_spent(id, true)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// A spend-mode payment: the file, then the pointer.
///
/// That order is not a preference. Pointer-first with the file never
/// delivered strands the note — the payer can no longer open the live
/// commitment and the payee has no chain data to redeem with — while
/// file-first with the pointer never moved is benign, because the bytes
/// alone do nothing for a spend-mode note.
async fn pay_job(
    proxy: &EventLoopProxy<UiEvent>,
    creds: kenter_wallet::StoreCredentials,
    session: kenter_ui::SessionCreds,
    id: &str,
    dest: &std::path::Path,
    commitment: [u8; 32],
) -> Result<(), String> {
    let net = Network::current();
    let (_, mut wallet) = open_for_pay(creds)?;
    let held = pay::held_token(wallet.store(), id).await?;

    // Staged, not saved. The bytes have to exist before the pointer moves
    // — afterwards this holder's key no longer matches the live commitment,
    // so a payee with no file has nothing to redeem and the note is
    // stranded. But a file at the chosen path after a failed payment looks
    // exactly like a payment that worked, so it stays a `.partial` until
    // the ledger agrees.
    let partial = pay::stage(dest, &held)?;

    let _ = proxy.send_event(UiEvent::Pay(PayState::Working {
        what: "moving the owner pointer".into(),
    }));

    // The submitting account pays the fee; the owner signature is separate,
    // which is why attributability here is this client's choice rather than
    // the protocol's.
    let vault_path = receive::default_vault_path().ok_or("set KENTER_VAULT")?;
    let vault = kenter_vault::SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    let slot = kenter_vault::KeyVault::list_keys(&vault)
        .map_err(|e| e.to_string())?
        .first()
        .map(|k| k.slot)
        .ok_or("no account in the vault to submit with")?;
    let submitter = vault
        .keypair(slot, &session.account)
        .map_err(|e| e.to_string())?;
    let mut mint = kenter_client::MintClient::new(
        kenter_client::TxBuilder::new(
            net.rpc_client(),
            submitter,
        ),
        net.contract,
    );

    if let Err(e) = pay::repoint(&mut wallet, &mut mint, &held, &session.owner, commitment).await {
        // Nothing moved, so leave nothing behind that suggests it did.
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }

    // The ledger has agreed; the file is now a real payment and may take its
    // name. Only now does the export count toward the note's exposure.
    pay::promote(
        &mut wallet,
        &partial,
        dest,
        &held,
        kenter_wallet::ExportKind::Handover,
    )
    .await?;

    // sync sees the pointer has moved away and flags the note; doing it here
    // rather than waiting means the billfold is right immediately.
    let _ = wallet.sync().await;
    Ok(())
}

/// The deposit itself, on a worker.
///
/// Spend mode reserves an owner index *before* printing, because the
/// commitment is fixed at registration and cannot be added afterwards — mode
/// is not something a note acquires later.
async fn deposit_job(
    proxy: &EventLoopProxy<UiEvent>,
    creds: kenter_wallet::StoreCredentials,
    session: kenter_ui::SessionCreds,
    amount: u64,
    pairs: u16,
    spend: bool,
) -> DepositState {
    use kenter_client::TokenMode;
    use kenter_wallet::{Store, TokenWallet};

    let fail = |m: String| DepositState::Failed { message: m };
    let net = Network::current();

    let Some(dir) = kenter_ui::wallet::default_wallet_dir() else {
        return fail("set KENTER_WALLET_DIR".into());
    };
    let Some(vault_path) = receive::default_vault_path() else {
        return fail("set KENTER_VAULT".into());
    };
    let vault = match kenter_vault::SoftVault::open(&vault_path) {
        Ok(v) => v,
        Err(e) => return fail(e.to_string()),
    };
    let custody = vault.custody().cloned();
    let slot = match kenter_vault::KeyVault::list_keys(&vault) {
        Ok(k) if !k.is_empty() => k[0].slot,
        Ok(_) => return fail("no account in the vault to submit with".into()),
        Err(e) => return fail(e.to_string()),
    };
    // The account credential, not the owner one: this signs the deposit
    // transaction, which the fee-paying account pays for.
    let submitter = match vault.keypair(slot, &session.account) {
        Ok(kp) => kp,
        Err(e) => return fail(e.to_string()),
    };
    let mut store = match kenter_wallet::FileStore::open(&dir, creds) {
        Ok(s) => s,
        Err(e) => return fail(e.to_string()),
    };

    // Spend mode needs its owner commitment before the note exists.
    let (mode, commitment, owner_index) = if spend {
        let index = match store.allocate_owner_index().await {
            Ok(i) => i,
            Err(e) => return fail(e.to_string()),
        };
        // The owner credential **and the right vault**: on a card wallet
        // this key lives on the card, so deriving it from the SoftVault
        // would fail even with the correct secret.
        let mut owner_vault = match kenter_ui::vault::GuiVault::open(custody.as_ref(), vault) {
            Ok(v) => v,
            Err(e) => return fail(e.to_string()),
        };
        match kenter_wallet::owner::commitment_for(&mut owner_vault, index, &session.owner) {
            Ok(c) => (TokenMode::Spend, c, Some(index)),
            Err(e) => return fail(e.to_string()),
        }
    } else {
        (TokenMode::PureBearer, [0u8; 32], None)
    };

    let result = deposit::run(
        net,
        submitter,
        amount,
        pairs,
        mode,
        commitment,
        |what| {
            let _ = proxy.send_event(UiEvent::Deposit(DepositState::Working { what }));
        },
    )
    .await;

    let made = match result {
        Ok(d) => d,
        Err(message) => return fail(message),
    };

    // Store it. The note exists on the ledger either way at this point, so a
    // store failure is reported with the id rather than swallowed — the
    // container can still be recovered from the error.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let chain = kenter_client::WalletChain::new(kenter_client::MintClient::new(
        kenter_client::TxBuilder::new(
            net.rpc_client(),
            kenter_crypto::keypair::StellarKeypair::random(),
        ),
        net.contract,
    ));
    let mut wallet = TokenWallet::new(chain, store);
    if let Err(e) = wallet.import(made.container, now).await {
        return fail(format!("{} is registered but was not stored: {e}", made.id));
    }
    if let Some(index) = owner_index {
        if let Err(e) = wallet.bind_owner(&made.id, index).await {
            return fail(format!("{} was stored but not bound: {e}", made.id));
        }
        // Record the commitment this deposit actually used. `bind_owner`
        // can only carry one across from a pending receive, and a note we
        // minted ourselves never had one — so without this the note has an
        // owner index and no commitment, and neither Pay nor Redeem can
        // prove ownership of it.
        if let Err(e) = wallet.record_owner_commitment(&made.id, commitment).await {
            return fail(format!(
                "{} was bound but its commitment was not stored: {e}",
                made.id
            ));
        }
    }

    DepositState::Done {
        id: kenter_ui::wallet::short(&made.id),
        amount: kenter_wallet::fmt_stroops(made.amount),
    }
}

/// Environment overrides from a file, and only when asked.
///
/// Not `dotenvy::dotenv()`, which walks **up** from the working directory
/// to the filesystem root. The variables decide which mint every deposit
/// escrows into (`KENTER_MINT`) and which vault and store are opened
/// (`KENTER_VAULT`, `KENTER_WALLET_DIR`). A walking loader would let a file
/// named `.env` in *any* ancestor — an extracted archive, a cloned repo,
/// the root of a non-system drive where Authenticated Users can write on
/// Windows — silently repoint the wallet at an attacker's contract, with
/// nothing on screen different. Double-clicking the exe sets the working
/// directory to the exe's folder, so the user need not be near a terminal.
///
/// So three rules. It never walks: either an explicit `--env-file <path>`,
/// or `./.env` in the working directory and nowhere else. It is implicit
/// only in debug builds, so a shipped binary reads no file unless told to.
/// And it says what it did, naming the file and every variable it set,
/// because the danger is a load that is silent.
/// Which file, if any, to read — the decision, with nothing else in it.
///
/// Split out so it can be tested: the security property is *which path is
/// chosen*, and asserting that needs no process environment, no working
/// directory and no temp files.
///
/// `Err` means the arguments were malformed.
fn env_file_path(args: &[String], debug_build: bool) -> Result<Option<std::path::PathBuf>, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--env-file" {
            return match it.next() {
                Some(path) => Ok(Some(std::path::PathBuf::from(path))),
                None => Err("--env-file needs a path".into()),
            };
        }
    }
    // No flag: `./.env` while developing, nothing at all in a release
    // build. A convenience worth having at a desk is not worth having in a
    // binary someone is paid in.
    Ok(if debug_build {
        Some(std::path::PathBuf::from(".env"))
    } else {
        None
    })
}

fn load_env_file() -> Option<std::path::PathBuf> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match env_file_path(&args, cfg!(debug_assertions)) {
        Ok(Some(p)) => p,
        Ok(None) => return None,
        Err(e) => {
            eprintln!("kenter: {e}");
            std::process::exit(2);
        }
    };
    if !path.is_file() {
        return None;
    }

    // `from_path` reads exactly this file. `dotenv()` is what searched.
    let loaded = dotenvy::from_path_iter(&path).ok()?;
    let mut names = Vec::new();
    for entry in loaded.flatten() {
        let (key, value) = entry;
        // Same precedence as dotenvy: a real environment variable wins,
        // so a file cannot override what the user set deliberately.
        if std::env::var_os(&key).is_none() {
            unsafe { std::env::set_var(&key, &value) };
            names.push(key);
        }
    }
    names.sort();
    eprintln!(
        "kenter: loaded {} from {}",
        if names.is_empty() { "nothing".to_string() } else { names.join(", ") },
        path.display()
    );
    Some(path)
}

fn main() {
    // A packaged wallet without its skins stops here, saying why.
    if let Err(e) = kenter_ui::check_skins() {
        eprintln!("kenter-ui: {e}");
        std::process::exit(1);
    }
    load_env_file();

    // Say which mint this is talking to, every time. Invisible config is
    // what made that afternoon expensive; one line costs nothing and makes a
    // mismatch obvious before anything is signed. Settings shows the same
    // contract id on screen, which is where a GUI user will actually see it.
    // A mainnet build without its contract ids, or with a contract
    // override it does not allow, stops here rather than opening on a
    // guess (`kenter_client::network`).
    let net = match Network::init() {
        Ok(net) => net,
        Err(e) => {
            eprintln!("kenter: cannot start: {e}");
            std::process::exit(2);
        }
    };
    eprintln!(
        "kenter: {} | mint {} | roster {}",
        net.name, net.contract, net.roster
    );

    let event_loop = EventLoop::<UiEvent>::with_user_event()
        .build()
        .expect("event loop");
    // Idle by default. `about_to_wait` switches to `WaitUntil` for as long as
    // something on screen is moving and back again when it stops, so a still
    // page costs nothing.
    event_loop.set_control_flow(ControlFlow::Wait);
    let mut app = App::new(event_loop.create_proxy());
    event_loop.run_app(&mut app).expect("run app");
}

/// What first run has collected for a card, before any of it is sent.
///
/// Dropped and zeroized the moment first run leaves the card path, so a
/// cancelled setup does not leave a PIN in memory for the rest of the
/// session.
#[derive(Default)]
struct CardSecrets {
    pin: Option<Zeroizing<String>>,
    duress: Option<Zeroizing<String>>,
    puk: Option<Zeroizing<String>>,
    /// The first of a two-entry pair, waiting for its repeat.
    pending: Option<Zeroizing<String>>,
}

impl CardSecrets {
    fn clear(&mut self) {
        *self = CardSecrets::default();
    }
}

struct App {
    ui: Ui,
    /// What is on screen.
    screen: Screen,
    /// The last wallet we read, kept so leaving the receive page does not blank
    /// the balance and make it look as though the tokens went somewhere.
    wallet: WalletView,
    /// The last account page we read, kept for the same reason.
    ///
    /// Every visit re-reads the ledger, and the read is seconds of RPC.
    /// Starting each one from `Default` meant the balances blanked on the way
    /// in and stayed blank until the network answered - so arriving at the
    /// page showed nothing, and a read that was slow or lost showed nothing
    /// forever. The figures are public ledger data that do not stop being
    /// true while they are being rechecked, so the page shows the last ones
    /// with `busy` saying they are being confirmed.
    account: AccountView,
    it: Interaction,
    cursor: (f32, f32),
    window: Option<Rc<Window>>,
    surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
    proxy: EventLoopProxy<UiEvent>,
    /// A wallet load is in flight. Guards against stacking workers on held-down
    /// R, and against a stale result landing on a newer one.
    loading: bool,
    /// A receive worker is running. It owns the screen until it reports back.
    receiving: bool,
    /// An unlock prompt is in flight; a second would orphan the first.
    unlocking: bool,
    /// The passphrase chosen during first run, held until the phrase is
    /// confirmed and the vault is written. Nothing is persisted before then
    /// (a secret is never written before it must be), so this is the only copy.
    setup_pass: Option<Zeroizing<String>>,
    /// One activation watcher at a time; it runs until the gate is cleared.
    activating: bool,
    /// Held modifier keys, so Ctrl+V can be told from a literal "v".
    mods: winit::keyboard::ModifiersState,
    /// The generated phrase, in memory only, from the moment it is shown to
    /// the moment the vault accepts it.
    setup_phrase: Option<Zeroizing<String>>,
    /// The backup file first run is restoring from, and what its header
    /// says. Drives the custody the vault is written with, and the notes
    /// that are put back once it is unlocked.
    restore_source: Option<kenter_ui::RestoreSource>,
    /// The file's **bytes**, read when it was chosen, not its path.
    ///
    /// Held in memory because the restore happens after the wallet has been
    /// created and opened, and by then several things have written to the
    /// directory the file may be sitting in. Keeping a path meant the
    /// notes were read from whatever was at that path *later*, which is a
    /// race the holder would lose silently and completely.
    restore_bytes: Option<Vec<u8>>,
    /// Symbols scanned off paper so far. Lives on the app rather than in
    /// the view because a scan is cumulative across several file dialogs
    /// and the view is rebuilt on every paint.
    sheet: Option<kenter_wallet::paper::Sheet>,
    /// The scan screen was opened from the first-run restore, before any
    /// wallet exists. Its exits lead back to that screen rather than to a
    /// billfold there is not yet a key for.
    scan_for_setup: bool,
    /// What the phrase was found to be against the scanned sheets: whether
    /// these are a card wallet's words, and the fingerprint they share.
    ///
    /// Set when the phrase is checked and taken when the wallet first
    /// opens, at which point the sheet is restored. Its presence is the
    /// signal that there are sheets waiting to go in.
    paper_origin: Option<(bool, String)>,
    /// The running capture thread. Dropping it releases the device, so
    /// every exit from the scan screen goes through that.
    capture: Option<kenter_ui::camera::Capture>,
    /// What the scan screen says about the camera.
    camera: kenter_ui::CameraView,
    /// The most recent frame, kept out of the view because it changes a
    /// dozen times a second and the view is rebuilt from scratch on every
    /// state change.
    frame: Option<(u32, u32, Vec<u8>)>,
    /// The card's PIN, duress PIN and PUK while first run is collecting
    /// them.
    ///
    /// Here rather than in `SetupState` for the same reason `PromptView`
    /// holds a character count and not a passphrase: a view model is cloned
    /// into a layout tree, printed by `Debug`, and rendered into PNGs by the
    /// mock. These are zeroized when first run ends, whichever way it ends.
    card_secrets: CardSecrets,
    /// Set to stop the receive worker. It watches the inbox indefinitely once
    /// an address exists, so leaving the page has to tell it to stop — nothing
    /// else will, and a window can be closed with a thread still polling.
    cancel: Arc<AtomicBool>,
    /// Set while a prompt is up: the channel the waiting worker is blocked on.
    /// Answering it is the only thing that unblocks that worker, so every path
    /// that leaves a prompt must send something.
    reply: Option<mpsc::Sender<Option<Zeroizing<Vec<u8>>>>>,
    /// The accepted passphrase, held for the session so signing does not
    /// prompt again. This is what `Policy::Session` is:
    /// the passphrase's at-rest job is done once the vault is open, and its
    /// intent job is given up deliberately in exchange for a usable client.
    session: Option<Zeroizing<Vec<u8>>>,
    /// What opens the vault holding the **submitting account**.
    ///
    /// Not the same as `session` on a card wallet. Owner keys are signed on
    /// the card with the PIN; the fee-paying Stellar account lives in a
    /// software vault opened by BIP85 child 2. Using one for the other is
    /// how the activation gate came to report "no passphrase in hand to
    /// sign with" on a wallet that has no passphrase by design.
    ///
    /// The same value as `session` for a software wallet.
    account_cred: Option<Zeroizing<Vec<u8>>>,
    /// The submitting account's address, derived from its key at unlock
    /// (`settings::verified_address`). `None` while locked. The only address
    /// shown as the holder's own or offered as a payout, because the vault's
    /// plaintext key list can be edited without the passphrase.
    account_address: Option<Result<Option<String>, String>>,
    /// Seals this wallet's backup, and names which wallet it is.
    ///
    /// Held for the session beside `creds`, from the same derivation: on a
    /// card wallet recomputing it is a tap and a PIN, and a backup that
    /// costs a ceremony is one nobody makes.
    backup: Option<kenter_vault::BackupCredentials>,
    /// Store keys for this session, once the holder has unlocked.
    ///
    /// `None` until the holder unlocks, and the billfold shows itself locked
    /// rather than empty.
    creds: Option<StoreCredentials>,
    /// What has been typed into the prompt.
    entry: Zeroizing<String>,
    /// The wallet has already been re-read for this receive. The watch sends a
    /// Ready every poll; without this each one would start an RPC sweep.
    receive_synced: bool,
}

impl App {
    fn new(proxy: EventLoopProxy<UiEvent>) -> Self {
        let wallet = WalletView::loading();
        App {
            account: AccountView::default(),
            account_cred: None,
            account_address: None,
            backup: None,
            card_secrets: CardSecrets::default(),
            ui: Ui::build_screen(&Screen::Wallet(wallet.clone())),
            screen: Screen::Wallet(wallet.clone()),
            wallet,
            it: Interaction::default(),
            cursor: (-1.0, -1.0),
            window: None,
            surface: None,
            proxy,
            loading: false,
            receiving: false,
            unlocking: false,
            setup_pass: None,
            activating: false,
            mods: winit::keyboard::ModifiersState::empty(),
            setup_phrase: None,
            restore_source: None,
            restore_bytes: None,
            sheet: None,
            scan_for_setup: false,
            paper_origin: None,
            capture: None,
            camera: kenter_ui::CameraView::Off,
            frame: None,
            cancel: Arc::new(AtomicBool::new(false)),
            reply: None,
            session: None,
            creds: None,
            entry: Zeroizing::new(String::new()),
            receive_synced: false,
        }
    }

    /// Put a screen on display: rebuild the tree (keeping the raster cache),
    /// re-run hit-testing under the cursor, and repaint.
    ///
    /// Hover is recomputed rather than carried over: the rebuilt tree may be a
    /// different shape, and a stale hover would highlight whatever element
    /// inherited that node id.
    fn show(&mut self, screen: Screen) {
        // A camera must not outlive the screen that owns it. Leaving the
        // paper flow by any route - Back, the nav bar, a worker finishing
        // - releases the device here, so no exit has to remember to.
        if self.capture.is_some() && !matches!(screen, Screen::Paper(_)) {
            self.capture = None;
            self.frame = None;
            self.camera = kenter_ui::CameraView::Off;
        }
        // Moving to a different page starts at the top; staying on the same
        // one keeps the position, so the inbox watch redrawing the address
        // screen every poll does not yank the holder back up.
        let same_page = screen.nav_index() == self.screen.nav_index();
        self.ui.rebuild(&screen);
        self.it.selected_nav = screen.nav_index();
        self.screen = screen;
        self.it.scroll = if same_page {
            self.ui.clamp_scroll(self.it.scroll)
        } else {
            0.0
        };
        self.it.hovered = self
            .ui
            .hit_test_with(self.cursor.0, self.cursor.1, &self.it);
        self.it.pressed = None;
        if let Some(w) = &self.window {
            w.request_redraw();
        }
    }

    /// Redraw the current screen after a change to the prompt's contents.
    /// Does the current screen have a text field taking keystrokes?
    ///
    /// While one does, every key belongs to it. Letting R through would fire
    /// a wallet refresh from a character the holder meant as part of their
    /// passphrase.
    fn is_typing(&self) -> bool {
        match &self.screen {
            Screen::Prompt { .. } => true,
            // The gate is a field with a button under it. Typing while an
            // unlock is already running would build a passphrase for an
            // attempt nobody asked for.
            Screen::Locked(v) => !v.busy,
            Screen::Reset(_) => true,
            Screen::Setup(SetupView { state }) => matches!(
                state,
                SetupState::Passphrase { .. }
                    | SetupState::Confirm { .. }
                    | SetupState::Restore { .. }
                    | SetupState::CardPin { .. }
                    | SetupState::CardDuress { .. }
                    // Only while the PUK is being typed back. While it is
                    // being read, keystrokes are not input and a stray one
                    // must not silently become a wrong answer.
                    | SetupState::CardPuk { confirming: true, .. }
                    | SetupState::CardConfirm { .. }
                    | SetupState::CardErase { .. }
            ),
            Screen::Deposit(DepositView { state }) => matches!(state, DepositState::Form { .. }),
            Screen::Pay(PayView { state }) => matches!(state, PayState::Address { .. }),
            Screen::Settings(v) => v.rpc_edit.as_ref().is_some_and(|e| !e.busy),
            Screen::Redeem(RedeemView { state }) => {
                matches!(state, RedeemState::Destination { .. })
            }
            _ => false,
        }
    }

    /// Repaint the field with the current character count. The characters
    /// themselves stay in `entry` and never enter the view model.
    fn refresh_entry(&mut self) {
        let n = self.entry.chars().count();
        match &self.screen {
            Screen::Prompt { view, under } => {
                let mut view = view.clone();
                view.entered = n;
                let under = *under;
                self.show(Screen::Prompt { view, under });
            }
            Screen::Reset(v) => {
                let mut v = v.clone();
                v.typed = self.entry.to_string();
                v.error = None;
                self.show(Screen::Reset(v));
            }
            Screen::Locked(v) => {
                // The error clears as soon as the next attempt is being
                // typed: leaving "wrong passphrase" up under a field someone
                // is already correcting says something that has stopped
                // being true.
                let busy = v.busy;
                // The reader line is carried, not re-read. Polling the card
                // on every keystroke would hammer a contactless reader that
                // already drops roughly every 1.6 s.
                let card = v.card.clone();
                self.show(Screen::Locked(LockedView {
                    entered: n,
                    error: None,
                    busy,
                    card,
                }));
            }
            Screen::Setup(SetupView { state }) => {
                let state = match state.clone() {
                    SetupState::Passphrase { error, .. } => {
                        SetupState::Passphrase { entered: n, error }
                    }
                    SetupState::Confirm {
                        positions, error, ..
                    } => SetupState::Confirm {
                        positions,
                        entered: n,
                        error,
                    },
                    SetupState::Restore {
                        error, file, paper, ..
                    } => SetupState::Restore {
                        entered: n,
                        error,
                        file,
                        paper,
                    },
                    SetupState::CardPin { again, error, .. } => SetupState::CardPin {
                        entered: n,
                        again,
                        error,
                    },
                    SetupState::CardDuress { again, error, .. } => SetupState::CardDuress {
                        entered: n,
                        again,
                        error,
                    },
                    SetupState::CardPuk {
                        puk,
                        confirming,
                        error,
                        ..
                    } => SetupState::CardPuk {
                        puk,
                        entered: n,
                        confirming,
                        error,
                    },
                    SetupState::CardConfirm {
                        positions, error, ..
                    } => SetupState::CardConfirm {
                        positions,
                        entered: n,
                        error,
                    },
                    // The word is shown, the PIN is counted.
                    SetupState::CardErase {
                        confirmed, error, ..
                    } => SetupState::CardErase {
                        confirmed,
                        typed: if confirmed {
                            String::new()
                        } else {
                            self.entry.to_string()
                        },
                        entered: n,
                        error,
                    },
                    other => other,
                };
                self.setup_keep(state);
            }
            Screen::Deposit(DepositView {
                state: DepositState::Form { spend, pairs, .. },
            }) => {
                let (spend, pairs) = (*spend, *pairs);
                self.show_deposit_form(spend, pairs, None);
            }
            Screen::Settings(v) if v.rpc_edit.is_some() => {
                let mut v = v.clone();
                if let Some(e) = v.rpc_edit.as_mut() {
                    e.typed = self.entry.to_string();
                    e.error = None;
                }
                self.show(Screen::Settings(v));
            }
            Screen::Pay(PayView {
                state: PayState::Address { row, error, .. },
            }) => {
                let (row, error) = (row.clone(), error.clone());
                let typed = self.entry.to_string();
                self.show(Screen::Pay(PayView {
                    state: PayState::Address { row, typed, error },
                }));
            }
            Screen::Redeem(RedeemView {
                state: RedeemState::Destination { quote, error, .. },
            }) => {
                let (quote, error) = (quote.clone(), error.clone());
                let typed = self.entry.to_string();
                self.show(Screen::Redeem(RedeemView {
                    state: RedeemState::Destination {
                        quote,
                        typed,
                        error,
                    },
                }));
            }
            _ => {}
        }
    }

    /// Rebuild the deposit form from what has been typed.
    ///
    /// The preview is recomputed on every keystroke rather than on submit,
    /// because the cost of granularity (D3) is only useful while the
    /// denomination is still being chosen.
    fn show_deposit_form(&mut self, spend: bool, pairs: u16, error: Option<String>) {
        let entered = self.entry.chars().count();
        let fee = deposit::ASSUMED_NODE_FEE;

        // The holder chooses the pair count; the network chooses who serves
        // (`docs/architecture/node-selection.md`).
        let pairs = pairs.max(3);
        let chosen = pairs - 2;
        let printer = format!(
            "{chosen} node{} chosen by the network - plus you at both ends",
            if chosen == 1 { "" } else { "s" },
        );
        let (preview, error) = match deposit::parse_amount(&self.entry) {
            Ok(amount) => match deposit::redemption_value(amount, pairs, fee) {
                Some(out) => (
                    Some(DepositPreview {
                        // The field shows a bare number: the symbol is on
                        // the label, and a prefix in an editable field would
                        // be something the caret can be put in front of.
                        face: kenter_wallet::fmt_stroops(amount)
                            .trim_start_matches(kenter_wallet::DEFAULT_SYMBOL)
                            .to_string(),
                        redeems_for: kenter_wallet::fmt_stroops(out),
                        fee: kenter_wallet::fmt_stroops(deposit::fees_for(pairs, fee)),
                    }),
                    error,
                ),
                // Caught here rather than at the contract, which would reject
                // it after the holder had committed to the figure.
                None => (
                    None,
                    Some(format!(
                        "too small for {pairs} pairs - the least you can print is {}",
                        kenter_wallet::fmt_stroops(deposit::floor(pairs, fee))
                    )),
                ),
            },
            Err(_) if entered == 0 => (None, error),
            Err(e) => (None, Some(e)),
        };
        self.show(Screen::Deposit(DepositView {
            state: DepositState::Form {
                entered,
                preview,
                spend,
                pairs,
                printer,
                error,
            },
        }));
    }

    /// Drive the pay screen. Returns true if the action belonged to it.
    fn pay_step(&mut self, action: Action) -> bool {
        let Screen::Pay(PayView { state }) = &self.screen else {
            return false;
        };
        match (state.clone(), action) {
            (PayState::Export { row, .. }, Action::ExportNote) => {
                self.export_note(row, kenter_wallet::ExportKind::Handover)
            }
            (PayState::Export { row, .. }, Action::ExportBackup) => {
                self.export_note(row, kenter_wallet::ExportKind::Backup)
            }

            // Q5: the client asks, and either answer is honest. Keeping it is
            // not negligence and removing it is not destruction - a backup
            // still holds the note either way.
            (PayState::Export { .. }, Action::KeepCopy) => {
                self.show_billfold();
                self.refresh();
            }
            (PayState::Export { row, .. }, Action::DropCopy) => self.mark_spent(row),

            (PayState::Address { row, .. }, Action::Confirm) => self.start_pay(row),

            _ => return false,
        }
        true
    }

    /// Write the container out, to a path the holder picks.
    ///
    /// The dialog runs here, on the event loop, rather than on the worker:
    /// a native modal wants the UI thread, and the OS owns input while it is
    /// up anyway, so blocking costs nothing a user can see. Only the write
    /// goes to a thread.
    ///
    /// `kind` is not cosmetic. `ExportKind::Handover` counts toward the
    /// note's exposure — the "someone else may redeem this first" figure on
    /// its card — and `Backup` deliberately does not, because a copy in the
    /// holder's own keeping is not a rival claimant.
    /// Ask where a note file should go.
    ///
    /// `None` means cancelled, which is an answer rather than an error:
    /// staying on the same screen with nothing changed is what "never mind"
    /// should look like.
    fn ask_where(&self, title: &str, id: &str) -> Option<std::path::PathBuf> {
        let start = kenter_ui::wallet::default_wallet_dir()
            .map(|d| pay::outbox_dir(&d))
            .unwrap_or_default();
        rfd::FileDialog::new()
            .set_title(title)
            .set_file_name(format!("{id}.symtoken"))
            .set_directory(&start)
            .add_filter("Kenter note", &["symtoken"])
            .save_file()
    }

    fn export_note(&mut self, row: PayableRow, kind: kenter_wallet::ExportKind) {
        let Some(creds) = self.creds.clone() else {
            return;
        };
        let title = match kind {
            kenter_wallet::ExportKind::Backup => "Save a backup of this note",
            _ => "Save the note to hand over",
        };
        let Some(dest) = self.ask_where(title, &row.id) else {
            return;
        };

        let proxy = self.proxy.clone();
        let id = row.id.clone();
        self.show(Screen::Pay(PayView {
            state: PayState::Working {
                what: "writing the file".into(),
            },
        }));
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let state = rt.block_on(async {
                match export_job(creds, &id, &dest, kind).await {
                    Ok(path) => PayState::Export {
                        row,
                        written: Some(path),
                        error: None,
                    },
                    Err(message) => PayState::Failed { message },
                }
            });
            let _ = proxy.send_event(UiEvent::Pay(state));
        });
    }

    fn mark_spent(&mut self, row: PayableRow) {
        let Some(creds) = self.creds.clone() else {
            return;
        };
        let creds2 = creds.clone();
        let proxy = self.proxy.clone();
        let id = row.id.clone();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            // Back to the billfold rather than to a list of notes: the
            // holder came here from a card, and the card is where the
            // result shows.
            if let Err(message) = rt.block_on(mark_spent_job(creds, &id)) {
                let _ = proxy.send_event(UiEvent::Pay(PayState::Failed { message }));
                return;
            }
            let _ = proxy.send_event(UiEvent::Wallet(load_view(Some(creds2))));
        });
    }

    fn start_pay(&mut self, row: PayableRow) {
        let (Some(creds), Some(session)) = (self.creds.clone(), self.session_creds()) else {
            return;
        };
        let address = self.entry.to_string();
        let commitment = match kenter_wallet::parse_receive_uri(&address) {
            Ok(c) => c,
            Err(e) => {
                // The address stays on screen with the error beside it, so
                // the holder can see what was wrong with what they pasted
                // rather than starting again from an empty field.
                self.show(Screen::Pay(PayView {
                    state: PayState::Address {
                        row,
                        typed: address,
                        error: Some(e.to_string()),
                    },
                }));
                return;
            }
        };
        // Where the file goes is asked here, before anything happens,
        // because the file has to be written before the pointer moves — the
        // reverse strands the note — so a dialog cancelled halfway through
        // would be a payment half made.
        let Some(dest) = self.ask_where("Save the note to send them", &row.id) else {
            return;
        };

        let proxy = self.proxy.clone();
        let id = row.id.clone();
        self.show(Screen::Pay(PayView {
            state: PayState::Working {
                what: "writing the file".into(),
            },
        }));
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let state = rt.block_on(async {
                match pay_job(&proxy, creds, session, &id, &dest, commitment).await {
                    Ok(()) => PayState::Paid {
                        where_to: hex::encode(commitment),
                        row,
                    },
                    Err(message) => PayState::Failed { message },
                }
            });
            let _ = proxy.send_event(UiEvent::Pay(state));
        });
    }

    /// Drive the deposit screen. Returns true if the action belonged to it.
    fn deposit_step(&mut self, action: Action) -> bool {
        let Screen::Deposit(DepositView { state }) = &self.screen else {
            // Done and Failed offer "Another", which restarts the form.
            return false;
        };
        match (state.clone(), action) {
            (DepositState::Form { spend, pairs, .. }, Action::ToggleMode) => {
                self.show_deposit_form(!spend, pairs, None);
            }
            (DepositState::Form { spend, pairs, .. }, Action::CyclePairs) => {
                // 3 is the minimum print (the mint's `min_pairs`); 8 is
                // mainnet's ceiling. Past a handful the fee and the floor
                // climb faster than the privacy is worth.
                let next = match pairs {
                    3 => 4,
                    4 => 5,
                    5 => 8,
                    _ => 3,
                };
                self.show_deposit_form(spend, next, None);
            }
            (DepositState::Form { spend, pairs, .. }, Action::Deposit | Action::Confirm) => {
                self.start_deposit(spend, pairs);
            }
            (DepositState::Done { .. } | DepositState::Failed { .. }, Action::Continue) => {
                self.entry = Zeroizing::new(String::new());
                self.show_deposit_form(false, 3, None);
            }
            _ => return false,
        }
        true
    }

    fn start_deposit(&mut self, spend: bool, pairs: u16) {
        let amount = match deposit::parse_amount(&self.entry) {
            Ok(a) => a,
            Err(e) => {
                self.show_deposit_form(spend, pairs, Some(e));
                return;
            }
        };
        let (Some(creds), Some(session)) = (self.creds.clone(), self.session_creds()) else {
            self.show_deposit_form(spend, pairs, Some("unlock first".into()));
            return;
        };
        let proxy = self.proxy.clone();
        self.show(Screen::Deposit(DepositView {
            state: DepositState::Working {
                what: "starting".into(),
            },
        }));
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let state = rt.block_on(deposit_job(&proxy, creds, session, amount, pairs, spend));
            let _ = proxy.send_event(UiEvent::Deposit(state));
        });
    }

    /// Answer the waiting worker and clear the entry either way.
    ///
    /// `None` declines. The worker is blocked until this runs, so it is called
    /// on every exit from a prompt — including the window closing.
    fn answer(&mut self, credential: Option<Zeroizing<Vec<u8>>>) {
        if let Some(tx) = self.reply.take() {
            let _ = tx.send(credential);
        }
        self.entry = Zeroizing::new(String::new());
    }

    /// Kick off a wallet read on a worker thread.
    fn refresh(&mut self) {
        if self.loading {
            return;
        }
        self.loading = true;
        let proxy = self.proxy.clone();
        let creds = self.creds.clone();
        let working = self.working_copy_inputs();
        std::thread::spawn(move || {
            // If the loop has already exited the send fails; nothing to do.
            let _ = proxy.send_event(UiEvent::Wallet(load_view(creds.clone())));
            // After the view, never before: the holder waits on the
            // billfold, and rewriting a spare copy is not worth a frame of
            // it. `refresh` runs after everything that changes the store,
            // which is exactly when this copy goes stale.
            if let Some((backup, seed)) = working {
                refresh_working_copy(creds, backup, seed);
            }
        });
    }

    /// Move to the page a sidebar entry names.
    ///
    /// Leaving the receive page always cancels its worker, whichever way the
    /// holder leaves - by the Back button, by Escape, or by clicking another
    /// nav entry. Missing one of those routes is how a thread survives the
    /// screen it belongs to.
    fn navigate(&mut self, index: usize) {
        // A scan opened from the first-run restore is still first run, on a
        // screen that is not a `Setup` one. Its own Back leads back to the
        // restore; the sidebar would lead to a billfold with no wallet.
        if self.scan_for_setup && matches!(self.screen, Screen::Paper(_)) {
            return;
        }
        // Nothing else is reachable until first run completes - there is no
        // store to show and no key to open it with. But a click that does
        // nothing at all reads as a broken window, which is how this was
        // first reported, so the refusal is said out loud on the one screen
        // that has somewhere to put it.
        if let Screen::Setup(SetupView { state }) = &self.screen {
            if let SetupState::Activate {
                address,
                funded,
                trustline_needed,
                ..
            } = state
            {
                let (address, funded, trustline_needed) =
                    (address.clone(), *funded, trustline_needed.clone());
                self.setup_keep(SetupState::Activate {
                    address,
                    copied: false,
                    funded,
                    trustline_needed,
                    busy: None,
                    error: Some(
                        "finish setting this account up first - the rest needs an \
                         account that can act"
                            .into(),
                    ),
                });
            }
            return;
        }
        // Any outstanding prompt is declined on the way out, whatever screen
        // it was over. Declining only for Receive would strand the *unlock*
        // worker when someone left its prompt by the sidebar: `reply` would
        // stay set, `unlocking` would stay true, and from then on Unlock
        // would do nothing and every later prompt would be auto-declined. A
        // worker blocked on a channel nobody will answer is a deadlock, and
        // it has to be impossible to walk away from rather than handled at
        // each exit.
        self.answer(None);
        if matches!(self.screen, Screen::Receive(_)) {
            self.stop_receive();
        }
        match index {
            1 => self.open_account(),
            2 => {
                self.entry = Zeroizing::new(String::new());
                self.show_deposit_form(false, 3, None);
            }
            3 => self.act(Action::Receive),
            4 => self.open_settings(),
            _ => {
                self.show_billfold();
                self.refresh();
            }
        }
    }

    /// Show what is known locally at once, then fill in the one fact that
    /// needs the ledger. The page is useful before the network answers, and
    /// still useful if it never does.
    fn open_settings(&mut self) {
        let account = self.shown_account();
        let view = settings::local(Network::current(), account.as_deref());
        self.show(Screen::Settings(view.clone()));
        let proxy = self.proxy.clone();
        let creds = self.creds.clone();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let filled = rt.block_on(async {
                let view = settings::with_account_status(view, Network::current(), account).await;
                // Only with the keys. The page is deliberately readable
                // while locked, and the store is sealed, so a locked client
                // shows no backup row rather than a wrong one.
                match creds
                    .and_then(|c| kenter_ui::wallet::default_wallet_dir().map(|d| (d, c)))
                    .and_then(|(d, c)| kenter_wallet::FileStore::open(&d, c).ok())
                {
                    Some(store) => settings::with_backup(view, &store).await,
                    None => view,
                }
            });
            let _ = proxy.send_event(UiEvent::Settings(filled));
        });
    }

    fn setup(&mut self, state: SetupState) {
        self.entry = Zeroizing::new(String::new());
        self.show(Screen::Setup(SetupView { state }));
    }

    /// Drive first run one step. Returns true if the action belonged to it.
    /// The custody screen, with a fresh look at the reader.
    ///
    /// Taken on arrival so a holder learns there is no reader *before*
    /// choosing the card, not after — the same reason `receive::readiness`
    /// runs when its page opens.
    fn custody_state(&self, error: Option<String>) -> SetupState {
        let found = kenter_ui::card::readiness();
        SetupState::Custody {
            // A phrase already in hand means this is a restore. The screen
            // asks the same question and means something different by it.
            restoring: self.setup_phrase.is_some(),
            card: Some(found.message()),
            card_ok: found.can_continue(),
            error,
        }
    }

    /// Generate the PUK and show it.
    ///
    /// One place, because it is reached from two: finishing the duress PIN,
    /// and backing out of the confirm step. Backing out generates a *new*
    /// one rather than re-showing the old, which is deliberate - a holder
    /// who could not type it back probably wrote it down wrong, and the
    /// cheapest fix is a fresh one they copy carefully.
    fn show_card_puk(&mut self) {
        let pin = self.card_secrets.pin.clone().unwrap_or_default();
        let mut rng = rand::thread_rng();
        let puk = kenter_ui::card::generate_puk(&pin, &mut rng);
        self.card_secrets.puk = Some(puk.clone());
        self.setup(SetupState::CardPuk {
            puk: puk.to_string(),
            entered: 0,
            confirming: false,
            error: None,
        });
    }

    /// The RPC server field on Settings: open it, use what was typed, go
    /// back to the default, or close it. Returns whether it took `action`.
    fn rpc_step(&mut self, action: Action) -> bool {
        let Screen::Settings(v) = &self.screen else { return false };
        let editing = v.rpc_edit.is_some();
        match action {
            Action::EditRpc => {
                let net = Network::current();
                // Start from the holder's own server if they have one, so
                // a typo can be fixed rather than retyped.
                let start = if net.rpc_is_custom { net.rpc.to_string() } else { String::new() };
                self.entry = Zeroizing::new(start.clone());
                let mut v = v.clone();
                v.rpc_edit = Some(kenter_ui::RpcEdit {
                    typed: start,
                    network: net.name.to_string(),
                    ..Default::default()
                });
                self.show(Screen::Settings(v));
                true
            }
            Action::Confirm if editing => {
                let url = self.entry.trim().to_string();
                if url.is_empty() {
                    return true;
                }
                self.save_rpc(Some(url));
                true
            }
            Action::RpcDefault if editing => {
                self.save_rpc(None);
                true
            }
            Action::Cancel | Action::Back if editing => {
                self.entry = Zeroizing::new(String::new());
                let mut v = v.clone();
                v.rpc_edit = None;
                self.show(Screen::Settings(v));
                true
            }
            _ => false,
        }
    }

    /// Check and save an RPC server off the event loop: the check is a
    /// network round trip to a server that may not answer.
    fn save_rpc(&mut self, url: Option<String>) {
        if let Screen::Settings(v) = &self.screen {
            let mut v = v.clone();
            if let Some(e) = v.rpc_edit.as_mut() {
                e.busy = true;
                e.error = None;
            }
            self.show(Screen::Settings(v));
        }
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let result = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt
                    .block_on(Network::set_rpc(url.as_deref()))
                    .map(|net| net.rpc_client().host_only()),
                Err(e) => Err(format!("tokio runtime: {e}")),
            };
            let _ = proxy.send_event(UiEvent::RpcSaved(result));
        });
    }

    /// Erase the card, off the event loop.
    fn erase_card(&mut self, pin: Zeroizing<String>) {
        self.setup(SetupState::Working {
            what: "erasing the card".into(),
        });
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let r = kenter_ui::card_setup::erase(pin.as_bytes());
            let _ = proxy.send_event(UiEvent::CardErased(r));
        });
    }

    /// Set the card's PINs and ask it for a phrase, off the event loop.
    ///
    /// `INIT` and `GENERATE MNEMONIC` are a secure-channel open plus two
    /// commands over NFC, which is seconds, not milliseconds.
    fn start_card_phrase(&mut self) {
        let (Some(pin), Some(puk), Some(duress)) = (
            self.card_secrets.pin.clone(),
            self.card_secrets.puk.clone(),
            self.card_secrets.duress.clone(),
        ) else {
            self.setup(SetupState::Failed {
                message: "the card details are no longer in memory - start again. Nothing \
                          was written to the card."
                    .into(),
            });
            return;
        };
        self.setup(SetupState::Working {
            what: "setting up the card".into(),
        });
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let r = kenter_ui::card_setup::generate_phrase(
                pin.as_bytes(),
                puk.as_bytes(),
                duress.as_bytes(),
                24,
            );
            let _ = proxy.send_event(UiEvent::CardPhrase(r));
        });
    }

    /// Write the seed. The first irreversible step in the whole ceremony.
    fn write_card_seed(&mut self, phrase: Zeroizing<String>) {
        let Some(pin) = self.card_secrets.pin.clone() else {
            self.setup(SetupState::Failed {
                message: "the PIN is no longer in memory - start again.".into(),
            });
            return;
        };
        self.setup(SetupState::Working {
            what: "writing the key to the card".into(),
        });
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let r = kenter_ui::card_setup::load_phrase(&phrase, pin.as_bytes());
            let _ = proxy.send_event(UiEvent::CardSeeded(r));
        });
    }

    /// Set the card's PINs and write the holder's own phrase to it.
    ///
    /// The restore counterpart of `start_card_phrase` followed by
    /// `write_card_seed`. It has to do the `INIT` too: that is where the PIN
    /// comes from, and the creation path only gets one because
    /// `generate_phrase` happens to perform it on the way to asking for
    /// words this path already has.
    fn restore_card_seed(&mut self, phrase: Zeroizing<String>) {
        let (Some(pin), Some(puk), Some(duress)) = (
            self.card_secrets.pin.clone(),
            self.card_secrets.puk.clone(),
            self.card_secrets.duress.clone(),
        ) else {
            self.setup(SetupState::Failed {
                message: "the card details are no longer in memory - start again. Nothing \
                          was written to the card."
                    .into(),
            });
            return;
        };
        self.setup(SetupState::Working {
            what: "putting your key back on the card".into(),
        });
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let r = kenter_ui::card_setup::restore_to_card(
                &phrase,
                pin.as_bytes(),
                puk.as_bytes(),
                duress.as_bytes(),
            );
            let _ = proxy.send_event(UiEvent::CardSeeded(r));
        });
    }

    /// Derive the wallet's keys, make the account, write the backup.
    ///
    /// Off the event loop: BIP85 on a card is three secure-channel round
    /// trips over NFC, and the vault write is disk.
    fn finish_card_setup(&mut self) {
        let Some(pin) = self.card_secrets.pin.clone() else {
            self.setup(SetupState::Failed {
                message: "the PIN is no longer in memory. The card holds your key - unlock                           it to finish setting up."
                    .into(),
            });
            return;
        };
        self.setup(SetupState::Working {
            what: "setting up your account".into(),
        });
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let r = kenter_ui::card_setup::provision(pin.as_bytes());
            let _ = proxy.send_event(UiEvent::CardReady(r));
        });
    }

    fn setup_step(&mut self, action: Action) -> bool {
        let Screen::Setup(SetupView { state }) = &self.screen else {
            return false;
        };
        let state = state.clone();
        match (state, action) {
            (SetupState::Start, Action::NewWallet) => {
                // Where the key lives comes before anything else a new wallet
                // asks, because it decides what the later steps even are and
                // cannot be changed afterwards without moving every note.
                self.setup(self.custody_state(None));
            }
            (SetupState::Custody { .. }, Action::CheckCard) => {
                self.setup(self.custody_state(None));
            }
            (SetupState::Custody { .. }, Action::UseSoftware) => {
                self.setup(SetupState::Passphrase {
                    entered: 0,
                    error: None,
                });
            }
            (SetupState::Custody { .. }, Action::UseCard) => {
                // The reader is looked at again on the press rather than
                // trusted from page load: a card arrives or leaves between
                // the two, and acting on a stale answer is how a holder ends
                // up typing a PIN at nothing.
                let found = kenter_ui::card::readiness();
                if found.can_continue() {
                    self.card_secrets.clear();
                    self.setup(SetupState::CardIntro {
                        card: found.message(),
                        blank: matches!(found, kenter_ui::card::Readiness::Blank),
                    });
                } else {
                    self.setup(self.custody_state(Some(found.message())));
                }
            }
            (SetupState::CardIntro { .. }, Action::EraseCard) => {
                self.setup(SetupState::CardErase {
                    confirmed: false,
                    typed: String::new(),
                    entered: 0,
                    error: None,
                });
            }
            (SetupState::CardErase { confirmed, .. }, Action::Confirm) => {
                let typed = self.entry.to_string();
                if !confirmed {
                    // Case-insensitive: the point is that the warning was
                    // read, not that caps lock was found.
                    if !typed.trim().eq_ignore_ascii_case("erase") {
                        self.setup_keep(SetupState::CardErase {
                            confirmed: false,
                            typed,
                            entered: 0,
                            error: Some("type ERASE to confirm, or keep the card".into()),
                        });
                        return true;
                    }
                    self.setup(SetupState::CardErase {
                        confirmed: true,
                        typed: String::new(),
                        entered: 0,
                        error: None,
                    });
                    return true;
                }
                if let Err(e) = kenter_ui::card::check_pin("PIN", &typed, kenter_ui::card::PIN_LEN)
                {
                    self.setup_keep(SetupState::CardErase {
                        confirmed: true,
                        typed: String::new(),
                        entered: self.entry.chars().count(),
                        error: Some(e),
                    });
                    return true;
                }
                self.erase_card(Zeroizing::new(typed));
            }
            (SetupState::CardErase { .. }, Action::Back) => {
                self.setup(self.custody_state(None));
            }
            (SetupState::CardIntro { .. }, Action::Continue) => {
                self.setup(SetupState::CardPin {
                    entered: 0,
                    again: false,
                    error: None,
                });
            }
            (SetupState::CardIntro { .. }, Action::Back) => {
                self.card_secrets.clear();
                self.setup(self.custody_state(None));
            }

            // ---- PIN, twice -------------------------------------------
            (SetupState::CardPin { again, .. }, Action::Confirm) => {
                let typed = self.entry.to_string();
                if let Err(e) = kenter_ui::card::check_pin("PIN", &typed, kenter_ui::card::PIN_LEN)
                {
                    self.setup_keep(SetupState::CardPin {
                        entered: self.entry.chars().count(),
                        again,
                        error: Some(e),
                    });
                    return true;
                }
                if !again {
                    self.card_secrets.pending = Some(Zeroizing::new(typed));
                    self.setup(SetupState::CardPin {
                        entered: 0,
                        again: true,
                        error: None,
                    });
                } else if self.card_secrets.pending.as_deref() == Some(&typed) {
                    self.card_secrets.pin = self.card_secrets.pending.take();
                    self.setup(SetupState::CardDuress {
                        entered: 0,
                        again: false,
                        error: None,
                    });
                } else {
                    // Back to the first entry, not the second: there is
                    // nothing to compare against any more, and asking for
                    // the repeat of a PIN they may have mistyped first time
                    // would confirm the wrong one.
                    self.card_secrets.pending = None;
                    self.setup(SetupState::CardPin {
                        entered: 0,
                        again: false,
                        error: Some("those did not match - start again".into()),
                    });
                }
            }
            (SetupState::CardPin { .. }, Action::Back) => {
                self.card_secrets.clear();
                self.setup(self.custody_state(None));
            }

            // ---- duress PIN, twice, and never equal to the PIN ---------
            (SetupState::CardDuress { again, .. }, Action::Confirm) => {
                let typed = self.entry.to_string();
                let pin = self.card_secrets.pin.clone().unwrap_or_default();
                if let Err(e) = kenter_ui::card::check_duress(&pin, &typed) {
                    self.setup_keep(SetupState::CardDuress {
                        entered: self.entry.chars().count(),
                        again,
                        error: Some(e),
                    });
                    return true;
                }
                if !again {
                    self.card_secrets.pending = Some(Zeroizing::new(typed));
                    self.setup(SetupState::CardDuress {
                        entered: 0,
                        again: true,
                        error: None,
                    });
                } else if self.card_secrets.pending.as_deref() == Some(&typed) {
                    self.card_secrets.duress = self.card_secrets.pending.take();
                    self.show_card_puk();
                } else {
                    self.card_secrets.pending = None;
                    self.setup(SetupState::CardDuress {
                        entered: 0,
                        again: false,
                        error: Some("those did not match - start again".into()),
                    });
                }
            }
            // Declining still produces one: there is no "no duress PIN"
            // state on the card, so this generates and keeps it rather than
            // skipping a step.
            (SetupState::CardDuress { .. }, Action::SkipDuress) => {
                let pin = self.card_secrets.pin.clone().unwrap_or_default();
                let mut rng = rand::thread_rng();
                // Same generator as the PUK, so the same "not equal to the
                // PIN" rule applies; the first six digits are the duress PIN.
                let d = kenter_ui::card::generate_puk(&pin, &mut rng);
                self.card_secrets.duress = Some(Zeroizing::new(
                    d.chars().take(kenter_ui::card::PIN_LEN).collect(),
                ));
                self.show_card_puk();
            }
            (SetupState::CardDuress { .. }, Action::Back) => {
                self.card_secrets.pending = None;
                self.setup(SetupState::CardPin {
                    entered: 0,
                    again: false,
                    error: None,
                });
            }

            // ---- PUK: shown, then typed back ---------------------------
            (
                SetupState::CardPuk {
                    puk, confirming, ..
                },
                Action::Confirm,
            ) => {
                if !confirming {
                    self.setup(SetupState::CardPuk {
                        puk,
                        entered: 0,
                        confirming: true,
                        error: None,
                    });
                } else if kenter_ui::card::puk_matches(&puk, self.entry.as_str()) {
                    // Restoring: the words exist already and have been
                    // checked against the backup, so there is nothing to
                    // generate and nothing to confirm back. Asking a holder
                    // to retype three words they just typed in full would
                    // be ceremony for its own sake.
                    match self.setup_phrase.clone() {
                        Some(phrase) => self.restore_card_seed(phrase),
                        None => self.start_card_phrase(),
                    }
                } else {
                    self.setup_keep(SetupState::CardPuk {
                        puk,
                        entered: self.entry.chars().count(),
                        confirming: true,
                        error: Some("that is not the PUK shown - check what you wrote down".into()),
                    });
                }
            }
            // ---- the phrase, and the first write ----------------------
            (SetupState::CardPhrase { words, .. }, Action::Continue) => {
                self.setup(SetupState::CardConfirm {
                    positions: kenter_ui::setup::challenge(words.len()),
                    entered: 0,
                    error: None,
                });
            }
            (SetupState::CardPhrase { .. }, Action::Reveal) => {
                self.set_revealed(true);
            }
            (SetupState::CardPhrase { .. }, Action::Back) => {
                // Back from the phrase goes forward, not out: the card
                // already has its PINs, and re-running GENERATE MNEMONIC
                // would hand out words that no longer match anything the
                // holder has started writing down. The only way out of the
                // ceremony from here is to abandon it.
                let n = self
                    .setup_phrase
                    .as_deref()
                    .map_or(24, |p| p.split_whitespace().count());
                self.setup(SetupState::CardConfirm {
                    positions: kenter_ui::setup::challenge(n),
                    entered: 0,
                    error: None,
                });
            }
            (SetupState::CardConfirm { .. }, Action::Back) => {
                let words = self
                    .setup_phrase
                    .as_deref()
                    .map(|p| p.split_whitespace().map(String::from).collect())
                    .unwrap_or_default();
                self.setup(SetupState::CardPhrase {
                    words,
                    revealed: false,
                });
            }
            (SetupState::CardConfirm { positions, .. }, Action::Confirm) => {
                let Some(phrase) = self.setup_phrase.clone() else {
                    self.setup(SetupState::Failed {
                        message: "the phrase is no longer in memory - start the card setup \
                                  again. Nothing was written to the card."
                            .into(),
                    });
                    return true;
                };
                if !kenter_ui::setup::check(&phrase, &positions, self.entry.as_str()) {
                    self.setup_keep(SetupState::CardConfirm {
                        positions,
                        entered: self.entry.chars().count(),
                        error: Some(
                            "those are not the right words - check what you wrote down".into(),
                        ),
                    });
                    return true;
                }
                self.write_card_seed(phrase);
            }

            (SetupState::CardPuk { confirming, .. }, Action::Back) => {
                if confirming {
                    self.show_card_puk();
                } else {
                    self.setup(SetupState::CardDuress {
                        entered: 0,
                        again: false,
                        error: None,
                    });
                }
            }

            (SetupState::Custody { .. }, Action::Back) => {
                self.setup(SetupState::Start);
            }
            (SetupState::Start, Action::RestoreWallet) => {
                self.setup(SetupState::Restore {
                    entered: 0,
                    error: None,
                    file: self.restore_source.clone(),
                    paper: self.paper_summary(),
                });
            }

            (SetupState::Passphrase { .. }, Action::Confirm) => {
                // Short enough to guess is worse than none, because it
                // encrypts notes that are bearer instruments.
                if self.entry.chars().count() < 8 {
                    self.setup_keep(SetupState::Passphrase {
                        entered: self.entry.chars().count(),
                        error: Some("use at least 8 characters".into()),
                    });
                    return true;
                }
                self.setup_pass = Some(Zeroizing::new(self.entry.to_string()));
                // Restoring reaches this step with a phrase already in hand.
                // Generating one here would silently replace what the holder
                // just typed, and they would be set up as a different wallet
                // with no indication anything had gone wrong.
                if self.setup_phrase.is_some() {
                    self.finish_setup();
                    return true;
                }
                match setup::new_phrase() {
                    Ok(phrase) => {
                        let words = phrase
                            .split_whitespace()
                            .map(String::from)
                            .collect::<Vec<_>>();
                        self.setup_phrase = Some(phrase);
                        self.setup(SetupState::Phrase {
                            words,
                            revealed: false,
                        });
                    }
                    Err(message) => self.setup(SetupState::Failed { message }),
                }
            }

            (SetupState::Phrase { .. }, Action::Continue) => {
                let n = self
                    .setup_phrase
                    .as_ref()
                    .map(|p| p.split_whitespace().count())
                    .unwrap_or(24);
                self.setup(SetupState::Confirm {
                    positions: setup::challenge(n),
                    entered: 0,
                    error: None,
                });
            }

            (SetupState::Confirm { positions, .. }, Action::Confirm) => {
                let ok = self
                    .setup_phrase
                    .as_ref()
                    .is_some_and(|p| setup::check(p, &positions, &self.entry));
                if !ok {
                    self.setup_keep(SetupState::Confirm {
                        positions,
                        entered: self.entry.chars().count(),
                        error: Some("that is not what the phrase says".into()),
                    });
                    return true;
                }
                self.finish_setup();
            }
            // Back from Confirm returns to the phrase rather than the start:
            // it has been generated, and regenerating would discard a phrase
            // the holder may already have written down.
            (SetupState::Confirm { .. }, Action::Cancel) => {
                let words = self
                    .setup_phrase
                    .as_ref()
                    .map(|p| p.split_whitespace().map(String::from).collect())
                    .unwrap_or_default();
                self.setup(SetupState::Phrase {
                    words,
                    revealed: false,
                });
            }

            (SetupState::Restore { .. }, Action::Confirm) => {
                let phrase = self.entry.to_string();
                let keep = |app: &mut Self, error: String| {
                    let file = app.restore_source.clone();
                    let paper = app.paper_summary();
                    app.setup_keep(SetupState::Restore {
                        entered: app.entry.chars().count(),
                        error: Some(error),
                        file,
                        paper,
                    });
                };
                if let Err(error) = setup::validate_phrase(&phrase) {
                    keep(self, error);
                    return true;
                }
                // As early as it can go: the phrase is checked against the
                // file *before* a vault is built on it. The alternative is
                // discovering a mismatch at the end of restore, after
                // choosing a passphrase and funding an account that
                // belong to a wallet the holder did not mean to make.
                if let Some(source) = self.restore_source.clone() {
                    match setup::phrase_matches(&phrase, &source) {
                        Ok(true) => {}
                        Ok(false) => {
                            keep(
                                self,
                                "those words do not open that backup - check the phrase, \
                                 or choose the file that goes with it"
                                    .into(),
                            );
                            return true;
                        }
                        Err(e) => {
                            keep(self, e);
                            return true;
                        }
                    }
                }
                // The same check against paper, and at the same moment:
                // the sheets name their wallet in clear, so a wrong phrase
                // or the wrong folder of sheets is caught here rather than
                // after a vault and an account exist for it. A sheet does
                // not say which kind of wallet it is, so the match decides
                // that as well (`setup::phrase_opens_paper`).
                self.paper_origin = None;
                let sheet_wallet = self
                    .sheet
                    .as_ref()
                    .and_then(|s| s.wallet())
                    .map(String::from);
                if let Some(fingerprint) = sheet_wallet {
                    if let Some(file) = &self.restore_source {
                        if file.fingerprint != fingerprint {
                            keep(
                                self,
                                "the file and the sheets are from different wallets -                                  choose the file that goes with them, or scan the right                                  sheets"
                                    .into(),
                            );
                            return true;
                        }
                    }
                    match setup::phrase_opens_paper(&phrase, &fingerprint) {
                        Ok(Some(card_rooted)) => {
                            self.paper_origin = Some((card_rooted, fingerprint));
                        }
                        Ok(None) => {
                            keep(
                                self,
                                "those words do not open these sheets - check the phrase,                                  or the sheets may be from a different wallet"
                                    .into(),
                            );
                            return true;
                        }
                        Err(e) => {
                            keep(self, e);
                            return true;
                        }
                    }
                }
                self.setup_phrase = Some(Zeroizing::new(phrase));

                // A software wallet cannot become a card wallet by moving
                // its seed: a card derives the store and backup keys
                // through BIP85, so the same words on a card are a
                // *different wallet* that cannot read these notes
                // (see `docs/architecture/custody.md`). So the choice is
                // offered only when it is real - a card-rooted file, or no
                // file at all, where nothing here knows which kind these
                // words were.
                let offer_card = match self.restored_origin() {
                    Some((card_rooted, _)) => card_rooted,
                    None => true,
                };
                if offer_card {
                    self.setup(self.custody_state(None));
                } else {
                    self.setup(SetupState::Passphrase {
                        entered: 0,
                        error: None,
                    });
                }
            }

            (SetupState::Restore { .. }, Action::ChooseBackupFile) => {
                self.choose_backup_file();
            }

            // Paper on first run. The scan screen is the same one settings
            // opens; only its exits differ, and `scan_for_setup` is what
            // tells it.
            (SetupState::Restore { .. }, Action::ScanPaper) => {
                self.scan_for_setup = true;
                self.open_scan();
            }

            (
                SetupState::Activate {
                    funded,
                    trustline_needed,
                    ..
                },
                Action::Continue,
            ) if funded && trustline_needed.is_none() => {
                // Straight into a session with the passphrase just chosen.
                // The ordinary unlock path would prompt for it a third time,
                // which proves nothing the first two did not and left a
                // freshly created wallet showing as locked.
                let credential = self
                    .setup_pass
                    .as_ref()
                    .map(|p| Zeroizing::new(p.as_bytes().to_vec()));
                self.setup_pass = None;
                self.setup_phrase = None;
                let w = WalletView::locked();
                self.wallet = w.clone();
                self.show(Screen::Wallet(w));
                match credential {
                    Some(c) => {
                        self.unlocking = true;
                        receive::spawn_unlock_with(self.proxy.clone(), c);
                    }
                    // A restore that got here without one still has the
                    // prompt to fall back on.
                    None => self.start_unlock(),
                }
            }

            (SetupState::Failed { .. }, Action::Cancel)
            | (SetupState::Passphrase { .. }, Action::Cancel)
            | (SetupState::Restore { .. }, Action::Cancel) => {
                self.setup_pass = None;
                self.setup_phrase = None;
                self.restore_source = None;
                self.restore_bytes = None;
                self.sheet = None;
                self.scan_for_setup = false;
                self.paper_origin = None;
                self.setup(SetupState::Start);
            }

            _ => return false,
        }
        true
    }

    /// Show or hide the recovery phrase.
    ///
    /// Hiding purges the raster cache as well. `Label::secret` already keeps
    /// the phrase out of it, so this is belt and braces — it clears anything
    /// that reached the cache by another route, at the cost of one cold
    /// repaint on a screen nobody is timing.
    fn set_revealed(&mut self, revealed: bool) {
        // Both phrase screens, and for the same reason: hiding has to purge
        // the raster cache or the words stay in memory as a bitmap after
        // they have left the screen.
        let next = match &self.screen {
            Screen::Setup(SetupView {
                state: SetupState::Phrase { words, .. },
            }) => Some(SetupState::Phrase {
                words: words.clone(),
                revealed,
            }),
            Screen::Setup(SetupView {
                state: SetupState::CardPhrase { words, .. },
            }) => Some(SetupState::CardPhrase {
                words: words.clone(),
                revealed,
            }),
            _ => None,
        };
        if let Some(state) = next {
            if !revealed {
                self.ui.purge_cache();
            }
            self.setup_keep(state);
        }
    }

    /// Re-show a setup state without clearing what has been typed — for an
    /// error the holder should be able to correct rather than retype.
    fn setup_keep(&mut self, state: SetupState) {
        self.show(Screen::Setup(SetupView { state }));
    }

    /// The scanned sheets, as a line for the restore screen. `None` until
    /// a symbol of ours has been read.
    fn paper_summary(&self) -> Option<String> {
        let sheet = self.sheet.as_ref()?;
        let wallet = sheet.wallet()?;
        Some(format!("wallet {wallet} - {}", sheet.progress().describe()))
    }

    /// What kind of wallet is being restored, and its fingerprint, from
    /// whichever backup said so. The file's header names it outright; the
    /// sheets only answer once the phrase has been matched against them.
    /// `None` means nothing here knows, and the holder is asked.
    fn restored_origin(&self) -> Option<(bool, String)> {
        match (&self.restore_source, &self.paper_origin) {
            (Some(s), _) => Some((s.card_rooted, s.fingerprint.clone())),
            (None, Some(p)) => Some(p.clone()),
            (None, None) => None,
        }
    }

    /// Leave a first-run scan for the restore screen, sheets in hand.
    ///
    /// The phrase typed before the scan was opened is still in `entry`
    /// (the scan screen takes no keystrokes), so the field keeps its count
    /// rather than asking for the words again.
    fn back_to_restore(&mut self) {
        self.scan_for_setup = false;
        let entered = self.entry.chars().count();
        self.setup_keep(SetupState::Restore {
            entered,
            error: None,
            file: self.restore_source.clone(),
            paper: self.paper_summary(),
        });
    }

    /// The scan screen's exits while it was opened from first run.
    ///
    /// Back and the restore button both return to the restore screen: the
    /// one discards nothing (a holder can come back and scan more), and the
    /// other cannot restore yet - the key it needs comes from the phrase.
    fn setup_scan_step(&mut self, action: Action) -> bool {
        if !self.scan_for_setup || !matches!(self.screen, Screen::Paper(_)) {
            return false;
        }
        match action {
            Action::Back | Action::RestoreScanned => {
                self.back_to_restore();
                true
            }
            _ => false,
        }
    }

    /// Put the scanned sheets in, once the restored wallet is open.
    ///
    /// The paper counterpart of `restore_notes_after_setup`, and it lands
    /// on the paper result screen rather than quietly on the billfold:
    /// that screen names any note whose sheet was never scanned, which is
    /// the one thing a holder rebuilding from paper most needs to know.
    fn restore_paper_after_setup(&mut self) -> bool {
        if self.paper_origin.take().is_none() || self.sheet.is_none() {
            return false;
        }
        self.restore_scanned();
        true
    }

    /// Point first run at the backup the phrase goes with.
    ///
    /// Read before the phrase is asked for, because the header says which
    /// kind of wallet these words are for and the holder has no way to know.
    fn choose_backup_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Open your wallet backup")
            .add_filter("Kenter backup", &[kenter_ui::backup::EXT])
            .pick_file()
        else {
            return;
        };
        let entered = self.entry.chars().count();
        match setup::inspect_backup(&path).and_then(|source| {
            // Read now, while nothing else has touched the directory.
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("reading {}: {e}", path.display()))?;
            Ok((source, bytes))
        }) {
            Ok((source, bytes)) => {
                self.restore_source = Some(source.clone());
                self.restore_bytes = Some(bytes);
                self.setup_keep(SetupState::Restore {
                    entered,
                    error: None,
                    file: Some(source),
                    paper: self.paper_summary(),
                });
            }
            Err(e) => {
                let file = self.restore_source.clone();
                self.setup_keep(SetupState::Restore {
                    entered,
                    error: Some(e),
                    file,
                    paper: self.paper_summary(),
                });
            }
        }
    }

    /// Put the notes back, once the restored wallet is open.
    ///
    /// Runs after the unlock rather than with the vault write, because the
    /// store is sealed with keys that only exist once the wallet is open.
    /// Quiet on success: the billfold is about to show the notes, which
    /// says it better than a dialog.
    fn restore_notes_after_setup(&mut self) {
        let (Some(bytes), Some(creds), Some(backup)) = (
            self.restore_bytes.take(),
            self.creds.clone(),
            self.backup.clone(),
        ) else {
            return;
        };
        // Kept for the record below: the holder wants to be told where
        // their backup is, not merely that there is one.
        let whence = self.restore_source.take().map(|s| s.path);
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let outcome = rt.block_on(async {
                let dir = kenter_ui::wallet::default_wallet_dir()
                    .ok_or_else(|| "set KENTER_WALLET_DIR".to_string())?;
                let mut store =
                    kenter_wallet::FileStore::open(&dir, creds).map_err(|e| e.to_string())?;
                let contents =
                    kenter_ui::backup::open(&backup.key, &backup.fingerprint, &bytes)?;
                let report = kenter_wallet::backup::restore(&mut store, &contents)
                    .await
                    .map_err(|e| e.to_string())?;
                // The file the notes came out of is this wallet's backup.
                // Without this the first billfold after a recovery warns
                // about every note it has just handed back, which is false
                // and is the worst possible moment to be wrong.
                kenter_ui::backup::adopt(&mut store, &contents, whence).await?;
                Ok(report.tokens_added)
            });
            if let Err(e) = &outcome {
                eprintln!("kenter: could not restore the notes: {e}");
            }
            let _ = proxy.send_event(UiEvent::RestoredAtSetup(outcome));
        });
    }

    /// Write the vault. Argon2 makes this slow enough to matter.
    fn finish_setup(&mut self) {
        let (Some(pass), Some(phrase)) = (&self.setup_pass, &self.setup_phrase) else {
            self.setup(SetupState::Failed {
                message: "setup lost its place".into(),
            });
            return;
        };
        let pass = pass.clone();
        let phrase = phrase.clone();
        let proxy = self.proxy.clone();
        // How this wallet derives, from the backup header rather than from
        // a question: a card wallet rebuilt as a software one is silently
        // the wrong wallet (`setup::create_as`).
        let custody = match self.restored_origin() {
            Some((true, fingerprint)) => kenter_vault::Custody::RecoveredCard {
                seed_fingerprint: fingerprint,
            },
            _ => kenter_vault::Custody::Software,
        };
        self.setup(SetupState::Working {
            what: "writing the vault".into(),
        });
        std::thread::spawn(move || {
            let state = match setup::create_as(pass.as_bytes(), &phrase, custody) {
                Ok(address) => SetupState::Activate {
                    address,
                    copied: false,
                    funded: false,
                    trustline_needed: None,
                    busy: Some("asking the ledger about this account".into()),
                    error: None,
                },
                Err(message) => SetupState::Failed { message },
            };
            // Show the gate, then fill it in. The first look is almost
            // always "not funded", but it is read rather than assumed —
            // a restored wallet whose account already exists should not be
            // told to fund it again.
            let follow_up = matches!(state, SetupState::Activate { .. });
            let address = match &state {
                SetupState::Activate { address, .. } => address.clone(),
                _ => String::new(),
            };
            let _ = follow_up;
            let _ = address;
            let _ = proxy.send_event(UiEvent::Setup(state));
        });
    }

    /// Open the account page: the balances a deposit spends and a redemption
    /// fills.
    ///
    /// Needs an unlock, though everything on it is public ledger data. The
    /// vault's plaintext key list cannot be trusted for the address: anyone
    /// who can write the file can change it without the passphrase -- and
    /// this is the address the holder funds. The one
    /// address worth showing is derived from the key, and that takes the
    /// credential.
    fn open_account(&mut self) {
        if self.account_address.is_none() {
            self.show(Screen::Account(AccountView {
                error: Some(
                    "unlock to show your account - its address is read from your key,                      not from the vault file"
                        .into(),
                ),
                ..Default::default()
            }));
            self.start_unlock();
            return;
        }
        let address = match self.verified_account() {
            Ok(address) => address,
            Err(e) => {
                self.show(Screen::Account(AccountView {
                    error: Some(e),
                    ..Default::default()
                }));
                return;
            }
        };
        self.show(Screen::Account(AccountView {
            address: address.clone(),
            busy: Some("reading the ledger".into()),
            error: None,
            // Last known figures, not blanks. Only `address` is forced: the
            // cache may be empty on the first visit, and it is the one field
            // that is known without asking anybody.
            ..self.account.clone()
        }));
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            // A read that cannot start has to say so. Returning quietly left
            // the page on "reading the ledger" with nothing behind it and no
            // way to tell a slow network from a dead worker.
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = proxy.send_event(UiEvent::Account(AccountView {
                        address,
                        error: Some(format!("could not start the ledger read: {e}")),
                        ..Default::default()
                    }));
                    return;
                }
            };
            let a = rt.block_on(account::read(Network::current(), &address));
            let fmt = kenter_wallet::fmt_amount;
            let view = AccountView {
                address: a.address.clone(),
                xlm: a
                    .holdings
                    .as_ref()
                    .map(|h| fmt(h.native.max(0) as u64, "XLM "))
                    .unwrap_or_else(|| "none - this account does not exist yet".into()),
                xlm_spendable: a
                    .holdings
                    .as_ref()
                    .map(|h| fmt(h.spendable_native().max(0) as u64, "XLM "))
                    .unwrap_or_else(|| "none".into()),
                asset_code: a.asset_code.clone().unwrap_or_else(|| "asset".into()),
                asset_balance: kenter_wallet::fmt_stroops(a.asset_balance().max(0) as u64),
                trustline: a.has_trustline(),
                blocked_by: a.blocked_by(),
                copied: false,
                stalled: Vec::new(),
                busy: None,
                error: a.error.clone(),
            };
            let _ = proxy.send_event(UiEvent::Account(view.clone()));

            // Second pass: the scan is one ledger read per slot, so it runs
            // after the page is already useful rather than holding it up.
            let stalled = rt
                .block_on(account::stalled_prints(Network::current(), &address))
                .unwrap_or_default();
            if !stalled.is_empty() {
                let mut view = view;
                view.stalled = stalled
                    .into_iter()
                    .map(|s| kenter_ui::StalledPrint {
                        slot_id: s.slot_id,
                        amount: kenter_wallet::fmt_stroops(s.amount.max(0) as u64),
                        progress: format!("{} of {} links confirmed", s.confirmed, s.total),
                    })
                    .collect();
                let _ = proxy.send_event(UiEvent::Account(view));
            }
        });
    }

    /// Cancel a stalled print and take the escrow back.
    ///
    /// The contract has always allowed this — depositor-only, state
    /// `Printing`, full refund, no expiry — and until now nothing called it,
    /// so a print that died mid-walk took the deposit with it for good.
    fn recover_escrow(&mut self, slot_id: u32) {
        // Cancelling a print is a transaction the submitting account pays
        // for, so this is the account credential, not the owner-key one.
        let Some(session) = self.account_cred.clone() else {
            self.start_unlock();
            return;
        };
        let Screen::Account(v) = &self.screen else {
            return;
        };
        let mut v = v.clone();
        v.busy = Some(format!("cancelling print {slot_id}"));
        self.show(Screen::Account(v));

        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            match rt.block_on(account::cancel(Network::current(), &session, slot_id)) {
                Ok(refund) => eprintln!(
                    "kenter: print {slot_id} cancelled, {} refunded",
                    kenter_wallet::fmt_stroops(refund.max(0) as u64)
                ),
                Err(e) => eprintln!("kenter: could not cancel print {slot_id}: {e}"),
            }
            // Re-read either way: the ledger is the answer to whether the
            // money came back, not what this thread believes it did.
            let _ = proxy.send_event(UiEvent::Reopen);
        });
    }

    /// The note at this index of the open compartment.
    fn note_at(&self, i: usize) -> Option<NoteCard> {
        let view = match &self.screen {
            Screen::Wallet(v) => v,
            _ => &self.wallet,
        };
        view.tabs.get(view.selected_tab)?.notes.get(i).cloned()
    }

    /// Hand this note over, straight from its card.
    ///
    /// No picker in between: the holder has already chosen the note by
    /// opening it. The branch is the same one the picker makes — a bearer
    /// note has nothing to sign, a spend-mode note has nothing to hand over
    /// on its own — and `NoteCard` already carries every field a
    /// `PayableRow` needs, so this costs no read.
    fn pay_from_card(&mut self, i: usize) {
        let Some(n) = self.note_at(i) else { return };
        if self.creds.is_none() {
            self.start_unlock();
            return;
        }
        let row = PayableRow {
            id: n.id,
            short_id: n.short_id,
            amount: n.amount,
            spend_mode: n.spend_mode,
            exposure: n.exposure,
        };
        self.entry = Zeroizing::new(String::new());
        let state = if row.spend_mode {
            PayState::Address {
                row,
                typed: String::new(),
                error: None,
            }
        } else {
            PayState::Export {
                row,
                written: None,
                error: None,
            }
        };
        self.show(Screen::Pay(PayView { state }));
    }

    /// Redeem this note, straight from its card.
    ///
    /// Unlike Pay this needs a read: the quote is face minus *this note's*
    /// own fees, which depends on its pair count, and the payout account
    /// comes from the vault. So it goes through the same quoting path the
    /// picker uses and lands on the confirmation rather than skipping it —
    /// the one screen before an irreversible act is not the one to drop.
    fn redeem_from_card(&mut self, i: usize) {
        let Some(n) = self.note_at(i) else { return };
        let Some(creds) = self.creds.clone() else {
            self.start_unlock();
            return;
        };
        let to = match self.verified_account() {
            Ok(to) => to,
            Err(message) => {
                self.show(Screen::Redeem(RedeemView {
                    state: RedeemState::Failed { message },
                }));
                return;
            }
        };
        let proxy = self.proxy.clone();
        let id = n.id.clone();
        self.show(Screen::Redeem(RedeemView {
            state: RedeemState::Working {
                what: format!("pricing {}", n.short_id),
            },
        }));
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let state = rt.block_on(async {
                match redeem_quotes(creds, to).await {
                    Ok(notes) => match notes.into_iter().find(|q| q.id == id) {
                        Some(quote) => RedeemState::Confirm { quote },
                        // Quoting leaves out notes whose fees exceed their
                        // face, so a missing one is a real answer.
                        None => RedeemState::Failed {
                            message:
                                "this note cannot be redeemed - its fees exceed its face value"
                                    .into(),
                        },
                    },
                    Err(message) => RedeemState::Failed { message },
                }
            });
            let _ = proxy.send_event(UiEvent::Redeem(state));
        });
    }

    /// Drive the redemption screen. Returns true if the action belonged to it.
    fn redeem_step(&mut self, action: Action) -> bool {
        let Screen::Redeem(RedeemView { state }) = &self.screen else {
            return false;
        };
        match (state.clone(), action) {
            (RedeemState::Confirm { quote }, Action::Confirm) => self.start_redeem(quote),
            (RedeemState::Confirm { quote }, Action::EditDestination) => {
                // Start empty rather than pre-filled with the holder's own
                // address: editing 56 characters in place is worse than
                // pasting the one they mean, and a half-edited address that
                // still parses is the failure to avoid.
                self.entry.clear();
                self.show(Screen::Redeem(RedeemView {
                    state: RedeemState::Destination {
                        quote,
                        typed: String::new(),
                        error: None,
                    },
                }));
            }
            (RedeemState::Destination { quote, typed, .. }, Action::Confirm) => {
                self.accept_destination(quote, typed)
            }
            (RedeemState::Destination { mut quote, .. }, Action::UseOwnAccount) => {
                quote.to_account = quote.own_account.clone();
                self.entry.clear();
                self.show(Screen::Redeem(RedeemView {
                    state: RedeemState::Confirm { quote },
                }));
            }
            // Back belongs to this screen before it belongs to the wallet:
            // backing out of choosing a destination means abandoning the
            // choice, not abandoning the redemption.
            (RedeemState::Destination { quote, .. }, Action::Back) => {
                self.entry.clear();
                self.show(Screen::Redeem(RedeemView {
                    state: RedeemState::Confirm { quote },
                }));
            }
            _ => return false,
        }
        true
    }

    /// Take the typed account as the destination, if the ledger will have it.
    ///
    /// Two checks, both before the irreversible step. The address has to
    /// parse, and the account has to be able to hold the asset: a transfer
    /// to an account with no trustline makes the whole redemption trap, so
    /// without this the holder presses Redeem and gets a contract error
    /// number where "they cannot receive USDC" is the actual reason.
    fn accept_destination(&mut self, quote: RedeemQuote, typed: String) {
        let address = typed.trim().to_string();
        let refuse = |app: &mut Self, quote: RedeemQuote, msg: String| {
            app.show(Screen::Redeem(RedeemView {
                state: RedeemState::Destination {
                    quote,
                    typed: typed.trim().to_string(),
                    error: Some(msg),
                },
            }));
        };
        if address.is_empty() {
            refuse(self, quote, "type or paste an account address".into());
            return;
        }
        if let Err(e) = kenter_client::tx::address_xdr(&address) {
            refuse(self, quote, format!("not an account address: {e}"));
            return;
        }
        if address == quote.own_account {
            // Not an error - just the default, reached the long way.
            let mut quote = quote;
            quote.to_account = quote.own_account.clone();
            self.entry.clear();
            self.show(Screen::Redeem(RedeemView {
                state: RedeemState::Confirm { quote },
            }));
            return;
        }
        let proxy = self.proxy.clone();
        self.show(Screen::Redeem(RedeemView {
            state: RedeemState::Working {
                what: format!("checking {}", kenter_ui::wallet::short(&address)),
            },
        }));
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let state = rt.block_on(async {
                let account = account::read(Network::current(), &address).await;
                let refused = if account.holdings.is_none() {
                    Some("this account does not exist on the ledger yet".to_string())
                } else if account.has_trustline() == Some(false) {
                    let code = account
                        .asset_code
                        .clone()
                        .unwrap_or_else(|| "the asset".into());
                    Some(format!(
                        "this account has no {code} trustline, so it cannot be paid"
                    ))
                } else {
                    // `None` means the asset is still unknown, which is not
                    // the same as "no trustline" and must not be shown as a
                    // refusal. The contract is the real check either way.
                    None
                };
                match refused {
                    Some(message) => RedeemState::Destination {
                        quote,
                        typed: address.clone(),
                        error: Some(message),
                    },
                    None => {
                        let mut quote = quote;
                        quote.to_account = address.clone();
                        RedeemState::Confirm { quote }
                    }
                }
            });
            let _ = proxy.send_event(UiEvent::Redeem(state));
        });
    }

    fn start_redeem(&mut self, quote: RedeemQuote) {
        let (Some(creds), Some(session)) = (self.creds.clone(), self.session_creds()) else {
            return;
        };
        let proxy = self.proxy.clone();
        let id = quote.id.clone();
        // Whatever the confirmation screen showed as the destination. It
        // defaults to this client's own account, but it is the quote's
        // field rather than an assumption, so paying someone else is a
        // change of one value and not of this code path.
        let to = quote.to_account.clone();
        self.show(Screen::Redeem(RedeemView {
            state: RedeemState::Working {
                what: "burning the note".into(),
            },
        }));
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let state = rt.block_on(async {
                match redeem_job(creds, session, &id, &to).await {
                    Ok(paid) => RedeemState::Done {
                        paid: kenter_wallet::fmt_stroops(paid.max(0) as u64),
                        to_account: quote.to_account,
                    },
                    Err(message) => RedeemState::Failed { message },
                }
            });
            let _ = proxy.send_event(UiEvent::Redeem(state));
        });
    }

    /// Open a compartment of the billfold.
    ///
    /// Closes whatever card was open: the index refers to a position in the
    /// tab being left, and carrying it across would expand an unrelated note.
    fn billfold_tab(&mut self, i: usize) {
        let mut w = self.wallet.clone();
        w.selected_tab = i;
        w.expanded = None;
        self.wallet = w.clone();
        self.show(Screen::Wallet(w));
    }

    /// Establish the trustline the mint's asset needs.
    ///
    /// Not part of first run, and not because it was forgotten: a
    /// `ChangeTrust` needs the account to exist, and at the end of first run
    /// it has not been funded yet. So the order is create, fund, trust — and
    /// the middle step happens outside this client.
    fn add_trustline(&mut self) {
        // Two screens offer this, and they hold the credential in different
        // places: Settings runs after an unlock, first run runs before one
        // has ever happened. Taking either beats making someone unlock a
        // vault they created ten seconds ago.
        let Some(session) = self.account_cred.clone().or_else(|| {
            self.session.clone().or_else(|| {
                self.setup_pass
                    .as_ref()
                    .map(|p| Zeroizing::new(p.as_bytes().to_vec()))
            })
        }) else {
            return;
        };
        let proxy = self.proxy.clone();

        // From first run, the answer goes back to the gate rather than to a
        // settings page nobody has opened.
        if let Screen::Setup(SetupView {
            state: SetupState::Activate { address, .. },
        }) = &self.screen
        {
            let address = address.clone();
            self.setup_keep(SetupState::Activate {
                address: address.clone(),
                copied: false,
                funded: true,
                trustline_needed: None,
                busy: Some("adding the trustline".into()),
                error: None,
            });
            std::thread::spawn(move || {
                let Ok(rt) = tokio::runtime::Runtime::new() else {
                    return;
                };
                let net = Network::current();
                let error = rt.block_on(submit_trustline(net, &session)).err();
                let a = rt.block_on(setup::activation(net, &address));
                let _ = proxy.send_event(UiEvent::Setup(SetupState::Activate {
                    address,
                    copied: false,
                    funded: a.funded,
                    trustline_needed: a.trustline_needed,
                    busy: None,
                    error: error.or(a.unreachable),
                }));
            });
            return;
        }

        if let Screen::Account(v) = &self.screen {
            let mut v = v.clone();
            v.busy = Some("adding the trustline".into());
            self.show(Screen::Account(v));
            std::thread::spawn(move || {
                let Ok(rt) = tokio::runtime::Runtime::new() else {
                    return;
                };
                if let Err(e) = rt.block_on(submit_trustline(Network::current(), &session)) {
                    eprintln!("trustline: {e}");
                }
                // Re-read rather than patching the row: the ledger is the
                // answer to "is there a trustline now", not what this thread
                // believes it just did.
                let _ = proxy.send_event(UiEvent::Reopen);
            });
            return;
        }

        let mut view = match &self.screen {
            Screen::Settings(v) => v.clone(),
            _ => return,
        };
        view.trustline_needed = None;
        view.rows.push(("trustline".into(), "adding…".into()));
        self.show(Screen::Settings(view));

        let account = self.shown_account();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let net = Network::current();
            let outcome = rt.block_on(submit_trustline(net, &session));
            // Re-read rather than patching the row: the ledger is the answer
            // to "is there a trustline now", not what this thread believes.
            let mut view = settings::local(Network::current(), account.as_deref());
            if let Err(e) = outcome {
                view.note = Some(format!("could not add the trustline: {e}"));
            }
            let filled =
                rt.block_on(settings::with_account_status(view, Network::current(), account));
            let _ = proxy.send_event(UiEvent::Settings(filled));
        });
    }

    /// Write the wallet's backup where the holder says.
    ///
    /// The file plus the recovery phrase *is* the wallet,
    /// so the dialog starts somewhere other than the wallet directory: a
    /// backup saved beside the thing it backs up is not one, and the default
    /// path is what most people will accept.
    fn save_backup(&mut self) {
        let (Some(creds), Some(backup)) = (self.creds.clone(), self.backup.clone()) else {
            self.note_settings("unlock first - the backup is sealed with the wallet's own key");
            return;
        };
        let seed = kenter_ui::backup::seed_source(self.custody().as_ref(), &backup.fingerprint);
        let Some(dest) = rfd::FileDialog::new()
            .set_title("Save your wallet backup")
            .set_file_name(kenter_ui::backup::file_name(&backup.fingerprint))
            .add_filter("Kenter backup", &[kenter_ui::backup::EXT])
            .save_file()
        else {
            return;
        };

        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let note = rt.block_on(async {
                let dir = kenter_ui::wallet::default_wallet_dir()
                    .ok_or_else(|| "set KENTER_WALLET_DIR".to_string())?;
                let mut store = kenter_wallet::FileStore::open(&dir, creds)
                    .map_err(|e| e.to_string())?;
                kenter_ui::backup::save(
                    &mut store,
                    &backup.key,
                    &seed,
                    &dest,
                    kenter_ui::backup::now(),
                )
                .await
            });
            let _ = proxy.send_event(UiEvent::BackupDone(
                note.map(|p| p.display().to_string()),
            ));
        });
    }

    /// Merge a backup file into this wallet.
    ///
    /// Additive, so this cannot lose anything: a note already held is kept
    /// exactly as it is, and only notes the wallet does not have are added
    /// (`kenter_wallet::backup::restore`). That is what lets it be a button
    /// rather than a ceremony with a confirmation.
    fn restore_backup(&mut self) {
        let (Some(creds), Some(backup)) = (self.creds.clone(), self.backup.clone()) else {
            self.note_settings("unlock first - a backup is sealed with the wallet's own key");
            return;
        };
        let Some(src) = rfd::FileDialog::new()
            .set_title("Open a wallet backup")
            .add_filter("Kenter backup", &[kenter_ui::backup::EXT])
            .pick_file()
        else {
            return;
        };

        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let note = rt.block_on(async {
                let dir = kenter_ui::wallet::default_wallet_dir()
                    .ok_or_else(|| "set KENTER_WALLET_DIR".to_string())?;
                let mut store = kenter_wallet::FileStore::open(&dir, creds)
                    .map_err(|e| e.to_string())?;
                let report = kenter_ui::backup::restore_file(
                    &mut store,
                    &backup.key,
                    &backup.fingerprint,
                    &src,
                )
                .await?;
                Ok(if report.is_empty() {
                    "nothing new - every note in that file was already here".to_string()
                } else {
                    format!(
                        "restored {} note{}{}",
                        report.tokens_added,
                        if report.tokens_added == 1 { "" } else { "s" },
                        if report.tokens_kept > 0 {
                            format!(" - {} were already here", report.tokens_kept)
                        } else {
                            String::new()
                        }
                    )
                })
            });
            let _ = proxy.send_event(UiEvent::Restored(note));
        });
    }

    /// Check the spend notes a restore just brought in really belong to
    /// this wallet.
    ///
    /// Runs here and not in the billfold refresh for two reasons: the
    /// refresh has no vault by design (it is a read path), and each note
    /// costs a key derivation, which on a card is an NFC round trip. A
    /// restore is where unverified records enter, so it is where the check
    /// belongs — once, not on every paint.
    ///
    /// Reports only when something changed. A clean result is the normal
    /// one and saying so would be noise.
    fn verify_restored_ownership(&mut self) {
        let (Some(creds), Some(owner)) = (self.creds.clone(), self.session.clone()) else {
            return;
        };
        let custody = self.custody();
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let outcome = rt.block_on(async {
                let net = Network::current();
                let dir = kenter_ui::wallet::default_wallet_dir()
                    .ok_or_else(|| "set KENTER_WALLET_DIR".to_string())?;
                let vault_path =
                    receive::default_vault_path().ok_or("set KENTER_VAULT")?;
                let soft = kenter_vault::SoftVault::open(&vault_path)
                    .map_err(|e| e.to_string())?;
                let vault = kenter_ui::vault::GuiVault::open(custody.as_ref(), soft)
                    .map_err(|e| e.to_string())?;
                let store = kenter_wallet::FileStore::open(&dir, creds)
                    .map_err(|e| e.to_string())?;
                let chain = kenter_client::WalletChain::new(kenter_client::MintClient::new(
                    kenter_client::TxBuilder::new(
                        net.rpc_client(),
                        kenter_crypto::keypair::StellarKeypair::random(),
                    ),
                    net.contract,
                ));
                let mut wallet = kenter_wallet::TokenWallet::with_vault(chain, store, vault);
                wallet
                    .verify_ownership(&owner)
                    .await
                    .map_err(|e| e.to_string())
            });
            let _ = proxy.send_event(UiEvent::OwnershipChecked(outcome));
        });
    }

    /// Paint the billfold from the store, with no ledger.
    ///
    /// Instant, and honest: every note reads unverified until the sweep
    /// comes back. Falls back to the spinner when the store cannot be
    /// opened, which is the same thing the reconciled path would do.
    fn show_local(&mut self) {
        let view = self
            .creds
            .clone()
            .zip(kenter_ui::wallet::default_wallet_dir())
            .and_then(|(creds, dir)| kenter_ui::wallet::load_local(&dir, creds))
            .unwrap_or_else(WalletView::loading);
        self.wallet = view.clone();
        self.show(Screen::Wallet(view));
    }

    /// What the working copy needs, or `None` while locked.
    fn working_copy_inputs(
        &self,
    ) -> Option<(
        kenter_vault::BackupCredentials,
        kenter_wallet::backup::SeedSource,
    )> {
        let backup = self.backup.clone()?;
        let seed = kenter_ui::backup::seed_source(self.custody().as_ref(), &backup.fingerprint);
        Some((backup, seed))
    }

    /// Re-read the settings page with a line explaining what just happened.
    fn after_backup(&mut self, note: String) {
        let Some(creds) = self.creds.clone() else {
            self.note_settings(&note);
            return;
        };
        let proxy = self.proxy.clone();
        let account = self.shown_account();
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let filled = rt.block_on(async {
                let mut view = settings::local(Network::current(), account.as_deref());
                view.note = Some(note);
                let view = settings::with_account_status(view, Network::current(), account).await;
                match kenter_ui::wallet::default_wallet_dir()
                    .and_then(|dir| kenter_wallet::FileStore::open(&dir, creds).ok())
                {
                    Some(store) => settings::with_backup(view, &store).await,
                    None => view,
                }
            });
            let _ = proxy.send_event(UiEvent::Settings(filled));
        });
    }

    /// Put a line on the settings page without rebuilding it.
    fn note_settings(&mut self, why: &str) {
        if let Screen::Settings(v) = &self.screen {
            let mut v = v.clone();
            v.note = Some(why.into());
            self.show(Screen::Settings(v));
        }
    }

    /// Pick a note file the payer sent, and file it for the watch.
    ///
    /// It copies into the inbox rather than handing the bytes straight to
    /// the verifier, so there is exactly one acceptance path: the same
    /// watch, the same G1-G3 gates, the same record of what was moved
    /// aside. A second route into someone's wallet is a second place for
    /// the gates to be wrong.
    fn import_note(&mut self) {
        let Some(dir) = kenter_ui::wallet::default_wallet_dir() else {
            return;
        };
        let inbox = receive::inbox_dir(&dir);
        let Some(src) = rfd::FileDialog::new()
            .set_title("Open the note they sent you")
            .add_filter("Kenter note", &["symtoken"])
            .pick_file()
        else {
            return;
        };
        if let Err(e) = receive::copy_into_inbox(&inbox, &src) {
            eprintln!("import: {e}");
            return;
        }
        // Nothing else to do: the watch is already running behind this
        // screen and will pick the file up on its next poll.
    }

    /// Take text from the clipboard into the field being typed in.
    ///
    /// Trimmed, and control characters dropped. An address copied out of a
    /// message or a web page usually arrives with whitespace or a newline
    /// attached, and a trailing newline in a destination address is a failed
    /// payment with a baffling reason.
    fn paste(&mut self) {
        let text = match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("clipboard: {e}");
                return;
            }
        };
        let cleaned: String = text.trim().chars().filter(|c| !c.is_control()).collect();
        if cleaned.is_empty() {
            return;
        }
        self.entry.push_str(&cleaned);
        self.refresh_entry();
    }

    /// Put this screen's address on the clipboard.
    ///
    /// A failure is shown rather than swallowed: on a machine with no
    /// clipboard the holder needs to know the button did nothing, because
    /// the alternative is pasting whatever was there before into a payment.
    fn copy_address(&mut self) {
        let Some(text) = self.copyable() else { return };
        let result = arboard::Clipboard::new().and_then(|mut c| c.set_text(text));
        match (&self.screen, result) {
            (
                Screen::Setup(SetupView {
                    state:
                        SetupState::Activate {
                            address,
                            funded,
                            trustline_needed,
                            ..
                        },
                }),
                Ok(()),
            ) => {
                let (address, funded, trustline_needed) =
                    (address.clone(), *funded, trustline_needed.clone());
                self.setup_keep(SetupState::Activate {
                    address,
                    copied: true,
                    funded,
                    trustline_needed,
                    busy: None,
                    error: None,
                });
            }
            (Screen::Account(v), Ok(())) => {
                let mut v = v.clone();
                v.copied = true;
                self.show(Screen::Account(v));
            }
            (Screen::Receive(ReceiveView { state }), outcome) => {
                let state = match state.clone() {
                    ReceiveState::Ready {
                        uri,
                        hex,
                        index,
                        status,
                        inbox,
                        ledger,
                        ..
                    } => ReceiveState::Ready {
                        uri,
                        hex,
                        index,
                        status,
                        inbox,
                        ledger,
                        note: Some(match outcome {
                            Ok(()) => "address copied".into(),
                            Err(e) => format!("could not copy: {e}"),
                        }),
                    },
                    other => other,
                };
                self.show(Screen::Receive(ReceiveView { state }));
            }
            (_, Err(e)) => eprintln!("clipboard: {e}"),
            _ => {}
        }
    }

    /// Open the paper screen, with what printing would produce.
    ///
    /// The page count is computed before any dialog because it is the
    /// thing a holder decides with, and it is not guessable from the
    /// number of notes.
    fn open_paper(&mut self) {
        let (Some(creds), Some(backup)) = (self.creds.clone(), self.backup.clone()) else {
            self.show(Screen::Paper(kenter_ui::PaperView {
                state: kenter_ui::PaperState::Offer {
                    notes: 0,
                    symbols: 0,
                    pages: 0,
                    locked: true,
                },
            }));
            return;
        };
        self.show(Screen::Paper(kenter_ui::PaperView {
            state: kenter_ui::PaperState::Working {
                what: "working out how many pages".into(),
            },
        }));
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let state = match paper_chunks(creds, &backup) {
                Err(message) => kenter_ui::PaperState::Failed { message },
                Ok((chunks, notes)) => kenter_ui::PaperState::Offer {
                    notes,
                    symbols: chunks.len(),
                    pages: kenter_ui::sheet::layout(&chunks).len(),
                    locked: false,
                },
            };
            let _ = proxy.send_event(UiEvent::Paper(state));
        });
    }

    /// Write the sheets where the holder says.
    fn print_paper(&mut self, svg: bool) {
        let (Some(creds), Some(backup)) = (self.creds.clone(), self.backup.clone()) else {
            return;
        };
        let name = if svg {
            format!("kenter-paper-{}.svg", backup.fingerprint)
        } else {
            format!("kenter-paper-{}.pdf", backup.fingerprint)
        };
        let Some(dest) = rfd::FileDialog::new()
            .set_title("Save your paper backup")
            .set_file_name(&name)
            .add_filter(if svg { "SVG pages" } else { "PDF" }, &[if svg { "svg" } else { "pdf" }])
            .save_file()
        else {
            return;
        };

        self.show(Screen::Paper(kenter_ui::PaperView {
            state: kenter_ui::PaperState::Working { what: "drawing the pages".into() },
        }));
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let state = match write_paper(creds, &backup, &dest, svg) {
                Ok((path, pages)) => kenter_ui::PaperState::Printed { path, pages },
                Err(message) => kenter_ui::PaperState::Failed { message },
            };
            let _ = proxy.send_event(UiEvent::Paper(state));
        });
    }

    /// What the capture thread had to say.
    ///
    /// Frames arrive here a dozen times a second, so the common path does
    /// the least it can: store the frame and ask for a repaint. Rebuilding
    /// the page on every frame would re-rasterize the whole scene at
    /// 12Hz to show a picture that is painted over it anyway.
    fn on_camera(&mut self, e: kenter_ui::camera::Event) {
        use kenter_ui::camera::Event;
        match e {
            Event::Preview {
                width,
                height,
                luma,
            } => {
                self.frame = Some((width, height, luma));
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }

            Event::Opened {
                name,
                px_per_module,
                ..
            } => {
                self.camera = kenter_ui::CameraView::Live {
                    name,
                    px_per_module,
                };
                self.show_scan(Vec::new(), 0, 0);
            }

            Event::Symbol(s) => {
                let sheet = self
                    .sheet
                    .get_or_insert_with(kenter_wallet::paper::Sheet::new);
                // The same symbol lands on most frames while the holder
                // holds the page still. Only a change in what is held is
                // worth rebuilding the screen for.
                let before = sheet.progress();
                let problems = match sheet.add(*s) {
                    Ok(()) => Vec::new(),
                    Err(e) => vec![e.to_string()],
                };
                let after = sheet.progress();
                if problems.is_empty()
                    && after.complete == before.complete
                    && after.partial == before.partial
                {
                    return;
                }
                self.show_scan(problems, 0, 0);
            }

            // Only the research harness asks for full frames; the
            // client never does, so one cannot arrive here.
            Event::Shot { .. } => {}

            Event::Trouble(message) => {
                // The thread stops on its own after trouble; dropping the
                // handle here joins it and releases the device.
                self.capture = None;
                self.frame = None;
                self.camera = kenter_ui::CameraView::Refused(message);
                self.show_scan(Vec::new(), 0, 0);
            }

            Event::Closed => {
                self.frame = None;
                if matches!(self.camera, kenter_ui::CameraView::Live { .. }) {
                    self.camera = kenter_ui::CameraView::Off;
                    self.show_scan(Vec::new(), 0, 0);
                }
            }
        }
    }

    /// Turn the camera on.
    ///
    /// Everything it reports arrives as a `UiEvent`, including failure:
    /// opening a device blocks for long enough to be felt, so nothing
    /// here waits for it.
    fn start_camera(&mut self) {
        if self.capture.is_some() {
            return;
        }
        self.camera = kenter_ui::CameraView::Starting;
        let proxy = self.proxy.clone();
        self.capture = Some(kenter_ui::camera::Capture::start(move |e| {
            let _ = proxy.send_event(UiEvent::Camera(e));
        }));
        self.show_scan(Vec::new(), 0, 0);
    }

    /// Turn it off and let go of the device.
    fn stop_camera(&mut self) {
        // Dropping joins the thread, which is what actually releases the
        // camera - leaving it to the garbage of a later frame would show
        // the holder a "camera busy" error when they came back.
        self.capture = None;
        self.frame = None;
        self.camera = kenter_ui::CameraView::Off;
        self.show_scan(Vec::new(), 0, 0);
    }

    /// Start a scan, or come back to one already in progress.
    fn open_scan(&mut self) {
        if self.sheet.is_none() {
            self.sheet = Some(kenter_wallet::paper::Sheet::new());
        }
        self.show_scan(Vec::new(), 0, 0);
    }

    /// Paint the scan screen from the sheet as it stands.
    fn show_scan(&mut self, problems: Vec<String>, foreign: usize, unreadable: usize) {
        let Some(sheet) = &self.sheet else { return };
        let progress = sheet.progress();

        // One row per item, named by what it is. "Note 3 is missing" is
        // actionable; "symbol 7 of 14" is not.
        let name = |i: u16| {
            if i == 0 {
                "wallet record".to_string()
            } else {
                format!("note {i}")
            }
        };
        let mut items: Vec<kenter_ui::PaperItem> = Vec::new();
        for i in &progress.complete {
            items.push(kenter_ui::PaperItem {
                what: name(*i),
                state: "complete".into(),
                done: true,
                note: *i > 0,
            });
        }
        for (i, missing) in &progress.partial {
            let list: Vec<String> = missing.iter().map(|m| m.to_string()).collect();
            items.push(kenter_ui::PaperItem {
                what: name(*i),
                state: format!("needs symbol {}", list.join(", ")),
                done: false,
                note: *i > 0,
            });
        }
        for i in &progress.absent {
            items.push(kenter_ui::PaperItem {
                what: name(*i),
                state: "nothing scanned yet".into(),
                done: false,
                note: *i > 0,
            });
        }
        items.sort_by(|a, b| a.what.cmp(&b.what));

        let camera = self.camera.clone();
        let for_setup = self.scan_for_setup;
        self.show(Screen::Paper(kenter_ui::PaperView {
            state: kenter_ui::PaperState::Scanning {
                wallet: sheet.wallet().map(|w| format!("wallet {w}")),
                complete: progress.is_complete(),
                items,
                foreign,
                unreadable,
                problems,
                camera,
                for_setup,
            },
        }));
    }

    /// Add images to the scan. Repeatable, because a holder scans a stack,
    /// finds a page missing, and comes back with it.
    fn add_scan_images(&mut self) {
        let Some(paths) = rfd::FileDialog::new()
            .set_title("Photos or scans of your paper backup")
            .add_filter("Images", &["png", "jpg", "jpeg", "tif", "tiff", "bmp"])
            .pick_files()
        else {
            return;
        };
        let (scanned, found, mut problems) = kenter_ui::scan::read_all(&paths);

        // Merge into the running sheet rather than replacing it: the
        // symbols from earlier dialogs are still wanted.
        let sheet = self.sheet.get_or_insert_with(kenter_wallet::paper::Sheet::new);
        for s in found.symbols {
            if let Err(e) = sheet.add(s) {
                problems.push(e.to_string());
            }
        }
        let _ = scanned;
        self.show_scan(problems, found.foreign, found.unreadable);
    }

    /// Restore from whatever has been scanned, complete or not.
    fn restore_scanned(&mut self) {
        let (Some(sheet), Some(creds), Some(backup)) =
            (self.sheet.clone(), self.creds.clone(), self.backup.clone())
        else {
            return;
        };
        self.show(Screen::Paper(kenter_ui::PaperView {
            state: kenter_ui::PaperState::Working { what: "putting the notes back".into() },
        }));
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let state = match restore_from_sheet(creds, &backup, &sheet) {
                Ok(s) => s,
                Err(message) => kenter_ui::PaperState::Failed { message },
            };
            let _ = proxy.send_event(UiEvent::Paper(state));
        });
    }

    /// Put the recovery phrase on the clipboard.
    ///
    /// Not gated — see `setup.rs` for why gating compares against the
    /// wrong alternative.
    fn copy_phrase(&mut self) {
        // Both phrase screens. Matching only the software one would render
        // the button on the card screen and have it do nothing - the same
        // hazard as in `set_revealed`, which must know about `CardPhrase`
        // too. A `let-else` on one variant is a quiet way to half-support
        // a second.
        let (words, revealed, card) = match &self.screen {
            Screen::Setup(SetupView {
                state: SetupState::Phrase { words, revealed },
            }) => (words.clone(), *revealed, false),
            Screen::Setup(SetupView {
                state: SetupState::CardPhrase { words, revealed },
            }) => (words.clone(), *revealed, true),
            _ => return,
        };
        let text = Zeroizing::new(words.join(" "));
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.as_str())) {
            // No "copied" flag on this screen: the acknowledgement would sit
            // next to the phrase itself, and the phrase is the one thing on
            // screen worth looking at.
            Ok(()) => eprintln!("kenter: recovery phrase copied"),
            Err(e) => eprintln!("clipboard: {e}"),
        }
        self.setup_keep(if card {
            SetupState::CardPhrase { words, revealed }
        } else {
            SetupState::Phrase { words, revealed }
        });
    }

    /// Watch the account until it can act, doing each step as it becomes
    /// possible.
    ///
    /// Funding arrives from outside the client, so the honest shape is to
    /// wait rather than to offer a button that cannot do the thing. Once XLM
    /// lands, the trustline follows automatically: the holder already chose
    /// this client and this mint, and making them confirm a consequence of
    /// that choice is ceremony.
    ///
    /// The elapsed time is shown rather than a spinner. A spinner says only
    /// that something is happening; a counter says how long it has been
    /// happening, which is what tells someone their transfer has not arrived.
    fn watch_activation(&mut self) {
        let Screen::Setup(SetupView {
            state: SetupState::Activate { address, .. },
        }) = &self.screen
        else {
            return;
        };
        if self.activating {
            return;
        }
        self.activating = true;
        let address = address.clone();
        let proxy = self.proxy.clone();
        // The credential that opens the **account** vault, which is what
        // signs a trustline. `setup_pass` is only the software path's, and
        // reaching for it on a card wallet produced "no passphrase in hand
        // to sign with" about a wallet that has no passphrase by design.
        let credential = self.account_cred.clone().or_else(|| {
            self.setup_pass
                .as_ref()
                .map(|p| Zeroizing::new(p.as_bytes().to_vec()))
        });
        let cancel = self.cancel.clone();

        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return;
            };
            let started = std::time::Instant::now();
            let mut adding = false;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let a = rt.block_on(account::read(Network::current(), &address));

                let (funded, trustline_needed) = (
                    a.usable(),
                    match a.has_trustline() {
                        Some(false) => a.asset_code.clone(),
                        _ => None::<String>,
                    },
                );

                // Ready: stop watching and let the holder through.
                if funded && trustline_needed.is_none() && a.asset_code.is_some() {
                    let _ = proxy.send_event(UiEvent::Setup(SetupState::Activate {
                        address,
                        copied: false,
                        funded: true,
                        trustline_needed: None,
                        busy: None,
                        error: a.error,
                    }));
                    return;
                }

                // Funded and missing a trustline: add it, once.
                if funded && trustline_needed.is_some() && !adding {
                    adding = true;
                    let _ = proxy.send_event(UiEvent::Setup(SetupState::Activate {
                        address: address.clone(),
                        copied: false,
                        funded: true,
                        trustline_needed: trustline_needed.clone(),
                        busy: Some("XLM arrived - adding the trustline".into()),
                        error: None,
                    }));
                    let error = match &credential {
                        Some(c) => rt.block_on(submit_trustline(Network::current(), c)).err(),
                        None => Some("no passphrase in hand to sign with".into()),
                    };
                    if let Some(e) = error {
                        // Report and keep watching: a failed trustline is
                        // usually a fee or a reserve away from working, and
                        // stopping would strand the holder with no next step.
                        adding = false;
                        let _ = proxy.send_event(UiEvent::Setup(SetupState::Activate {
                            address: address.clone(),
                            copied: false,
                            funded: true,
                            trustline_needed,
                            busy: Some("retrying".into()),
                            error: Some(e),
                        }));
                    }
                    continue;
                }

                let secs = started.elapsed().as_secs();
                let _ = proxy.send_event(UiEvent::Setup(SetupState::Activate {
                    address: address.clone(),
                    copied: false,
                    funded,
                    trustline_needed,
                    busy: Some(if funded {
                        format!("working - {secs}s")
                    } else {
                        format!("waiting for XLM - {secs}s")
                    }),
                    error: a.error,
                }));
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        });
    }

    /// The one piece of text this screen exists to hand to another program.
    fn copyable(&self) -> Option<String> {
        match &self.screen {
            Screen::Setup(SetupView {
                state: SetupState::Activate { address, .. },
            }) => Some(address.clone()),
            Screen::Account(v) => Some(v.address.clone()),
            // The hex, not the URI: it is what a payer pastes into a field,
            // and the URI is already on screen as a QR for the other case.
            Screen::Receive(ReceiveView {
                state: ReceiveState::Ready { hex, .. },
            }) => Some(hex.clone()),
            _ => None,
        }
    }

    /// Show the billfold, without resurrecting a view that is out of date.
    ///
    /// `self.wallet` is the last view that was read, which early in a session
    /// is the *locked* one. Re-showing it after unlocking would put the
    /// client back into a state it is no longer in, and the Unlock button
    /// there does nothing because there is nothing left to unlock.
    fn show_billfold(&mut self) {
        let stale_lock = self.wallet.locked && self.creds.is_some();
        let view = if stale_lock {
            WalletView::loading()
        } else {
            self.wallet.clone()
        };
        self.show(Screen::Wallet(view));
    }

    /// Show what a reset of this wallet would move (`kenter_ui::reset`).
    fn open_reset(&mut self) {
        let (Some(vault), Some(store)) = (
            receive::default_vault_path(),
            kenter_ui::wallet::default_wallet_dir(),
        ) else {
            self.show_gate(Some("no vault or wallet folder is configured".into()));
            return;
        };
        let plan = kenter_ui::reset::plan(&vault, &store, unix_secs());
        self.entry = Zeroizing::new(String::new());
        self.show(Screen::Reset(kenter_ui::ResetView {
            archive: plan.archive.display().to_string(),
            moving: plan
                .moves
                .iter()
                .filter_map(|(from, _)| from.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect(),
            backups: plan.backups,
            typed: String::new(),
            error: None,
        }));
    }

    /// Move this wallet aside and go to first run, if the word was typed.
    fn confirm_reset(&mut self) {
        let Screen::Reset(view) = &self.screen else { return };
        let mut view = view.clone();
        if !kenter_ui::reset::confirmed(self.entry.as_str()) {
            view.error = Some(format!("type {} to confirm, in capitals", kenter_ui::reset::CONFIRM_WORD));
            self.show(Screen::Reset(view));
            return;
        }
        let (Some(vault), Some(store)) = (
            receive::default_vault_path(),
            kenter_ui::wallet::default_wallet_dir(),
        ) else {
            return;
        };
        // Planned again, not reused from the screen: what is on disk now is
        // what gets moved.
        let plan = kenter_ui::reset::plan(&vault, &store, unix_secs());
        if let Err(e) = kenter_ui::reset::perform(&plan) {
            view.error = Some(format!("the reset stopped: {e}"));
            self.show(Screen::Reset(view));
            return;
        }
        // Nothing of the old wallet is held any more.
        self.entry = Zeroizing::new(String::new());
        self.session = None;
        self.creds = None;
        self.account_cred = None;
        self.account_address = None;
        self.show(Screen::Setup(SetupView {
            state: SetupState::Start,
        }));
    }

    /// Open the store with what has been typed into the gate.
    ///
    /// Goes straight to `spawn_unlock_with`, which opens the vault and asks
    /// it for store credentials. The old path went through the authorizer,
    /// and to get the passphrase back out of it it ran
    /// `authorize(AuthAction::Receive { index: 0 })` - a pay-tag
    /// authorization used purely as a carrier. That is where the front
    /// door's "Create a pay tag - owner index 0" came from. No key was
    /// derived and no index was reserved, so the screen named an operation
    /// that was not happening.
    fn submit_unlock(&mut self) {
        if self.unlocking {
            return;
        }
        let typed = self.entry.to_string();
        let credential = Zeroizing::new(self.entry.as_bytes().to_vec());
        self.entry = Zeroizing::new(String::new());
        self.unlocking = true;

        match self.custody() {
            Some(kenter_vault::Custody::Card {
                seed_fingerprint,
                card_identity,
            }) => {
                // Refused here rather than sent to the card: with no card
                // there is nothing to send it to, and a PIN typed at an
                // empty reader would come back looking like a wrong PIN.
                let p = kenter_ui::card::presence(&card_identity);
                if !p.can_try() {
                    self.unlocking = false;
                    self.show_gate(Some(p.message(&card_identity)));
                    return;
                }
                self.show(Screen::Locked(LockedView {
                    busy: true,
                    card: Some(kenter_ui::CardGate {
                        hint: p.message(&card_identity),
                        ready: true,
                    }),
                    ..Default::default()
                }));
                receive::spawn_card_unlock(
                    self.proxy.clone(),
                    Zeroizing::new(typed),
                    seed_fingerprint,
                );
            }
            _ => {
                self.show(Screen::Locked(LockedView {
                    busy: true,
                    ..Default::default()
                }));
                receive::spawn_unlock_with(self.proxy.clone(), credential);
            }
        }
    }

    /// The two credentials this session holds, or `None` if locked.
    ///
    /// Built in one place so no caller has to remember which secret goes
    /// where - with both secrets the same type, a swap is easy to make and
    /// only shows up at the card.
    fn verified_account(&self) -> Result<String, String> {
        match &self.account_address {
            None => Err("unlock first - your account address is read from your key".into()),
            Some(Err(e)) => Err(e.clone()),
            Some(Ok(None)) => Err("no account in the vault - finish first run".into()),
            Some(Ok(Some(a))) => Ok(a.clone()),
        }
    }

    /// The verified address if unlocked, for display rows that have a
    /// "locked" wording of their own.
    fn shown_account(&self) -> Option<String> {
        self.verified_account().ok()
    }

    fn session_creds(&self) -> Option<kenter_ui::SessionCreds> {
        Some(kenter_ui::SessionCreds {
            owner: self.session.clone()?,
            account: self.account_cred.clone()?,
        })
    }

    /// What opens this installation, read from the vault rather than
    /// inferred from whether a seed sits in it: a card wallet's vault holds
    /// no seed, and must still be recognised as a wallet.
    fn custody(&self) -> Option<kenter_vault::Custody> {
        receive::default_vault_path()
            .and_then(|p| kenter_vault::SoftVault::open(p).ok())
            .and_then(|v| v.custody().cloned())
    }

    /// The gate, asking the question this wallet actually answers.
    ///
    /// Re-reads the reader each time it is shown, so "put your card on the
    /// reader" becomes "your card is on the reader" by pressing Look again
    /// rather than by restarting the app.
    fn show_gate(&mut self, error: Option<String>) {
        let card = match self.custody() {
            Some(kenter_vault::Custody::Card { card_identity, .. }) => {
                let p = kenter_ui::card::presence(&card_identity);
                Some(kenter_ui::CardGate {
                    hint: p.message(&card_identity),
                    ready: p.can_try(),
                })
            }
            _ => None,
        };
        self.entry = Zeroizing::new(String::new());
        self.show(Screen::Locked(LockedView {
            entered: 0,
            error,
            busy: false,
            card,
        }));
    }

    /// Something needs the store and it is sealed: show the gate.
    ///
    /// Callers do not raise an authorization prompt over their own page,
    /// which would leave, say, the billfold tab lit above a pay-tag prompt.
    /// There is one way into this client, and it looks
    /// the same whether it is the first thing of the session or the third
    /// thing a deposit needed.
    fn start_unlock(&mut self) {
        if self.unlocking {
            return;
        }
        // Already unlocked: "Unlock" can only sensibly mean "show me, then",
        // and doing nothing is how a stale locked screen becomes a dead end.
        if self.creds.is_some() {
            self.show_billfold();
            self.refresh();
            return;
        }
        self.show_gate(None);
    }

    /// Tell the receive worker to stop and stop waiting on it.
    fn stop_receive(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.receiving = false;
    }

    /// Arriving at the Accept page.
    ///
    /// Shows the pay tag that is already outstanding rather than reserving
    /// another. A tag is good for one payment and is consumed when a note
    /// binds to it, so it rotates on being used and at no other time
    /// (two payers on one tag land on one commitment the ledger links);
    /// reserving one per arrival would leave a code the payer was still
    /// holding with nobody watching for it.
    ///
    /// Starting the worker at all means unlocking, so a locked session gets
    /// the idle page and the button that starts it deliberately. Arriving at
    /// a page must not demand a passphrase for the arrival itself.
    fn open_receive(&mut self) {
        match (receive::readiness(), self.session.is_some()) {
            (Err(reason), _) => self.show(Screen::Receive(ReceiveView::failed(reason))),
            (Ok(hint), false) => self.show(Screen::Receive(ReceiveView::idle(&hint))),
            (Ok(_), true) => self.start_receive(false),
        }
    }

    /// Publish, retire, or just look at the standing pay tag.
    fn standing(&mut self, op: receive::Standing) {
        self.show(Screen::Receive(ReceiveView {
            state: ReceiveState::Standing {
                hex: None,
                busy: Some(
                    match op {
                        receive::Standing::Show => "reading",
                        receive::Standing::Publish => "deriving index 0",
                        receive::Standing::Retire => "retiring",
                    }
                    .into(),
                ),
            },
        }));
        receive::spawn_standing(
            self.proxy.clone(),
            Network::current(),
            self.session.clone(),
            op,
        );
    }

    /// Show a pay tag and watch for a payment to it.
    ///
    /// `fresh` is the **Different tag** button: it reserves a new index
    /// instead of showing the live tag. The one case the automatic rotation
    /// cannot cover is being paid by two people at once, where one tag in two
    /// hands would put both notes on one commitment and link them publicly.
    fn start_receive(&mut self, fresh: bool) {
        if self.receiving {
            return;
        }
        // Re-checked here too, not just on arrival: "Try again" is the button
        // on the failure screen, and the fix is a CLI command run in another
        // window, so the answer can change between the two.
        if let Err(reason) = receive::readiness() {
            self.show(Screen::Receive(ReceiveView::failed(reason)));
            return;
        }
        self.receiving = true;
        // A fresh flag per run: the old worker may still be unwinding, and it
        // must not be able to see this one's cancellation or vice versa.
        self.cancel = Arc::new(AtomicBool::new(false));
        self.receive_synced = false;
        receive::spawn(
            self.proxy.clone(),
            Network::current(),
            self.cancel.clone(),
            self.session.clone(),
            fresh,
        );
        self.working(if fresh {
            "reserving another owner index"
        } else {
            "reading your pay tag"
        });
    }

    /// A neutral "something is happening" page while a worker decides.
    fn working(&mut self, what: &str) {
        self.show(Screen::Receive(ReceiveView {
            state: ReceiveState::Working { what: what.into() },
        }));
    }

    fn act(&mut self, action: Action) {
        // The reset screen answers only its own few actions.
        if matches!(self.screen, Screen::Reset(_)) {
            match action {
                Action::ConfirmReset | Action::Confirm => self.confirm_reset(),
                Action::Back | Action::Cancel => self.show_gate(None),
                _ => {}
            }
            return;
        }
        if action == Action::ResetWallet {
            self.open_reset();
            return;
        }
        if self.setup_step(action)
            || self.setup_scan_step(action)
            || self.deposit_step(action)
            || self.pay_step(action)
            || self.redeem_step(action)
            || self.rpc_step(action)
        {
            return;
        }
        match action {
            // Handled at the top of `act`.
            Action::ResetWallet | Action::ConfirmReset => {}
            Action::PaperBackup => self.open_paper(),
            Action::UseCamera => self.start_camera(),
            Action::StopCamera => self.stop_camera(),
            Action::PrintPaper => self.print_paper(false),
            Action::PrintPaperSvg => self.print_paper(true),
            Action::ScanPaper => self.open_scan(),
            Action::AddImages => self.add_scan_images(),
            Action::RestoreScanned => self.restore_scanned(),
            Action::SaveBackup => self.save_backup(),
            Action::RestoreBackup => self.restore_backup(),
            Action::Receive => self.open_receive(),
            // The inbox watch is stopped on the way in. It reports a Ready
            // state every poll, and Standing is a Receive screen, so leaving
            // it running would paint the rotating tag back over this page a
            // second and a half after arriving at it.
            Action::ShowStanding => {
                self.stop_receive();
                self.standing(receive::Standing::Show);
            }
            Action::ToggleStanding => {
                let on = matches!(
                    self.screen,
                    Screen::Receive(ReceiveView {
                        state: ReceiveState::Standing { hex: Some(_), .. }
                    })
                );
                self.standing(if on {
                    receive::Standing::Retire
                } else {
                    receive::Standing::Publish
                });
            }
            // Only meaningful during first run, which `setup_step` handles
            // before this match is reached. Ignored rather than unreachable:
            // a stale click after the screen changed is not a bug.
            // First-run only; `setup_step` has already claimed these if
            // first run is showing, and outside it they mean nothing.
            // On the gate this means "look at the reader again". During
            // first run the custody screen claims it first.
            Action::CheckCard if matches!(self.screen, Screen::Locked(_)) => {
                self.show_gate(None);
            }
            Action::UseSoftware
            | Action::UseCard
            | Action::CheckCard
            | Action::SkipDuress
            | Action::EraseCard => {}
            Action::CopyPhrase => self.copy_phrase(),
            Action::Check => self.open_account(),
            Action::Recover(slot) => self.recover_escrow(slot),
            Action::NewReceive => {
                self.stop_receive();
                self.start_receive(true);
            }
            Action::Back => {
                // Leaving a prompt without answering would strand the worker,
                // and leaving the page without cancelling would leave it
                // polling the inbox behind a screen nobody is looking at.
                self.answer(None);
                self.stop_receive();
                self.show_billfold();
                // The watch may have completed a receive; the balance behind
                // this page is stale either way.
                self.refresh();
            }
            Action::Confirm => {
                let credential = Zeroizing::new(self.entry.as_bytes().to_vec());
                self.answer(Some(credential));
                // The worker that asked decides what comes next and will send
                // it; until then, say what is happening rather than flashing
                // back to a page the answer may be about to replace.
                self.working("checking");
            }
            Action::Cancel => {
                self.answer(None);
                self.stop_receive();
                self.working("cancelling");
            }
            Action::Unlock => {
                if matches!(self.screen, Screen::Locked(_)) {
                    self.submit_unlock();
                } else {
                    self.start_unlock();
                }
            }
            Action::ImportNote => self.import_note(),
            Action::PayNote(i) => self.pay_from_card(i),
            Action::RedeemNote(i) => self.redeem_from_card(i),
            Action::SelectTab(i) => self.billfold_tab(i),
            // Click an open card to close it: the same gesture both ways,
            // and no separate affordance to find.
            Action::ExpandNote(i) => {
                let mut w = self.wallet.clone();
                w.expanded = (w.expanded != Some(i)).then_some(i);
                self.wallet = w.clone();
                self.show(Screen::Wallet(w));
            }
            Action::Copy => self.copy_address(),
            Action::AddTrustline => self.add_trustline(),
            // Only meaningful on Settings, where `rpc_step` takes them first.
            Action::EditRpc | Action::RpcDefault => {}
            // Only meaningful inside first run, which has already had its
            // turn above.
            Action::NewWallet
            | Action::RestoreWallet
            | Action::ChooseBackupFile
            | Action::Reveal
            | Action::Continue
            | Action::Deposit
            | Action::ToggleMode
            | Action::CyclePairs
            | Action::ExportNote
            | Action::ExportBackup
            | Action::KeepCopy
            | Action::DropCopy
            // Handled by `redeem_step`, which runs first and owns the
            // screen these belong to.
            | Action::EditDestination
            | Action::UseOwnAccount
 => {}
            // Not built yet. Does nothing rather than pretending to.
        }
    }

    fn redraw(&mut self) {
        let (Some(window), Some(surface)) = (&self.window, &mut self.surface) else {
            return;
        };
        // Render to the window's *physical* inner size (hi-DPI correct), not the
        // logical W×H — otherwise the UI fills only a top-left W×H box.
        let size = window.inner_size();
        let (pw, ph) = (size.width.max(1), size.height.max(1));
        surface
            .resize(NonZeroU32::new(pw).unwrap(), NonZeroU32::new(ph).unwrap())
            .unwrap();
        let live = self
            .frame
            .as_ref()
            .map(|(w, h, luma)| kenter_ui::LiveFrame {
                width: *w,
                height: *h,
                luma,
            });
        let canvas = self.ui.render_live(&self.it, pw, ph, live.as_ref());
        let mut buffer = surface.buffer_mut().unwrap();
        canvas_to_argb(&canvas, &mut buffer);
        window.pre_present_notify();
        buffer.present().unwrap();
    }
}

/// How long one frame of an indeterminate bar is shown.
///
/// Twelve frames at 80ms is a 0.96s loop — slow enough to read as deliberate
/// rather than frantic, fast enough that a glance catches it moving. The
/// whole cost of running it is twelve cached blits a second; nothing
/// re-rasterizes after the first pass through the loop.
const FRAME: Duration = Duration::from_millis(80);

impl ApplicationHandler<UiEvent> for App {
    /// Advance the animation when the deadline set in `about_to_wait` lands.
    ///
    /// Only the frame counter moves. Nothing else in the client learns about
    /// time, so there is no path by which a slow or missed tick can change
    /// what the client *does* — only how it looks.
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if matches!(cause, StartCause::ResumeTimeReached { .. }) && self.ui.has_animation() {
            self.it.frame = self.it.frame.wrapping_add(1);
            if let Some(w) = &self.window {
                w.request_redraw();
            }
        }
    }

    /// Ask to be woken for the next frame, or not at all.
    ///
    /// This runs after every batch of events, so the page that is on screen
    /// right now decides: a `Working` page keeps the clock going and anything
    /// else stops it. Nothing has to remember to turn it off — the bar going
    /// away is what turns it off.
    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        event_loop.set_control_flow(if self.ui.has_animation() {
            ControlFlow::WaitUntil(Instant::now() + FRAME)
        } else {
            ControlFlow::Wait
        });
    }

    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        let attrs = Window::default_attributes()
            .with_title("Kenter")
            .with_inner_size(LogicalSize::new(W, H))
            .with_resizable(false);
        let window = Rc::new(event_loop.create_window(attrs).expect("window"));
        let context = softbuffer::Context::new(window.clone()).expect("softbuffer context");
        let surface =
            softbuffer::Surface::new(&context, window.clone()).expect("softbuffer surface");
        self.window = Some(window);
        self.surface = Some(surface);
        // Ask once, on opening, rather than at the first thing that needs it.
        // Everything here reads an encrypted store, so deferring only moves
        // the prompt to a less predictable moment.
        // Routed on what the vault *says*, not on whether a seed happens to
        // be in it. `can_unlock()` alone is `has_seed()`, false for a card
        // wallet as well as for an empty machine - so a provisioned card
        // would be indistinguishable from no wallet, and its owner sent to
        // first run with their wallet on the reader in front of them.
        //
        // A card wallet with no card present still goes to the gate, and
        // must never fall through to first run: offering a new wallet to
        // someone who left their card in another room is how they end up
        // with two.
        if self.custody().is_some() || receive::can_unlock() {
            // The gate, not a prompt. An authorization prompt here would
            // fire over whatever page happened to be underneath - so the
            // first thing anyone saw would be "Authorize / Create a pay tag"
            // with the billfold tab lit, and the way out of it a passphrase
            // field below the buttons.
            self.show_gate(None);
        } else {
            // No seed: there is nothing to unlock and nowhere to put a note,
            // so first run is not a suggestion, it is the only thing that
            // works.
            self.show(Screen::Setup(SetupView {
                state: SetupState::Start,
            }));
        }
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: UiEvent) {
        match event {
            UiEvent::Wallet(view) => {
                self.loading = false;
                self.wallet = view.clone();
                // Only take over the screen if the wallet is what is showing —
                // a refresh must not yank a receive address off the display.
                if matches!(self.screen, Screen::Wallet(_)) {
                    self.show(Screen::Wallet(view));
                }
            }

            UiEvent::Ask(ask) => {
                // One prompt at a time. A second would orphan the first
                // worker, which is blocked on a channel nobody would answer.
                if self.reply.is_some() {
                    let _ = ask.reply.send(None);
                    return;
                }
                self.reply = Some(ask.reply);
                self.entry = Zeroizing::new(String::new());
                let under = self.screen.nav_index();
                self.show(Screen::Prompt {
                    view: ask.view,
                    under,
                });
            }

            UiEvent::Setup(state) => {
                // The gate watches the ledger for as long as it is showing.
                // Driven from here rather than from creation so it also
                // covers the states the watcher itself produces; the
                // `activating` flag keeps that from spawning a second
                // watcher on every tick, and clearing it once the gate is
                // satisfied means a later first run still gets one.
                let gate = matches!(state, SetupState::Activate { .. });
                let cleared = matches!(
                    state,
                    SetupState::Activate {
                        funded: true,
                        trustline_needed: None,
                        ..
                    }
                );
                self.setup_keep(state);
                if cleared {
                    self.activating = false;
                } else if gate {
                    self.watch_activation();
                }
            }

            UiEvent::Account(view) => {
                // Cached even when the page has been left, so coming back
                // shows the last figures rather than blanks.
                if view.error.is_none() {
                    self.account = view.clone();
                }
                if matches!(self.screen, Screen::Account(_)) {
                    self.show(Screen::Account(view));
                }
            }

            UiEvent::CardPhrase(Ok(phrase)) => {
                let words = phrase.split_whitespace().map(String::from).collect();
                self.setup_phrase = Some(phrase);
                self.setup(SetupState::CardPhrase {
                    words,
                    revealed: false,
                });
            }
            UiEvent::CardPhrase(Err(why)) => {
                // INIT may or may not have landed before this failed, so the
                // message cannot promise the card is untouched - only that
                // no key was written, which is the part that decides whether
                // there is a wallet to lose.
                self.card_secrets.clear();
                self.setup(SetupState::Failed {
                    message: format!("{why}. No key was written, so there is no wallet on                                       the card - you can start again."),
                });
            }
            UiEvent::CardSeeded(Ok(_pubkey)) => {
                // The card holds the key, so the phrase has done its job and
                // everything else is derived from what is now on the card.
                self.setup_phrase = None;
                self.finish_card_setup();
            }
            UiEvent::CardSeeded(Err(why)) => {
                // Deliberately keeps the phrase: the card may have taken the
                // key and failed only on read-back, and discarding the words
                // at that moment would be the one unrecoverable mistake in
                // this flow.
                self.setup(SetupState::Failed {
                    message: format!(
                        "{why}. Keep the 24 words you wrote down - if the card did take                          the key, they are the only copy."
                    ),
                });
            }

            UiEvent::CardErased(Ok(())) => {
                // Straight back to the intro, which now reads the card as
                // blank and offers to set it up - the thing the holder came
                // here to be able to do.
                let found = kenter_ui::card::readiness();
                self.setup(SetupState::CardIntro {
                    card: found.message(),
                    blank: matches!(found, kenter_ui::card::Readiness::Blank),
                });
            }
            UiEvent::CardErased(Err(why)) => {
                // A wrong PIN lands here and costs an attempt, so the
                // message has to be the card's rather than a generic
                // failure - "4 attempts left" is the actionable part.
                self.setup(SetupState::Failed {
                    message: format!("{why}. Nothing was erased."),
                });
            }
            UiEvent::CardReady(Ok(w)) => {
                self.card_secrets.clear();
                // Kept past the PIN being cleared, because the trustline is
                // signed by the submitting account and this is what opens
                // the vault holding it.
                self.account_cred = Some(w.account_credential);
                eprintln!("kenter: backup written to {}", w.backup_path);
                // The same gate the software path ends on. Funding and a
                // trustline do not care where the key lives.
                self.setup_keep(SetupState::Activate {
                    address: w.address,
                    copied: false,
                    funded: false,
                    trustline_needed: None,
                    busy: None,
                    error: None,
                });
                self.watch_activation();
            }
            UiEvent::CardReady(Err(why)) => {
                // The card is already a wallet at this point. Everything
                // this step makes is derived from its seed, so it can be
                // re-made - which is exactly what a restore does. Say that,
                // rather than leaving a holder thinking the card is spoilt.
                self.setup(SetupState::Failed {
                    message: format!(
                        "{why}. The card itself is fine and holds your key - this is the                          account and backup file, which are derived from it and can be                          made again."
                    ),
                });
            }

            UiEvent::Reopen => {
                if matches!(self.screen, Screen::Account(_)) {
                    self.open_account();
                }
            }

            UiEvent::Redeem(state) => {
                if matches!(self.screen, Screen::Redeem(_)) {
                    let done = matches!(state, RedeemState::Done { .. });
                    self.show(Screen::Redeem(RedeemView { state }));
                    if done {
                        self.refresh();
                    }
                }
            }

            UiEvent::Pay(state) => {
                if matches!(self.screen, Screen::Pay(_)) {
                    let paid = matches!(state, PayState::Paid { .. });
                    self.show(Screen::Pay(PayView { state }));
                    if paid {
                        self.refresh();
                    }
                }
            }

            UiEvent::Deposit(state) => {
                // Only while the holder is still watching, and never over a
                // later screen they navigated to on purpose.
                if matches!(self.screen, Screen::Deposit(_)) {
                    let done = matches!(state, DepositState::Done { .. });
                    self.show(Screen::Deposit(DepositView { state }));
                    if done {
                        self.refresh();
                    }
                }
            }

            UiEvent::Unlocked {
                creds,
                credential,
                account,
                backup,
                address,
            } => {
                self.unlocking = false;
                self.account_address = Some(address);
                self.creds = Some(creds);
                self.session = Some(credential);
                self.account_cred = Some(account);
                self.backup = Some(backup);
                // The loading view, not the one that was on screen. That was
                // `WalletView::locked()` — so unlocking re-showed "locked",
                // and left it up for the seconds `refresh` spends on the
                // ledger. The client was unlocked and saying otherwise,
                // which is the whole of the "unlocking takes several seconds
                // with no feedback" report: Argon2id is ~23ms, and every
                // second after it was this line.
                // What is on disk, at once. A reconcile is a round trip
                // per note and takes seconds; the records take none, so
                // waiting for the ledger before painting anything left a
                // holder staring at a spinner with no idea whether their
                // notes were there. They appear unverified and upgrade.
                self.show_local();

                // Ordered, not raced. As two threads started back to back,
                // with nothing re-reading the store when the restore
                // finished, whenever the refresh won the billfold would
                // show an empty wallet and stay that way. The restore can
                // lose that race because it touches disk and the refresh
                // opens with an RPC sweep.
                // Paper waits for the file when there are both, and goes
                // in from `RestoredAtSetup`: one writer at a time keeps the
                // billfold's re-read after the last of them.
                if self.restore_bytes.is_some() {
                    self.restore_notes_after_setup();
                } else if !self.restore_paper_after_setup() {
                    self.refresh();
                }
            }

            // Both land on the settings page, re-read rather than patched:
            // saving and restoring both change what the page says about the
            // backup, and the store is the answer to that, not this thread.
            UiEvent::BackupDone(outcome) => {
                self.after_backup(match outcome {
                    Ok(path) => format!("backup saved to {path}"),
                    Err(e) => format!("could not save the backup: {e}"),
                });
            }
            UiEvent::Restored(outcome) => {
                if outcome.is_ok() {
                    self.verify_restored_ownership();
                }
                self.after_backup(match outcome {
                    Ok(what) => what,
                    Err(e) => format!("could not restore: {e}"),
                });
                // The billfold is now a different wallet, so the figure on
                // it is stale even though nothing on screen changed.
                self.refresh();
            }

            // Reported only when it failed. On success the billfold is
            // already showing the notes, which says it better.
            UiEvent::RestoredAtSetup(outcome) => {
                if let Err(e) = outcome {
                    self.wallet.empty_hint =
                        format!("your keys are back, but the notes did not restore: {e}");
                    let w = self.wallet.clone();
                    self.show(Screen::Wallet(w));
                } else {
                    // The notes are on disk now, so show them before
                    // spending seconds checking them. This is the moment a
                    // holder most wants to see them.
                    self.show_local();
                    self.verify_restored_ownership();
                }
                // Sheets as well as a file: the file is in, now the paper.
                if !self.restore_paper_after_setup() {
                    self.refresh();
                }
            }

            // Only ever reported when it found something. A restore that
            // checks out needs no sentence of its own.
            UiEvent::OwnershipChecked(outcome) => match outcome {
                Err(e) => eprintln!("kenter: could not check ownership: {e}"),
                Ok(report) if report.is_clean() => {}
                Ok(report) => {
                    let mut parts = Vec::new();
                    if !report.corrected.is_empty() {
                        parts.push(format!(
                            "{} note{} had a damaged ownership record, repaired from the ledger",
                            report.corrected.len(),
                            if report.corrected.len() == 1 { "" } else { "s" }
                        ));
                    }
                    if !report.disowned.is_empty() {
                        parts.push(format!(
                            "{} note{} claimed to be yours and {} not - the notes are kept, \
                             the claim is not",
                            report.disowned.len(),
                            if report.disowned.len() == 1 { "" } else { "s" },
                            if report.disowned.len() == 1 { "is" } else { "are" }
                        ));
                    }
                    for (id, why) in &report.disowned {
                        eprintln!("kenter: disowned {id}: {why}");
                    }
                    self.wallet.empty_hint = parts.join("; ");
                    let w = self.wallet.clone();
                    self.show(Screen::Wallet(w));
                    self.refresh();
                }
            },

            UiEvent::Camera(e) => self.on_camera(e),

            UiEvent::Paper(state) => {
                // A completed restore changes the billfold, so re-read it
                // behind the screen the holder is still looking at.
                let done = matches!(state, kenter_ui::PaperState::Restored { .. });
                self.show(Screen::Paper(kenter_ui::PaperView { state }));
                if done {
                    self.sheet = None;
                    self.refresh();
                }
            }

            UiEvent::NotUnlocked(why) => {
                self.unlocking = false;
                // Back to the gate with the reason, not onward to a billfold
                // that cannot show anything. A wrong passphrase is the
                // expected case and belongs on the screen that can retry it.
                self.show_gate(Some(why));
            }

            UiEvent::Settings(view) => {
                // Only if settings is still what is showing: the ledger read
                // can outlast the holder's interest in it.
                if let Screen::Settings(now) = &self.screen {
                    // A field the holder is typing in survives the
                    // background refresh that lands under it.
                    let mut view = view;
                    view.rpc_edit = now.rpc_edit.clone();
                    self.show(Screen::Settings(view));
                }
            }

            UiEvent::RpcSaved(result) => {
                let Screen::Settings(v) = &self.screen else { return };
                let mut v = v.clone();
                match result {
                    Ok(host) => {
                        self.entry = Zeroizing::new(String::new());
                        v.rpc_edit = None;
                        self.show(Screen::Settings(v));
                        self.open_settings();
                        self.note_settings(&format!("now talking to {host}"));
                    }
                    Err(e) => {
                        if let Some(edit) = v.rpc_edit.as_mut() {
                            edit.busy = false;
                            edit.error = Some(e);
                        }
                        self.show(Screen::Settings(v));
                    }
                }
            }

            UiEvent::Receive(state) => {
                // Ready arrives repeatedly while the inbox is watched, and the
                // worker is still running behind it — only a terminal state
                // ends the run.
                if !matches!(state, ReceiveState::Ready { .. }) {
                    self.receiving = false;
                }
                self.reply = None;
                self.entry = Zeroizing::new(String::new());
                let created = matches!(
                    state,
                    ReceiveState::Ready { .. }
                        | ReceiveState::Received { .. }
                        | ReceiveState::Held { .. }
                );
                // Only if the receive page is still what is showing. Backing
                // out of a prompt answers the worker, and its "cancelled"
                // reply must not drag the holder back to a page they left.
                //
                // The standing-tag page is only replaced by standing-tag
                // news: a watch cancelled on the way in can still have one
                // report in flight, and it must not land on top of a page
                // the holder has just opened.
                let standing = matches!(
                    self.screen,
                    Screen::Receive(ReceiveView {
                        state: ReceiveState::Standing { .. }
                    })
                );
                if matches!(self.screen, Screen::Receive(_))
                    && (!standing || matches!(state, ReceiveState::Standing { .. }))
                {
                    self.show(Screen::Receive(ReceiveView { state }));
                }
                // A pending receive or a new token means the wallet behind
                // this page is stale. Guarded so the watch's status updates,
                // which arrive every poll, do not each fire an RPC sweep.
                if created && !self.receive_synced {
                    self.receive_synced = true;
                    self.refresh();
                }
                // Both outcomes put a note in the billfold, so both make the
                // balance behind this page stale.
                if matches!(
                    self.screen,
                    Screen::Receive(ReceiveView {
                        state: ReceiveState::Received { .. } | ReceiveState::Held { .. }
                    })
                ) {
                    self.refresh();
                }
            }
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => {
                // Release any worker blocked on a prompt, and stop the one
                // watching the inbox, before the loop dies.
                self.answer(None);
                self.stop_receive();
                event_loop.exit()
            }

            WindowEvent::CursorMoved { position, .. } => {
                // winit gives physical coords; the layout (and hit rects) are in
                // logical space, so map back through the DPI scale factor.
                let scale = self
                    .window
                    .as_ref()
                    .map(|w| w.scale_factor())
                    .unwrap_or(1.0);
                let logical = position.to_logical::<f32>(scale);
                self.cursor = (logical.x, logical.y);
                let hovered = self
                    .ui
                    .hit_test_with(self.cursor.0, self.cursor.1, &self.it);
                if hovered != self.it.hovered {
                    self.it.hovered = hovered;
                    if let Some(w) = &self.window {
                        w.request_redraw();
                    }
                }
            }

            WindowEvent::CursorLeft { .. } => {
                if self.it.hovered.is_some() {
                    self.it.hovered = None;
                    if let Some(w) = &self.window {
                        w.request_redraw();
                    }
                }
            }

            WindowEvent::MouseInput {
                state,
                button: MouseButton::Left,
                ..
            } => {
                let hit = self
                    .ui
                    .hit_test_with(self.cursor.0, self.cursor.1, &self.it);
                match state {
                    ElementState::Pressed => {
                        self.it.pressed = hit;
                        // Held, not toggled: the phrase is on screen for as
                        // long as a finger is down and no longer, which keeps
                        // the window that an OS thumbnail or a screen
                        // recording could catch it in as small as possible.
                        if hit.and_then(|n| self.ui.action_at(n)) == Some(Action::Reveal) {
                            self.set_revealed(true);
                            return;
                        }
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                    ElementState::Released => {
                        self.it.pressed = None;
                        // Releasing Reveal hides the phrase again, on
                        // either screen. Matching only the software one
                        // left the card's phrase on screen after the
                        // button came up - hold-to-reveal that does not
                        // stop revealing.
                        if matches!(
                            &self.screen,
                            Screen::Setup(SetupView {
                                state: SetupState::Phrase { revealed: true, .. }
                                    | SetupState::CardPhrase { revealed: true, .. }
                            })
                        ) {
                            self.set_revealed(false);
                            return;
                        }
                        if let Some(node) = hit {
                            if let Some(i) = self.ui.nav_ids.iter().position(|&n| n == node) {
                                self.navigate(i);
                                return;
                            }
                            // `act` may replace the screen, so redraw through
                            // it rather than after it.
                            if let Some(action) = self.ui.action_at(node) {
                                self.act(action);
                                return;
                            }
                        }
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                }
            }

            // Without this the modifier state stays empty forever and
            // Ctrl+V is indistinguishable from typing "v".
            WindowEvent::ModifiersChanged(m) => self.mods = m.state(),

            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        logical_key,
                        state: ElementState::Pressed,
                        ..
                    },
                ..
            } => {
                // While a prompt is up every key belongs to the field. Letting
                // R through would fire a wallet refresh from a keystroke the
                // holder meant as part of their passphrase.
                if self.is_typing() {
                    // Paste. Without this Ctrl+V arrives as the character
                    // "v", so a pasted 56-character address reads as one
                    // character typed.
                    if self.mods.control_key()
                        && matches!(
                            logical_key.as_ref(),
                            Key::Character("v") | Key::Character("V")
                        )
                    {
                        self.paste();
                        return;
                    }
                    let gate = matches!(self.screen, Screen::Locked(_));
                    match logical_key.as_ref() {
                        // On the gate there is no worker waiting on a
                        // channel, so Enter opens the store rather than
                        // answering anybody.
                        Key::Named(NamedKey::Enter) if gate => self.submit_unlock(),
                        // And nothing to cancel *to*: the gate is the
                        // bottom of the stack.
                        Key::Named(NamedKey::Escape) if gate => {}
                        Key::Named(NamedKey::Enter) => self.act(Action::Confirm),
                        Key::Named(NamedKey::Escape) => self.act(Action::Cancel),
                        Key::Named(NamedKey::Backspace) => {
                            self.entry.pop();
                            self.refresh_entry();
                        }
                        Key::Named(NamedKey::Space) => {
                            self.entry.push(' ');
                            self.refresh_entry();
                        }
                        Key::Character(c) => {
                            self.entry.push_str(c);
                            self.refresh_entry();
                        }
                        _ => {}
                    }
                    return;
                }
                match logical_key.as_ref() {
                    Key::Character("r") | Key::Character("R") => self.refresh(),
                    Key::Named(NamedKey::Escape) => match self.screen {
                        Screen::Wallet(_) => event_loop.exit(),
                        // Reachable only while an unlock is running, since
                        // the gate is otherwise typing. There is nowhere to
                        // back out to, and `Back` from here would land on a
                        // billfold the client cannot read.
                        Screen::Locked(_) => {}
                        // There is nowhere to back out *to* during first run,
                        // and quitting would be a surprising thing for Escape
                        // to do on a screen showing a recovery phrase.
                        Screen::Setup(_) => self.act(Action::Cancel),
                        // Escape backs out to the wallet before it closes the
                        // window - one key, and the destructive meaning is
                        // never the first one.
                        _ => self.act(Action::Back),
                    },
                    _ => {}
                }
            }

            WindowEvent::MouseWheel { delta, .. } => {
                if !self.ui.scrollable() {
                    return;
                }
                // A line of a notch, or the pixels a trackpad reports. 48 is
                // roughly a row, so one notch moves one item rather than a
                // screenful.
                let dy = match delta {
                    MouseScrollDelta::LineDelta(_, y) => y * 48.0,
                    MouseScrollDelta::PixelDelta(p) => p.y as f32,
                };
                let next = self.ui.clamp_scroll(self.it.scroll - dy);
                if next != self.it.scroll {
                    self.it.scroll = next;
                    // The rows moved under the cursor, so what is hovered did
                    // too, without the mouse going anywhere.
                    self.it.hovered = self
                        .ui
                        .hit_test_with(self.cursor.0, self.cursor.1, &self.it);
                    if let Some(w) = &self.window {
                        w.request_redraw();
                    }
                }
            }

            WindowEvent::RedrawRequested => self.redraw(),

            _ => {}
        }
    }
}

#[cfg(test)]
mod env_file_tests {
    use super::env_file_path;
    use std::path::PathBuf;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// A release binary reads no file unless told to.
    ///
    /// A loader like `dotenvy::dotenv()` walks up from the working
    /// directory to the filesystem root, and whatever `.env` it found first
    /// would choose the mint every deposit escrows into, silently.
    #[test]
    fn a_release_build_reads_no_file_on_its_own() {
        assert_eq!(env_file_path(&args(&[]), false).unwrap(), None);
        assert_eq!(env_file_path(&args(&["--whatever"]), false).unwrap(), None);
    }

    /// While developing, exactly `./.env` — a relative path with one
    /// component, so there is nowhere for it to walk to.
    #[test]
    fn a_debug_build_reads_the_working_directory_and_no_further() {
        let p = env_file_path(&args(&[]), true).unwrap().expect("a path");
        assert_eq!(p, PathBuf::from(".env"));
        assert_eq!(p.components().count(), 1, "no ancestor component");
    }

    /// An explicit path is honoured in either build: naming the file is
    /// the whole difference between config and an ambush.
    #[test]
    fn an_explicit_path_is_honoured() {
        for debug in [true, false] {
            let p = env_file_path(&args(&["--env-file", "/tmp/x.env"]), debug)
                .unwrap()
                .expect("a path");
            assert_eq!(p, PathBuf::from("/tmp/x.env"));
        }
    }

    #[test]
    fn a_flag_without_a_path_is_an_error() {
        assert!(env_file_path(&args(&["--env-file"]), true).is_err());
    }
}

/// Seconds since the epoch, for naming a reset's archive folder.
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
