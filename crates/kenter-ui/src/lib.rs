//! Kenter Desktop UI — the shared model.
//!
//! **Taffy** owns structure (the layout tree); **pelt** owns appearance (each
//! element is painted from an SVG skin under `skins/kenter/`); a thin content
//! layer draws text over each element. The same model feeds two front-ends:
//!
//! - `bin/mock` — render one frame to a PNG for fast visual iteration.
//! - `bin/kenter-ui` — a live winit window presenting the CPU canvas via
//!   softbuffer, with hover / press / nav-selection interaction.
//!
//! Rendering is CPU: each element's pelt → premultiplied RGBA, alpha-composited
//! ("over") into a canvas. The renderer owns and clears the buffer every frame,
//! so there is no transparent-compositing ghosting (the reason pelt exists).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use pelt::{Pelt, PeltImage};
use taffy::prelude::*;

/// Running a receive off the event loop, and the shell half of the
/// authorization port.
pub mod receive;
/// What this client is, where it keeps things, and whether it can act.
pub mod settings;
/// First run: a passphrase, a seed, a store, an account.
pub mod setup;
/// The desktop's concrete wallet: the real chain, the real store, software
/// custody. One alias so the flows agree on what they are operating.
pub mod vault;

/// The two secrets a session holds, named so they cannot be swapped.
///
/// A software wallet has one secret used for both. A **card wallet has one
/// secret and two credentials derived from it**, and they are not
/// interchangeable:
///
/// - `owner` authorises owner-key operations, which happen **on the card**.
///   It is the PIN.
/// - `account` opens the software vault holding the **fee-paying Stellar
///   account**, which is kept off the card (see
///   `docs/architecture/custody.md`). It is BIP85 child 2.
///
/// Both are `Zeroizing<Vec<u8>>`, so passing them positionally lets the
/// wrong one through the type checker, and several call sites take both
/// (the activation gate, the Account page, and both deposit paths). Naming
/// them does not make a mix-up impossible, but it makes one visible at the
/// call site instead of at a card.
#[derive(Clone)]
pub struct SessionCreds {
    pub owner: zeroize::Zeroizing<Vec<u8>>,
    pub account: zeroize::Zeroizing<Vec<u8>>,
}

/// The wallet, over whichever custody this installation uses.
///
/// Generic over the vault on purpose: naming `SoftVault` here concretely
/// would leave a card wallet creatable but unusable. `TokenWallet` is
/// generic over `V: DerivingVault` and `StellarKeycard` implements it, so
/// this alias is the only place the custody choice has to stay open.
pub type GuiWallet = kenter_wallet::TokenWallet<
    kenter_client::WalletChain,
    kenter_wallet::FileStore,
    vault::GuiVault,
>;

pub mod account;
/// Deposit: value in, a note out.
/// Is there a card, and can a wallet be put on it? First run asks before it
/// asks for a PIN.
pub mod card;
pub mod card_setup;
/// The wallet backup file: writing one, remembering it, restoring from it.
pub mod backup;
pub mod deposit;
/// Handing a note over: Export for bearer, Pay for spend mode.
pub mod pay;
/// QR symbols, rendered as SVG so they go through the same pelt path.
/// The paper backup as a PDF — the printable artefact.
pub mod pdf;
pub mod qr;
/// Reading a paper backup back: QR symbols out of a scan or a photograph.
pub mod scan;
/// Reading paper backups through a camera. Windows, Linux and macOS each
/// compile a different capture backend (see `Cargo.toml`); only Windows
/// has been run.
pub mod camera;
/// The printable paper backup: a page of QR symbols.
pub mod sheet;
/// Redeeming a note.
pub mod redemption;
/// Loading a real wallet view from disk and the ledger.
pub mod wallet;
/// Resetting a wallet that cannot be opened.
pub mod reset;

pub use taffy::NodeId;

pub const W: u32 = 960;
pub const H: u32 = 620;

/// Horizontal placement of a text label within its element box.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Anchor {
    Start,
    Middle,
    End,
}

/// A line of content text painted over an element (not part of the skin art).
#[derive(Clone)]
struct Label {
    text: String,
    size: f32,
    color: String,
    weight: u32,
    anchor: Anchor,
    inset: f32,
    vfrac: f32,
    /// This text is a secret — a recovery phrase. Never cached, zeroized on
    /// drop. See [`Label::secret`].
    sensitive: bool,
}

impl Drop for Label {
    fn drop(&mut self) {
        if self.sensitive {
            use zeroize::Zeroize;
            self.text.zeroize();
        }
    }
}

impl Label {
    /// Mark this text as a secret.
    ///
    /// Two things follow, and neither is optional for a recovery phrase. The
    /// layer is **never cached**, because the raster cache is keyed by content
    /// and deliberately outlives tree rebuilds (it is what makes typing
    /// affordable), so a cached phrase would sit in process memory as a bitmap
    /// long after the screen was closed and turn up in any core dump. And the
    /// text is **zeroized on drop**, because `Label` is cloned into the layout
    /// tree and a plain `String` would leave copies behind.
    ///
    /// This reduces exposure; it does not eliminate it. usvg and tiny-skia
    /// allocate their own buffers while rasterizing and this crate does not
    /// control them. The real mitigations stay the same two:
    /// show it only while held, and purge on leaving ([`Ui::purge_cache`]).
    // Unused until the first-run screen shows a recovery phrase. Built ahead
    // of it deliberately: the hazard it guards against is a property of the
    // cache, not of that screen, and retrofitting it would mean the screen
    // existing unsafely first.
    #[allow(dead_code)]
    fn secret(mut self) -> Self {
        self.sensitive = true;
        self
    }
}

fn lbl(
    text: &str,
    size: f32,
    color: &str,
    weight: u32,
    anchor: Anchor,
    inset: f32,
    vfrac: f32,
) -> Label {
    Label {
        text: text.to_string(),
        size,
        color: color.to_string(),
        weight,
        anchor,
        inset,
        vfrac,
        sensitive: false,
    }
}

/// What clicking an element means. Carried on the element rather than looked up
/// by position, so a shell matches on intent instead of on which node happened
/// to be built third.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Leave the wallet page for the receive flow.
    Receive,
    /// Open the standing pay tag: the one code that can be published ahead
    /// of the payer (owner-key index 0).
    ShowStanding,
    /// Publish the standing tag, or retire it. One action, because the
    /// screen already shows which way it will go.
    ToggleStanding,
    /// Ask for the passphrase and open the sealed store.
    Unlock,
    /// First run: make a new wallet.
    NewWallet,
    /// First run: keep the key on this computer, behind a passphrase.
    UseSoftware,
    /// First run: keep the key on a card.
    UseCard,
    /// First run: look at the reader again.
    CheckCard,
    /// The locked gate: this wallet cannot be opened; show the reset.
    ResetWallet,
    /// The reset screen: move this wallet aside and start a first run.
    ConfirmReset,
    /// First run: restore one from a phrase.
    RestoreWallet,
    /// First run: point at the backup file the phrase goes with.
    ChooseBackupFile,
    /// First run: erase an already-set-up card so it can be reused.
    EraseCard,
    /// First run: decline to choose a duress PIN.
    ///
    /// Not "no duress PIN" — there is no such state. Declining means one is
    /// generated and shown, because offering to skip and then not skipping
    /// would be a lie.
    SkipDuress,
    /// Show the recovery phrase while this is held down.
    Reveal,
    /// Move to the next step of first run.
    Continue,
    /// Start a deposit.
    Deposit,
    /// Switch the note between bearer and spend mode.
    ToggleMode,
    /// Step the pair count: more pairs, more privacy, more cost.
    CyclePairs,
    /// Establish the trustline the mint's asset needs.
    AddTrustline,
    /// Open the RPC server field on Settings.
    EditRpc,
    /// Go back to the build's default RPC server.
    RpcDefault,
    /// Put the recovery phrase on the clipboard.
    ///
    /// Always offered: the alternative is transcribing twenty-four words by
    /// hand, and a single wrong one loses the wallet (`setup.rs`).
    CopyPhrase,
    /// Ask the ledger again whether this account can act yet.
    Check,
    /// Cancel this stalled print and take the escrow back.
    Recover(u32),
    /// Hand over this note from its card — export if bearer, repoint if
    /// spend mode. The index is within the open compartment.
    ///
    /// There is no "pick a note to pay with" screen: the billfold already
    /// is one, sorted into compartments, and a second list of the same
    /// notes was a place pretending to be an action.
    PayNote(usize),
    /// Redeem this note from its card.
    RedeemNote(usize),
    /// Choose a different account for the escrow payout.
    EditDestination,
    /// Put the payout back to the holder's own account.
    UseOwnAccount,
    /// Open a compartment of the billfold.
    SelectTab(usize),
    /// Open or close a card.
    ExpandNote(usize),
    /// Take a note file the payer sent and put it where the watch sees it.
    ///
    /// Acceptance has always worked by dropping a file into the inbox
    /// folder. That is a real path and it stays, but telling someone to
    /// find a directory in Explorer is not an interface.
    ImportNote,
    /// Write a bearer note out as a file to hand over.
    ExportNote,
    /// Same, but recorded as the holder's own backup — which `exposure()`
    /// deliberately does not count, because a backup is not another party
    /// who might redeem first.
    ExportBackup,
    /// Keep a copy of a note just exported.
    KeepCopy,
    /// Move an exported note to Spent, keeping the bytes.
    DropCopy,
    /// Put this screen's address on the clipboard.
    ///
    /// Addresses are long and exact, and moving one into another window is
    /// the single most common thing a holder does with it. Reading 56
    /// characters off a screen is slow and is a way to send money to the
    /// wrong place.
    Copy,
    /// Back to the wallet.
    Back,
    /// Reserve an owner index and derive a commitment.
    NewReceive,
    /// Open the paper-backup screen.
    PaperBackup,
    /// Print the paper backup: PDF to print, or SVG to engrave.
    PrintPaper,
    PrintPaperSvg,
    /// Open the scan screen, and add images to it.
    ScanPaper,
    /// Start the camera on the scan screen.
    UseCamera,
    /// Stop it and release the device.
    StopCamera,
    AddImages,
    /// Restore from whatever has been scanned, complete or not.
    RestoreScanned,
    /// Write a backup of the whole wallet, somewhere the holder picks.
    ///
    /// Distinct from [`Action::ExportBackup`], which copies one note. This
    /// is the file that, with the recovery phrase, is the wallet.
    SaveBackup,
    /// Merge a backup file into this wallet.
    RestoreBackup,
    /// Accept the authorization prompt.
    Confirm,
    /// Dismiss the authorization prompt. Declining, not failing.
    Cancel,
}

/// Interactive role of an element — how its rendered state responds to input.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Nav(usize),
    Button(Action),
}

/// What to paint on a laid-out node.
struct Skin {
    name: &'static str,
    /// Set on a panel that clips and scrolls the column inside it.
    scroll_content: Option<NodeId>,
    /// An SVG built at runtime instead of loaded from `skins/`. This is how a
    /// QR symbol gets drawn: it goes through pelt and the same size-keyed
    /// raster cache as every other element rather than needing its own
    /// compositing path.
    inline: Option<String>,
    base_state: &'static str,
    /// Cycle this element through [`FRAMES`] instead of holding `base_state`.
    animated: bool,
    labels: Vec<Label>,
    kind: Option<Kind>,
    /// Paint the live camera frame over this element.
    ///
    /// The skin still draws underneath, so the panel is what shows before
    /// the first frame arrives and whenever the camera is not running.
    viewfinder: bool,
}

/// The frame states an animated skin cycles through, in order.
///
/// These are the `data-pelt-state` names in `skins/kenter/progress.svg`, and
/// the count has to match it — a name with no group in the file renders as
/// nothing, which is a blank bar rather than an error.
///
/// Frames are states rather than a swept token because state is part of the
/// raster cache key: the loop costs `FRAMES.len()` entries once and then every
/// frame is a blit. A token would be a fresh entry per distinct value, growing
/// for as long as the animation ran.
pub(crate) const FRAMES: [&str; 12] = [
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11",
];

impl Skin {
    fn new(name: &'static str) -> Self {
        Skin {
            name,
            scroll_content: None,
            inline: None,
            base_state: "default",
            animated: false,
            labels: Vec::new(),
            kind: None,
            viewfinder: false,
        }
    }

    /// Paint the live camera frame over this element.
    fn viewfinder(mut self) -> Self {
        self.viewfinder = true;
        self
    }

    /// A skin painted from an SVG string built at runtime.
    fn inline_svg(svg: String) -> Self {
        Skin {
            inline: Some(svg),
            ..Skin::new("inline")
        }
    }
    /// Mark this element as a scroll viewport over `content`.
    fn scrolls(mut self, content: NodeId) -> Self {
        self.scroll_content = Some(content);
        self
    }

    /// Draw a non-interactive element in one of the skin's other states — used
    /// to make the passphrase field read as a focused input rather than as
    /// another list row.
    fn base_state(mut self, state: &'static str) -> Self {
        self.base_state = state;
        self
    }
    /// Run this element through [`FRAMES`] for as long as it is on screen.
    ///
    /// The element says it is animated; nothing here says when to tick. The
    /// shell notices the flag, drives the clock, and passes the frame in
    /// through [`Interaction`] — the same way hover and scroll arrive, so an
    /// animated element still has no mutable state of its own.
    fn animated(mut self) -> Self {
        self.animated = true;
        self
    }
    fn label(mut self, l: Label) -> Self {
        self.labels.push(l);
        self
    }
    /// `content`, drawn as this skin's text layer draws the label `name`:
    /// its position, size, weight and colour all come from the skin file,
    /// so restyling text is an edit in Inkscape, not in code.
    fn text(self, name: &str, content: &str) -> Self {
        let l = styled(self.name, name, content);
        self.label(l)
    }
    /// [`Self::text`] for a secret: never cached, zeroized on drop.
    fn text_secret(self, name: &str, content: &str) -> Self {
        let l = styled(self.name, name, content).secret();
        self.label(l)
    }
    fn kind(mut self, k: Kind) -> Self {
        self.kind = Some(k);
        self
    }
}

/// One camera frame, borrowed for the length of a paint.
///
/// Luminance rather than colour: the decoder reads luminance, the preview
/// is of a black-and-white page, and carrying three channels would be
/// three times the copying for a greyer picture.
pub struct LiveFrame<'a> {
    pub width: u32,
    pub height: u32,
    pub luma: &'a [u8],
}

/// Paint a camera frame into the viewfinder rectangle.
///
/// Letterboxed, never stretched. A stretched preview would lie about
/// framing, and framing is the one thing the holder is using it to judge.
fn paint_live(
    canvas: &mut [u8],
    out_w: u32,
    out_h: u32,
    rect: (f32, f32, f32, f32),
    sx: f32,
    sy: f32,
    frame: &LiveFrame<'_>,
) {
    if frame.width == 0 || frame.height == 0 {
        return;
    }
    let (rx, ry, rw, rh) = rect;
    let (dx0, dy0) = ((rx * sx) as i32, (ry * sy) as i32);
    let (dw, dh) = ((rw * sx) as i32, (rh * sy) as i32);
    if dw <= 0 || dh <= 0 {
        return;
    }

    // Fit, keeping the aspect ratio, and centre what is left over.
    let scale = (dw as f32 / frame.width as f32).min(dh as f32 / frame.height as f32);
    let fw = (frame.width as f32 * scale) as i32;
    let fh = (frame.height as f32 * scale) as i32;
    let ox = dx0 + (dw - fw) / 2;
    let oy = dy0 + (dh - fh) / 2;

    for y in 0..fh {
        let dy = oy + y;
        if dy < 0 || dy >= out_h as i32 {
            continue;
        }
        let sy_px = (y as f32 / scale) as u32;
        if sy_px >= frame.height {
            continue;
        }
        for x in 0..fw {
            let dx = ox + x;
            if dx < 0 || dx >= out_w as i32 {
                continue;
            }
            let sx_px = (x as f32 / scale) as u32;
            if sx_px >= frame.width {
                continue;
            }
            let v = frame.luma[(sy_px * frame.width + sx_px) as usize];
            let i = ((dy as u32 * out_w + dx as u32) * 4) as usize;
            if i + 3 < canvas.len() {
                canvas[i] = v;
                canvas[i + 1] = v;
                canvas[i + 2] = v;
                canvas[i + 3] = 255;
            }
        }
    }
}

/// Live interaction state, applied at render time (nothing in the tree mutates).
#[derive(Clone, Copy, Default)]
pub struct Interaction {
    pub hovered: Option<NodeId>,
    pub pressed: Option<NodeId>,
    pub selected_nav: usize,
    /// How far the scrollable panel is scrolled, in logical pixels. Clamped by
    /// [`Ui::clamp_scroll`] against the page actually on screen.
    pub scroll: f32,
    /// Which frame an animated skin is showing. Counts up forever and is
    /// taken modulo [`FRAMES`], so nothing has to reset it between screens.
    pub frame: u32,
}

/// Absolute (post-layout) rect of an interactive element, for hit-testing.
struct HitRect {
    node: NodeId,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
}

/// Cache key for a rasterized layer: (node, layer-kind, state, phys w, phys h,
/// content hash). Each element/state/size rasterizes once; a hover re-renders
/// only the element whose state changed, not the whole scene.
///
/// The content hash is what lets the cache outlive the tree. Typing into the
/// passphrase field rebuilds the whole layout once per keystroke, and a cold
/// raster of a full page is a quarter of a second — unusable as a per-character
/// cost. Taffy hands out node ids in construction order, so a rebuilt tree
/// reuses them; hashing the element's actual content (skin name, inline SVG,
/// every label) means an unchanged element hits its old entry and a changed one
/// misses, with no risk of node 7 on one page being served node 7's art from
/// another.
type CacheKey = (NodeId, &'static str, &'static str, u32, u32, u64);

/// The built UI: a laid-out Taffy tree + skins, ready to render at any
/// interaction state.
/// What a note is waiting on, if anything.
///
/// Depositing and accepting ask the same question — *is this real and mine
/// yet* — so they share one vocabulary rather than each inventing a status
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteState {
    /// Registered, Active on the ledger, and ours.
    Live,
    /// Held, but the ledger could not be reached. Not a failure: "here is
    /// what you hold, unverified" is honest where a zero is not.
    Unverified,
    /// A deposit in flight. Value escrowed, no instrument yet.
    Printing { done: u32, total: u32 },
    /// Received, partway through G1–G3. Not yet paid.
    Verifying,
    /// A print that failed or expired. The escrow is still in the slot.
    Stalled,
    /// The record on this machine disagrees with the ledger.
    ///
    /// Either the amount differs, or the ledger's live record is not
    /// this note at all — its chain commitment or its claim key says so
    /// (`TokenStatus::Counterfeit`). Corruption or forgery; the client
    /// cannot tell which, and the holder does not need it to. Either
    /// way the record on this machine is not to be believed.
    ///
    /// Kept apart from [`NoteState::Stalled`], which means the ledger has
    /// never heard of the note at all. That one is usually a deposit that
    /// did not finish; this one is a record that disagrees with a deposit
    /// that did.
    Disputed,
    /// Redeemed, or the ledger says the pointer moved away.
    Spent(&'static str),
    /// The holder's own assertion that it is gone. An opinion, not a fact,
    /// and reversible — kept apart from [`NoteState::Spent`] for that reason.
    MarkedSpent,
}

impl NoteState {
    /// Can anything be done with this note?
    ///
    /// `Live` and `Unverified` both yes — unverified usually means the
    /// ledger was unreachable, and refusing to act on a note because of a
    /// network problem is the wrong way to be cautious. Everything else no:
    /// a stalled print has no instrument, and a spent note has nothing left
    /// to move. Offering a verb that can only fail is worse than offering
    /// none.
    pub fn is_actionable(&self) -> bool {
        matches!(self, NoteState::Live | NoteState::Unverified)
    }

    /// Something is wrong here, as opposed to merely unfinished or spent.
    ///
    /// Drives the one place red is used on a note. `Stalled` is not
    /// included: a print that did not finish is a thing to look into, and
    /// the escrow is still the holder's.
    pub fn is_wrong(&self) -> bool {
        matches!(self, NoteState::Disputed)
    }

    /// The short label on a collapsed card.
    pub fn label(&self) -> String {
        match self {
            NoteState::Live => "live".into(),
            NoteState::Unverified => "unverified".into(),
            NoteState::Printing { done, total } => format!("printing {done}/{total}"),
            NoteState::Verifying => "verifying".into(),
            NoteState::Stalled => "stalled".into(),
            NoteState::Disputed => "amount disputed".into(),
            NoteState::Spent(why) => (*why).to_string(),
            NoteState::MarkedSpent => "marked spent".into(),
        }
    }

    /// Is this note finished and usable?
    pub fn is_live(&self) -> bool {
        matches!(self, NoteState::Live)
    }

    /// Does it belong in the Spent compartment rather than among the notes?
    pub fn is_done(&self) -> bool {
        matches!(self, NoteState::Spent(_) | NoteState::MarkedSpent)
    }
}

/// One note, as a card.
#[derive(Debug, Clone)]
pub struct NoteCard {
    /// Full id, for the shell to act on.
    pub id: String,
    pub short_id: String,
    /// Face value, formatted.
    pub amount: String,
    /// Face minus this note's own fees — a real differentiator inside a
    /// denomination tab, where two notes of equal face redeem for different
    /// amounts if they were printed with different pair counts.
    pub redeems_for: String,
    /// `true` for spend mode. Different instruments, not a status detail.
    pub spend_mode: bool,
    pub state: NoteState,
    /// Whether the bytes are in a backup. Binary and monotonic: a note's
    /// container never changes after receipt, so once backed up, always.
    pub backed_up: bool,
    /// What the record claimed, when the ledger disagreed with it.
    ///
    /// `None` normally. Present only for [`NoteState::Disputed`], so the
    /// card can show both figures - the holder is owed the difference, not
    /// just the corrected number.
    pub claimed: Option<String>,
    /// Parties who may hold a redeemable copy. Never counts own backups.
    pub exposure: u32,
}

/// A compartment of the billfold.
#[derive(Debug, Clone)]
pub struct DenomTab {
    /// `$25.0000000`, or `Other`, or `Spent`.
    pub label: String,
    pub notes: Vec<NoteCard>,
}

/// Everything the billfold renders. The UI holds no wallet logic and does no
/// IO — a shell reconciles against the ledger and hands the result over,
/// which keeps this crate renderable from a PNG mock with no chain, vault or
/// store present.
#[derive(Debug, Clone)]
pub struct WalletView {
    /// Total face value held, formatted. **Never "spendable"**: it is a fact
    /// about what is in the billfold, not a claim about what can be paid,
    /// and notes of different value cannot be combined into one payment.
    pub balance: String,
    /// Sub-line — a count, or why the figure is uncertain.
    pub subtitle: String,
    /// Compartments, largest denomination first, with `Spent` last.
    pub tabs: Vec<DenomTab>,
    pub selected_tab: usize,
    /// Which card in the selected tab is open, if any.
    pub expanded: Option<usize>,
    /// Shown when there is nothing to list, so an empty billfold explains
    /// itself instead of rendering a blank panel.
    pub empty_hint: String,
    /// The store is sealed and no key has been supplied.
    pub locked: bool,
    /// A read of the ledger is in flight behind this page.
    ///
    /// Separate from `locked`, and the slow one of the two: unlocking is
    /// 20-odd milliseconds of Argon2id, while reconciling is RPC round trips
    /// and takes seconds. The figure on screen during it is the *old* one, so
    /// the page has to say it is still being checked.
    pub loading: bool,
    /// Escrow stuck in a dead print slot. Money, so it is said on the
    /// billfold rather than hidden on a card nobody opens.
    pub stalled: Option<String>,
    /// Notes held that are in no backup. Same argument as `stalled`, and a
    /// stronger one: a stalled print is recoverable from the ledger, whereas
    /// a note that exists only on this disk is recoverable from nothing.
    ///
    /// `None` when the backup covers what is held — silence is the reward
    /// for being backed up, rather than a tick nobody reads.
    pub backup: Option<String>,
    /// Records that contradict the ledger about their own value.
    ///
    /// Above everything, and in red. The other two lines are about value
    /// the holder might lose; this one is about value they never had, and
    /// about a note or a backup that somebody may have built to deceive
    /// them.
    pub disputed: Option<String>,
}

impl WalletView {
    fn bare(balance: &str, subtitle: &str, hint: &str) -> WalletView {
        WalletView {
            balance: balance.into(),
            subtitle: subtitle.into(),
            tabs: Vec::new(),
            selected_tab: 0,
            expanded: None,
            empty_hint: hint.into(),
            locked: false,
            loading: false,
            stalled: None,
            backup: None,
            disputed: None,
        }
    }

    /// The placeholder the PNG mock renders — no wallet required.
    pub fn sample() -> WalletView {
        let note = |short: &str, amt: &str, out: &str, spend: bool, state: NoteState| NoteCard {
            claimed: None,
            id: short.into(),
            short_id: short.into(),
            amount: amt.into(),
            redeems_for: out.into(),
            spend_mode: spend,
            state,
            backed_up: true,
            exposure: 0,
        };
        WalletView {
            balance: "$56.0000000".into(),
            subtitle: "5 notes held".into(),
            tabs: vec![
                DenomTab {
                    label: "$25.0000000".into(),
                    notes: vec![
                        note(
                            "GD7MDB…CLHR",
                            "$25.0000000",
                            "$24.9994000",
                            false,
                            NoteState::Live,
                        ),
                        note(
                            "GCBSLN…RIRA",
                            "$25.0000000",
                            "$24.9988000",
                            true,
                            NoteState::Live,
                        ),
                    ],
                },
                DenomTab {
                    label: "$5.0000000".into(),
                    notes: vec![note(
                        "GBVCZF…CGU5",
                        "$5.0000000",
                        "$4.9994000",
                        false,
                        NoteState::Printing { done: 2, total: 3 },
                    )],
                },
                DenomTab {
                    label: "$0.5000000".into(),
                    notes: vec![
                        note(
                            "GAXQ2M…TT4P",
                            "$0.5000000",
                            "$0.4994000",
                            false,
                            NoteState::Live,
                        ),
                        note(
                            "GDLJFQ…37RS",
                            "$0.5000000",
                            "$0.4994000",
                            false,
                            NoteState::Unverified,
                        ),
                    ],
                },
            ],
            selected_tab: 0,
            expanded: None,
            empty_hint: String::new(),
            locked: false,
            loading: false,
            stalled: None,
            backup: None,
            disputed: None,
        }
    }

    /// Shown while the billfold is being read and reconciled.
    ///
    /// Deliberately not a number. An explicit "not known yet" is not a false
    /// statement, so the window can open at once and fill in.
    pub fn loading() -> WalletView {
        let mut v = WalletView::bare("—", "reading your notes…", "reconciling against the ledger");
        v.loading = true;
        v
    }

    /// The store is sealed and no key has been supplied this session.
    ///
    /// Distinct from empty, and the distinction matters: an empty billfold
    /// says you hold nothing, a locked one says the client cannot see what
    /// you hold. Painting a zero would be a false statement about money.
    pub fn locked() -> WalletView {
        let mut v = WalletView::bare(
            "—",
            "locked",
            "your notes are encrypted on disk - unlock to see them",
        );
        v.locked = true;
        v
    }

    /// A billfold with nothing in it yet.
    pub fn empty(hint: &str) -> WalletView {
        WalletView::bare("$0.0000000", "no notes held", hint)
    }
}

/// Which page the window is showing.
///
/// Not a modal over the wallet: a full page. A modal would need absolute
/// positioning and a scrim, and would buy nothing here - receiving is not a
/// quick confirmation, it is a thing you sit on while a payer acts.
#[derive(Debug, Clone)]
pub enum Screen {
    Wallet(WalletView),
    Receive(ReceiveView),
    Settings(SettingsView),
    Account(AccountView),
    Deposit(DepositView),
    Pay(PayView),
    Redeem(RedeemView),
    /// First run. No nav, because nothing else is reachable yet.
    Setup(SetupView),
    /// The store is sealed. No nav, for the same reason as `Setup`: without
    /// credentials there is no page that can do its job.
    Locked(LockedView),
    /// The locked wallet cannot be opened, and the holder is resetting it.
    /// No nav, like `Locked`: it is reached only from there.
    Reset(ResetView),
    /// Backing up to paper, and reading it back.
    ///
    /// Its own screen rather than a mode of Settings, because the import
    /// half has a state nothing else here does: **partial success, as the
    /// normal case**. Every other flow in this client either worked or
    /// did not; a scan gives you three notes of four and that is a result
    /// to act on, not an error to dismiss.
    Paper(PaperView),
    /// An authorization prompt, over whichever page asked for it.
    ///
    /// Its own screen rather than a state of Receive, because unlocking the
    /// billfold needs the same prompt and has nothing to do with receiving.
    /// `under` is the nav entry to keep lit, so answering a prompt does not
    /// appear to navigate.
    Prompt {
        view: PromptView,
        under: usize,
    },
}

impl Screen {
    /// Which sidebar entry is lit. Derived from the screen rather than tracked
    /// alongside it, so the highlight cannot disagree with the page — which it
    /// did as soon as a button could navigate as well as the nav could.
    pub fn nav_index(&self) -> usize {
        match self {
            Screen::Wallet(_) => 0,
            Screen::Account(_) => 1,
            Screen::Deposit(_) => 2,
            Screen::Pay(_) => 0,
            Screen::Redeem(_) => 0,
            Screen::Receive(_) => 3,
            // Reached from Settings and stays lit there: paper is a
            // backup, and a holder who lands on it has not navigated away
            // from the page they pressed it on.
            Screen::Paper(_) => 4,
            // Nothing is lit, and nothing is clickable either.
            Screen::Locked(_) => 0,
            Screen::Reset(_) => 0,
            Screen::Settings(_) => 4,
            Screen::Prompt { under, .. } => *under,
            Screen::Setup(_) => 0,
        }
    }
}

/// The sidebar, in order. These are the surfaces that exist; an entry here
/// that goes nowhere is worse than no entry, because it reads as broken rather
/// than as unbuilt.
pub const NAV: [&str; 5] = ["Billfold", "Account", "Deposit", "Accept", "Settings"];

/// The Stellar account, as the screen shows it.
///
/// Separate from the billfold on purpose: these are fungible balances and a
/// note is not one. See `account.rs`.
#[derive(Debug, Clone, Default)]
pub struct AccountView {
    pub address: String,
    /// Formatted XLM: total, and what is actually spendable after reserve.
    pub xlm: String,
    pub xlm_spendable: String,
    /// The mint's asset — the balance a deposit spends.
    pub asset_code: String,
    pub asset_balance: String,
    /// `None` while the asset is still unknown, which is not "no".
    pub trustline: Option<bool>,
    /// What stands between this account and a working client, if anything.
    pub blocked_by: Option<String>,
    pub copied: bool,
    /// Escrow stuck in prints that never finished, newest first.
    pub stalled: Vec<StalledPrint>,
    pub busy: Option<String>,
    pub error: Option<String>,
}

/// The gate in front of a client whose store is sealed.
///
/// A whole screen rather than a flag on the billfold. Locked is a fact about
/// the *client*, not about one page: without store credentials the account
/// page cannot read a balance it can act on, Deposit has nothing to spend,
/// and Accept cannot derive an owner key. Leaving the sidebar live would
/// mean one condition refused in four different voices, each discovered by
/// walking into it.
#[derive(Debug, Clone, Default)]
pub struct LockedView {
    /// How many characters have been typed. The passphrase itself is never
    /// in the view model - only its length, so the screen can draw dots.
    pub entered: usize,
    /// Why the last attempt failed, if one did.
    pub error: Option<String>,
    /// An unlock is in flight. Argon2id is short, but the store read behind
    /// it is not, and a second Enter would start a second one.
    pub busy: bool,
    /// Set when this wallet's seed is on a card, with what the reader says.
    ///
    /// The gate asks a different question per custody — six digits to a
    /// card, or a passphrase to a file — and asking the wrong one is not a
    /// cosmetic error: it invites a holder to type one secret where the
    /// other belongs.
    pub card: Option<CardGate>,
}

/// The reset screen (`reset.rs`): what a reset would move, and the word
/// being typed to confirm it.
#[derive(Debug, Clone, Default)]
pub struct ResetView {
    /// Where everything would be moved to.
    pub archive: String,
    /// What would be moved, by name.
    pub moving: Vec<String>,
    /// Paper-backup files among them.
    pub backups: Vec<String>,
    /// The confirmation as typed so far. Not a secret: it is one fixed word.
    pub typed: String,
    pub error: Option<String>,
}

/// What the reader says while a card wallet waits to be opened.
#[derive(Debug, Clone, Default)]
pub struct CardGate {
    /// One line about the reader, from `card::Presence`.
    pub hint: String,
    /// Whether an unlock can be attempted at all. False means no card, no
    /// reader, or not a Keycard - nothing typed here can help until that
    /// changes.
    pub ready: bool,
}

/// A stalled print, as the screen shows it.
#[derive(Debug, Clone)]
pub struct StalledPrint {
    pub slot_id: u32,
    pub amount: String,
    pub progress: String,
}

/// What this client is and whether it can act — a status page, not a
/// preferences page. Plain rows because every answer is one fact, and the
/// page's job is to be read, not configured.
#[derive(Debug, Clone, Default)]
pub struct SettingsView {
    pub rows: Vec<(String, String)>,
    pub note: Option<String>,
    /// Asset code needing a trustline before this client can be paid out.
    ///
    /// The one action a status page earns: everything else here is a fact,
    /// but a missing trustline is a fact the holder has to *do* something
    /// about, and the consequence of not doing it is a redemption that cannot
    /// pay them.
    pub trustline_needed: Option<String>,
    /// What the wallet can say about its backup, and whether that is a
    /// problem. `true` means notes are held that no backup covers.
    ///
    /// The second action a status page earns, by the `trustline_needed`
    /// argument and more strongly: an un-backed-up note is a fact the
    /// holder has to do something about, and the consequence of not doing
    /// it is losing money outright rather than failing to be paid.
    pub backup: Option<(String, bool)>,
    /// The RPC server field, while it is open.
    pub rpc_edit: Option<RpcEdit>,
}

/// Choosing the RPC server this client talks to (Settings).
///
/// The network itself is fixed by the build; this only says where it is
/// reached. A new server is asked which network it serves before it is
/// used, so `busy` covers that round trip.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcEdit {
    pub typed: String,
    pub error: Option<String>,
    pub busy: bool,
    /// The network this build is for, to say what the server must serve.
    pub network: String,
}

/// A backup file the holder has pointed at, as its header reads.
///
/// Read before anything is asked of them, because
/// the header is cleartext and it answers the one question first run cannot:
/// whether these twenty-four words are a software wallet's seed or a card's.
/// The two derive different keys, and only the file knows which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSource {
    pub path: String,
    /// What is in it: "a card wallet, 5 notes, saved 3 days ago".
    pub summary: String,
    /// What the holder must supply for this one.
    pub needs: String,
    /// Which wallet it belongs to, so the phrase can be checked against it
    /// before the vault is built on it.
    pub fingerprint: String,
    /// How this wallet derives. Carried into the vault record.
    pub card_rooted: bool,
}

/// The paper flow, both directions.
// Not `Eq`: the camera carries a pixels-per-module figure, and that is
// a measurement rather than an identity.
#[derive(Debug, Clone, PartialEq)]
pub struct PaperView {
    pub state: PaperState,
}

/// One item on the import screen, as the holder reads it.
///
/// Named by **what it is**, not by symbol number: "note 3 is missing" is
/// something a person can act on, and "symbol 7 of 14 is missing" is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaperItem {
    /// "wallet record", "note 1".
    pub what: String,
    /// "complete", "needs symbol 2", "nothing scanned yet".
    pub state: String,
    pub done: bool,
    /// A note, rather than the wallet record.
    ///
    /// Carried as a flag instead of being recovered from `what` so the
    /// heading can count notes without matching on a display string.
    pub note: bool,
}

/// The camera, as the scan screen shows it.
#[derive(Debug, Clone, PartialEq)]
pub enum CameraView {
    /// Not running. Image files still work, and on a machine with no
    /// camera this is the only state there is.
    Off,
    /// Asked for, not yet answering. Opening a device takes a moment.
    Starting,
    /// Running, with what it is worth. `px_per_module` is the number
    /// that decides whether a symbol can resolve at all, so the screen
    /// says it rather than hiding it behind a quality word.
    Live {
        name: String,
        px_per_module: f32,
    },
    /// There is a camera but it cannot do this job, or it failed. The
    /// message says which, and always names image files as the way on.
    Refused(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PaperState {
    /// What printing will produce, before any file dialog. The page count
    /// is the thing a holder decides with and it is not guessable.
    Offer {
        notes: usize,
        symbols: usize,
        pages: usize,
        /// `None` until the wallet is open; paper needs the backup key.
        locked: bool,
    },
    Working {
        what: String,
    },
    /// Written. Says where, how to print it, and to test it now.
    Printed {
        path: String,
        pages: usize,
    },
    /// Mid-scan. The screen this flow exists for.
    Scanning {
        /// Which wallet the symbols say they belong to, if any have been
        /// read. Known without a key.
        wallet: Option<String>,
        items: Vec<PaperItem>,
        /// Symbols seen that were not ours, and ones too blurry to read.
        foreign: usize,
        unreadable: usize,
        /// Files that could not be opened, or symbols that disagreed.
        problems: Vec<String>,
        /// Nothing is missing.
        complete: bool,
        /// What the camera is doing, if anything.
        camera: CameraView,
        /// Scanning during first run, before any wallet exists. There is
        /// no key yet to open what is read, so the way out is back to the
        /// restore screen with the sheets in hand, not a restore.
        for_setup: bool,
    },
    /// What came back, and what did not.
    Restored {
        added: usize,
        /// Items on the sheets the wallet already held. Scanning your own
        /// sheets back to check them lands here with `added` at zero, and
        /// that is a success, not a no-op.
        kept: usize,
        /// Items that were scanned but could not be read.
        missed: Vec<String>,
        /// Items never seen at all \u2014 the sheet to go and look for.
        absent: Vec<String>,
        /// Items with some of their symbols read but not all, each with how
        /// many are still missing. Not restored, and not lost: the rest is
        /// on the same page.
        partial: Vec<(String, usize)>,
        /// Notes that read and opened but did not check out, so were not
        /// stored, with why.
        rejected: Vec<(String, String)>,
    },
    Failed {
        message: String,
    },
}

/// The receive flow as the screen shows it.
#[derive(Debug, Clone)]
pub struct ReceiveView {
    pub state: ReceiveState,
}

impl ReceiveView {
    pub fn idle(hint: &str) -> ReceiveView {
        ReceiveView {
            state: ReceiveState::Idle {
                hint: hint.to_string(),
            },
        }
    }
    pub fn failed(message: impl Into<String>) -> ReceiveView {
        ReceiveView {
            state: ReceiveState::Failed {
                message: message.into(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReceiveState {
    /// Nothing reserved yet.
    Idle {
        hint: String,
    },
    /// A worker is deriving.
    Working {
        what: String,
    },
    /// A commitment exists and can be shown to a payer.
    Ready {
        /// `KENTER:RECV/...` - what the QR encodes.
        uri: String,
        /// The same commitment as plain hex, for pasting into a chat window.
        hex: String,
        index: u32,
        /// What happens next, in the holder's terms. Updated as the watch runs.
        status: String,
        /// Where to put the token file the payer sends.
        inbox: String,
        /// Which ledger source the gates will ask.
        ///
        /// On the screen because the gates are one endpoint's word: a
        /// payee is told "you are paid" on the strength of reads nothing
        /// proves against the ledger itself, and a trust they cannot see
        /// is one they cannot judge.
        ledger: String,
        /// Anything the watch wants to report — a file it refused and why.
        note: Option<String>,
    },
    /// The payment landed and every gate passed. This is the only state in
    /// which the holder has actually been paid.
    Received {
        /// Abbreviated token id.
        id: String,
        amount: String,
        index: u32,
    },
    /// The standing pay tag, published or not.
    ///
    /// A page of its own rather than a section under the rotating tag: it is
    /// a decision with a cost, and a cost stated beside a QR code somebody is
    /// mid-way through copying is a cost nobody reads.
    Standing {
        /// Its commitment as hex when published; `None` when it is off.
        hex: Option<String>,
        /// What is happening, while it happens.
        busy: Option<String>,
    },
    /// A **bearer** note arrived, passed G1 and G2, and is in the billfold.
    ///
    /// Not [`Self::Received`], because there is no G3 for a bearer note
    /// (see `docs/architecture/spend-mode.md`): the ledger says it is live,
    /// which is not the same as knowing the payer kept no copy. Held, not
    /// settled — and not a refusal either.
    Held {
        id: String,
        amount: String,
    },
    Failed {
        message: String,
    },
}

/// Redeeming, as the screen shows it.
#[derive(Debug, Clone)]
pub struct RedeemView {
    pub state: RedeemState,
}

/// What a note redeems for, as the screen shows it.
#[derive(Debug, Clone)]
pub struct RedeemQuote {
    pub id: String,
    pub short_id: String,
    pub face: String,
    pub payout: String,
    pub fee: String,
    pub spend_mode: bool,
    pub to_account: String,
    /// The holder's own account. `to_account` starts here and the screen
    /// compares against it to say whether this payout leaves the wallet.
    pub own_account: String,
}

impl RedeemQuote {
    /// Is the escrow going somewhere other than the holder's own account?
    pub fn elsewhere(&self) -> bool {
        self.to_account != self.own_account
    }
}

#[derive(Debug, Clone)]
pub enum RedeemState {
    /// What is about to happen, and to which account.
    Confirm {
        quote: RedeemQuote,
    },
    /// Choosing where the escrow lands.
    ///
    /// A separate screen rather than an editable row on the confirmation,
    /// because the confirmation's job is to be read once and agreed with.
    /// A field that can be typed into on that screen is a field that can be
    /// typed into by accident.
    Destination {
        quote: RedeemQuote,
        typed: String,
        error: Option<String>,
    },
    Working {
        what: String,
    },
    /// What the contract actually paid — not the quote, which was this
    /// client's arithmetic.
    Done {
        paid: String,
        to_account: String,
    },
    Failed {
        message: String,
    },
}

/// Handing a note over, as the screen shows it.
#[derive(Debug, Clone)]
pub struct PayView {
    pub state: PayState,
}

/// One note in the picker.
#[derive(Debug, Clone)]
pub struct PayableRow {
    pub id: String,
    pub short_id: String,
    pub amount: String,
    pub spend_mode: bool,
    /// Parties who may already hold a copy. Handovers and card exports; never
    /// the holder's own backups.
    pub exposure: u32,
}

#[derive(Debug, Clone)]
pub enum PayState {
    /// A bearer note: write the file, and say what that does and does not do.
    Export {
        row: PayableRow,
        written: Option<String>,
        error: Option<String>,
    },
    /// A spend-mode note: where is it going?
    ///
    /// Carries the address itself, not a character count. This is the one
    /// field in the client that decides *who gets the money*, and a count
    /// cannot be checked against the address someone sent you — it cannot
    /// even tell you whether the paste worked. Not a secret, so there is
    /// nothing to mask.
    Address {
        row: PayableRow,
        typed: String,
        error: Option<String>,
    },
    Working {
        what: String,
    },
    Paid {
        row: PayableRow,
        where_to: String,
    },
    Failed {
        message: String,
    },
}

/// Deposit, as the screen shows it.
#[derive(Debug, Clone)]
pub struct DepositView {
    pub state: DepositState,
}

#[derive(Debug, Clone)]
pub enum DepositState {
    /// Choosing what to make. `spend` and `pairs` are asked every time
    /// (Q3, D4) rather than hidden in a setting.
    Form {
        entered: usize,
        /// The parsed amount and its consequences, recomputed as it is typed
        /// so the cost of granularity is visible while choosing it (D3).
        preview: Option<DepositPreview>,
        spend: bool,
        pairs: u16,
        /// Where this note will be printed, in words. Always shown: a
        /// self-print and a networked print produce notes that differ in what
        /// they are worth trusting, and which one happened must never be
        /// something the holder has to infer afterwards.
        printer: String,
        error: Option<String>,
    },
    Working {
        what: String,
    },
    Done {
        id: String,
        amount: String,
    },
    Failed {
        message: String,
    },
}

/// The arithmetic a holder needs before committing to a denomination.
#[derive(Debug, Clone)]
pub struct DepositPreview {
    pub face: String,
    pub redeems_for: String,
    pub fee: String,
}

/// First run, as the screen shows it.
#[derive(Debug, Clone)]
pub struct SetupView {
    pub state: SetupState,
}

/// Note what is **not** in here: the recovery phrase in any state except
/// [`SetupState::Phrase`], which is the one screen that must show it. It is
/// never copied into Confirm, which carries only the positions being asked
/// for, so the words exist in exactly one place in the view model and leave
/// it as soon as that screen does.
#[derive(Debug, Clone)]
pub enum SetupState {
    /// Create or restore.
    Start,
    /// Where the key lives: this computer, or a card.
    ///
    /// Asked once, at creation, because it cannot be changed later without
    /// moving every note — and asked in the holder's terms rather than in
    /// backends', since "SoftVault or KeycardVault" is not a question anyone
    /// outside this repo can answer.
    Custody {
        /// Asked as part of a restore rather than a creation.
        ///
        /// The same question either way — where does the key live — but not
        /// the same stakes, and the copy says so. Creating, the choice is
        /// permanent. Restoring, it has already been made once and is being
        /// made again, and the honest line is that the words work either
        /// way.
        restoring: bool,
        /// What a look at the reader found, if one has been taken. Shown so
        /// a holder learns there is no reader *before* choosing the card.
        card: Option<String>,
        /// Whether that look found something a wallet could go on.
        card_ok: bool,
        error: Option<String>,
    },
    /// What putting a wallet on this card commits to, before the first
    /// keystroke.
    CardIntro {
        /// What the reader found, in the holder's words.
        card: String,
        /// A blank card can be provisioned; an initialized one cannot be
        /// `INIT`ed again and must be reset deliberately first.
        blank: bool,
    },
    /// The card's PIN: six digits, entered twice.
    CardPin {
        entered: usize,
        /// Second entry. There is nothing to check the first against, so
        /// the repeat *is* the check.
        again: bool,
        error: Option<String>,
    },
    /// The duress PIN: six digits, twice, and not equal to the PIN.
    CardDuress {
        entered: usize,
        again: bool,
        error: Option<String>,
    },
    /// The generated PUK, shown once and confirmed by re-entry.
    CardPuk {
        /// Generated, not chosen. Rendered as a secret label, so it never
        /// enters the raster cache.
        puk: String,
        entered: usize,
        /// False while it is being read, true while it is being typed back.
        confirming: bool,
        error: Option<String>,
    },
    /// The card's own phrase, hidden unless held.
    ///
    /// Separate from [`Phrase`](SetupState::Phrase) only in what it says:
    /// the words came off the card's RNG, and they are the one copy that
    /// will ever exist, because the applet keeps none.
    CardPhrase {
        words: Vec<String>,
        revealed: bool,
    },
    /// Type three of the card's words back, before anything is written.
    CardConfirm {
        positions: Vec<usize>,
        entered: usize,
        error: Option<String>,
    },
    /// Erase a card so it can be set up again.
    ///
    /// Two gates, because they prove different things. The typed word
    /// proves the warning was read; the PIN proves the card is yours. A
    /// PIN alone is muscle memory, and a word alone is readable off the
    /// screen by anyone holding someone else's card.
    CardErase {
        /// False while the word is being typed, true while the PIN is.
        confirmed: bool,
        /// The confirmation word, in clear. **Deliberately not a count.**
        /// Type-to-confirm only works if you can see that you typed the
        /// word, and the word is printed on the same screen - masking it
        /// would hide something that is not secret while proving nothing.
        typed: String,
        /// Characters of the PIN. A count, because that one *is* secret.
        entered: usize,
        error: Option<String>,
    },
    /// Choose the passphrase that will encrypt everything.
    Passphrase {
        entered: usize,
        error: Option<String>,
    },
    /// The phrase, hidden unless held.
    Phrase {
        words: Vec<String>,
        revealed: bool,
    },
    /// Type three of them back.
    Confirm {
        positions: Vec<usize>,
        entered: usize,
        error: Option<String>,
    },
    /// Enter an existing phrase, and point at the backup it goes with.
    Restore {
        entered: usize,
        error: Option<String>,
        /// The backup file chosen, if one has been. Optional, because a
        /// holder who has lost the file can still recover their keys and
        /// their account — just not their notes.
        file: Option<RestoreSource>,
        /// Paper sheets scanned so far, as a line the holder can read:
        /// which wallet they name and what is complete. The other way to
        /// bring notes back, and the one that exists for the case the
        /// file does not: a new machine with only the phrase and a folder
        /// of sheets.
        paper: Option<String>,
    },
    Working {
        what: String,
    },
    /// The account exists but cannot act yet.
    ///
    /// A blocking step, not a notice. An unfunded account can do nothing at
    /// all — no deposit, no pay, no redeem — and a client that hands
    /// someone a billfold in that state has told them they are finished when
    /// they are not. `ready` decides whether the way out is open.
    Activate {
        address: String,
        copied: bool,
        funded: bool,
        /// `Some(code)` while this mint's asset still needs a trustline.
        trustline_needed: Option<String>,
        /// What is happening right now, if anything.
        busy: Option<String>,
        error: Option<String>,
    },
    Failed {
        message: String,
    },
}

/// An authorization prompt, as the screen shows it.
///
/// Note what is **not** here: the credential. The view model carries only how
/// many characters have been typed, and the renderer turns that into dots. The
/// passphrase lives in the event loop's input buffer and goes straight to the
/// worker; it is never put into a type that gets cloned into a layout tree,
/// printed by `Debug`, or rendered into a PNG by the mock.
#[derive(Debug, Clone)]
pub struct PromptView {
    /// `AuthAction::summary()`.
    pub title: String,
    /// Why we are asking, in a sentence.
    pub why: String,
    /// `AuthAction::rows()` - what is being authorized. A prompt that shows
    /// none of these is a password box, which proves presence and not consent.
    pub rows: Vec<(String, String)>,
    /// How many characters have been entered.
    pub entered: usize,
    /// e.g. "that passphrase was not accepted".
    pub error: Option<String>,
}

/// The one region of a page that scrolls: a fixed viewport with a taller
/// column of rows inside it.
///
/// One region rather than a general mechanism because every page here has the
/// same shape — chrome that must stay put, and a list that does not fit. A
/// list is exactly where "it does not fit" means the window stops working:
/// before this, a wallet with enough tokens pushed the titlebar off the top of
/// the screen and ran its own rows past the bottom.
#[derive(Clone, Copy)]
struct Scroll {
    /// The clipping box, in absolute logical coordinates.
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    /// Total height of the rows inside it.
    content: f32,
}

pub struct Ui {
    tree: TaffyTree<()>,
    skins: HashMap<NodeId, Skin>,
    root: NodeId,
    hits: Vec<HitRect>,
    pub nav_ids: Vec<NodeId>,
    /// The scrollable viewport, if this page has one.
    scroll: Option<Scroll>,
    /// Node whose subtree moves with the scroll offset.
    scroll_content: Option<NodeId>,
    /// Where the live camera frame goes, in logical coordinates. Found at
    /// build time so painting does not have to walk the tree looking.
    viewfinder: Option<(f32, f32, f32, f32)>,
    cache: RefCell<HashMap<CacheKey, Rc<PeltImage>>>,
}

/// Hash of everything that decides what a layer rasterizes to.
fn content_hash(skin: &Skin, layer: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    layer.hash(&mut h);
    skin.name.hash(&mut h);
    skin.inline.hash(&mut h);
    if layer == "labels" {
        for l in &skin.labels {
            l.text.hash(&mut h);
            l.size.to_bits().hash(&mut h);
            l.color.hash(&mut h);
            l.weight.hash(&mut h);
            (l.anchor as u8).hash(&mut h);
            l.inset.to_bits().hash(&mut h);
            l.vfrac.to_bits().hash(&mut h);
        }
    }
    h.finish()
}

fn skin_path(name: &str) -> String {
    format!("{}/{}.svg", skin_dir().display(), name)
}

/// Where the skins are: `skins/kenter/` beside the executable in an
/// installed build (the installers ship them there), else the source tree
/// while developing, so an edit in Inkscape still shows on the next
/// repaint. Resolved once.
///
/// The source tree alone would not do: it is a path fixed at compile time,
/// which an installed copy on another machine does not have.
///
/// **A packaged build has no fallback** (feature `packaged`). The
/// source-tree path is the *build machine's*; on a user's
/// machine an ordinary user can often create it (a second drive's root),
/// and skins define what the screens say. So an installed wallet reads
/// skins only from beside itself, and stops if they are missing.
fn skin_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| match installed_skin_dir() {
        Some(d) if d.is_dir() => d,
        #[cfg(feature = "packaged")]
        _ => {
            eprintln!("kenter-ui: {}", missing_skins_message());
            std::process::exit(1);
        }
        #[cfg(not(feature = "packaged"))]
        _ => std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("skins").join("kenter"),
    })
}

fn installed_skin_dir() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("skins").join("kenter")))
}

fn missing_skins_message() -> String {
    format!(
        "the wallet's skins are missing: expected {}. Reinstall Kenter.",
        installed_skin_dir().map(|d| d.display().to_string()).unwrap_or_else(|| "skins\\kenter beside the wallet".into())
    )
}

/// Check, at startup, that a packaged wallet has its skins, so a broken
/// install says so before any window opens. Always `Ok` in a development
/// build, which falls back to the source tree.
pub fn check_skins() -> Result<(), String> {
    if cfg!(feature = "packaged") && !installed_skin_dir().is_some_and(|d| d.is_dir()) {
        return Err(missing_skins_message());
    }
    Ok(())
}

/// A skin's declared text styles and canvas, cached against the file's
/// modification time so an edit in Inkscape shows on the next repaint.
fn text_specs(skin: &str) -> Option<(Vec<pelt::labels::TextStyle>, f32, f32)> {
    use std::sync::Mutex;
    use std::time::SystemTime;
    type Entry = (SystemTime, Vec<pelt::labels::TextStyle>, f32, f32);
    static CACHE: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);
    let path = skin_path(skin);
    let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some((t, styles, w, h)) = cache.get(skin) {
        if *t == mtime {
            return Some((styles.clone(), *w, *h));
        }
    }
    let src = std::fs::read_to_string(&path).ok()?;
    let (_, _, w, h) = pelt::labels::view_box(&src)?;
    let styles = pelt::labels::text_styles(&src);
    cache.insert(skin.to_string(), (mtime, styles.clone(), w, h));
    Some((styles, w, h))
}

/// One named text style from a skin, with that skin's canvas.
fn text_spec(skin: &str, name: &str) -> Option<(pelt::labels::TextStyle, f32, f32)> {
    let (styles, w, h) = text_specs(skin)?;
    styles.into_iter().find(|t| t.name == name).map(|t| (t, w, h))
}

/// Shown for a label the skin does not declare: loud on purpose, so a
/// renamed or deleted sample is seen at once rather than drawn plausibly.
const MISSING_TEXT: &str = "#ff00ff";

/// A [`Label`] for `content` in the style the skin gives `name`.
///
/// The skin's canvas is the element at its real size, so a sample's
/// baseline `y` maps to the fraction the label renderer works in
/// (`render_labels`: baseline = height * vfrac + size * 0.34).
fn styled(skin: &str, name: &str, content: &str) -> Label {
    let Some((t, w, h)) = text_spec(skin, name) else {
        eprintln!("kenter-ui: skins/kenter/{skin}.svg has no text labelled {name:?}");
        return lbl(content, 12.0, MISSING_TEXT, 700, Anchor::Start, 8.0, 0.5);
    };
    let (anchor, inset) = match t.anchor {
        pelt::labels::TextAnchor::Start => (Anchor::Start, t.x),
        pelt::labels::TextAnchor::Middle => (Anchor::Middle, 0.0),
        pelt::labels::TextAnchor::End => (Anchor::End, w - t.x),
    };
    lbl(content, t.size, &t.fill, t.weight, anchor, inset, (t.y - t.size * 0.34) / h)
}

impl Ui {
    /// Does anything on this page move?
    ///
    /// The shell asks the page rather than keeping its own list of which
    /// screens animate. A list would be a second place to update, and the
    /// failure it invites is the quiet one: a new `Working` screen that draws
    /// a bar and never ticks it, which looks exactly like the hang the bar
    /// exists to rule out.
    pub fn has_animation(&self) -> bool {
        self.skins.values().any(|s| s.animated)
    }

    /// Build the shell from a sample view — convenience for the PNG mock.
    pub fn build() -> Ui {
        Ui::build_with(&WalletView::sample())
    }

    /// Build the wallet page — convenience for callers (and the PNG mock) that
    /// have only a [`WalletView`].
    pub fn build_with(view: &WalletView) -> Ui {
        Ui::build_screen(&Screen::Wallet(view.clone()))
    }

    /// Build the shell for a screen and compute layout at the fixed W×H size.
    pub fn build_screen(screen: &Screen) -> Ui {
        let mut tree: TaffyTree<()> = TaffyTree::new();
        let mut skins: HashMap<NodeId, Skin> = HashMap::new();

        // Sidebar nav. A locked client gets none: the gate is the whole
        // window, so there is nothing to click past it. Setup already worked
        // this way and had to refuse clicks in words instead, which is the
        // thing a missing sidebar says without saying anything.
        let chrome = !matches!(screen, Screen::Locked(_) | Screen::Reset(_));
        let nav_ids: Vec<NodeId> = NAV
            .iter()
            .enumerate()
            .filter(|_| chrome)
            .map(|(i, name)| {
                leaf(
                    &mut tree,
                    &mut skins,
                    Style {
                        size: Size {
                            width: percent(1.0),
                            height: length(44.0),
                        },
                        ..Default::default()
                    },
                    Skin::new("nav-item").kind(Kind::Nav(i)).text("label", name),
                )
            })
            .collect();
        let sidebar = tree
            .new_with_children(
                Style {
                    flex_direction: FlexDirection::Column,
                    size: Size {
                        width: length(200.0),
                        height: auto(),
                    },
                    // Fixed width. Allowed to shrink, it gives way whenever
                    // the page beside it is wide, down to ~110px on Settings.
                    flex_shrink: 0.0,
                    padding: Rect {
                        left: length(12.0),
                        right: length(12.0),
                        top: length(16.0),
                        bottom: length(16.0),
                    },
                    gap: Size {
                        width: length(0.0),
                        height: length(6.0),
                    },
                    ..Default::default()
                },
                &nav_ids,
            )
            .unwrap();
        skins.insert(sidebar, Skin::new("sidebar"));

        let content = match screen {
            Screen::Wallet(v) => wallet_page(&mut tree, &mut skins, v),
            Screen::Receive(r) => receive_page(&mut tree, &mut skins, r),
            Screen::Settings(v) => settings_page(&mut tree, &mut skins, v),
            Screen::Prompt { view, .. } => prompt_page(&mut tree, &mut skins, view),
            Screen::Setup(v) => setup_page(&mut tree, &mut skins, v),
            Screen::Account(v) => account_page(&mut tree, &mut skins, v),
            Screen::Deposit(v) => deposit_page(&mut tree, &mut skins, v),
            Screen::Pay(v) => pay_page(&mut tree, &mut skins, v),
            Screen::Redeem(v) => redeem_page(&mut tree, &mut skins, v),
            Screen::Paper(v) => paper_page(&mut tree, &mut skins, v),
            Screen::Locked(v) => locked_page(&mut tree, &mut skins, v),
            Screen::Reset(v) => reset_page(&mut tree, &mut skins, v),
        };
        let main = tree
            .new_with_children(
                Style {
                    flex_direction: FlexDirection::Column,
                    flex_grow: 1.0,
                    // Flexbox gives every flex item an automatic minimum size
                    // of its own content, which silently makes a column
                    // unshrinkable once anything inside it is long. Zeroing it
                    // here and on the body is what lets the panel below
                    // actually be a viewport: without it the panel's basis of
                    // 0 is overridden on the way back up, and a long list
                    // grows the window's layout instead of scrolling.
                    // Zero on both axes: the page gives way, not the
                    // sidebar beside it.
                    min_size: Size {
                        width: length(0.0),
                        height: length(0.0),
                    },
                    padding: Rect::length(24.0),
                    gap: Size {
                        width: length(0.0),
                        height: length(20.0),
                    },
                    ..Default::default()
                },
                &content,
            )
            .unwrap();
        // Bound, not inlined: a slice of a temporary array does not outlive
        // the statement that builds it.
        let shell: Vec<NodeId> = if chrome {
            vec![sidebar, main]
        } else {
            vec![main]
        };
        let body = tree
            .new_with_children(
                Style {
                    flex_direction: FlexDirection::Row,
                    size: Size {
                        width: percent(1.0),
                        height: auto(),
                    },
                    flex_grow: 1.0,
                    min_size: Size {
                        width: auto(),
                        height: length(0.0),
                    },
                    ..Default::default()
                },
                &shell,
            )
            .unwrap();
        let titlebar = leaf(
            &mut tree,
            &mut skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(40.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            // Placed clear of the logo in the skin's text layer.
            Skin::new("titlebar").text("title", "Kenter"),
        );
        // The logo, a placeholder Kenter link (`skins/kenter/logo.svg`),
        // positioned over the left end of the titlebar rather than inside
        // it, so the titlebar stays one painted leaf and its height is
        // untouched. Last child, so it paints above the bar.
        let logo = leaf(
            &mut tree,
            &mut skins,
            Style {
                position: Position::Absolute,
                inset: taffy::Rect {
                    left: length(10.0),
                    top: length(6.0),
                    right: auto(),
                    bottom: auto(),
                },
                size: Size {
                    width: length(28.0),
                    height: length(28.0),
                },
                ..Default::default()
            },
            Skin::new("logo"),
        );
        let root = tree
            .new_with_children(
                Style {
                    flex_direction: FlexDirection::Column,
                    size: Size {
                        width: length(W as f32),
                        height: length(H as f32),
                    },
                    ..Default::default()
                },
                &[titlebar, body, logo],
            )
            .unwrap();
        skins.insert(root, Skin::new("window-bg"));

        tree.compute_layout(
            root,
            Size {
                width: AvailableSpace::Definite(W as f32),
                height: AvailableSpace::Definite(H as f32),
            },
        )
        .unwrap();

        let mut hits = Vec::new();
        let mut viewfinder = None;
        collect_hits(&tree, root, 0.0, 0.0, &skins, &mut hits, &mut viewfinder);

        // Find the scroll viewport and measure what is inside it. Content is
        // summed from the rows rather than read off the column: Taffy reports
        // the column at the height it was given, which is the viewport's, and
        // using that would make everything look like it fits.
        let mut scroll = None;
        let mut scroll_content = None;
        if let Some((&panel, content)) = skins
            .iter()
            .find_map(|(n, sk)| sk.scroll_content.map(|c| (n, c)))
        {
            let (x, y) = absolute(&tree, root, panel).unwrap_or((0.0, 0.0));
            let l = tree.layout(panel).unwrap();
            let pad = 16.0 * 2.0;
            let gap = 8.0;
            let kids = tree.children(content).unwrap();
            let total: f32 = kids
                .iter()
                .map(|k| tree.layout(*k).unwrap().size.height)
                .sum::<f32>()
                + gap * kids.len().saturating_sub(1) as f32;
            scroll = Some(Scroll {
                x,
                y,
                w: l.size.width,
                h: l.size.height,
                content: total + pad,
            });
            scroll_content = Some(content);
        }

        Ui {
            tree,
            skins,
            root,
            hits,
            viewfinder,
            nav_ids,
            scroll,
            scroll_content,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Drop every rasterized layer.
    ///
    /// Called on leaving a screen that displayed a secret. Belt and braces
    /// next to [`Label::secret`]: that stops a phrase entering the cache, this
    /// clears anything that reached it another way. Costs one cold repaint.
    pub fn purge_cache(&self) {
        self.cache.borrow_mut().clear();
    }

    /// Swap in a different screen, keeping the raster cache.
    ///
    /// Everything that did not change is still in the cache under the same key,
    /// so a keystroke costs one label re-render instead of a whole page.
    pub fn rebuild(&mut self, screen: &Screen) {
        let cache = std::mem::take(&mut *self.cache.borrow_mut());
        let next = Ui::build_screen(screen);
        *next.cache.borrow_mut() = cache;
        *self = next;
    }

    /// Fetch a rasterized layer from the cache, building (and inserting) it on a
    /// miss. Returns an `Rc` so the caller composites without a deep copy.
    fn cached(
        &self,
        key: CacheKey,
        build: impl FnOnce() -> Result<PeltImage, pelt::PeltError>,
    ) -> Option<Rc<PeltImage>> {
        if let Some(img) = self.cache.borrow().get(&key) {
            return Some(img.clone());
        }
        match build() {
            Ok(img) => {
                let rc = Rc::new(img);
                self.cache.borrow_mut().insert(key, rc.clone());
                Some(rc)
            }
            Err(e) => {
                eprintln!("layer {} render failed: {e}", key.1);
                None
            }
        }
    }

    /// What clicking this node means, if it is a button.
    ///
    /// Intent, not geometry: the shell matches on [`Action`] instead of on
    /// which node happened to be built third, so rearranging a page cannot
    /// silently rewire a button.
    pub fn action_at(&self, node: NodeId) -> Option<Action> {
        match self.skins.get(&node).and_then(|s| s.kind) {
            Some(Kind::Button(a)) => Some(a),
            _ => None,
        }
    }

    /// Topmost interactive element under the point, if any.
    ///
    /// Hit rects are recorded unscrolled, so a point inside the scroll
    /// viewport is mapped back through the offset before it is matched — and
    /// a point that has scrolled out of the viewport hits nothing, because a
    /// button hidden under the header must not still be clickable.
    pub fn hit_test(&self, x: f32, y: f32) -> Option<NodeId> {
        self.hit_test_with(x, y, &Interaction::default())
    }

    /// [`Self::hit_test`] at a given scroll position.
    pub fn hit_test_with(&self, x: f32, y: f32, it: &Interaction) -> Option<NodeId> {
        let inside_viewport = self
            .scroll
            .map(|s| x >= s.x && x < s.x + s.w && y >= s.y && y < s.y + s.h)
            .unwrap_or(false);
        self.hits
            .iter()
            .rev()
            .find(|r| {
                // Rows live inside the viewport; chrome does not. Only the
                // former moved.
                let within = self
                    .scroll
                    .map(|s| {
                        r.y >= s.y - 1.0
                            && r.y < s.y + s.h + self.scroll_max() + 1.0
                            && r.x >= s.x - 1.0
                    })
                    .unwrap_or(false);
                let (px, py) = if within {
                    if !inside_viewport {
                        return false;
                    }
                    (x, y + self.scroll_offset(it))
                } else {
                    (x, y)
                };
                px >= r.x && px < r.x + r.w && py >= r.y && py < r.y + r.h
            })
            .map(|r| r.node)
    }

    /// Render the shell at the logical W×H size → premultiplied RGBA. Used by the
    /// PNG mock; the window renders at physical size via [`Ui::render_scaled`].
    pub fn render(&self, it: &Interaction) -> Vec<u8> {
        self.render_scaled(it, W, H)
    }

    /// Render the shell to `out_w`×`out_h` pixels (the window's physical inner
    /// size), scaling the fixed logical layout uniformly. Pelts are SVG, so they
    /// rasterize crisply at any scale — this is how we stay sharp on hi-DPI.
    pub fn render_scaled(&self, it: &Interaction, out_w: u32, out_h: u32) -> Vec<u8> {
        self.render_live(it, out_w, out_h, None)
    }

    /// [`Self::render_scaled`] with a camera frame painted into the
    /// viewfinder, if this page has one and a frame has arrived.
    ///
    /// The frame goes on **after** the scene rather than through the skin
    /// cache: it changes every time, so caching it would evict the whole
    /// cache a dozen times a second to store images nothing ever asks for
    /// twice.
    pub fn render_live(
        &self,
        it: &Interaction,
        out_w: u32,
        out_h: u32,
        live: Option<&LiveFrame<'_>>,
    ) -> Vec<u8> {
        let sx = out_w as f32 / W as f32;
        let sy = out_h as f32 / H as f32;
        let mut canvas = vec![0u8; (out_w * out_h * 4) as usize];
        let full = Clip {
            x0: 0,
            y0: 0,
            x1: out_w as i32,
            y1: out_h as i32,
        };
        self.paint(
            self.root,
            0.0,
            0.0,
            sx,
            sy,
            out_w,
            out_h,
            it,
            full,
            &mut canvas,
        );
        if let (Some(frame), Some(rect)) = (live, self.viewfinder) {
            paint_live(&mut canvas, out_w, out_h, rect, sx, sy, frame);
        }
        canvas
    }

    #[allow(clippy::too_many_arguments)]
    fn paint(
        &self,
        node: NodeId,
        ox: f32,
        oy: f32,
        sx: f32,
        sy: f32,
        cw: u32,
        ch: u32,
        it: &Interaction,
        clip: Clip,
        canvas: &mut [u8],
    ) {
        let l = self.tree.layout(node).unwrap();
        // Accumulate offsets in logical space; scale only at the paint site.
        let x = ox + l.location.x;
        let mut y = oy + l.location.y;
        let w = l.size.width;
        let h = l.size.height;

        // The scrolled column moves under its viewport; everything below it
        // inherits the shift because offsets accumulate on the way down.
        let mut clip = clip;
        if Some(node) == self.scroll_content {
            y -= self.scroll_offset(it);
        }
        if let Some(sc) = self.scroll {
            if self
                .skins
                .get(&node)
                .is_some_and(|sk| sk.scroll_content.is_some())
            {
                // Clip to the viewport from here down, so a row scrolled past
                // the top does not paint over the header above it.
                clip = clip.intersect(Clip {
                    x0: (sc.x * sx).floor() as i32,
                    y0: (sc.y * sy).floor() as i32,
                    x1: ((sc.x + sc.w) * sx).ceil() as i32,
                    y1: ((sc.y + sc.h) * sy).ceil() as i32,
                });
            }
        }

        if let Some(skin) = self.skins.get(&node) {
            let pw = (w * sx).round().max(1.0) as u32;
            let ph = (h * sy).round().max(1.0) as u32;
            let px = (x * sx).round() as i32;
            let py = (y * sy).round() as i32;
            let state = effective_state(node, skin, it);
            if let Some(img) = self.cached(
                (node, "skin", state, pw, ph, content_hash(skin, "skin")),
                || render_skin(skin, state, pw, ph),
            ) {
                composite(canvas, cw, ch, &img, px, py, clip);
            }
            if !skin.labels.is_empty() {
                // A secret never enters the cache: it would outlive the screen
                // as a bitmap. Rasterized fresh each frame and wiped after
                // compositing, which costs one re-render on one screen.
                if skin.labels.iter().any(|l| l.sensitive) {
                    if let Ok(mut img) = render_labels(&skin.labels, w, h, pw, ph) {
                        composite(canvas, cw, ch, &img, px, py, clip);
                        use zeroize::Zeroize;
                        img.rgba.zeroize();
                    }
                } else if let Some(text) = self.cached(
                    // Labels don't depend on state; build in the logical box,
                    // raster at physical.
                    (node, "labels", "", pw, ph, content_hash(skin, "labels")),
                    || render_labels(&skin.labels, w, h, pw, ph),
                ) {
                    composite(canvas, cw, ch, &text, px, py, clip);
                }
            }
        }
        for c in self.tree.children(node).unwrap() {
            self.paint(c, x, y, sx, sy, cw, ch, it, clip, canvas);
        }
    }

    /// How far the page can scroll, in logical pixels. Zero when it fits.
    pub fn scroll_max(&self) -> f32 {
        self.scroll
            .map(|s| (s.content - s.h).max(0.0))
            .unwrap_or(0.0)
    }

    /// Whether this page has anything that scrolls at all.
    pub fn scrollable(&self) -> bool {
        self.scroll_max() > 0.0
    }

    fn scroll_offset(&self, it: &Interaction) -> f32 {
        it.scroll.clamp(0.0, self.scroll_max())
    }

    /// Clamp an offset to this page. The caller keeps the offset across
    /// rebuilds, and a page with a shorter list must not stay scrolled past
    /// its own end.
    pub fn clamp_scroll(&self, offset: f32) -> f32 {
        offset.clamp(0.0, self.scroll_max())
    }
}

/// A pixel rectangle outside which nothing is drawn.
#[derive(Clone, Copy)]
pub struct Clip {
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
}

impl Clip {
    fn intersect(self, o: Clip) -> Clip {
        Clip {
            x0: self.x0.max(o.x0),
            y0: self.y0.max(o.y0),
            x1: self.x1.min(o.x1),
            y1: self.y1.min(o.y1),
        }
    }
    fn holds(&self, x: i32, y: i32) -> bool {
        x >= self.x0 && x < self.x1 && y >= self.y0 && y < self.y1
    }
}

/// Add a leaf with a skin and return its node.
fn leaf(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    style: Style,
    skin: Skin,
) -> NodeId {
    let n = tree.new_leaf(style).unwrap();
    skins.insert(n, skin);
    n
}

/// Roughly how many characters of 13px body text fit across a field row.
///
/// Measured, not guessed at: 960 wide, less the 200 sidebar, 48 of main
/// padding, 32 of panel padding and 32 of row inset leaves ~648px, and Segoe UI
/// at 13px averages a shade under 6.6px per character. Rounded down, because
/// the failure mode is asymmetric — a line one character too long is silently
/// clipped at the raster edge, and a line one character short is invisible.
const ROW_CHARS: usize = 92;

/// The same, for the address panel that sits beside the 216px QR: the column
/// is ~352px once the symbol, the gap and the paddings are taken out.
const DETAIL_CHARS: usize = 52;

/// Break `text` into lines that fit a field row.
///
/// Words first; a single word longer than a line is hard-split, because the
/// strings this has to survive are filesystem paths and hex, which contain no
/// spaces at all and are exactly the ones worth reading in full.
fn wrap(text: &str, max: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let mut word = word;
        // A word that cannot fit on a line of its own, split across as many as
        // it needs.
        while word.chars().count() > max {
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            let cut = word
                .char_indices()
                .nth(max)
                .map(|(i, _)| i)
                .unwrap_or(word.len());
            let (head, rest) = word.split_at(cut);
            lines.push(head.to_string());
            word = rest;
        }
        if line.is_empty() {
            line.push_str(word);
        } else if line.chars().count() + 1 + word.chars().count() <= max {
            line.push(' ');
            line.push_str(word);
        } else {
            lines.push(std::mem::replace(&mut line, word.to_string()));
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// A full-width row of label over value — the shape every field on the receive
/// page uses. In one place so an authorization prompt cannot grow a row that
/// looks unlike the ones beside it.
///
/// The value wraps and the row grows to hold it. Clipping was the old
/// behaviour and it is the wrong one here: the longest string this page renders
/// is the "no seed — run this command" message, which is useless with its tail
/// cut off, and a truncated hex address is worse than useless.
fn field_row(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    label: &str,
    value: &str,
) -> NodeId {
    field_row_in(tree, skins, label, value, ROW_CHARS)
}

/// [`field_row`] whose value is amber: something the holder should act on.
///
/// Amber rather than the red already in the palette, which marks a thing
/// that has **failed** (`QR unavailable`). A note in no backup has not
/// failed; it is a standing risk, and one the holder can clear in two
/// clicks. Spending red on it would leave nothing louder for the cases
/// where something is actually broken.
///
/// Used sparingly on purpose. Every row painted this colour makes the
/// others quieter, and the backup warnings only appear when they are true
/// and actionable — silence is the reward for being backed up.
fn warn_row(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    label: &str,
    value: &str,
) -> NodeId {
    field_row_coloured(tree, skins, label, value, "value-warn", ROW_CHARS)
}

/// [`field_row`] in red: `value-alarm` in `field-row.svg`.
///
/// Red is spent on almost nothing. The palette already used it for a thing
/// that has **failed**. A record that contradicts the ledger is the first
/// note-level state to earn it: not unfinished, not spent, but wrong — and
/// possibly wrong on purpose. Amber (`value-warn`) is desaturated to sit
/// with it, so the two read as one family of "look at this".
fn alarm_row(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    label: &str,
    value: &str,
) -> NodeId {
    field_row_coloured(tree, skins, label, value, "value-alarm", ROW_CHARS)
}

/// [`field_row`] in a narrower column.
///
/// The budget has to be passed because the row does not know its own width
/// until Taffy has laid it out, and by then the text is already built. The one
/// place this matters is the address panel beside the QR, which is a third
/// narrower than a full-width row — wrapping it to the full-width budget put
/// the clipping straight back.
fn field_row_in(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    label: &str,
    value: &str,
    max_chars: usize,
) -> NodeId {
    field_row_coloured(tree, skins, label, value, "value", max_chars)
}

fn field_row_coloured(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    label: &str,
    value: &str,
    value_style: &str,
    max_chars: usize,
) -> NodeId {
    let lines = wrap(value, max_chars);
    // The skin shows a key and two value lines. The gap between the two
    // samples is the line step, and everything above them is the key's
    // band, so the row grows by a step per line and the key stays put.
    let (step, top) = match (
        text_spec("field-row", "value"),
        text_spec("field-row", "value-next"),
    ) {
        (Some((first, _, h)), Some((next, _, _))) => (next.y - first.y, h - 2.0 * (next.y - first.y)),
        _ => (18.0, 28.0),
    };
    let height = top + step * lines.len() as f32;
    let at = |mut l: Label, y_px: f32| {
        l.vfrac = y_px / height;
        l
    };
    let key = styled("field-row", "key", label);
    let key_top = text_spec("field-row", "key").map(|(t, _, _)| t.y - t.size * 0.34).unwrap_or(14.0);
    let mut skin = Skin::new("field-row").label(at(key, key_top));
    let first_top = text_spec("field-row", "value")
        .map(|(t, _, _)| t.y - t.size * 0.34)
        .unwrap_or(30.0);
    for (i, line) in lines.iter().enumerate() {
        let l = styled("field-row", value_style, line);
        skin = skin.label(at(l, first_top + step * i as f32));
    }
    leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(height),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        skin,
    )
}

/// A stack of rows inside a panel. The panel is the page's scroll viewport.
///
/// `flex_shrink: 0.0` on the column is the whole reason the chrome survives:
/// a Taffy column shrinks its children to fit by default, so an over-long list
/// does not overflow, it squashes everything around it — including the
/// titlebar, which was being pushed off the top of the window.
fn panel_of(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    rows: &[NodeId],
) -> NodeId {
    let list = tree
        .new_with_children(
            Style {
                flex_direction: FlexDirection::Column,
                size: Size {
                    width: percent(1.0),
                    height: auto(),
                },
                flex_shrink: 0.0,
                gap: Size {
                    width: length(0.0),
                    height: length(8.0),
                },
                ..Default::default()
            },
            rows,
        )
        .unwrap();
    let panel = tree
        .new_with_children(
            Style {
                flex_direction: FlexDirection::Column,
                size: Size {
                    width: percent(1.0),
                    height: auto(),
                },
                // Basis 0 with a zero minimum is what makes this a viewport
                // rather than a box that reports its contents' height. With
                // the default `auto` basis the panel asks for however tall the
                // list is, the column cannot fit it, and Flexbox takes the
                // difference out of whatever *can* shrink — which was the
                // titlebar, pushed off the top of the window by a long list.
                flex_basis: length(0.0),
                min_size: Size {
                    width: auto(),
                    height: length(0.0),
                },
                flex_grow: 1.0,
                padding: Rect::length(16.0),
                ..Default::default()
            },
            &[list],
        )
        .unwrap();
    skins.insert(panel, Skin::new("panel").scrolls(list));
    panel
}

/// The indeterminate bar that says a worker is still running.
///
/// One widget for all five `Working` states rather than one per screen, so
/// "something is happening" looks the same wherever it happens and there is a
/// single place to change it.
///
/// It is motion and nothing else: the caller still supplies the words. A bar
/// on its own cannot say *what* is being waited on, and for anything that can
/// fail to arrive it must not try.
fn working_bar(tree: &mut TaffyTree<()>, skins: &mut HashMap<NodeId, Skin>) -> NodeId {
    leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(6.0),
            },
            flex_shrink: 0.0,
            margin: Rect {
                left: length(0.0),
                right: length(0.0),
                top: length(4.0),
                bottom: length(12.0),
            },
            ..Default::default()
        },
        Skin::new("progress").animated(),
    )
}

/// The whole body of a `Working` screen: the header, the bar, and the step.
///
/// Every one of the five was already header + one-row panel, so the only new
/// thing is the bar — and routing them all through here is what keeps it from
/// being added to four of the five.
fn working_body(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    head: NodeId,
    label: &str,
    what: &str,
) -> Vec<NodeId> {
    let bar = working_bar(tree, skins);
    let rows = vec![field_row(tree, skins, label, what)];
    let panel = panel_of(tree, skins, &rows);
    vec![head, bar, panel]
}

/// A row of buttons, left-aligned. `(text, action, primary)`.
fn buttons_row(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    buttons: &[(&str, Action, bool)],
) -> NodeId {
    let ids: Vec<NodeId> = buttons
        .iter()
        .map(|(text, action, primary)| {
            let skin = if *primary {
                "button-primary"
            } else {
                "button-secondary"
            };
            leaf(
                tree,
                skins,
                Style {
                    size: Size {
                        width: length(150.0),
                        height: length(44.0),
                    },
                    ..Default::default()
                },
                Skin::new(skin).kind(Kind::Button(*action)).text("label", text),
            )
        })
        .collect();
    // Wraps rather than overflows. Four 150px buttons fit across the
    // content area; Settings has had five whenever a trustline was missing,
    // and the sixth (RPC server) made it plain that the row was pushing the
    // page wider than the window and squeezing the sidebar.
    tree.new_with_children(
        Style {
            size: Size {
                width: percent(1.0),
                height: auto(),
            },
            min_size: Size {
                width: auto(),
                height: length(44.0),
            },
            flex_shrink: 0.0,
            flex_wrap: FlexWrap::Wrap,
            gap: Size {
                width: length(12.0),
                height: length(12.0),
            },
            ..Default::default()
        },
        &ids,
    )
    .unwrap()
}

/// The wallet page: balance, actions, held tokens.
fn wallet_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &WalletView,
) -> Vec<NodeId> {
    // Balance card.
    let balance = leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(128.0),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("balance")
            .text("caption", "Face value held")
            .text("amount", &view.balance)
            .text("count", &view.subtitle),
    );

    // Unlocked, the billfold has no buttons of its own. Its verbs belong to
    // the notes (top level is *places*, note level is *actions*), and
    // Accept is a place the sidebar already reaches — so a row here would be
    // three ways of saying what is already on screen. Locked is different:
    // unlocking is the only thing that can work, and nothing else is.
    let button_row = view
        .locked
        .then(|| buttons_row(tree, skins, &[("Unlock", Action::Unlock, true)]));

    // The compartments. The tab bar is the at-a-glance view - counts live on
    // the tabs, so it answers "what have I got" without opening anything,
    // which is the one thing tabs would otherwise cost.
    let tab_ids: Vec<NodeId> = view
        .tabs
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let label = format!("{}  {}", t.label, t.notes.len());
            leaf(
                tree,
                skins,
                Style {
                    size: Size {
                        width: length(150.0),
                        height: length(36.0),
                    },
                    flex_shrink: 0.0,
                    ..Default::default()
                },
                Skin::new("tab")
                    .kind(Kind::Button(Action::SelectTab(i)))
                    .base_state(if i == view.selected_tab {
                        "active"
                    } else {
                        "default"
                    })
                    .text("label", &label),
            )
        })
        .collect();
    let tab_bar = tree
        .new_with_children(
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(36.0),
                },
                flex_shrink: 0.0,
                gap: Size {
                    width: length(6.0),
                    height: length(0.0),
                },
                ..Default::default()
            },
            &tab_ids,
        )
        .unwrap();

    let empty_row = |tree: &mut TaffyTree<()>, skins: &mut HashMap<NodeId, Skin>| {
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(56.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("empty-row")
                // "No notes held" is a claim about someone's money, and a
                // sealed billfold is in no position to make it.
                .text("title", if view.locked {
                        "Locked"
                    } else {
                        "No notes held"
                    })
                .text("hint", &view.empty_hint),
        )
    };

    let mut rows: Vec<NodeId> = Vec::new();
    if let Some(disputed) = &view.disputed {
        // First, and red. A holder about to accept goods for a note needs
        // to see this before the balance, not after opening a card.
        rows.push(alarm_row(tree, skins, "do not trust", disputed));
    }
    if let Some(backup) = &view.backup {
        // Above `stuck`, because escrow in a dead slot can be recovered and
        // a note nobody has a copy of cannot. Amber for the same reason it
        // is first.
        rows.push(warn_row(tree, skins, "at risk", backup));
    }
    if let Some(stalled) = &view.stalled {
        // Money, so it is on the billfold and not on a card nobody opens.
        rows.push(field_row(tree, skins, "stuck", stalled));
    }
    match view.tabs.get(view.selected_tab) {
        None => rows.push(empty_row(tree, skins)),
        Some(tab) => {
            for (i, n) in tab.notes.iter().enumerate() {
                let open = view.expanded == Some(i);
                let mode = if n.spend_mode { "spend" } else { "bearer" };
                // Inside a tab every note shares a denomination, so the card
                // distinguishes them by what actually differs.
                let right = format!("{mode} \u{b7} {}", n.state.label());

                // The card and its opened detail go in a container, and the
                // container is the thing that expands. As flat siblings in
                // one list, every one of them wearing `list-row`, an open
                // note would read as two unrelated rows appearing under an
                // unrelated row - three stacked rectangles with nothing
                // saying they belonged together.
                let card = leaf(
                    tree,
                    skins,
                    Style {
                        size: Size {
                            width: percent(1.0),
                            height: length(52.0),
                        },
                        flex_shrink: 0.0,
                        ..Default::default()
                    },
                    Skin::new("note-card")
                        .base_state(if open { "focus" } else { "default" })
                        .kind(Kind::Button(Action::ExpandNote(i)))
                        .text(
                            if n.state.is_live() { "amount" } else { "amount-dim" },
                            &n.amount,
                        )
                        .text("id", &n.short_id)
                        .text("status", &right),
                );
                let mut kids = vec![card];
                if open {
                    kids.push(field_row(tree, skins, "redeems for", &n.redeems_for));
                    if let Some(claimed) = &n.claimed {
                        // Both figures, because the holder is owed the
                        // difference and not just the corrected number -
                        // and because "it says X but it is worth Y" is the
                        // sentence that makes them look at where it came
                        // from.
                        kids.push(alarm_row(
                            tree,
                            skins,
                            "does not match the ledger",
                            &format!(
                                "this record claims {claimed}; the mint holds {} for it. \
                                 Trust the mint - and treat whoever gave you this note, \
                                 or the backup it came from, as suspect",
                                n.amount
                            ),
                        ));
                    }
                    kids.push(if n.backed_up {
                        field_row(tree, skins, "backup", "in a backup you made")
                    } else {
                        // Amber: this note's bytes exist in one place, and
                        // the holder can fix that from Settings in two
                        // clicks. Quiet grey said the same words and read
                        // as a status line.
                        warn_row(
                            tree,
                            skins,
                            "backup",
                            "not in any backup - the file is the money",
                        )
                    });
                    if n.exposure > 0 {
                        kids.push(field_row(
                            tree,
                            skins,
                            "copies out there",
                            &format!(
                                "{} may hold a redeemable copy; whoever redeems first wins",
                                n.exposure
                            ),
                        ));
                    }
                }
                // The verbs live on the note — top level is *places*, note
                // level is *actions*. A separate Pay place would leave the
                // expanded card showing facts and no verbs, and someone
                // looking for Export would find only Redeem.
                if open && n.state.is_actionable() {
                    // "Export", not "Pay", for a bearer note: there is
                    // nothing to sign and nothing moves on-chain. Calling it
                    // Pay would promise a transfer the client cannot make.
                    let hand_over = if n.spend_mode { "Pay" } else { "Export" };
                    kids.push(buttons_row(
                        tree,
                        skins,
                        &[
                            (hand_over, Action::PayNote(i), true),
                            ("Redeem", Action::RedeemNote(i), false),
                        ],
                    ));
                }
                let group = tree
                    .new_with_children(
                        Style {
                            flex_direction: FlexDirection::Column,
                            size: Size {
                                width: percent(1.0),
                                height: auto(),
                            },
                            flex_shrink: 0.0,
                            // Notes are separate objects and have to look it.
                            // Flush against each other they read as one list
                            // with rules between, which is what the stacked-
                            // rectangles complaint was about.
                            margin: Rect {
                                left: length(0.0),
                                right: length(0.0),
                                top: length(0.0),
                                bottom: length(6.0),
                            },
                            ..Default::default()
                        },
                        &kids,
                    )
                    .unwrap();
                skins.insert(
                    group,
                    Skin::new("note-group").base_state(if open { "focus" } else { "default" }),
                );
                rows.push(group);
            }
            if tab.notes.is_empty() {
                rows.push(empty_row(tree, skins));
            }
        }
    }

    // Through `panel_of` like every other page: this one had its own copy,
    // which is how the wallet - the page most likely to have a list too long
    // for the window - was the one page that could not scroll.
    let panel = panel_of(tree, skins, &rows);

    let mut out = match button_row {
        Some(row) => vec![balance, row, tab_bar, panel],
        None => vec![balance, tab_bar, panel],
    };

    // The slow wait on this client is here, not on the unlock that precedes
    // it: Argon2id is ~23ms in release, while reconciling against the ledger
    // is RPC round trips and runs for seconds. During it the balance on
    // screen is the previous one, so the page has to show that it is still
    // being checked - a stale figure presented as settled is a false
    // statement about money.
    if view.loading {
        let bar = working_bar(tree, skins);
        out.insert(1, bar);
    }
    out
}

/// Redeeming a note.
fn redeem_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &RedeemView,
) -> Vec<NodeId> {
    fn header(
        tree: &mut TaffyTree<()>,
        skins: &mut HashMap<NodeId, Skin>,
        title: &str,
        sub: &str,
    ) -> NodeId {
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(96.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("header")
                .text("eyebrow", "Redeem")
                .text("title", title)
                .text("subtitle", sub),
        )
    }

    match &view.state {
        RedeemState::Confirm { quote } => {
            let elsewhere = quote.elsewhere();
            let head = header(
                tree,
                skins,
                &format!("Redeem {}", quote.face),
                "this destroys the note - there is no undo and no one to ask",
            );
            let rows = vec![
                field_row(tree, skins, "note", &quote.short_id),
                // Who ends up with the money, not who pressed the button.
                field_row(
                    tree,
                    skins,
                    if elsewhere {
                        "they receive"
                    } else {
                        "you receive"
                    },
                    &quote.payout,
                ),
                field_row(tree, skins, "this note's fee", &quote.fee),
                // Checkable, because paying out to the wrong account is the
                // mistake available here - and since the payout can leave
                // the wallet entirely, the row says which case this is
                // rather than leaving 56 characters to be compared.
                field_row(tree, skins, "paid to", &quote.to_account),
                field_row(
                    tree,
                    skins,
                    "",
                    if elsewhere {
                        "not your account - the escrow goes straight there and never passes through your balance"
                    } else {
                        "your own account"
                    },
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            // The destination is in the verb when it is not the default, so
            // the last thing read before an irreversible act names where the
            // money goes.
            let confirm = if elsewhere {
                format!("Redeem to {}", crate::wallet::short(&quote.to_account))
            } else {
                "Redeem".to_string()
            };
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    (&confirm, Action::Confirm, true),
                    ("Change", Action::EditDestination, false),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        RedeemState::Destination {
            quote,
            typed,
            error,
        } => {
            let head = header(
                tree,
                skins,
                "Pay the escrow to",
                "the note is destroyed either way - this only chooses where the value lands",
            );
            let shown = if typed.is_empty() {
                "|".to_string()
            } else {
                format!("{typed}|")
            };
            // Said while there is still time to fix it, rather than as a
            // contract error after the holder has committed.
            let verdict = if typed.is_empty() {
                String::new()
            } else if typed.len() == 56 && typed.starts_with('G') {
                "looks like an account address".to_string()
            } else {
                format!(
                    "not an account address - {} characters, expected 56 starting with G",
                    typed.chars().count()
                )
            };
            let mut rows = vec![
                leaf(
                    tree,
                    skins,
                    Style {
                        size: Size { width: percent(1.0), height: length(56.0) },
                        flex_shrink: 0.0,
                        ..Default::default()
                    },
                    Skin::new("entry-row")
                        .text("label", "account")
                        .text("value", &shown)
                        .text("hint", "Enter to use"),
                ),
                field_row(
                    tree,
                    skins,
                    "what happens",
                    "the note is burned and the mint pays this account directly - they need no Kenter client, only a trustline for the asset",
                ),
                field_row(tree, skins, "note", &quote.short_id),
                field_row(tree, skins, "they receive", &quote.payout),
            ];
            if !verdict.is_empty() {
                rows.push(field_row(tree, skins, "", &verdict));
            }
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Use this account", Action::Confirm, true),
                    ("My account", Action::UseOwnAccount, false),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        RedeemState::Working { what } => {
            let head = header(tree, skins, "Redeeming", what);
            working_body(tree, skins, head, "step", what)
        }

        RedeemState::Done { paid, to_account } => {
            let head = header(tree, skins, &format!("Paid {paid}"), "the note is gone");
            let rows = vec![
                field_row(tree, skins, "received", paid),
                field_row(tree, skins, "into", to_account),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(tree, skins, &[("Billfold", Action::Back, true)]);
            vec![head, buttons, panel]
        }

        RedeemState::Failed { message } => {
            let head = header(
                tree,
                skins,
                "Did not redeem",
                "the note is untouched unless the reason says otherwise",
            );
            let rows = vec![field_row(tree, skins, "reason", message)];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(tree, skins, &[("Back", Action::Back, true)]);
            vec![head, buttons, panel]
        }
    }
}

/// Handing a note over.
fn pay_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &PayView,
) -> Vec<NodeId> {
    fn header(
        tree: &mut TaffyTree<()>,
        skins: &mut HashMap<NodeId, Skin>,
        title: &str,
        sub: &str,
    ) -> NodeId {
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(96.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("header")
                .text("eyebrow", "Pay")
                .text("title", title)
                .text("subtitle", sub),
        )
    }

    match &view.state {
        PayState::Export {
            row,
            written,
            error,
        } => {
            let head = header(
                tree,
                skins,
                &format!("Hand over {}", row.amount),
                "a bearer note is a file - once they have it, it is theirs",
            );
            let mut rows = vec![
                field_row(tree, skins, "note", &row.short_id),
                field_row(
                    tree,
                    skins,
                    "what this does",
                    "writes the file. The client cannot see the handover, confirm it, or undo it.",
                ),
            ];
            match written {
                Some(path) => {
                    rows.push(field_row(tree, skins, "written to", path));
                    rows.push(field_row(
                        tree,
                        skins,
                        "keep a copy?",
                        "removing it moves the note to Spent and keeps the bytes - a backup still contains it, so this is bookkeeping, not destruction",
                    ));
                }
                None if row.exposure > 0 => rows.push(field_row(
                    tree,
                    skins,
                    "already exported",
                    &format!(
                        "{} other part{} may hold a redeemable copy; whoever redeems first wins",
                        row.exposure,
                        if row.exposure == 1 { "y" } else { "ies" }
                    ),
                )),
                None => {}
            }
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = match written {
                Some(_) => buttons_row(
                    tree,
                    skins,
                    &[
                        ("Keep it", Action::KeepCopy, false),
                        ("Move to Spent", Action::DropCopy, true),
                    ],
                ),
                // Two verbs, because the answer changes what the client
                // believes about this note. A handover means someone else
                // may redeem it first, and the card says so; a backup is
                // still only yours. One button would have to guess, and
                // guessing wrong either invents a rival claimant or hides
                // a real one.
                None => buttons_row(
                    tree,
                    skins,
                    &[
                        ("Hand over\u{2026}", Action::ExportNote, true),
                        ("Save a backup\u{2026}", Action::ExportBackup, false),
                        ("Back", Action::Back, false),
                    ],
                ),
            };
            vec![head, buttons, panel]
        }

        PayState::Address { row, typed, error } => {
            let head = header(
                tree,
                skins,
                &format!("Pay {}", row.amount),
                "their pay tag - Ctrl+V to paste, or scan their QR",
            );
            let shown = format!("{typed}|");
            // Asked of the same parser Enter will use, so the verdict
            // cannot endorse something the payment would then reject. The
            // first version of this line guessed independently and called a
            // Stellar account address valid — which is the one wrong thing
            // most likely to be pasted here, and it said yes to it.
            let verdict = if typed.is_empty() {
                String::new()
            } else if kenter_wallet::parse_receive_uri(typed).is_ok() {
                "a Kenter pay tag".to_string()
            } else if typed.len() == 56 && typed.starts_with('G') {
                // Name the mistake rather than the symptom. "Address" alone
                // is ambiguous: the Account page has an account address
                // sitting behind a Copy button.
                "that is an account address, not a pay tag - get the tag from their Accept screen"
                    .to_string()
            } else {
                format!(
                    "not a pay tag - {} characters, expected 64 hex or a KENTER:RECV link",
                    typed.len()
                )
            };
            let mut rows = vec![
                leaf(
                    tree,
                    skins,
                    Style {
                        size: Size { width: percent(1.0), height: length(56.0) },
                        flex_shrink: 0.0,
                        ..Default::default()
                    },
                    Skin::new("entry-row")
                        .text("label", "pay tag")
                        // Small enough that 56 characters fit, because the
                        // point is comparing them against what the payee
                        // sent rather than admiring them.
                        .text("value", &shown)
                        .text("hint", "Enter to pay"),
                ),
                field_row(
                    tree,
                    skins,
                    "what happens",
                    "you save the note to a file and send it to them yourself, then the ledger records the transfer - in that order, because the reverse strands the note",
                ),
                field_row(tree, skins, "note", &row.short_id),
            ];
            if !verdict.is_empty() {
                rows.push(field_row(tree, skins, "", &verdict));
            }
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Pay", Action::Confirm, true),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        PayState::Working { what } => {
            let head = header(tree, skins, "Paying", what);
            working_body(tree, skins, head, "step", what)
        }

        PayState::Paid { row, where_to } => {
            let head = header(
                tree,
                skins,
                &format!("Paid {}", row.amount),
                "the ledger says it is theirs now",
            );
            let rows = vec![
                field_row(tree, skins, "note", &row.short_id),
                field_row(tree, skins, "to", where_to),
                field_row(
                    tree,
                    skins,
                    "send them the file",
                    "it is in your outbox. They are not paid until they have it - the pointer alone gives them nothing to redeem.",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(tree, skins, &[("Billfold", Action::Back, true)]);
            vec![head, buttons, panel]
        }

        PayState::Failed { message } => {
            let head = header(
                tree,
                skins,
                "Payment did not finish",
                "check the reason below",
            );
            let rows = vec![field_row(tree, skins, "reason", message)];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(tree, skins, &[("Back", Action::Back, true)]);
            vec![head, buttons, panel]
        }
    }
}

/// Deposit: value in, a note out.
fn deposit_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &DepositView,
) -> Vec<NodeId> {
    fn header(
        tree: &mut TaffyTree<()>,
        skins: &mut HashMap<NodeId, Skin>,
        title: &str,
        sub: &str,
    ) -> NodeId {
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(96.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("header")
                .text("eyebrow", "Deposit")
                .text("title", title)
                .text("subtitle", sub),
        )
    }

    match &view.state {
        DepositState::Form {
            entered,
            preview,
            spend,
            pairs,
            printer,
            error,
        } => {
            let head = header(
                tree,
                skins,
                "Make a note",
                "value goes into escrow and an instrument comes back",
            );

            // The amount, shown as typed: this is not a secret, and masking a
            // number the holder is checking would be theatre.
            let shown = if *entered == 0 {
                "|".to_string()
            } else {
                format!(
                    "{}|",
                    preview
                        .as_ref()
                        .map(|p| p.face.clone())
                        .unwrap_or_else(|| "…".into())
                )
            };
            let mut rows = vec![leaf(
                tree,
                skins,
                Style {
                    size: Size {
                        width: percent(1.0),
                        height: length(56.0),
                    },
                    flex_shrink: 0.0,
                    ..Default::default()
                },
                Skin::new("entry-row-large")
                    .text("label", "amount")
                    .text("value", &shown)
                    .text("hint", "Enter to deposit"),
            )];

            rows.push(field_row(
                tree,
                skins,
                "mode  (i)  bearer is like cash; spend mode needs your key to move",
                if *spend {
                    "spend - only your key can move it; every transfer is recorded"
                } else {
                    "bearer - whoever holds the file can spend it; handovers leave no trace"
                },
            ));
            rows.push(field_row(
                tree,
                skins,
                "pairs",
                &format!("{pairs} - more independent nodes, and a higher fee and floor"),
            ));
            rows.push(field_row(tree, skins, "printed by", printer));
            if let Some(p) = preview {
                rows.push(field_row(
                    tree,
                    skins,
                    "redeems for",
                    &format!("{} - this note's fee is {}", p.redeems_for, p.fee),
                ));
            }
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Deposit", Action::Deposit, true),
                    (
                        if *spend { "Make bearer" } else { "Make spend" },
                        Action::ToggleMode,
                        false,
                    ),
                    ("Pairs +", Action::CyclePairs, false),
                ],
            );
            vec![head, buttons, panel]
        }

        DepositState::Working { what } => {
            // Four on-chain steps, and only the last leaves a redeemable
            // instrument, so the step is named rather than left to the bar -
            // if it stops, the holder needs to know where. The bar says the
            // worker is alive; only the words say what it is doing.
            let head = header(tree, skins, "Printing", what);
            let bar = working_bar(tree, skins);
            let rows = vec![
                field_row(tree, skins, "step", what),
                field_row(
                    tree,
                    skins,
                    "not yet a note",
                    "the deposit is in escrow until the last step registers it",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            vec![head, bar, panel]
        }

        DepositState::Done { id, amount } => {
            let head = header(
                tree,
                skins,
                &format!("Deposited {amount}"),
                "the note is yours",
            );
            let rows = vec![
                field_row(tree, skins, "note", id),
                field_row(
                    tree,
                    skins,
                    "back it up",
                    "the file is the money - your recovery phrase does not restore it",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Another", Action::Continue, false),
                    ("Billfold", Action::Back, true),
                ],
            );
            vec![head, buttons, panel]
        }

        DepositState::Failed { message } => {
            let head = header(
                tree,
                skins,
                "Deposit did not finish",
                "check the reason below",
            );
            let rows = vec![field_row(tree, skins, "reason", message)];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Try again", Action::Continue, true),
                    ("Billfold", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }
    }
}

/// First run.
fn setup_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &SetupView,
) -> Vec<NodeId> {
    fn header(
        tree: &mut TaffyTree<()>,
        skins: &mut HashMap<NodeId, Skin>,
        title: &str,
        sub: &str,
    ) -> NodeId {
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(96.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("header")
                .text("eyebrow", "Set up")
                .text("title", title)
                .text("subtitle", sub),
        )
    }

    /// A masked text field. The count comes from the shell; the characters
    /// never enter the view model.
    fn field(
        tree: &mut TaffyTree<()>,
        skins: &mut HashMap<NodeId, Skin>,
        label: &str,
        entered: usize,
        hint: &str,
    ) -> NodeId {
        // A caret, because the border alone does not say *where* the next
        // character goes, and an empty field with no caret reads as a label
        // rather than as something waiting for input.
        let dots: String = format!("{}|", "\u{2022}".repeat(entered.min(64)));
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(56.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("entry-row-large")
                .text("label", label)
                .text("value", &dots)
                .text("hint", hint),
        )
    }

    match &view.state {
        SetupState::Start => {
            let head = header(
                tree,
                skins,
                "Welcome",
                "your notes are encrypted on disk, so this has to happen first",
            );
            let rows = vec![
                field_row(tree, skins, "what this makes", "a recovery phrase, a passphrase, and an account to pay fees with"),
                field_row(
                    tree,
                    skins,
                    "worth knowing now",
                    "your recovery phrase restores your keys, not your notes - the note files are the money, and need backing up separately",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("New wallet", Action::NewWallet, true),
                    ("Restore", Action::RestoreWallet, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::Custody {
            restoring,
            card,
            card_ok,
            error,
        } => {
            let head = header(
                tree,
                skins,
                if *restoring {
                    "Where should your key go back?"
                } else {
                    "Where should your key live?"
                },
                if *restoring {
                    "your words work either way - this only decides where they end up"
                } else {
                    "this cannot be changed later without moving every note, so it is asked once"
                },
            );
            let mut rows = vec![
                field_row(
                    tree,
                    skins,
                    "this computer",
                    if *restoring {
                        "no card needed. The key sits here behind a passphrase you \
                         choose now - you can move it to a card later by restoring again"
                    } else {
                        "a passphrase protects it. Simple, and anything that gets into \
                         this machine gets your key with it"
                    },
                ),
                field_row(
                    tree,
                    skins,
                    "a card",
                    if *restoring {
                        "put it back on a card, as it was. Any blank card will do - \
                         it is the words that make it your wallet, not the silicon"
                    } else {
                        "nothing can be signed without the card in your hand. Lose it and \
                         your recovery phrase brings the key back"
                    },
                ),
                // Said here rather than discovered later: the two secrets are
                // the honest cost of the card, and a holder choosing it
                // should know before they choose, not after.
                field_row(
                    tree,
                    skins,
                    "either way",
                    if *restoring {
                        "same wallet, same notes, same backups - the choice changes \
                         nothing about what comes back"
                    } else {
                        "your phrase restores keys, never notes - the note files are the \
                         money and need backing up separately"
                    },
                ),
            ];
            if let Some(c) = card {
                rows.push(field_row(tree, skins, "the reader", c));
            }
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("This computer", Action::UseSoftware, true),
                    // Offered whatever the reader says: pressing it is how a
                    // holder finds out *why* not, and a greyed button with no
                    // explanation is the thing being avoided.
                    (
                        if *card_ok {
                            "Use a card"
                        } else {
                            "Use a card\u{2026}"
                        },
                        Action::UseCard,
                        false,
                    ),
                    ("Look again", Action::CheckCard, false),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::CardIntro { card, blank } => {
            let head = header(
                tree,
                skins,
                "Put your wallet on this card",
                if *blank {
                    "a new card - this will give it a PIN and a key"
                } else {
                    "this card is already set up"
                },
            );
            let mut rows = vec![
                field_row(
                    tree,
                    skins,
                    "the card becomes the wallet",
                    "your owner keys, the key that encrypts your notes, and the key that \
                     encrypts your backup all come from the card's seed",
                ),
                field_row(
                    tree,
                    skins,
                    "there is no undo",
                    "moving custody afterwards means moving every note you hold",
                ),
                // Said here and not in four screens' time, which is the
                // entire reason this screen exists.
                field_row(
                    tree,
                    skins,
                    "you will write down 24 words",
                    "have paper in front of you before you start",
                ),
                field_row(tree, skins, "the reader", card),
            ];
            // An initialized card is a fork in the flow, not a warning. We
            // cannot INIT it again and will not quietly adopt whatever is on
            // it, so the two ways forward are named.
            if !*blank {
                rows.push(field_row(
                    tree,
                    skins,
                    "already set up",
                    "if this card already holds a wallet, go back and unlock it instead. \
                     To use it for a new one it has to be erased first, which destroys \
                     any notes on it.",
                ));
            }
            let panel = panel_of(tree, skins, &rows);
            let mut labels: Vec<(&str, Action, bool)> = Vec::new();
            if *blank {
                labels.push(("Set up this card", Action::Continue, true));
            } else {
                // The intro tells the holder the card has to be erased
                // first. Saying that with no way to do it would be a dead
                // end, so the erase is offered right here.
                labels.push(("Erase this card", Action::EraseCard, false));
            }
            labels.push(("Back", Action::Back, false));
            let buttons = buttons_row(tree, skins, &labels);
            vec![head, buttons, panel]
        }

        SetupState::CardPin {
            entered,
            again,
            error,
        } => {
            let head = header(
                tree,
                skins,
                if *again {
                    "Type your PIN again"
                } else {
                    "Choose a PIN for the card"
                },
                if *again {
                    "the two have to match - nothing else can check it for you"
                } else {
                    "six digits, and the card asks for it every time it signs"
                },
            );
            let mut rows = vec![
                // A number with a consequence the holder can act on, which
                // is the test for whether it belongs in the copy.
                field_row(
                    tree,
                    skins,
                    "five wrong tries",
                    "blocks the card, and only the PUK on the next screen can unblock it - \
                     so pick something you will not mistype",
                ),
                field_row(
                    tree,
                    skins,
                    "it never leaves the card",
                    "this computer does not store it, and cannot recover it for you",
                ),
            ];
            rows.push(field(tree, skins, "PIN", *entered, "Enter to continue"));
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Continue", Action::Confirm, true),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::CardDuress {
            entered,
            again,
            error,
        } => {
            let head = header(
                tree,
                skins,
                if *again {
                    "Type your duress PIN again"
                } else {
                    "Choose a duress PIN"
                },
                "a second PIN that opens a decoy wallet",
            );
            let mut rows = vec![
                // The hardest copy in the flow. It has to say that the card
                // opens *normally*, that what appears is a decoy rather than
                // a wipe, and that the real notes come back - without
                // claiming the protection is broader than it is. Someone
                // holding this PIN can still block the main PIN, change the
                // PUK or erase the card; those are denial of service, not
                // theft, and the recovery is the phrase plus the backup.
                field_row(
                    tree,
                    skins,
                    "what it does",
                    "if you are forced to unlock the card, this PIN opens it normally and \
                     shows a wallet with little in it",
                ),
                field_row(
                    tree,
                    skins,
                    "your real notes",
                    "are hidden, not deleted - your real PIN still opens them, and nothing \
                     is destroyed",
                ),
                field_row(
                    tree,
                    skins,
                    "what it cannot stop",
                    "someone who has this PIN can still lock you out of the card. They \
                     cannot take your notes; you would restore from your phrase and backup.",
                ),
            ];
            rows.push(field(
                tree,
                skins,
                "duress PIN",
                *entered,
                "Enter to continue",
            ));
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            // "Skip" does not mean "none" - there is no such state. Declining
            // generates one and shows it, which is why the button says
            // choose-for-me rather than skip.
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Continue", Action::Confirm, true),
                    ("Choose one for me", Action::SkipDuress, false),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::CardPuk {
            puk,
            entered,
            confirming,
            error,
        } => {
            let head = header(
                tree,
                skins,
                if *confirming {
                    "Type the PUK back"
                } else {
                    "Write down your PUK"
                },
                if *confirming {
                    "so we know it was written down correctly"
                } else {
                    "the only thing that can unblock the card if the PIN is mistyped five times"
                },
            );
            let mut rows = Vec::new();
            if *confirming {
                rows.push(field(tree, skins, "PUK", *entered, "Enter to continue"));
            } else {
                rows.push(leaf(
                    tree,
                    skins,
                    Style {
                        size: Size {
                            width: percent(1.0),
                            height: length(56.0),
                        },
                        flex_shrink: 0.0,
                        ..Default::default()
                    },
                    Skin::new("puk-row").text_secret("puk", &crate::card::group_puk(puk)),
                ));
            }
            rows.push(field_row(
                tree,
                skins,
                "keep it with your 24 words",
                "a PUK you cannot find is discovered on the day the card blocks, which is \
                 the worst day to discover it",
            ));
            rows.push(field_row(
                tree,
                skins,
                "we chose it, not you",
                "twelve digits is past what anyone invents well, and it has to avoid a \
                 pattern the card would reject",
            ));
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    (
                        if *confirming {
                            "Continue"
                        } else {
                            "I wrote it down"
                        },
                        Action::Confirm,
                        true,
                    ),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::CardErase {
            confirmed,
            typed,
            entered,
            error,
        } => {
            let head = header(
                tree,
                skins,
                "Erase this card",
                if *confirmed {
                    "enter the card's PIN to erase it"
                } else {
                    "this destroys everything on it"
                },
            );
            let mut rows = vec![
                field_row(
                    tree,
                    skins,
                    "what goes",
                    "the card's key, its PIN and PUK, and any notes stored on it. Notes are \
                     bearer instruments - the file is the money, and this deletes it.",
                ),
                // The honest scope of the damage. Keys come back from the
                // phrase; notes do not, and that is the reason this screen
                // is not a button.
                field_row(
                    tree,
                    skins,
                    "what comes back",
                    "a wallet restored from its 24 words gets the same keys - but never the \
                     notes. Those are only in your backups.",
                ),
                field_row(tree, skins, "there is no undo", "and nobody to ask"),
            ];
            if *confirmed {
                rows.push(field(tree, skins, "PIN", *entered, "Enter to continue"));
            } else {
                rows.push(leaf(
                    tree,
                    skins,
                    Style {
                        size: Size {
                            width: percent(1.0),
                            height: length(56.0),
                        },
                        flex_shrink: 0.0,
                        ..Default::default()
                    },
                    Skin::new("entry-row-xl")
                        .text("label", "type ERASE to continue")
                        .text("value", &format!("{typed}|"))
                        .text("hint", "Enter to continue"),
                ));
            }
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    (
                        if *confirmed {
                            "Erase the card"
                        } else {
                            "Continue"
                        },
                        Action::Confirm,
                        // Never the primary button. The way out of this
                        // screen should be the easier one to hit.
                        false,
                    ),
                    ("Keep the card", Action::Back, true),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::CardPhrase { words, revealed } => {
            let head = header(
                tree,
                skins,
                "Write down these 24 words",
                "on paper - hold Reveal to show them, and keep them off any shared screen",
            );
            let mut rows = Vec::new();
            if *revealed {
                for (row, chunk) in words.chunks(6).enumerate() {
                    let numbered: Vec<String> = chunk
                        .iter()
                        .enumerate()
                        .map(|(i, w)| format!("{}. {w}", row * 6 + i + 1))
                        .collect();
                    rows.push(leaf(
                        tree,
                        skins,
                        Style {
                            size: Size {
                                width: percent(1.0),
                                height: length(42.0),
                            },
                            flex_shrink: 0.0,
                            ..Default::default()
                        },
                        Skin::new("phrase-row").text_secret("words", &numbered.join("   ")),
                    ));
                }
            } else {
                rows.push(field_row(
                    tree,
                    skins,
                    "hidden",
                    "hold Reveal to show the card's recovery phrase",
                ));
            }
            // The honest version of the card's custody claim. "Never leaves
            // the card" is false at the moment it is on screen, and a client
            // that overstates
            // this one has no standing to be believed about the rest.
            rows.push(field_row(
                tree,
                skins,
                "shown here once, now",
                "the card made these words and kept no copy. After this they never leave \
                 it - but they are on this screen at this moment, so do the next part \
                 somewhere private.",
            ));
            rows.push(field_row(
                tree,
                skins,
                "nothing is on the card yet",
                "it is written after you have confirmed the words, so a mistake now costs \
                 a retry rather than a wallet",
            ));
            let panel = panel_of(tree, skins, &rows);
            let mut labels: Vec<(&str, Action, bool)> = vec![
                ("Reveal", Action::Reveal, false),
                ("Copy phrase", Action::CopyPhrase, false),
            ];
            {
            }
            labels.push(("I wrote it down", Action::Continue, true));
            labels.push(("Back", Action::Back, false));
            let buttons = buttons_row(tree, skins, &labels);
            vec![head, buttons, panel]
        }

        SetupState::CardConfirm {
            positions,
            entered,
            error,
        } => {
            let asked = positions
                .iter()
                .map(|p| (p + 1).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let head = header(
                tree,
                skins,
                "Check the words",
                "the last step before anything is written to the card",
            );
            let mut rows = vec![
                field_row(
                    tree,
                    skins,
                    "type words",
                    &format!("{asked} - separated by spaces"),
                ),
                // What this step is honestly worth: a pause at the one
                // irreversible moment. It does not prove the words were
                // written down, and the copy must not pretend otherwise.
                field_row(
                    tree,
                    skins,
                    "after this",
                    "the card is given its PIN and its key, and the words you wrote down \
                     are the only way back if it is lost",
                ),
            ];
            rows.push(field(tree, skins, "words", *entered, "Enter to continue"));
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Set up the card", Action::Confirm, true),
                    ("Show me again", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::Passphrase { entered, error } => {
            let head = header(
                tree,
                skins,
                "Choose a passphrase",
                "it encrypts your notes and your keys on this machine",
            );
            let mut rows = vec![field(
                tree,
                skins,
                "passphrase",
                *entered,
                "Enter to continue",
            )];
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            rows.push(field_row(
                tree,
                skins,
                "if you lose it",
                "your recovery phrase and your note backups are the way back in",
            ));
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Continue", Action::Confirm, true),
                    ("Back", Action::Cancel, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::Phrase { words, revealed } => {
            let head = header(
                tree,
                skins,
                "Write this down",
                "on paper - hold Reveal to show it, and keep it off any screen that is being shared",
            );
            let mut rows = Vec::new();
            if *revealed {
                // Six to a line, numbered, the way the CLI prints it.
                for (row, chunk) in words.chunks(6).enumerate() {
                    let numbered: Vec<String> = chunk
                        .iter()
                        .enumerate()
                        .map(|(i, w)| format!("{}. {w}", row * 6 + i + 1))
                        .collect();
                    rows.push(leaf(
                        tree,
                        skins,
                        Style {
                            size: Size {
                                width: percent(1.0),
                                height: length(42.0),
                            },
                            flex_shrink: 0.0,
                            ..Default::default()
                        },
                        Skin::new("phrase-row").text_secret("words", &numbered.join("   ")),
                    ));
                }
            } else {
                rows.push(field_row(
                    tree,
                    skins,
                    "hidden",
                    "hold Reveal to show your recovery phrase",
                ));
            }
            rows.push(field_row(
                tree,
                skins,
                "it restores",
                "your keys - not your notes. Back the note files up as well.",
            ));
            let panel = panel_of(tree, skins, &rows);
            let mut labels: Vec<(&str, Action, bool)> = vec![
                ("Reveal", Action::Reveal, false),
                ("Copy phrase", Action::CopyPhrase, false),
            ];
            {
            }
            labels.push(("I wrote it down", Action::Continue, true));
            let buttons = buttons_row(tree, skins, &labels);
            vec![head, buttons, panel]
        }

        SetupState::Confirm {
            positions,
            entered,
            error,
        } => {
            let asked: Vec<String> = positions.iter().map(|p| (p + 1).to_string()).collect();
            let head = header(
                tree,
                skins,
                "Check your copy",
                "so the phrase is not left only on this screen",
            );
            let mut rows = vec![field(
                tree,
                skins,
                &format!("words {} - separated by spaces", asked.join(", ")),
                *entered,
                "Enter to continue",
            )];
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Continue", Action::Confirm, true),
                    ("Back", Action::Cancel, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::Restore {
            entered,
            error,
            file,
            paper,
        } => {
            let head = header(
                tree,
                skins,
                "Restore a wallet",
                match file {
                    None => "your backup file or paper sheets, then your recovery phrase",
                    Some(f) => f.needs.as_str(),
                },
            );
            // The file first, and read before anything is asked of the
            // holder: its header is cleartext, and it is the only thing
            // that knows whether these words are a software wallet's seed
            // or a card's.
            let mut rows = vec![match (file, paper) {
                (None, None) => field_row(
                    tree,
                    skins,
                    "backup file",
                    "none chosen - without a file or paper sheets your keys come back but \
                     your notes do not",
                ),
                // Paper alone is a complete answer, not a missing file.
                (None, Some(_)) => field_row(tree, skins, "backup file", "none - using paper"),
                (Some(f), _) => field_row(tree, skins, "backup file", &f.summary),
            }];
            if let Some(f) = file {
                rows.push(field_row(tree, skins, "from", &f.path));
            }
            if let Some(p) = paper {
                rows.push(field_row(tree, skins, "paper", p));
            }
            let have_backup = file.is_some() || paper.is_some();
            rows.push(field(
                tree,
                skins,
                "recovery phrase",
                *entered,
                "Enter to continue",
            ));
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    (
                        if file.is_some() {
                            "Choose a different file\u{2026}"
                        } else {
                            "Choose your backup\u{2026}"
                        },
                        Action::ChooseBackupFile,
                        !have_backup,
                    ),
                    (
                        if paper.is_some() {
                            "Scan more sheets\u{2026}"
                        } else {
                            "Scan paper backup\u{2026}"
                        },
                        Action::ScanPaper,
                        false,
                    ),
                    ("Continue", Action::Confirm, have_backup),
                    ("Back", Action::Cancel, false),
                ],
            );
            vec![head, buttons, panel]
        }

        SetupState::Working { what } => {
            let head = header(tree, skins, "Working", what);
            working_body(tree, skins, head, "", what)
        }

        SetupState::Activate {
            address,
            copied,
            funded,
            trustline_needed,
            busy,
            error,
        } => {
            let ready = *funded && trustline_needed.is_none();
            let head = header(
                tree,
                skins,
                if ready {
                    "Ready"
                } else {
                    "Almost - this account cannot act yet"
                },
                match (busy, ready) {
                    (Some(what), _) => what.as_str(),
                    (None, true) => "funded, and able to be paid",
                    (None, false) => "two things stand between here and a working client",
                },
            );

            let mut rows = vec![field_row(tree, skins, "submitting account", address)];
            rows.push(field_row(
                tree,
                skins,
                "1. funded",
                if *funded {
                    "yes - this account can submit transactions"
                } else {
                    // The figure is on the screen, because "fund it" without
                    // an amount is an instruction someone cannot follow.
                    // 3 XLM clears the reserve - (2 + subentries) x 0.5, so
                    // 1.5 with a trustline - and leaves the rest for fees.
                    "send at least 3 XLM to the address below"
                },
            ));
            rows.push(field_row(
                tree,
                skins,
                "2. trustline",
                &match (funded, trustline_needed) {
                    (false, _) => {
                        "waiting - a trustline is a transaction, so funding comes first".to_string()
                    }
                    (true, Some(code)) => {
                        format!("NO - without one for {code}, a redemption cannot pay you")
                    }
                    (true, None) => "yes - a payout can reach this account".to_string(),
                },
            ));
            if let Some(e) = error {
                rows.push(field_row(tree, skins, "", e));
            }
            if *copied {
                rows.push(field_row(tree, skins, "", "address copied"));
            }
            // Funding arrives from outside this client — another wallet, an
            // exchange, a phone — so the address has to leave the screen
            // easily. Dark modules on a white quiet zone; a QR drawn in
            // theme colours is the classic unscannable one.
            if !*funded {
                if let Ok(svg) = qr::svg(address, "#0b0e16", "#ffffff") {
                    rows.push(leaf(
                        tree,
                        skins,
                        Style {
                            size: Size {
                                width: length(216.0),
                                height: length(216.0),
                            },
                            flex_shrink: 0.0,
                            ..Default::default()
                        },
                        Skin::inline_svg(svg),
                    ));
                }
            }
            let panel = panel_of(tree, skins, &rows);

            // Deliberately few buttons. The client is doing the work —
            // watching for the XLM, then adding the trustline itself — so
            // the only things to offer are the address and, once it is
            // done, the way out. A "check again" button on a screen that is
            // already checking invites someone to believe pressing it helps.
            let mut labels: Vec<(&str, Action, bool)> = Vec::new();
            if ready {
                labels.push(("Open my billfold", Action::Continue, true));
            }
            labels.push(("Copy address", Action::Copy, !ready));
            let buttons = buttons_row(tree, skins, &labels);
            vec![head, buttons, panel]
        }

        SetupState::Failed { message } => {
            let head = header(tree, skins, "Setup did not finish", "nothing was written");
            let rows = vec![field_row(tree, skins, "reason", message)];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(tree, skins, &[("Start again", Action::Cancel, true)]);
            vec![head, buttons, panel]
        }
    }
}

/// The account page: balances, and the address that fills them.
fn account_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &AccountView,
) -> Vec<NodeId> {
    let head = leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(96.0),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("header")
            .text("eyebrow", "Account")
            // The asset balance is the headline, because it is the number
            // that decides whether a deposit can happen at all.
            .text("title", &view.asset_balance)
            .text("subtitle", view.busy.as_deref().unwrap_or_else(|| {
                    view.blocked_by
                        .as_deref()
                        .unwrap_or("ready to deposit from")
                })),
    );

    let mut rows = vec![
        // Spelled out rather than implied: this is the one screen where
        // someone works out why a transaction they expected to work did not.
        field_row(
            tree,
            skins,
            &format!("{} available", view.asset_code),
            &view.asset_balance,
        ),
        field_row(tree, skins, "XLM for fees", &view.xlm_spendable),
        field_row(
            tree,
            skins,
            "XLM held",
            &format!("{} - the rest is the account reserve", view.xlm),
        ),
        field_row(
            tree,
            skins,
            "trustline",
            match view.trustline {
                Some(true) => "yes - a payout can reach this account",
                Some(false) => "NO - add one, or a redemption cannot pay you",
                None => "unknown - not read yet",
            },
        ),
        field_row(tree, skins, "address", &view.address),
        // Naming both crossings here is the whole point of the screen: it is
        // where the fungible balance turns into notes and back again.
        field_row(
            tree,
            skins,
            "what this is for",
            "Deposit turns this balance into notes. Redeeming a note brings its value back here.",
        ),
    ];
    // Money the holder already paid in and cannot otherwise reach. It goes
    // above the error line and the QR because it is the most actionable
    // thing that can be on this screen.
    for s in &view.stalled {
        rows.push(field_row(
            tree,
            skins,
            &format!("stuck in print {}", s.slot_id),
            &format!(
                "{} held - {} - press Recover to take it back",
                s.amount, s.progress
            ),
        ));
    }
    if let Some(e) = &view.error {
        rows.push(field_row(tree, skins, "", e));
    }
    if view.copied {
        rows.push(field_row(tree, skins, "", "address copied"));
    }

    // The QR is how someone funds this from a phone, so it sits with the
    // address rather than behind a button.
    // Dark modules on a white quiet zone, not theme colours: a QR drawn to
    // match a dark panel is the classic unscannable one.
    if let Ok(svg) = qr::svg(&view.address, "#0b0e16", "#ffffff") {
        rows.push(leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: length(216.0),
                    height: length(216.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::inline_svg(svg),
        ));
    }

    let panel = panel_of(tree, skins, &rows);
    let mut labels: Vec<(&str, Action, bool)> = vec![
        ("Copy address", Action::Copy, true),
        ("Refresh", Action::Check, false),
    ];
    // One at a time, oldest first: each is a separate transaction, and a
    // button that silently cancels several is worse than pressing it twice.
    if let Some(s) = view.stalled.first() {
        labels.insert(0, ("Recover escrow", Action::Recover(s.slot_id), true));
    }
    if view.trustline == Some(false) {
        labels.insert(0, ("Add trustline", Action::AddTrustline, true));
    }
    let buttons = buttons_row(tree, skins, &labels);

    // Reading this page is seconds of RPC, and the figures under it are the
    // previous read's. Without the bar the page looks settled, which is why
    // arriving here read as "nothing happened" and people pressed Refresh on
    // a read that was already running.
    match &view.busy {
        Some(_) => {
            let bar = working_bar(tree, skins);
            vec![head, bar, buttons, panel]
        }
        None => vec![head, buttons, panel],
    }
}

/// The gate. One thing to do, and the field to do it in.
///
/// Reading order is the fix for what this replaces. The old flow put the
/// passphrase field at the *bottom* of a details panel, under the Confirm
/// button that acts on it, so the one control that mattered was the last
/// thing found. Here the field is directly under the title and the button
/// is below it, which is the order the eye already travels.
fn locked_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &LockedView,
) -> Vec<NodeId> {
    let head = leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(96.0),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("header")
            .text("eyebrow", "Kenter")
            .text("title", "Locked")
            // Says only what unlocking does. The prompt this replaces
            // announced "Create a pay tag - owner index 0", because opening
            // the store borrowed the pay-tag authorization to carry the
            // passphrase. Nothing was being derived, and a client that
            // misnames a key operation on its own front door has no standing
            // to be believed later.
            .text("subtitle", "your notes are encrypted on disk - this opens them"),
    );

    // Dots from a count: the view model never holds the passphrase.
    let dots: String = format!("{}|", "\u{2022}".repeat(view.entered.min(64)));
    let field = leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(64.0),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("unlock-row")
            .text("label", if view.card.is_some() {
                    "PIN"
                } else {
                    "passphrase"
                })
            .text("value", &dots)
            .text("hint", "Enter to unlock"),
    );

    let mut out = vec![head, field];

    // Opening the store is Argon2id and then a read of every note in it.
    // The bar is here because this is the one screen someone sits and waits
    // on before anything else in the client works.
    if view.busy {
        out.push(working_bar(tree, skins));
    } else {
        let mut labels: Vec<(&str, Action, bool)> = vec![("Unlock", Action::Unlock, true)];
        // A card wallet with no card is waiting on the world, not on the
        // holder. Offer the re-check rather than leaving them to guess
        // whether the app noticed them putting it down.
        if view.card.is_some() {
            labels.push(("Look again", Action::CheckCard, false));
        }
        // The way out of a wallet that will never open: a lost or wiped
        // card, a forgotten passphrase. Secondary, and it leads to a screen
        // that explains and asks for a typed word before anything moves.
        labels.push(("Can't open it?", Action::ResetWallet, false));
        out.push(buttons_row(tree, skins, &labels));
    }

    // What the reader says, under the field it governs. A card wallet whose
    // card is absent cannot be opened by anything typed here, and saying so
    // is the difference between waiting and retrying.
    if let Some(card) = &view.card {
        let row = field_row(
            tree,
            skins,
            if card.ready { "card" } else { "no card" },
            &card.hint,
        );
        out.push(panel_of(tree, skins, &[row]));
    }

    // A wrong passphrase is the expected case, not an exception: it is said
    // on the screen that can act on it, under the field that caused it.
    if let Some(e) = &view.error {
        let row = field_row(tree, skins, "", e);
        out.push(panel_of(tree, skins, &[row]));
    }
    out
}

/// The reset page: what happens, where it all goes, and a typed word.
fn reset_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &ResetView,
) -> Vec<NodeId> {
    let head = leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(96.0),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("header")
            .text("eyebrow", "Kenter")
            .text("title", "Reset this wallet")
            .text("subtitle", "for a wallet whose card or passphrase is gone for good"),
    );
    // Three rows, so all of it is on screen without scrolling: the one that
    // says how the notes come back must not be the one below the fold.
    let backups = if view.backups.is_empty() {
        "no backup file beside the vault, so a printed sheet is the other way".to_string()
    } else {
        format!("restore from {} on the new wallet", view.backups.join(", "))
    };
    let rows = vec![
        field_row(
            tree,
            skins,
            "what happens",
            "Kenter starts again as if new. Nothing is deleted: this wallet is moved aside.",
        ),
        field_row(tree, skins, "moved to", &view.archive),
        field_row(
            tree,
            skins,
            "your notes",
            &format!(
                "Only this wallet's own card or passphrase, or a paper backup, opens them: {backups}."
            ),
        ),
    ];
    let facts = panel_of(tree, skins, &rows);

    let field = leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(64.0),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("unlock-row")
            .text("label", &format!("type {}", reset::CONFIRM_WORD))
            .text("value", &format!("{}|", view.typed))
            .text("hint", "then Enter"),
    );
    let mut out = vec![head, facts, field];
    out.push(buttons_row(
        tree,
        skins,
        &[
            ("Reset this wallet", Action::ConfirmReset, true),
            ("Back", Action::Back, false),
        ],
    ));
    if let Some(e) = &view.error {
        let row = field_row(tree, skins, "", e);
        out.push(panel_of(tree, skins, &[row]));
    }
    out
}

/// The settings page: a list of facts about this client.
fn settings_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &SettingsView,
) -> Vec<NodeId> {
    let head = leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(96.0),
            },
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("header")
            .text("eyebrow", "Settings")
            .text("title", "This client")
            .text("subtitle", view.note
                    .as_deref()
                    .unwrap_or("where things are, and whether it can act")),
    );
    // The backup row goes amber when it is a warning. It is the one row on
    // a status page that is not merely a fact: everything else here says
    // how things are, and this says something is at stake.
    if let Some(edit) = &view.rpc_edit {
        return rpc_edit_page(tree, skins, head, edit);
    }
    let at_risk = view.backup.as_ref().is_some_and(|(_, risk)| *risk);
    let rows: Vec<NodeId> = view
        .rows
        .iter()
        .map(|(k, v)| {
            if at_risk && k == "backup" {
                warn_row(tree, skins, k, v)
            } else {
                field_row(tree, skins, k, v)
            }
        })
        .collect();
    let panel = panel_of(tree, skins, &rows);

    // "Save" first and primary: it is the one a holder is here to press,
    // and restoring is rare and consequential enough not to sit under a
    // thumb. Both always offered — a backup that can only be made when the
    // wallet nags is a backup made once.
    let mut actions: Vec<(String, Action, bool)> = Vec::new();
    if let Some(code) = &view.trustline_needed {
        actions.push((format!("Add {code} trustline"), Action::AddTrustline, true));
    }
    actions.push((
        "Save a backup\u{2026}".into(),
        Action::SaveBackup,
        view.backup.as_ref().is_none_or(|(_, at_risk)| *at_risk),
    ));
    // Paper sits beside the file, because it is the same decision with
    // a different medium — and the one a holder reaches for when they
    // want a backup that survives the machine rather than the disk.
    actions.push(("Paper backup\u{2026}".into(), Action::PaperBackup, false));
    actions.push(("Restore\u{2026}".into(), Action::RestoreBackup, false));
    // Restoring from paper is its own door, beside the file's. Sheets are
    // a restoration artifact: a holder arrives holding them, with nothing
    // to export and no reason to walk through an export to reach the
    // scanner.
    actions.push(("Restore from paper\u{2026}".into(), Action::ScanPaper, false));
    actions.push(("RPC server\u{2026}".into(), Action::EditRpc, false));

    let spec: Vec<(&str, Action, bool)> = actions
        .iter()
        .map(|(l, a, p)| (l.as_str(), *a, *p))
        .collect();
    let buttons = buttons_row(tree, skins, &spec);
    vec![head, buttons, panel]
}

/// The RPC server field, in place of the settings rows while it is open.
fn rpc_edit_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    head: NodeId,
    edit: &RpcEdit,
) -> Vec<NodeId> {
    let shown = if edit.busy {
        edit.typed.clone()
    } else {
        format!("{}|", edit.typed)
    };
    let mut rows = vec![
        leaf(
            tree,
            skins,
            Style {
                size: Size { width: percent(1.0), height: length(56.0) },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("entry-row")
                .text("label", "rpc server")
                .text("value", &shown)
                .text("hint", if edit.busy { "checking\u{2026}" } else { "Enter to use it" }),
        ),
        field_row(
            tree,
            skins,
            "what is checked",
            &format!(
                "the server is asked which network it serves, and refused unless it is {} - \
                 this build's network cannot be changed here",
                edit.network
            ),
        ),
        field_row(
            tree,
            skins,
            "why it matters",
            "every balance, note check and transaction goes through this one server, \
             so use one you trust - Ctrl+V to paste",
        ),
    ];
    if let Some(e) = &edit.error {
        rows.push(warn_row(tree, skins, "", e));
    }
    let panel = panel_of(tree, skins, &rows);
    let buttons = buttons_row(
        tree,
        skins,
        &[
            ("Use this server", Action::Confirm, true),
            ("Use the default", Action::RpcDefault, false),
            ("Back", Action::Cancel, false),
        ],
    );
    vec![head, buttons, panel]
}

/// Backing up to paper, and reading it back.
fn paper_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &PaperView,
) -> Vec<NodeId> {
    let head = |tree: &mut TaffyTree<()>, skins: &mut HashMap<NodeId, Skin>, t: &str, sub: &str| {
        leaf(
            tree,
            skins,
            Style {
                size: Size { width: percent(1.0), height: length(96.0) },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("header")
                .text("eyebrow", "Paper backup")
                .text("title", t)
                .text("subtitle", sub),
        )
    };

    match &view.state {
        PaperState::Offer { notes, symbols, pages, locked } if *locked => {
            let h = head(tree, skins, "Unlock first", "paper is sealed with the wallet's own key");
            let _ = (notes, symbols, pages);
            let rows = vec![field_row(
                tree,
                skins,
                "locked",
                "unlock the billfold and come back - a paper backup is sealed the same \
                 way the file is, and that needs your key",
            )];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(tree, skins, &[("Back", Action::Back, false)]);
            vec![h, buttons, panel]
        }

        // Nothing to print is not a failure: a wallet with no notes is
        // precisely the wallet a holder restoring from paper is sitting
        // in front of, and the scanner has to be reachable from here.
        PaperState::Offer { pages, .. } if *pages == 0 => {
            let h = head(tree, skins, "Nothing to print yet", "this wallet holds no notes");
            let rows = vec![field_row(
                tree,
                skins,
                "to restore",
                "if you are holding sheets, scan them - paper restores into this \
                 wallet the same way a backup file does",
            )];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Scan sheets\u{2026}", Action::ScanPaper, true),
                    ("Back", Action::Back, false),
                ],
            );
            vec![h, buttons, panel]
        }

        PaperState::Offer { notes, symbols, pages, .. } => {
            let h = head(
                tree,
                skins,
                &format!("{pages} page{}", if *pages == 1 { "" } else { "s" }),
                "what printing this will produce",
            );
            let rows = vec![
                field_row(
                    tree,
                    skins,
                    "holds",
                    &format!(
                        "{notes} note{} and the wallet's own record - the owner-index \
                         counter and your standing pay tag",
                        if *notes == 1 { "" } else { "s" }
                    ),
                ),
                field_row(
                    tree,
                    skins,
                    "symbols",
                    &format!(
                        "{symbols} across {pages} page{}",
                        if *pages == 1 { "" } else { "s" }
                    ),
                ),
                // Said before they print, not only on the page: a holder
                // who thinks paper replaces their phrase will file the
                // sheet and throw the phrase away.
                warn_row(
                    tree,
                    skins,
                    "you will still need",
                    "your recovery phrase. These sheets are useless without it, and it \
                     is useless without them - keep them apart",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Save PDF\u{2026}", Action::PrintPaper, true),
                    ("Save SVG\u{2026} (to engrave)", Action::PrintPaperSvg, false),
                    ("Scan sheets\u{2026}", Action::ScanPaper, false),
                    ("Back", Action::Back, false),
                ],
            );
            vec![h, buttons, panel]
        }

        PaperState::Working { what } => {
            let h = head(tree, skins, "Working", what);
            working_body(tree, skins, h, "", what)
        }

        PaperState::Printed { path, pages } => {
            let h = head(
                tree,
                skins,
                "Printed",
                &format!("{pages} page{}", if *pages == 1 { "" } else { "s" }),
            );
            let rows = vec![
                field_row(tree, skins, "saved to", path),
                warn_row(
                    tree,
                    skins,
                    "print at 100%",
                    "any 'fit to page' shrinks the symbols below what a scanner reads, \
                     and you would not find out until you needed them",
                ),
                field_row(
                    tree,
                    skins,
                    "then scan it back",
                    "now, while you can still print another. An untested backup is a \
                     guess",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Scan it back", Action::ScanPaper, true),
                    ("Done", Action::Back, false),
                ],
            );
            vec![h, buttons, panel]
        }

        PaperState::Scanning {
            wallet,
            items,
            foreign,
            unreadable,
            problems,
            complete,
            camera,
            for_setup,
        } => {
            let title = if items.is_empty() {
                "Scan your sheets".to_string()
            } else if *complete {
                "Everything is here".to_string()
            } else {
                // Notes, named as notes. Counting *items* ("2 of 3
                // readable") would be true and unreadable: a holder is
                // looking at five QR symbols, the wallet record is one of
                // the three, and nothing on screen would say which unit
                // was being counted.
                //
                // The wallet record is left out of the count and keeps its
                // own row, because it is not a note and losing it does not
                // cost money.
                // "1 of 3 notes readable", not "note 1 of 3": the rows
                // below are labelled `note 1`, so the latter reads as the
                // name of one note rather than a count.
                let notes = items.iter().filter(|i| i.note).count();
                let have = items.iter().filter(|i| i.note && i.done).count();
                if notes == 0 {
                    // A backup always carries at least one note, so this
                    // is unreachable in practice -- but a heading that
                    // says "0 of 0" because an assumption slipped is
                    // worse than one that falls back to counting rows.
                    format!("{} of {} readable", items.iter().filter(|i| i.done).count(), items.len())
                } else {
                    format!(
                        "{have} of {notes} note{} readable",
                        if notes == 1 { "" } else { "s" }
                    )
                }
            };
            let h = head(
                tree,
                skins,
                &title,
                match wallet {
                    Some(w) => w.as_str(),
                    None => "photographs or scans of the pages, in any order",
                },
            );

            let mut rows = Vec::new();

            // The viewfinder is a real element in the layout, so the rest
            // of the page flows around it rather than being covered by it.
            // `paint_live` finds it again by its skin.
            let lens = match camera {
                CameraView::Off => None,
                _ => Some(leaf(
                    tree,
                    skins,
                    Style {
                        size: Size {
                            width: percent(1.0),
                            height: length(240.0),
                        },
                        flex_shrink: 0.0,
                        ..Default::default()
                    },
                    Skin::new("panel").viewfinder(),
                )),
            };

            match camera {
                CameraView::Off => {}
                CameraView::Starting => {
                    rows.push(field_row(tree, skins, "camera", "starting - this takes a moment"))
                }
                CameraView::Live { name, px_per_module } => {
                    rows.push(field_row(tree, skins, "camera", name));
                    // Stated plainly, because it is the number that decides
                    // whether anything can resolve, and a holder who is
                    // failing deserves to know it is distance, not luck.
                    rows.push(field_row(
                        tree,
                        skins,
                        "hold one symbol",
                        &format!(
                            "so that it fills the frame - {px_per_module:.1} pixels per module \
                             at this resolution, and a symbol needs 4"
                        ),
                    ));
                }
                CameraView::Refused(why) => rows.push(warn_row(tree, skins, "camera", why)),
            }

            if items.is_empty() && matches!(camera, CameraView::Off) {
                rows.push(field_row(
                    tree,
                    skins,
                    "what works",
                    "360dpi or better, or a phone photo with the whole page in frame, \
                     flat and in focus. Several files at once is fine",
                ));
            }
            for item in items {
                if item.done {
                    rows.push(field_row(tree, skins, &item.what, &item.state));
                } else {
                    rows.push(warn_row(tree, skins, &item.what, &item.state));
                }
            }
            if *unreadable > 0 {
                rows.push(warn_row(
                    tree,
                    skins,
                    "too blurry",
                    &format!(
                        "{unreadable} symbol{} found and could not be read - a sharper \
                         scan of that page would help",
                        if *unreadable == 1 { "" } else { "s" }
                    ),
                ));
            }
            if *foreign > 0 {
                rows.push(field_row(
                    tree,
                    skins,
                    "not ours",
                    &format!(
                        "{foreign} other QR code{} in the images, ignored",
                        if *foreign == 1 { "" } else { "s" }
                    ),
                ));
            }
            for p in problems {
                rows.push(alarm_row(tree, skins, "", p));
            }
            let panel = panel_of(tree, skins, &rows);

            // "Restore what I have" is never greyed. Three notes of four
            // is three notes, and a holder who has genuinely lost a sheet
            // must not be trapped on this screen.
            // The camera leads and the files are the fallback, so the
            // camera button is the primary one unless it is already going.
            let (cam_label, cam_action) = match camera {
                CameraView::Live { .. } | CameraView::Starting => {
                    ("Stop the camera", Action::StopCamera)
                }
                _ => ("Use the camera", Action::UseCamera),
            };
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    (cam_label, cam_action, !*complete),
                    ("Add images\u{2026}", Action::AddImages, false),
                    (
                        // During first run nothing can be opened yet: the
                        // key comes from the phrase, which has not been
                        // asked for. The sheets are carried back to the
                        // restore screen and go in once the wallet exists.
                        match (*for_setup, *complete) {
                            (false, true) => "Restore",
                            (false, false) => "Restore what I have",
                            (true, true) => "Use these sheets",
                            (true, false) => "Use what I have",
                        },
                        Action::RestoreScanned,
                        *complete,
                    ),
                    ("Back", Action::Back, false),
                ],
            );
            match lens {
                Some(l) => vec![h, buttons, l, panel],
                None => vec![h, buttons, panel],
            }
        }

        PaperState::Restored { added, kept, missed, absent, partial, rejected } => {
            // Nothing new is the expected outcome of scanning your own
            // sheets back to check them. Reported as "0 notes restored"
            // it reads as failure at the moment the holder has in fact
            // just proved their backup works.
            let verified = *added == 0 && *kept > 0;
            let h = if verified {
                head(
                    tree,
                    skins,
                    &format!("{kept} note{} verified", if *kept == 1 { "" } else { "s" }),
                    "the sheets read correctly - nothing needed restoring",
                )
            } else {
                head(
                    tree,
                    skins,
                    &format!("{added} note{} restored", if *added == 1 { "" } else { "s" }),
                    "from paper",
                )
            };
            let mut rows = Vec::new();
            // "Everything" only when nothing at all was left behind. A note
            // half-scanned, or read and refused, is not restored, and this
            // must not say it was.
            if missed.is_empty() && absent.is_empty() && partial.is_empty() && rejected.is_empty() {
                rows.push(field_row(
                    tree,
                    skins,
                    "everything",
                    if verified {
                        "every symbol read, and every note on them opened with this \
                         wallet's key"
                    } else {
                        "every item on the sheets came back"
                    },
                ));
            }
            for what in absent {
                rows.push(warn_row(
                    tree,
                    skins,
                    what,
                    "not scanned at all - if you can find its sheet, scan it and run \
                     this again. Doing so is safe and adds only what is missing",
                ));
            }
            for (what, missing) in partial {
                rows.push(warn_row(
                    tree,
                    skins,
                    what,
                    &format!(
                        "partly scanned, {missing} symbol{} still missing - scan its page \
                         again and run this again. Doing so is safe and adds only what is \
                         missing",
                        if *missing == 1 { "" } else { "s" }
                    ),
                ));
            }
            for what in missed {
                rows.push(warn_row(
                    tree,
                    skins,
                    what,
                    "scanned but could not be read - a sharper scan of that page may \
                     recover it",
                ));
            }
            for (what, why) in rejected {
                rows.push(warn_row(
                    tree,
                    skins,
                    what,
                    &format!("read, but it did not check out and was not stored: {why}"),
                ));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Scan more", Action::ScanPaper, !absent.is_empty() || !partial.is_empty()),
                    ("Done", Action::Back, absent.is_empty() && partial.is_empty()),
                ],
            );
            vec![h, buttons, panel]
        }

        PaperState::Failed { message } => {
            let h = head(tree, skins, "That did not work", "nothing was changed");
            let rows = vec![alarm_row(tree, skins, "", message)];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(tree, skins, &[("Back", Action::Back, true)]);
            vec![h, buttons, panel]
        }
    }
}

/// An authorization prompt. Shared by unlocking and by signing, because the
/// holder is answering the same question in both cases.
fn prompt_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &PromptView,
) -> Vec<NodeId> {
    fn header(
        tree: &mut TaffyTree<()>,
        skins: &mut HashMap<NodeId, Skin>,
        title: &str,
        sub: &str,
    ) -> NodeId {
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(96.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("header")
                .text("eyebrow", "Authorize")
                .text("title", title)
                .text("subtitle", sub),
        )
    }
    let head = header(tree, skins, &view.title, &view.why);
    let mut rows: Vec<NodeId> = view
        .rows
        .iter()
        .map(|(k, v)| field_row(tree, skins, k, v))
        .collect();
    // The field. Dots built from a count: the view model never holds
    // the passphrase itself.
    // A caret, because the border alone does not say *where* the next
    // character goes, and an empty field with no caret reads as a label
    // rather than as something waiting for input.
    let dots: String = format!("{}|", "\u{2022}".repeat(view.entered.min(64)));
    rows.push(leaf(
        tree,
        skins,
        Style {
            size: Size {
                width: percent(1.0),
                height: length(56.0),
            },
            // The passphrase field.
            flex_shrink: 0.0,
            ..Default::default()
        },
        Skin::new("entry-row-large")
            .text("label", "passphrase")
            .text("value", &dots)
            .text("hint", "Enter to confirm \u{b7} Esc to cancel"),
    ));
    if let Some(e) = &view.error {
        rows.push(field_row(tree, skins, "", e));
    }
    let panel = panel_of(tree, skins, &rows);
    let buttons = buttons_row(
        tree,
        skins,
        &[
            ("Confirm", Action::Confirm, true),
            ("Cancel", Action::Cancel, false),
        ],
    );
    vec![head, buttons, panel]
}

/// The receive page — one layout per state of the flow.
fn receive_page(
    tree: &mut TaffyTree<()>,
    skins: &mut HashMap<NodeId, Skin>,
    view: &ReceiveView,
) -> Vec<NodeId> {
    fn header(
        tree: &mut TaffyTree<()>,
        skins: &mut HashMap<NodeId, Skin>,
        title: &str,
        sub: &str,
    ) -> NodeId {
        leaf(
            tree,
            skins,
            Style {
                size: Size {
                    width: percent(1.0),
                    height: length(96.0),
                },
                flex_shrink: 0.0,
                ..Default::default()
            },
            Skin::new("header")
                .text("eyebrow", "Receive")
                .text("title", title)
                .text("subtitle", sub),
        )
    }

    match &view.state {
        ReceiveState::Idle { hint } => {
            let head = header(
                tree,
                skins,
                "Get paid",
                "a fresh key per payment, so your receipts are not linked to each other",
            );
            let rows = vec![
                field_row(tree, skins, "step 1", "create a pay tag"),
                field_row(tree, skins, "step 2", "show it to the payer"),
                field_row(
                    tree,
                    skins,
                    "step 3",
                    "open the token file they send - you are not paid until that succeeds",
                ),
                field_row(tree, skins, "", hint),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("New pay tag", Action::NewReceive, true),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }

        ReceiveState::Working { what } => {
            let head = header(tree, skins, "Working", what);
            working_body(tree, skins, head, "", what)
        }

        ReceiveState::Ready {
            uri,
            hex,
            index,
            status,
            inbox,
            ledger,
            note,
        } => {
            let head = header(tree, skins, "Show this to the payer", status);

            // Dark modules on a white quiet zone, not theme colours: a QR drawn
            // to match a dark panel is the classic unscannable one.
            let code = match qr::svg(uri, "#0b0e16", "#ffffff") {
                Ok(svg) => leaf(
                    tree,
                    skins,
                    Style {
                        size: Size {
                            width: length(216.0),
                            height: length(216.0),
                        },
                        ..Default::default()
                    },
                    Skin::inline_svg(svg),
                ),
                // Never silently show nothing. The hex beside it is still
                // usable, so name the half that is missing.
                Err(e) => leaf(
                    tree,
                    skins,
                    Style {
                        size: Size {
                            width: length(216.0),
                            height: length(216.0),
                        },
                        ..Default::default()
                    },
                    Skin::new("qr-unavailable").text("message", &format!("QR unavailable: {e}")),
                ),
            };

            // 64 hex characters do not fit one line at a readable size, and
            // wrapping mid-address invites a transcription error, so it is cut
            // in half deliberately and the second half labelled as a
            // continuation rather than as a field of its own.
            let (a, b) = hex.split_at(32);
            let mut rows = vec![
                field_row_in(tree, skins, "pay tag", a, DETAIL_CHARS),
                field_row_in(tree, skins, "\u{2026}continued", b, DETAIL_CHARS),
                // Not a footnote. Anyone arriving from a wallet whose "tag"
                // is a permanent handle will assume this one is too, and
                // handing one tag to two payers puts both notes on one
                // commitment where the ledger links them.
                field_row_in(
                    tree,
                    skins,
                    "good for",
                    "one payment - a second payer needs a different tag",
                    DETAIL_CHARS,
                ),
                field_row_in(tree, skins, "owner index", &index.to_string(), DETAIL_CHARS),
                field_row_in(tree, skins, "or drop their file here", inbox, DETAIL_CHARS),
                // Named because the checks that decide whether this payment
                // arrived are one endpoint's word about the ledger, and
                // nothing in the protocol proves that word. A holder who
                // can see what answered can judge whether to believe it;
                // one who cannot is trusting something they were never
                // shown.
                field_row_in(tree, skins, "checked against", ledger, DETAIL_CHARS),
            ];
            if let Some(n) = note {
                rows.push(field_row_in(tree, skins, "", n, DETAIL_CHARS));
            }
            let detail = panel_of(tree, skins, &rows);
            let side = tree
                .new_with_children(
                    Style {
                        flex_direction: FlexDirection::Row,
                        size: Size {
                            width: percent(1.0),
                            height: auto(),
                        },
                        flex_basis: length(0.0),
                        min_size: Size {
                            width: auto(),
                            height: length(0.0),
                        },
                        flex_grow: 1.0,
                        gap: Size {
                            width: length(16.0),
                            height: length(0.0),
                        },
                        ..Default::default()
                    },
                    &[code, detail],
                )
                .unwrap();
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Copy", Action::Copy, true),
                    ("Import a note\u{2026}", Action::ImportNote, false),
                    ("Different tag", Action::NewReceive, false),
                    ("Standing tag\u{2026}", Action::ShowStanding, false),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, side]
        }

        ReceiveState::Standing { hex, busy } => {
            let on = hex.is_some();
            let head = header(
                tree,
                skins,
                "Standing pay tag",
                if on {
                    "published - anyone can pay it without asking you first"
                } else {
                    "off - every payment needs a tag you hand over yourself"
                },
            );
            let mut rows = vec![field_row(
                tree,
                skins,
                "what it is",
                "one code you publish once and reuse, so somebody can pay you \
                 while you are away",
            )];
            // The cost, stated in the same breath as the benefit and before
            // the button, because index 0 trades unlinkability for reach
            // (every payment to it shares one owner commitment), and that
            // trade is the whole choice.
            rows.push(field_row(
                tree,
                skins,
                "what it costs",
                "every note paid to it carries the same owner commitment, so \
                 the ledger shows those payments all went to one person",
            ));
            rows.push(field_row(
                tree,
                skins,
                "what it does not do",
                "their note still has to reach your inbox - publishing a code \
                 does not collect anything by itself",
            ));
            if let Some(h) = hex {
                let (a, b) = h.split_at(32);
                rows.push(field_row_in(tree, skins, "standing tag", a, DETAIL_CHARS));
                rows.push(field_row_in(
                    tree,
                    skins,
                    "\u{2026}continued",
                    b,
                    DETAIL_CHARS,
                ));
            }
            if let Some(b) = busy {
                rows.push(field_row(tree, skins, "", b));
            }
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    if on {
                        ("Retire it", Action::ToggleStanding, false)
                    } else {
                        ("Publish it", Action::ToggleStanding, true)
                    },
                    ("Back", Action::Receive, false),
                ],
            );
            vec![head, buttons, panel]
        }

        ReceiveState::Held { id, amount } => {
            let head = header(
                tree,
                skins,
                &format!("Held - {amount}"),
                "a bearer note: in your billfold, but not yet settled",
            );
            let rows = vec![
                field_row(tree, skins, "token", id),
                // The distinction bearer mode rests on. Saying
                // "paid" here would be the client asserting something it
                // cannot check, and redemption is first-come.
                field_row(
                    tree,
                    skins,
                    "not settled",
                    "a bearer note proves nothing about who else has a copy - \
                     redeem it or re-deposit it to settle it",
                ),
                field_row(
                    tree,
                    skins,
                    "back this up",
                    "your recovery phrase does not restore a bearer note - \
                     back up the wallet's token files",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Billfold", Action::Back, true),
                    ("New pay tag", Action::NewReceive, false),
                ],
            );
            vec![head, buttons, panel]
        }

        ReceiveState::Received { id, amount, index } => {
            let head = header(
                tree,
                skins,
                &format!("Paid - {amount}"),
                "the ledger says this token is active and owned by you",
            );
            let rows = vec![
                field_row(tree, skins, "token", id),
                field_row(tree, skins, "owner index", &index.to_string()),
                // The one thing a new holder gets wrong. The phrase restores
                // the authority to spend, not the thing being spent: a bearer
                // token cannot be found from the ledger, so losing the bytes
                // loses the money even with a perfect backup of the seed.
                field_row(
                    tree,
                    skins,
                    "back this up",
                    "your recovery phrase restores the owner key, not the token - \
                     back up the wallet's token files too",
                ),
            ];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Receive again", Action::NewReceive, false),
                    ("Back", Action::Back, true),
                ],
            );
            vec![head, buttons, panel]
        }

        ReceiveState::Failed { message } => {
            let head = header(
                tree,
                skins,
                "Could not create an address",
                "nothing was promised to anyone",
            );
            let rows = vec![field_row(tree, skins, "reason", message)];
            let panel = panel_of(tree, skins, &rows);
            let buttons = buttons_row(
                tree,
                skins,
                &[
                    ("Try again", Action::NewReceive, true),
                    ("Back", Action::Back, false),
                ],
            );
            vec![head, buttons, panel]
        }
    }
}

/// The state variant to draw for a node given its role and the live interaction.
fn effective_state(node: NodeId, skin: &Skin, it: &Interaction) -> &'static str {
    match skin.kind {
        Some(Kind::Nav(i)) => {
            if i == it.selected_nav {
                "active"
            } else if it.hovered == Some(node) {
                "hover"
            } else {
                "default"
            }
        }
        Some(Kind::Button(_)) => {
            if it.pressed == Some(node) || it.hovered == Some(node) {
                "hover"
            } else {
                // Not "default": a button can be given a resting state, and
                // a selected tab is exactly that. Hardcoding default made
                // `active` unreachable for anything interactive.
                skin.base_state
            }
        }
        // An animated element is non-interactive by construction: there is no
        // hover or press state to lose, so the frame is the whole answer.
        None if skin.animated => FRAMES[it.frame as usize % FRAMES.len()],
        None => skin.base_state,
    }
}

/// Absolute logical position of `target`, walking down from `from`.
fn absolute(tree: &TaffyTree<()>, from: NodeId, target: NodeId) -> Option<(f32, f32)> {
    fn walk(
        tree: &TaffyTree<()>,
        node: NodeId,
        ox: f32,
        oy: f32,
        target: NodeId,
    ) -> Option<(f32, f32)> {
        let l = tree.layout(node).unwrap();
        let (x, y) = (ox + l.location.x, oy + l.location.y);
        if node == target {
            return Some((x, y));
        }
        tree.children(node)
            .unwrap()
            .into_iter()
            .find_map(|c| walk(tree, c, x, y, target))
    }
    walk(tree, from, 0.0, 0.0, target)
}

fn collect_hits(
    tree: &TaffyTree<()>,
    node: NodeId,
    ox: f32,
    oy: f32,
    skins: &HashMap<NodeId, Skin>,
    out: &mut Vec<HitRect>,
    live: &mut Option<(f32, f32, f32, f32)>,
) {
    let l = tree.layout(node).unwrap();
    let x = ox + l.location.x;
    let y = oy + l.location.y;
    if let Some(skin) = skins.get(&node) {
        if skin.kind.is_some() {
            out.push(HitRect {
                node,
                x,
                y,
                w: l.size.width,
                h: l.size.height,
            });
        }
        if skin.viewfinder {
            *live = Some((x, y, l.size.width, l.size.height));
        }
    }
    for c in tree.children(node).unwrap() {
        collect_hits(tree, c, x, y, skins, out, live);
    }
}

fn render_skin(skin: &Skin, state: &str, w: u32, h: u32) -> Result<PeltImage, pelt::PeltError> {
    let mut p = match &skin.inline {
        Some(svg) => Pelt::from_str(svg)?,
        None => Pelt::load(skin_path(skin.name))?,
    };
    // State only. Nothing about the look is set from code: the skin file
    // is the design (`skins/kenter/`), and what Inkscape shows is what is
    // drawn here.
    p.set_state(state);
    p.render(w, h)
}

/// Build the label SVG in the element's *logical* box (`lw`×`lh`) and rasterize
/// it at the *physical* size (`pw`×`ph`); usvg scales the viewBox, keeping text
/// crisp and correctly placed at any DPI.
fn render_labels(
    labels: &[Label],
    lw: f32,
    lh: f32,
    pw: u32,
    ph: u32,
) -> Result<PeltImage, pelt::PeltError> {
    let mut texts = String::new();
    for l in labels {
        let (x, anchor) = match l.anchor {
            Anchor::Start => (l.inset, "start"),
            Anchor::Middle => (lw / 2.0, "middle"),
            Anchor::End => (lw - l.inset, "end"),
        };
        let y = lh * l.vfrac + l.size * 0.34;
        texts.push_str(&format!(
            "<text x=\"{x:.1}\" y=\"{y:.1}\" font-family=\"Segoe UI, Arial, sans-serif\" \
             font-size=\"{size}\" font-weight=\"{weight}\" fill=\"{color}\" \
             text-anchor=\"{anchor}\">{txt}</text>",
            size = l.size,
            weight = l.weight,
            color = l.color,
            txt = xml_escape(&l.text),
        ));
    }
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {lw} {lh}\">{texts}</svg>"
    );
    let out = Pelt::from_str(&svg)?.render(pw, ph);
    // The SVG holds the words verbatim; wipe it rather than leaving it to the
    // allocator. Cheap, and unconditional so it cannot be forgotten for the
    // one caller that needs it.
    {
        use zeroize::Zeroize;
        svg.zeroize();
        texts.zeroize();
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Alpha-composite a premultiplied-RGBA source over the premultiplied canvas at
/// (dx, dy):  out = src + dst * (1 - src_a).
fn composite(canvas: &mut [u8], cw: u32, ch: u32, src: &PeltImage, dx: i32, dy: i32, clip: Clip) {
    for sy in 0..src.height as i32 {
        let cy = dy + sy;
        if cy < 0 || cy >= ch as i32 {
            continue;
        }
        for sx in 0..src.width as i32 {
            let cx = dx + sx;
            if cx < 0 || cx >= cw as i32 || !clip.holds(cx, cy) {
                continue;
            }
            let si = ((sy * src.width as i32 + sx) * 4) as usize;
            let ci = ((cy * cw as i32 + cx) * 4) as usize;
            let sa = src.rgba[si + 3] as u32;
            if sa == 0 {
                continue; // transparent source (most of a label/border layer) — skip
            }
            if sa == 255 {
                canvas[ci..ci + 4].copy_from_slice(&src.rgba[si..si + 4]); // opaque — copy
                continue;
            }
            let inv = 255 - sa;
            for k in 0..4 {
                let s = src.rgba[si + k] as u32;
                let d = canvas[ci + k] as u32;
                canvas[ci + k] = (s + (d * inv + 127) / 255).min(255) as u8;
            }
        }
    }
}

/// Save a premultiplied-RGBA canvas to a PNG (reuses pelt's tiny_skia encoder).
pub fn save_png(canvas: &[u8], w: u32, h: u32, path: &str) -> Result<(), pelt::PeltError> {
    PeltImage {
        width: w,
        height: h,
        rgba: canvas.to_vec(),
    }
    .save_png(path)
}

/// Convert the premultiplied-RGBA canvas to softbuffer's `0x00RRGGBB` u32 pixels.
pub fn canvas_to_argb(canvas: &[u8], out: &mut [u32]) {
    for (px, o) in canvas.chunks_exact(4).zip(out.iter_mut()) {
        *o = ((px[0] as u32) << 16) | ((px[1] as u32) << 8) | (px[2] as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_keeps_every_character() {
        let text = "no seed in C:/Users/someone/.kenter/vault.json - run: kenter seed \
                    generate --vault C:/Users/someone/.kenter/vault.json";
        let lines = wrap(text, ROW_CHARS);
        assert!(lines.len() > 1, "expected a wrap, got {lines:?}");
        assert_eq!(
            lines.join(" "),
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        for l in &lines {
            assert!(
                l.chars().count() <= ROW_CHARS,
                "{l:?} is {} chars",
                l.chars().count()
            );
        }
    }

    /// Paths and hex contain no spaces, so word-wrapping alone would leave an
    /// over-long line to be clipped - exactly the strings worth reading whole.
    #[test]
    fn an_unbreakable_run_is_split_rather_than_left_long() {
        let hex = "a".repeat(ROW_CHARS * 2 + 7);
        let lines = wrap(&hex, ROW_CHARS);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines.concat(), hex);
        assert!(lines.iter().all(|l| l.chars().count() <= ROW_CHARS));
    }

    /// The failure this whole mechanism exists for: without it, a list longer
    /// than the window is absorbed by Flexbox shrinking whatever else it can,
    /// so the titlebar is squeezed off the top of the screen and the rows
    /// still run past the bottom. The chrome must keep its size no matter how
    /// much is in the list, and the overflow must become scroll.
    #[test]
    fn a_long_list_does_not_eat_the_chrome() {
        let long = SettingsView {
            rows: (0..40)
                .map(|i| (format!("row {i}"), format!("value {i}")))
                .collect(),
            note: None,
            trustline_needed: None,
            backup: None,
            rpc_edit: None,
        };
        let ui = Ui::build_screen(&Screen::Settings(long));

        let titlebar = ui.tree.children(ui.root).unwrap()[0];
        assert_eq!(ui.tree.layout(titlebar).unwrap().size.height, 40.0);

        assert!(ui.scrollable(), "40 rows should not fit in one window");
        let s = ui.scroll.expect("a settings page has a scroll region");
        assert!(
            s.y + s.h <= H as f32,
            "the viewport runs past the bottom of the window: {} + {}",
            s.y,
            s.h
        );
        assert!(s.content > s.h, "content {} vs viewport {}", s.content, s.h);
    }

    // ---- the restore screens -------------------------------------------
    //
    // These are the only screens a holder sees when everything else has
    // already gone wrong, so "it renders and the buttons are the ones it
    // means" is worth pinning. The whole flow is rarely driven by hand;
    // this is the part a test can reach.

    fn source(card_rooted: bool) -> RestoreSource {
        RestoreSource {
            path: r"E:\kenter-backup-abcdef0123456789.kbk".into(),
            summary: if card_rooted {
                "a card wallet - 5 notes, saved 3 days ago".into()
            } else {
                "a software wallet - 5 notes, saved 3 days ago".into()
            },
            needs: if card_rooted {
                "the card's recovery phrase - the card itself is not needed".into()
            } else {
                "the wallet's recovery phrase".into()
            },
            fingerprint: "abcdef0123456789".into(),
            card_rooted,
        }
    }

    fn actions_on(ui: &Ui) -> Vec<Action> {
        ui.skins
            .values()
            .filter_map(|s| match s.kind {
                Some(Kind::Button(a)) => Some(a),
                _ => None,
            })
            .collect()
    }

    /// Every piece of text the page puts on screen, joined. Lets a test ask
    /// what a holder would actually read rather than what was passed in.
    fn text_on(ui: &Ui) -> String {
        let mut out = String::new();
        for skin in ui.skins.values() {
            for label in &skin.labels {
                out.push_str(&label.text);
                out.push('\n');
            }
        }
        out
    }

    /// Before a file is chosen the page has to say what the holder is
    /// missing, and offer the way to fix it.
    #[test]
    fn restore_without_a_file_asks_for_one() {
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::Restore {
                entered: 0,
                error: None,
                file: None,
                paper: None,
            },
        }));
        let acts = actions_on(&ui);
        assert!(acts.contains(&Action::ChooseBackupFile));
        // Continue stays reachable: a holder who has lost the file can
        // still get their keys and their account back, just not the notes.
        assert!(acts.contains(&Action::Confirm));
        assert!(acts.contains(&Action::Cancel));

        // And it says what going on without one costs, rather than leaving
        // a blank row they might read as "nothing needed here".
        let text = text_on(&ui);
        assert!(text.contains("none chosen"), "{text}");
        assert!(text.contains("your notes do not"), "{text}");
    }

    #[test]
    fn restore_with_a_file_renders_what_it_found() {
        for card_rooted in [true, false] {
            let ui = Ui::build_screen(&Screen::Setup(SetupView {
                state: SetupState::Restore {
                    entered: 12,
                    error: None,
                    file: Some(source(card_rooted)),
                    paper: None,
                },
            }));
            let acts = actions_on(&ui);
            assert!(acts.contains(&Action::Confirm));
            // Still offered, because the holder may have picked the wrong
            // one of two files and needs a way back.
            assert!(acts.contains(&Action::ChooseBackupFile));

            let text = text_on(&ui);
            assert!(text.contains("5 notes, saved 3 days ago"), "{text}");
            // The line that decides what the holder has to go and find.
            if card_rooted {
                assert!(text.contains("the card itself is not needed"), "{text}");
            } else {
                assert!(text.contains("a software wallet"), "{text}");
            }
        }
    }

    /// The error a holder is most likely to hit — right file, wrong words —
    /// must not take the file away with it.
    #[test]
    fn a_wrong_phrase_keeps_the_chosen_file_on_screen() {
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::Restore {
                entered: 60,
                error: Some("those words do not open that backup".into()),
                file: Some(source(true)),
                paper: None,
            },
        }));
        let text = text_on(&ui);
        assert!(text.contains("those words do not open that backup"), "{text}");
        // The file survives the error. Losing it would make the holder pick
        // it again to fix a mistake that was not about the file.
        assert!(text.contains("a card wallet - 5 notes"), "{text}");
        assert!(actions_on(&ui).contains(&Action::Confirm));
    }

    /// **The disaster case paper exists for:** a new machine, the phrase,
    /// and a folder of sheets, no `.kbk`. The way in has to be on first
    /// run, because the scan in settings needs a wallet that does not
    /// exist yet.
    #[test]
    fn first_run_restore_offers_paper() {
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::Restore {
                entered: 0,
                error: None,
                file: None,
                paper: None,
            },
        }));
        assert!(actions_on(&ui).contains(&Action::ScanPaper), "no way to paper on first run");
        assert!(text_on(&ui).contains("Scan paper backup"), "{}", text_on(&ui));
    }

    /// Sheets in hand are a backup. The page must say so rather than
    /// still warning that without a file the notes will not come back.
    #[test]
    fn restore_with_paper_says_so_and_drops_the_missing_file_warning() {
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::Restore {
                entered: 0,
                error: None,
                file: None,
                paper: Some("wallet 5e1f0c2a9d4b7368 - 3 notes readable".into()),
            },
        }));
        let text = text_on(&ui);
        assert!(text.contains("3 notes readable"), "{text}");
        assert!(text.contains("using paper"), "{text}");
        assert!(!text.contains("your notes do not"), "{text}");
        let acts = actions_on(&ui);
        assert!(acts.contains(&Action::Confirm));
        // A holder who finds another sheet goes back for it.
        assert!(acts.contains(&Action::ScanPaper));
        assert!(text.contains("Scan more sheets"), "{text}");
    }

    /// Scanning before a wallet exists cannot restore anything - there is
    /// no key yet - so the button must not promise a restore. It still
    /// exists when the scan is incomplete, for the same reason it does
    /// in settings: a lost sheet must not trap the holder.
    #[test]
    fn a_first_run_scan_carries_the_sheets_back_rather_than_restoring() {
        for complete in [true, false] {
            let ui = Ui::build_screen(&Screen::Paper(PaperView {
                state: PaperState::Scanning {
                    wallet: Some("wallet 5e1f0c2a9d4b7368".into()),
                    items: vec![item("note 1", "complete", true)],
                    foreign: 0,
                    unreadable: 0,
                    problems: Vec::new(),
                    complete,
                    camera: CameraView::Off,
                    for_setup: true,
                },
            }));
            let text = text_on(&ui);
            assert!(!text.contains("Restore"), "complete={complete}: {text}");
            assert!(text.contains("Use "), "complete={complete}: {text}");
            assert!(actions_on(&ui).contains(&Action::RestoreScanned));
        }
    }

    /// The custody screen asks one question in two situations, and the
    /// restoring one must still offer both answers.
    #[test]
    fn custody_while_restoring_offers_both_ways_back() {
        for restoring in [true, false] {
            let ui = Ui::build_screen(&Screen::Setup(SetupView {
                state: SetupState::Custody {
                    restoring,
                    card: Some("a card is ready".into()),
                    card_ok: true,
                    error: None,
                },
            }));
            let acts = actions_on(&ui);
            assert!(acts.contains(&Action::UseSoftware), "restoring={restoring}");
            assert!(acts.contains(&Action::UseCard), "restoring={restoring}");
            assert!(acts.contains(&Action::CheckCard), "restoring={restoring}");
        }
    }

    /// Offered even with no reader: pressing it is how a holder finds out
    /// why not, and that argument does not change during a restore.
    #[test]
    fn the_card_is_offered_during_a_restore_with_no_reader() {
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::Custody {
                restoring: true,
                card: Some("no card reader found".into()),
                card_ok: false,
                error: None,
            },
        }));
        assert!(actions_on(&ui).contains(&Action::UseCard));
    }

    // ---- the paper flow -------------------------------------------------

    fn scanning(items: Vec<PaperItem>, complete: bool) -> Screen {
        with_camera(items, complete, CameraView::Off)
    }

    fn with_camera(items: Vec<PaperItem>, complete: bool, camera: CameraView) -> Screen {
        Screen::Paper(PaperView {
            state: PaperState::Scanning {
                wallet: Some("wallet 5e1f0c2a9d4b7368".into()),
                items,
                foreign: 0,
                unreadable: 0,
                problems: Vec::new(),
                complete,
                camera,
                for_setup: false,
            },
        })
    }

    fn item(what: &str, state: &str, done: bool) -> PaperItem {
        let note = what.starts_with("note");
        PaperItem { what: what.into(), state: state.into(), done, note }
    }

    /// **The rule this screen exists for.** Three notes of four is three
    /// notes, and a holder who has genuinely lost a sheet must not be
    /// trapped on a page whose only exit is finding it.
    #[test]
    fn restore_is_offered_even_when_the_scan_is_incomplete() {
        let ui = Ui::build_screen(&scanning(
            vec![
                item("note 1", "complete", true),
                item("note 2", "nothing scanned yet", false),
            ],
            false,
        ));
        let acts = actions_on(&ui);
        assert!(acts.contains(&Action::RestoreScanned), "no way to restore what is here");
        assert!(acts.contains(&Action::AddImages));

        let text = text_on(&ui);
        assert!(text.contains("Restore what I have"), "{text}");
    }

    /// Progress reads per item, because "note 2 is missing" is actionable
    /// and "symbol 7 of 14" is not.
    ///
    /// The heading counts **notes** and says so. "2 of 4 readable", counting
    /// items, would be true and unreadable: the wallet record is one of the
    /// four, a holder is looking at some larger number of QR symbols, and
    /// nothing would name the unit.
    #[test]
    fn progress_names_items_rather_than_symbols() {
        let ui = Ui::build_screen(&scanning(
            vec![
                item("wallet record", "complete", true),
                item("note 1", "complete", true),
                item("note 2", "needs symbol 2", false),
                item("note 3", "nothing scanned yet", false),
            ],
            false,
        ));
        let text = text_on(&ui);
        for want in ["wallet record", "note 2", "needs symbol 2", "note 3", "nothing scanned yet"] {
            assert!(text.contains(want), "{want:?} missing from: {text}");
        }
        // One note of three, with the wallet record kept out of the
        // count and reported on its own row.
        assert!(text.contains("1 of 3 notes readable"), "{text}");
        assert!(!text.contains("of 4"), "the wallet record is not a note: {text}");
    }

    /// A complete scan says so and makes restoring the obvious move.
    #[test]
    fn a_complete_scan_says_everything_is_here() {
        let ui = Ui::build_screen(&scanning(
            vec![item("wallet record", "complete", true), item("note 1", "complete", true)],
            true,
        ));
        let text = text_on(&ui);
        assert!(text.contains("Everything is here"), "{text}");
        assert!(text.contains("Restore"), "{text}");
        assert!(!text.contains("Restore what I have"), "{text}");
    }

    /// Before anything is scanned, say what a usable scan is — not after
    /// the holder has made an unusable one.
    #[test]
    fn an_empty_scan_explains_what_will_work() {
        let ui = Ui::build_screen(&scanning(Vec::new(), false));
        let text = text_on(&ui);
        assert!(text.contains("360dpi"), "{text}");
        assert!(text.contains("whole page in frame"), "{text}");
    }

    /// The export screen states the page count before any file dialog,
    /// because that is what a holder decides with.
    #[test]
    fn the_offer_says_how_many_pages_and_what_else_is_needed() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Offer { notes: 4, symbols: 9, pages: 1, locked: false },
        }));
        let text = text_on(&ui);
        assert!(text.contains("1 page"), "{text}");
        assert!(text.contains("9 across 1 page"), "{text}");
        assert!(text.contains("recovery phrase"), "{text}");

        let acts = actions_on(&ui);
        assert!(acts.contains(&Action::PrintPaper));
        assert!(acts.contains(&Action::PrintPaperSvg));
    }

    /// After printing, the one piece of advice that turns an untested
    /// backup into a tested one — at the moment a holder will still act
    /// on it.
    #[test]
    fn printing_tells_them_to_scan_it_back_now() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Printed { path: "C:/x/backup.pdf".into(), pages: 2 },
        }));
        let text = text_on(&ui);
        assert!(text.contains("100%"), "{text}");
        assert!(text.contains("scan it back"), "{text}");
        assert!(actions_on(&ui).contains(&Action::ScanPaper));
    }

    /// A restore that left something behind says which sheet to go and
    /// find, and that trying again is safe.
    #[test]
    fn a_partial_restore_names_the_sheet_still_missing() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Restored {
                added: 3,
                kept: 0,
                missed: Vec::new(),
                absent: vec!["note 2".into()],
                partial: Vec::new(),
                rejected: Vec::new(),
            },
        }));
        let text = text_on(&ui);
        assert!(text.contains("3 notes restored"), "{text}");
        assert!(text.contains("note 2"), "{text}");
        assert!(text.contains("run this again"), "{text}");
        assert!(actions_on(&ui).contains(&Action::ScanPaper));
    }

    /// Paper needs the wallet's key, so a locked client says that rather
    /// than offering a button that cannot work.
    #[test]
    fn a_locked_wallet_cannot_print_paper() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Offer { notes: 0, symbols: 0, pages: 0, locked: true },
        }));
        let acts = actions_on(&ui);
        assert!(!acts.contains(&Action::PrintPaper));
        assert!(text_on(&ui).contains("unlock"), "{}", text_on(&ui));
    }

    /// **The door this flow was missing.** Sheets are a restoration
    /// artifact: reaching the scanner must not require first exporting
    /// something, because a holder who needs their sheets is the one with
    /// nothing left to export.
    #[test]
    fn settings_offers_restoring_from_paper_without_exporting_first() {
        let ui = Ui::build_screen(&Screen::Settings(SettingsView {
            rows: vec![("backup".into(), "none".into())],
            note: None,
            trustline_needed: None,
            backup: None,
            rpc_edit: None,
        }));
        assert!(actions_on(&ui).contains(&Action::ScanPaper), "no way in from settings");
        let text = text_on(&ui);
        assert!(text.contains("Restore from paper"), "{text}");
    }

    /// An empty wallet is the likeliest one to need its sheets, and was
    /// the one that could not open this screen at all: the offer refused
    /// outright when there was nothing to print.
    #[test]
    fn an_empty_wallet_can_still_reach_the_scanner() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Offer { notes: 0, symbols: 0, pages: 0, locked: false },
        }));
        let acts = actions_on(&ui);
        assert!(acts.contains(&Action::ScanPaper), "the scanner is unreachable");
        assert!(!acts.contains(&Action::PrintPaper), "there is nothing to print");
    }

    /// Scanning your own sheets back to check them adds nothing. Saying
    /// "0 notes restored" is what a total failure would say too, at the
    /// moment the holder has in fact just proved the backup works.
    #[test]
    fn a_verification_scan_reads_as_success() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Restored {
                added: 0,
                kept: 2,
                missed: Vec::new(),
                absent: Vec::new(),
                partial: Vec::new(),
                rejected: Vec::new(),
            },
        }));
        let text = text_on(&ui);
        assert!(text.contains("2 notes verified"), "{text}");
        assert!(!text.contains("0 notes restored"), "{text}");
    }

    /// A note half-scanned is not restored, and the screen must not say
    /// everything came back.
    #[test]
    fn a_half_scanned_note_is_named_not_counted_as_everything() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Restored {
                added: 2,
                kept: 0,
                missed: Vec::new(),
                absent: Vec::new(),
                partial: vec![("note 3".into(), 1)],
                rejected: Vec::new(),
            },
        }));
        let text = text_on(&ui);
        assert!(!text.contains("came back"), "{text}");
        assert!(text.contains("note 3"), "{text}");
        assert!(text.contains("1 symbol still missing"), "{text}");
        assert!(actions_on(&ui).contains(&Action::ScanPaper));
    }

    /// Nor a note that read but was refused.
    #[test]
    fn a_rejected_note_is_named_with_why() {
        let ui = Ui::build_screen(&Screen::Paper(PaperView {
            state: PaperState::Restored {
                added: 1,
                kept: 0,
                missed: Vec::new(),
                absent: Vec::new(),
                partial: Vec::new(),
                rejected: vec![("note GABC".into(), "chain does not verify".into())],
            },
        }));
        let text = text_on(&ui);
        assert!(!text.contains("came back"), "{text}");
        assert!(text.contains("chain does not verify"), "{text}");
    }

    /// **The camera is the way in, files are the fallback.** A holder
    /// arriving to restore should not have to produce image files first.
    #[test]
    fn the_scan_screen_leads_with_the_camera() {
        let ui = Ui::build_screen(&scanning(Vec::new(), false));
        let acts = actions_on(&ui);
        assert!(acts.contains(&Action::UseCamera), "no camera button");
        assert!(acts.contains(&Action::AddImages), "files must stay available");
        let text = text_on(&ui);
        assert!(text.contains("Use the camera"), "{text}");
    }

    /// A running camera gets a surface to paint into, and the button
    /// becomes the way to stop it rather than a second way to start it.
    #[test]
    fn a_live_camera_has_a_viewfinder_and_a_way_out() {
        let ui = Ui::build_screen(&with_camera(
            Vec::new(),
            false,
            CameraView::Live {
                name: "Surface Camera Rear".into(),
                px_per_module: 6.62,
            },
        ));
        assert!(ui.viewfinder.is_some(), "nowhere to paint the frame");
        let acts = actions_on(&ui);
        assert!(acts.contains(&Action::StopCamera));
        assert!(!acts.contains(&Action::UseCamera));

        // The number that decides whether anything can read, said out
        // loud: a holder who is failing should know it is distance.
        let text = text_on(&ui);
        assert!(text.contains("6.6 pixels per module"), "{text}");
        assert!(text.contains("Surface Camera Rear"), "{text}");
    }

    /// With no camera running there is nothing to paint, so the page must
    /// not reserve a hole where a picture never arrives.
    #[test]
    fn no_camera_means_no_viewfinder() {
        let ui = Ui::build_screen(&scanning(Vec::new(), false));
        assert!(ui.viewfinder.is_none());
    }

    /// A camera too coarse to resolve a symbol is refused in words, and
    /// the refusal points at the path that still works. Too few pixels
    /// looks exactly like bad focus, so a holder left to guess would keep
    /// trying.
    #[test]
    fn a_camera_that_cannot_work_says_so_and_names_the_way_on() {
        let ui = Ui::build_screen(&with_camera(
            Vec::new(),
            false,
            CameraView::Refused(
                "this camera is 1280x720, giving 3.3 pixels per module against the 4 a \
                 symbol needs - scan the sheets instead and add the images"
                    .into(),
            ),
        ));
        let text = text_on(&ui);
        assert!(text.contains("3.3 pixels per module"), "{text}");
        assert!(text.contains("add the images"), "{text}");
        // And the files are still right there.
        assert!(actions_on(&ui).contains(&Action::AddImages));
    }

    /// A short page must not pretend to scroll — an offset it cannot honour
    /// would move rows under a clip that never moves.
    #[test]
    fn a_short_list_does_not_scroll() {
        let short = SettingsView {
            rows: vec![("one".into(), "1".into())],
            note: None,
            trustline_needed: None,
            backup: None,
            rpc_edit: None,
        };
        let ui = Ui::build_screen(&Screen::Settings(short));
        assert!(!ui.scrollable());
        assert_eq!(ui.clamp_scroll(500.0), 0.0);
    }

    /// Scrolling must not leave buttons clickable where they are no longer
    /// drawn, and must find the ones that moved into view.
    #[test]
    fn hit_testing_follows_the_scroll() {
        let notes = (0..30)
            .map(|i| NoteCard {
                claimed: None,
                id: format!("G{i}"),
                short_id: format!("G{i}"),
                amount: "$1.0000000".into(),
                redeems_for: "$0.9994000".into(),
                spend_mode: false,
                state: NoteState::Live,
                backed_up: false,
                exposure: 0,
            })
            .collect();
        let mut view = WalletView::sample();
        view.tabs = vec![DenomTab {
            label: "$1.0000000".into(),
            notes,
        }];
        view.selected_tab = 0;
        let ui = Ui::build_screen(&Screen::Wallet(view));
        assert!(ui.scrollable());

        // A nav item is chrome: it does not move when the list does.
        let nav = ui.nav_ids[0];
        let scrolled = Interaction {
            scroll: ui.scroll_max(),
            ..Default::default()
        };
        assert_eq!(
            ui.hit_test_with(60.0, 62.0, &Interaction::default()),
            Some(nav)
        );
        assert_eq!(ui.hit_test_with(60.0, 62.0, &scrolled), Some(nav));
    }

    /// Build a one-element Ui around a single label, so the cache behaviour
    /// can be observed without a page that renders secrets existing yet.
    fn one_label(label: Label) -> Ui {
        let mut tree: TaffyTree<()> = TaffyTree::new();
        let mut skins: HashMap<NodeId, Skin> = HashMap::new();
        let style = Style {
            size: Size {
                width: length(200.0),
                height: length(40.0),
            },
            ..Default::default()
        };
        let root = tree.new_leaf(style).unwrap();
        skins.insert(root, Skin::new("field-row").label(label));
        tree.compute_layout(
            root,
            Size {
                width: AvailableSpace::Definite(200.0),
                height: AvailableSpace::Definite(40.0),
            },
        )
        .unwrap();
        Ui {
            tree,
            skins,
            root,
            hits: Vec::new(),
            viewfinder: None,
            nav_ids: Vec::new(),
            scroll: None,
            scroll_content: None,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Every label the code asks a skin for is one the skin declares.
    ///
    /// The skins are the design and an artist edits them freely; renaming or
    /// deleting a sample in Inkscape would otherwise show only as magenta
    /// text on whatever screen uses it. Pairs are read from this file: the
    /// literal name in each `.text(...)` with the nearest `Skin::new(...)`
    /// before it, plus the direct `styled(...)` / `text_spec(...)` lookups.
    #[test]
    fn every_label_the_code_uses_is_in_its_skin() {
        let src = include_str!("lib.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut skin = String::new();
        let mut i = 0;
        while i < body.len() {
            let rest = &body[i..];
            if let Some(r) = rest.strip_prefix("Skin::new(") {
                // A skin named by a variable (the buttons) is not checked.
                skin = match r.strip_prefix('"') {
                    Some(q) => q[..q.find('"').unwrap()].to_string(),
                    None => String::new(),
                };
            }
            for (call, explicit) in [
                (".text(\"", false),
                (".text_secret(\"", false),
                ("styled(\"", true),
                ("text_spec(\"", true),
            ] {
                if let Some(r) = rest.strip_prefix(call) {
                    let first = &r[..r.find('"').unwrap()];
                    if explicit {
                        // Only `("skin", "name"`: a variable second argument
                        // is one of the runtime choices listed below.
                        if let Some(r2) = r[first.len() + 1..].strip_prefix(", \"") {
                            pairs.push((first.into(), r2[..r2.find('"').unwrap()].into()));
                        }
                    } else if !skin.is_empty() {
                        pairs.push((skin.clone(), first.into()));
                    }
                }
            }
            i += rest.chars().next().map_or(1, char::len_utf8);
        }
        // Chosen at runtime, so not a literal at the call site.
        for extra in [
            ("note-card", "amount-dim"),
            ("field-row", "value-warn"),
            ("field-row", "value-alarm"),
            ("button-primary", "label"),
            ("button-secondary", "label"),
        ] {
            pairs.push((extra.0.into(), extra.1.into()));
        }
        assert!(pairs.len() > 50, "found only {} - is the scan broken?", pairs.len());
        let missing: Vec<_> = pairs
            .iter()
            .filter(|(skin, name)| text_spec(skin, name).is_none())
            .collect();
        assert!(missing.is_empty(), "skins without the text the code asks for: {missing:?}");
    }

    fn cached_layers(ui: &Ui, kind: &str) -> usize {
        ui.cache.borrow().keys().filter(|k| k.1 == kind).count()
    }

    /// The secret-in-cache hazard. The raster cache is keyed by
    /// content and deliberately outlives tree rebuilds, so a cached recovery
    /// phrase would sit in memory as a bitmap long after its screen closed.
    #[test]
    fn a_secret_label_never_enters_the_raster_cache() {
        let ui = one_label(
            lbl(
                "abandon ability able",
                14.0,
                "#fff",
                600,
                Anchor::Start,
                8.0,
                0.5,
            )
            .secret(),
        );
        ui.render_scaled(&Interaction::default(), 200, 40);
        ui.render_scaled(&Interaction::default(), 200, 40);
        assert_eq!(cached_layers(&ui, "labels"), 0, "a secret was cached");
    }

    /// The other half: bypassing the cache for secrets must not have disabled
    /// it for everything, which would make typing cost a cold page repaint.
    #[test]
    fn an_ordinary_label_is_still_cached() {
        let ui = one_label(lbl("balance", 14.0, "#fff", 600, Anchor::Start, 8.0, 0.5));
        ui.render_scaled(&Interaction::default(), 200, 40);
        assert_eq!(cached_layers(&ui, "labels"), 1);
    }

    #[test]
    fn purging_drops_every_rasterized_layer() {
        let ui = one_label(lbl("balance", 14.0, "#fff", 600, Anchor::Start, 8.0, 0.5));
        ui.render_scaled(&Interaction::default(), 200, 40);
        assert!(!ui.cache.borrow().is_empty());
        ui.purge_cache();
        assert!(ui.cache.borrow().is_empty());
    }

    #[test]
    fn an_empty_value_still_makes_one_line() {
        assert_eq!(wrap("", ROW_CHARS), vec![String::new()]);
    }

    /// Ink per frame, as (count of lit pixels, mean x of those pixels).
    ///
    /// Renders one row of the bar, because the bar is uniform vertically and
    /// one row is enough to say where the ink is.
    fn frame_ink(state: &str) -> (usize, f32) {
        let mut p = Pelt::load(skin_path("progress")).expect("progress.svg loads");
        p.set_state(state);
        let img = p.render(320, 6).expect("renders");
        let row = 3usize;
        let mut n = 0usize;
        let mut sum = 0f32;
        for x in 0..320usize {
            let px = (row * 320 + x) * 4;
            // The track is a 6% white wash and the bar is the accent at 0.75,
            // so green well above blue is the bar and nothing else is.
            let (r, g, b, a) = (
                img.rgba[px],
                img.rgba[px + 1],
                img.rgba[px + 2],
                img.rgba[px + 3],
            );
            if a > 128 && g > b + 24 && g > r + 24 {
                n += 1;
                sum += x as f32;
            }
        }
        (n, if n == 0 { f32::NAN } else { sum / n as f32 })
    }

    /// Every frame named in `FRAMES` has to exist in the file.
    ///
    /// A missing `data-pelt-state` group is not an error anywhere in the
    /// stack - `filter_svg_state` just finds nothing and the element renders
    /// empty. On an indeterminate bar that is a blank gap in the loop, which
    /// reads as exactly the stall the bar exists to deny.
    #[test]
    fn every_frame_state_exists_and_carries_the_bar() {
        for f in FRAMES {
            let (ink, _) = frame_ink(f);
            assert!(
                ink > 0,
                "frame {f} drew no bar - is there a <g data-pelt-state={f:?}>?"
            );
        }
    }

    /// The loop must not thin out or stall where it wraps.
    ///
    /// The bar is drawn twice, a full period apart, so the part leaving the
    /// right edge and the part entering at the left always sum to one bar.
    /// If that ever stops holding, one frame of the loop goes thin or blank
    /// and the animation stutters once per cycle.
    #[test]
    fn the_wrap_keeps_the_ink_constant() {
        let inks: Vec<usize> = FRAMES.iter().map(|f| frame_ink(f).0).collect();
        let (lo, hi) = (*inks.iter().min().unwrap(), *inks.iter().max().unwrap());
        assert!(
            hi - lo <= 2,
            "the bar changes width across the loop: {inks:?} (min {lo}, max {hi})"
        );
        assert!(lo >= 90, "the bar is thinner than it should be: {inks:?}");
    }

    /// Consecutive frames have to actually differ, or it is a still image.
    #[test]
    fn consecutive_frames_move() {
        let xs: Vec<f32> = FRAMES.iter().map(|f| frame_ink(f).1).collect();
        for (i, w) in xs.windows(2).enumerate() {
            assert!(
                (w[1] - w[0]).abs() > 1.0,
                "frames {} and {} look the same ({:?})",
                FRAMES[i],
                FRAMES[i + 1],
                w
            );
        }
    }

    /// Unlocking is ~23ms of Argon2id; reconciling against the ledger is
    /// seconds of RPC. The bar belongs on the second one, and the billfold
    /// is where that wait is spent.
    #[test]
    fn the_billfold_animates_while_it_reads_the_ledger() {
        let reading = Ui::build_screen(&Screen::Wallet(WalletView::loading()));
        assert!(reading.has_animation(), "the loading billfold drew no bar");

        let locked = Ui::build_screen(&Screen::Wallet(WalletView::locked()));
        assert!(
            !locked.has_animation(),
            "a locked billfold is not waiting on anything - it is waiting on you"
        );
    }

    /// Re-reading the account is seconds of RPC behind figures that are
    /// already on screen, so it has to look busy rather than look finished.
    #[test]
    fn a_rereading_account_page_says_so() {
        let reading = Ui::build_screen(&Screen::Account(AccountView {
            address: "GABC".into(),
            busy: Some("reading the ledger".into()),
            ..Default::default()
        }));
        assert!(reading.has_animation(), "a busy account page drew no bar");

        let settled = Ui::build_screen(&Screen::Account(AccountView {
            address: "GABC".into(),
            ..Default::default()
        }));
        assert!(
            !settled.has_animation(),
            "a settled account page asked for a clock"
        );
    }

    /// A PUK on screen is a secret, and the raster cache outlives the
    /// screen that drew it. Cached, it would sit in
    /// memory as a bitmap long after setup finished.
    #[test]
    fn the_puk_never_enters_the_raster_cache() {
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::CardPuk {
                puk: "482073915064".into(),
                entered: 0,
                confirming: false,
                error: None,
            },
        }));
        let it = Interaction::default();
        let _ = ui.render(&it);
        let _ = ui.render(&it);

        // Not "nothing is cached": the headings and the advice rows are
        // ordinary text and cache correctly. The claim is narrower and the
        // one that matters - every label-bearing element is cached *except*
        // the secret ones, so the PUK is the layer that is missing.
        let with_labels = ui.skins.values().filter(|s| !s.labels.is_empty()).count();
        let secret = ui
            .skins
            .values()
            .filter(|s| s.labels.iter().any(|l| l.sensitive))
            .count();
        assert_eq!(secret, 1, "expected exactly one secret element - the PUK");
        assert_eq!(
            cached_layers(&ui, "labels"),
            with_labels - secret,
            "the PUK's label layer was cached, and would outlive the screen as a bitmap"
        );
    }

    /// Every card screen has to build. They are reached only by walking the
    /// ceremony, so a panic in one is otherwise found by hand.
    #[test]
    fn every_card_setup_screen_builds() {
        let states = [
            SetupState::CardIntro {
                card: "a new card".into(),
                blank: true,
            },
            SetupState::CardIntro {
                card: "a card is ready".into(),
                blank: false,
            },
            SetupState::CardPin {
                entered: 3,
                again: false,
                error: None,
            },
            SetupState::CardPin {
                entered: 0,
                again: true,
                error: Some("no match".into()),
            },
            SetupState::CardDuress {
                entered: 6,
                again: false,
                error: None,
            },
            SetupState::CardDuress {
                entered: 0,
                again: true,
                error: Some("same".into()),
            },
            SetupState::CardPuk {
                puk: "482073915064".into(),
                entered: 0,
                confirming: false,
                error: None,
            },
            SetupState::CardPuk {
                puk: "482073915064".into(),
                entered: 4,
                confirming: true,
                error: Some("wrong".into()),
            },
            SetupState::CardErase {
                confirmed: false,
                typed: "ERA".into(),
                entered: 0,
                error: None,
            },
            SetupState::CardErase {
                confirmed: true,
                typed: String::new(),
                entered: 6,
                error: Some("no".into()),
            },
        ];
        for state in states {
            let label = format!("{state:?}");
            let ui = Ui::build_screen(&Screen::Setup(SetupView { state }));
            let _ = ui.render(&Interaction::default());
            // No screen in this flow animates: nothing is in flight until
            // 3.6, which is the first step that writes to the card.
            assert!(!ui.has_animation(), "{label} asked for a clock");
        }
    }

    /// The card's phrase is as much a secret as the software one, and the
    /// raster cache outlives the screen that drew it.
    #[test]
    fn the_cards_phrase_never_enters_the_raster_cache() {
        let words: Vec<String> = (0..24).map(|i| format!("word{i}")).collect();
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::CardPhrase {
                words,
                revealed: true,
            },
        }));
        let it = Interaction::default();
        let _ = ui.render(&it);
        let _ = ui.render(&it);

        let with_labels = ui.skins.values().filter(|s| !s.labels.is_empty()).count();
        let secret = ui
            .skins
            .values()
            .filter(|s| s.labels.iter().any(|l| l.sensitive))
            .count();
        // Four rows of six words.
        assert_eq!(secret, 4, "expected the four word rows to be secret");
        assert_eq!(
            cached_layers(&ui, "labels"),
            with_labels - secret,
            "a word row was cached, and would outlive the screen as a bitmap"
        );
    }

    /// Hidden means hidden: a phrase that is not revealed must not have its
    /// words anywhere in the tree, not merely be covered up.
    #[test]
    fn a_hidden_card_phrase_does_not_hold_its_words() {
        let words: Vec<String> = (0..24).map(|i| format!("zzz{i}")).collect();
        let ui = Ui::build_screen(&Screen::Setup(SetupView {
            state: SetupState::CardPhrase {
                words,
                revealed: false,
            },
        }));
        let leaked = ui
            .skins
            .values()
            .flat_map(|s| s.labels.iter())
            .any(|l| l.text.contains("zzz"));
        assert!(
            !leaked,
            "a hidden phrase still had its words in the layout tree"
        );
    }

    /// The gate must ask the question this wallet answers. Asking for a
    /// passphrase on a card wallet invites someone to type one secret
    /// where the other belongs.
    #[test]
    fn the_gate_asks_for_a_pin_on_a_card_wallet() {
        fn labels(ui: &Ui) -> Vec<String> {
            ui.skins
                .values()
                .flat_map(|s| s.labels.iter())
                .map(|l| l.text.clone())
                .collect()
        }

        let soft = Ui::build_screen(&Screen::Locked(LockedView::default()));
        let t = labels(&soft);
        assert!(t.iter().any(|l| l == "passphrase"), "{t:?}");
        assert!(!t.iter().any(|l| l == "PIN"));

        let card = Ui::build_screen(&Screen::Locked(LockedView {
            card: Some(CardGate {
                hint: "your card is on the reader".into(),
                ready: true,
            }),
            ..Default::default()
        }));
        let t = labels(&card);
        assert!(t.iter().any(|l| l == "PIN"), "{t:?}");
        assert!(!t.iter().any(|l| l == "passphrase"));
        // And the reader's state is on screen, because nothing typed can
        // help while the card is absent.
        assert!(t.iter().any(|l| l.contains("on the reader")), "{t:?}");
    }

    /// An absent card still shows the gate rather than anything else, and
    /// says why. Falling through to a software setup offer is how someone
    /// who left their card elsewhere ends up with two wallets.
    #[test]
    fn an_absent_card_still_renders_the_gate() {
        let ui = Ui::build_screen(&Screen::Locked(LockedView {
            card: Some(CardGate {
                hint: "no card reader found - plug one in and try again".into(),
                ready: false,
            }),
            ..Default::default()
        }));
        let t: Vec<String> = ui
            .skins
            .values()
            .flat_map(|s| s.labels.iter())
            .map(|l| l.text.clone())
            .collect();
        assert!(t.iter().any(|l| l == "no card"), "{t:?}");
        assert!(t.iter().any(|l| l.contains("plug one in")), "{t:?}");
        assert!(t.iter().any(|l| l == "Look again"), "{t:?}");
    }

    /// The gate has no sidebar, which is what "blocks the whole UI" means
    /// mechanically: there are no nav nodes, so there is nothing to click.
    #[test]
    fn a_dead_card_has_a_way_out() {
        fn labels(ui: &Ui) -> Vec<String> {
            ui.skins
                .values()
                .flat_map(|s| s.labels.iter())
                .map(|l| l.text.clone())
                .collect()
        }
        // The gate a card wallet sits on with no card: the reset is offered.
        let gate = Ui::build_screen(&Screen::Locked(LockedView {
            card: Some(CardGate {
                hint: "a reader, but no card in it".into(),
                ready: false,
            }),
            ..Default::default()
        }));
        assert!(labels(&gate).iter().any(|l| l == "Can't open it?"));

        // The reset screen says nothing is deleted, where it all goes, what
        // the backups are, and asks for the word. No sidebar.
        let reset = Ui::build_screen(&Screen::Reset(ResetView {
            archive: "/home/x/.kenter/reset-42".into(),
            moving: vec!["vault.json".into(), "wallet".into()],
            backups: vec!["kenter-backup-1.kbk".into()],
            typed: "RES".into(),
            error: None,
        }));
        let t = labels(&reset);
        assert!(reset.nav_ids.is_empty(), "the reset screen rendered a sidebar");
        assert!(t.iter().any(|l| l.contains("Nothing is deleted")), "{t:?}");
        assert!(t.iter().any(|l| l.contains("reset-42")), "{t:?}");
        assert!(t.iter().any(|l| l.contains("kenter-backup-1.kbk")), "{t:?}");
        assert!(t.iter().any(|l| l == "type RESET"), "{t:?}");
        assert!(t.iter().any(|l| l == "RES|"), "{t:?}");
    }

    #[test]
    fn a_locked_client_has_nowhere_else_to_go() {
        let gate = Ui::build_screen(&Screen::Locked(LockedView::default()));
        assert!(gate.nav_ids.is_empty(), "the gate rendered a sidebar");

        let open = Ui::build_screen(&Screen::Wallet(WalletView::sample()));
        assert_eq!(
            open.nav_ids.len(),
            NAV.len(),
            "an unlocked client lost its nav"
        );
    }

    /// Opening the store is the one wait that stands between someone and
    /// every other screen, so it has to show it is working.
    #[test]
    fn the_gate_animates_only_while_it_is_opening() {
        let typing = Ui::build_screen(&Screen::Locked(LockedView::default()));
        assert!(
            !typing.has_animation(),
            "the gate animated while waiting for typing"
        );

        let opening = Ui::build_screen(&Screen::Locked(LockedView {
            busy: true,
            ..Default::default()
        }));
        assert!(
            opening.has_animation(),
            "the gate drew no bar while opening the store"
        );
    }

    /// The clock is driven off this, so a `Working` page must admit to moving
    /// and an ordinary page must not - otherwise the shell either never ticks
    /// or never sleeps.
    #[test]
    fn only_a_working_page_asks_for_a_clock() {
        let working = Ui::build_screen(&Screen::Receive(ReceiveView {
            state: ReceiveState::Working {
                what: "checking".into(),
            },
        }));
        assert!(
            working.has_animation(),
            "a Working page drew no animated element"
        );

        let idle = Ui::build_screen(&Screen::Wallet(WalletView::sample()));
        assert!(
            !idle.has_animation(),
            "the billfold asked to be woken for animation"
        );
    }

    /// The whole point of frames-as-states: the loop is bounded in the cache.
    ///
    /// Twelve frames of a swept *token* would be twelve entries too - the
    /// difference only shows over time, because a token sweeps through values
    /// that never repeat while the frame set closes on itself. Running the
    /// loop twice and seeing the same count is what says it closed.
    #[test]
    fn the_frame_loop_does_not_grow_the_cache() {
        let ui = Ui::build_screen(&Screen::Receive(ReceiveView {
            state: ReceiveState::Working {
                what: "checking".into(),
            },
        }));
        let mut it = Interaction::default();

        for f in 0..FRAMES.len() as u32 {
            it.frame = f;
            let _ = ui.render(&it);
        }
        let after_one_loop = cached_layers(&ui, "skin");

        for f in 0..(FRAMES.len() as u32 * 3) {
            it.frame = f;
            let _ = ui.render(&it);
        }
        assert_eq!(
            cached_layers(&ui, "skin"),
            after_one_loop,
            "the cache grew on a second pass through the same frames"
        );
    }
}
