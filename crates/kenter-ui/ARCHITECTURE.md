# kenter-ui — Architecture

**Role.** The desktop wallet's graphical client. It is a `winit` window whose
contents are composited on the CPU from **pelt** SVG skins laid out by
**Taffy**, presented through `softbuffer`. Structure comes from a Taffy tree,
each element's look is painted from an SVG under `skins/kenter/`, and a thin
content layer draws text on top. Pelts rasterize to premultiplied RGBA and are
alpha-composited ("over") into a canvas that becomes a window frame or a PNG.

The crate is a shell over `kenter-wallet`: it reaches the chain through
`kenter-client`'s `WalletChain` and the disk through the same `FileStore` the
CLI uses, so the two desktop surfaces cannot disagree about what a wallet
holds. It is **desktop-only**. The winit/softbuffer/resvg stack is far too
heavy for the browser wallet, which never links this crate; everything that
must also run in `wasm32` lives in `kenter-wallet`.

## Boundaries

- **Depends on:** `pelt` (the SVG-skin appearance engine, an external crate;
  rasterizes through `usvg`/`resvg`), `taffy` (layout only), `winit` +
  `softbuffer` (window and a CPU framebuffer the renderer owns and clears each
  frame). No GPU crates.
- **Wallet stack:** `kenter-wallet` (`fs` feature), `kenter-client`
  (`wallet` feature), `kenter-crypto`, `kenter-vault` (software custody),
  `stellar-keycard` (card custody over PC/SC), `kenter-network` and
  `kenter-print` (networked printing for deposits).
- **Paper and QR:** `qrcode` (symbols for pay tags and backup sheets), `rxing`
  and `rqrr` (reading symbols back from images), `nokhwa` (camera capture,
  one backend per OS), `image` (scan files), `miniz_oxide` (PDF streams).
- **Other:** `arboard` (text clipboard), `rfd` (native save dialog),
  `tokio` (one runtime per worker thread), `zeroize`.
- **Depended on by:** nothing; it is a leaf. The `kenter-ui` binary is the
  wallet, `kenter-ui-mock` is the styling loop. The installers build it with
  the `packaged` feature.

## Structure

| Module | What it does |
|---|---|
| `lib.rs` | The model: `Screen`, `Action`, view structs, `Ui::build_with`, layout, hit-testing, the raster cache and the renderer. Does no IO. |
| `main.rs` | Binary `kenter-ui`: the event loop, keyboard and mouse input, worker threads, and the passphrase/PIN buffers. |
| `mock.rs` | Binary `kenter-ui-mock`: renders one screen with sample content to a PNG. |
| `wallet.rs` | Loads a `WalletView` from the wallet on disk and reconciles it against the ledger. |
| `vault.rs` | `GuiVault`, one enum over `SoftVault` and the card vault, so the client is not generic over custody. |
| `setup.rs`, `card.rs`, `card_setup.rs` | First run: software or card custody, recovery phrase, duress PIN, restore. |
| `account.rs` | The Stellar account: XLM and the mint's asset, trustline, the address to fund. |
| `deposit.rs` | Printing a note: escrow, the drand-seeded draw, confirmations, registration, through `kenter_print::print_selected`. |
| `receive.rs` | Accepting a note: pay tags, the authorization prompt, and the inbox watch. |
| `pay.rs` | Handing a note over: Export for bearer, Pay for spend mode. |
| `redemption.rs` | Redeeming a note against the mint to an account the holder names. |
| `backup.rs` | The wallet backup file: writing, recording and restoring. |
| `sheet.rs`, `pdf.rs`, `scan.rs`, `camera.rs` | Paper backups: layout, SVG and PDF emitters, reading symbols from images and from a camera. |
| `qr.rs` | QR symbols rendered as SVG. |
| `settings.rs` | A status page: which wallet, where files live, the RPC server, whether the submitting account exists. |
| `reset.rs` | Moving an unopenable wallet aside so a first run can start. |

## Core model

- **`Screen`** is the page on display: `Wallet` (the billfold), `Account`,
  `Deposit`, `Receive`, `Pay`, `Redeem`, `Settings`, `Paper`, plus the gates
  `Setup`, `Locked` and `Reset`, and `Prompt` (an authorization prompt drawn
  over the page that asked for it). The sidebar has five entries: Billfold,
  Account, Deposit, Accept, Settings. The lit entry is derived from the
  screen, never tracked beside it, so the highlight cannot disagree with the
  page.
- **`Action`**: buttons carry the intent they trigger rather than being
  identified by position, so the shell matches on intent and rearranging a
  page cannot silently rewire a button.
- **`Ui`** holds a laid-out `TaffyTree`, a `NodeId → Skin` map, the
  interactive hit rects and a raster cache. It is built by `Ui::build_with`
  at the fixed logical size 960×620.
- **Skin** (internal): what to paint on a node. An SVG name, a base state,
  theme tokens, content labels and an optional interactive kind.
- **Label** (internal): a line of text drawn over an element as a one-off
  `<text>` pelt, so skins stay text-free and reusable. Its style (size,
  weight, colour, baseline) comes from a labelled sample text in the skin
  file, so the artist sets type in the SVG. A label the skin does not declare
  renders in magenta, so a renamed sample is seen at once.
- **State at render time.** The tree never mutates. `render_scaled` takes an
  `Interaction { hovered, pressed, selected_nav, scroll, … }` and picks each
  element's `data-pelt-state` variant (`default`, `hover`, `active`) from it.
- **Animation as states.** The progress skin cycles through twelve named
  frame states. Frames are states rather than a swept token because state is
  part of the cache key: the loop costs twelve entries once, then every frame
  is a blit.

## The billfold, not a balance

The main screen lists notes; it does not lead with a balance. Three facts in
the mint make a balance misleading:

- **There is no change.** `spend` carries no amount. A note moves whole or
  not at all, so holding 25 and 5 does not let you pay 7.3.
- **A sum of notes is not a spendable figure.** It totals instruments that
  mostly cannot be combined.
- **Face value is not redemption value.** A note redeems for
  `amount − node_fee × 2 × pairs`, so two notes of equal face can redeem for
  different amounts.

The Stellar account is a separate page for the same reason. It holds
ordinary fungible balances (XLM for fees and reserve, the mint's asset for
deposits). Folding it into the billfold would produce exactly the "sum you
can spend" the billfold avoids. It has no send button: sending value out of
the account without making a note would be a different product, and an
unlabelled send button beside a bearer-note wallet invites moving money to
the wrong place.

Display rules that follow:

- **A failed chain read does not blank the screen.** It shows what is held,
  with a status line saying the ledger could not be reached. "Here is what
  you hold, unverified" is honest; a zero would be a false statement about
  someone's money.
- **An empty wallet explains itself** with a row, rather than a blank panel
  that looks like a failed load.
- **Anything not spendable renders as outgoing**, so colour never implies
  value the holder does not have. That includes a token flagged as spent
  away, which is still `Active` on the ledger.
- **Nothing false is painted while loading.** The wallet view loads on a
  worker and arrives as a user event; until then figures show an em dash.

## Threads and the event loop

Everything slow runs on a worker thread with its own single-task tokio
runtime and arrives at the event loop as a user event: the wallet read (one
RPC round trip per held note), receive, deposit, redemption, card I/O. The
window opens at once and a slow ledger never freezes it.

**The event loop owns secrets as they are typed.** Keystrokes land there, in
a `Zeroizing<String>` cleared the moment it is handed to a worker. The view
model carries only a character count, which the renderer turns into dots.
There is no path by which a passphrase or PIN reaches a `Debug` print, a PNG
or the layout tree.

**Authorization crosses a thread boundary.** `receive.rs` holds `GuiPrompter`,
the shell's half of `kenter_wallet::Prompter`. It posts the request to the
event loop and blocks the worker until an answer comes back. Blocking is
correct: the worker's runtime has one task and nothing else to do while a
person decides. The policy is `Session` (one unlock covers the session).
Showing the billfold needs neither seed nor credential; operations that sign
ask when they need to.

**Custody is chosen once, at startup.** `GuiVault` dispatches to the software
vault or the card. The credential is the passphrase for one and the PIN for
the other; both mean "the secret that authorizes an owner-key operation",
which is all `DerivingVault` depends on.

## Flows and their invariants

### First run

Nothing is persisted until the recovery phrase is confirmed. `SoftVault`
refuses to overwrite a seed, because replacing one orphans every note owned
by a key derived from it. Writing the seed before the holder has copied the
phrase would turn that safeguard into a trap: close the window at the wrong
moment and the vault is unrecoverable and cannot be redone. So the phrase is
generated in memory, shown, confirmed, and only then written.

Card setup has the same property for free: `GENERATE MNEMONIC` stores
nothing on the card. The host assembles the words, shows them, derives the
seed and sends it back with `LOAD KEY`. A holder who walks away mid-ceremony
leaves the card untouched. Card readiness (is there a reader, does the card
already hold a key) is checked before any PIN is asked for. Declining to
choose a duress PIN generates and shows one; there is no "no duress PIN"
state.

The recovery phrase is drawn as a secret label: its raster layer is never
cached and its text is zeroized on drop. This reduces exposure, not
eliminates it, since the rasterizer allocates its own buffers; the phrase is
shown only while a button is held, and the cache is purged on leaving.

### Deposit

The holder chooses the face amount, bearer or spend mode, and the pair count
(more pairs, more privacy, more cost). The network chooses which nodes
serve: after a drand beacon round seeds the slot, nodes claim positions
and the lowest scores win (see `docs/architecture/node-selection.md`). The
wallet has no node list and no relay setting; it reaches each selected node
through the relay its roster record names. The depositor holds both end
pairs, which the mint exempts from staking. A deposit makes one note at a
time.

### Accept (receive)

The flow is: reserve an owner index, get authorization, derive that index's
commitment, record the pending receive, show the pay tag. It does not call
`TokenWallet::start_receive`, which does reserve-derive-record in one step,
because the prompt has to name the index it authorizes, so the index must
exist first. The ordering guarantee is kept by hand: the pending record is
written before the tag is shown, so a crash cannot leave a payment inbound
to an index the wallet forgot. Cancelling burns an index, which costs
nothing; reusing one would link two payments to the same commitment.

Receive is a full page, not a modal: it is something you sit on while a
payer acts.

**The inbox.** Until the payer's `.symtoken` passes the receive gates
(G1–G3 in `kenter-wallet`) the holder is not paid; holding the bytes is not
owning the note. The handover is a watched directory, `<wallet>/inbox/`,
polled every 1.5 s while the tag is on screen. A file usually arrives from a
chat client or a download, so a fixed place to put it is one step, and a
payment can land while the holder looks at something else. Three rules:

- **Nothing is judged the first time it is seen.** A file still being copied
  parses as malformed, which is a permanent rejection, so a file must keep
  the same size and mtime across two polls first.
- **Handled files are moved, not deleted**, into `accepted/` or `rejected/`,
  never overwriting, since two notes can arrive under one name.
- **Retryable and permanent differ.** `WalletError::ReceiveGate` carries
  `retryable` and the watch branches on it: the payer's on-chain spend may
  simply not have landed yet.

A pure-bearer note in the inbox is refused by G3 with a message to import it
instead. Mode is fixed at registration, so it will never acquire an owner,
and for pure bearer holding the bytes already is owning it.

`watch` reports through a `Report` sink rather than the event-loop proxy, so
the whole loop runs in tests with a `Vec` and no window. Cancellation is an
`AtomicBool` checked between every step; leaving the page, closing the window
and starting another receive all set it.

### Pay and Export

Two verbs, because the client can do different amounts of work for each.

- **Bearer: Export.** Handing a bearer note over happens outside the
  software, which cannot confirm or reverse it. The client writes the file
  (through a native save dialog) and records that a copy left, by kind: a
  backup is a copy kept, a handover is a copy given away.
- **Spend mode: Pay.** The payee needs both the container bytes and the
  on-chain owner change. The file is delivered first and the transaction
  second, because the failure modes are not symmetric. If the owner pointer
  moves and the file never arrives, nobody can redeem the note. If the file
  arrives and the pointer never moves, the bytes alone do nothing
  (`SpendModeRequiresOwner`) and the payer still owns it. The payee's inbox
  watch covers the gap, since G3 is retryable.

### Redeem

The holder presents the chain data from the container; the mint checks it
against the `chain_hash` committed at registration and pays
`amount − node_fee × 2 × pairs` from escrow. Pure-bearer redemption also
signs the recipient with the note's claim key, whose secret half never
reaches the ledger, so a chain published by a failed transaction is not
enough to redeem. Spend-mode notes also need the owner's proof. The payout
goes to any account the holder names, so paying a non-Kenter user is one
transaction. Redemption is irreversible against an adminless mint, so its
prompt carries the amount, the note and the destination account. See
`docs/architecture/spend-mode.md`.

### Backups

The backup written beside the vault at card provisioning survives a corrupt
store and nothing else; it does not protect against a lost laptop. Only a
backup the holder saves elsewhere is recorded with `Store::record_backup`,
and only that record answers "am I covered?" on the billfold.

A paper backup lays the backup out as QR symbols. Both emitters share one
layout, so the tested geometry is the made geometry:

- **PDF** is what a holder prints. It carries its page size, so a module is
  0.30 mm on paper rather than whatever a viewer decides. It is written by
  hand (filled rectangles and base-14 Helvetica, PDF 1.4), and tests parse it
  back with a real PDF library.
- **SVG** is vector paths, which a laser engraver or CNC takes, so the same
  sheet can be cut into metal.

The sheet carries the wallet fingerprint, a note that the recovery phrase is
also needed, numbered symbols and the date, and nothing about amounts.
Reading back works from image files (a scan or a phone photo) or a camera.
The camera reads one symbol at a time, because a whole page across a 1920 px
sensor is under three pixels per module; the camera screen checks the
negotiated format against that floor rather than showing a viewfinder that
cannot work. A scan that recovers some notes of several is a result to act
on, so paper has its own screen.

### Reset

A vault can become impossible to open: a wiped or lost card, a forgotten
passphrase. A reset moves the vault, the note store and any paper-backup
files beside the vault into a dated folder next to them, then offers a first
run. It never deletes, because the client cannot know a wallet is gone.

## Rendering

- **Render physical, hit-test logical.** Layout and hit rects live in logical
  space (960×620). `render_scaled` paints at the window's physical inner size;
  cursor input is mapped back through the scale factor before hit-testing.
  Pelts are SVG, so they are crisp at any scale.
- **Raster cache.** Keyed by `(NodeId, layer kind, state, physical w, h,
  content hash)`. The content hash covers skin name, inline SVG and every
  label, so a rebuilt tree (which Taffy numbers in construction order, reusing
  ids) hits the old entry for an unchanged element and misses for a changed
  one, with no risk of serving one page's art for another. The cache
  outlives tree rebuilds because typing rebuilds the layout once per
  keystroke and a cold full-page raster costs about 250 ms.
- **Owned, cleared framebuffer.** The renderer zeroes the canvas each frame
  and composites over it, so there is no transparent-compositing ghosting.
- **Premultiplied throughout.** `composite` short-circuits fully transparent
  and fully opaque source pixels.
- **QR as SVG.** A QR goes through pelt and the same cache as everything
  else, as one `<path>` of module squares with `crispEdges`. It is
  dark-on-white regardless of theme, because a QR matching a dark panel is
  the classic unscannable one. Tests rasterize at one pixel per module and
  compare every pixel with the encoder's matrix.
- **Render is IO-free.** `Ui::build_with` takes plain view structs, which is
  what lets `kenter-ui-mock` render any screen with no chain, vault or store.

## Skins

The skins under `skins/kenter/` are the source of truth for appearance: an
SVG must look the same in Inkscape as in the app, with no runtime styling.
Text styles are read from a skin's labelled samples and cached against the
file's mtime, so an edit shows on the next repaint.

Skins are resolved once at startup:

- From `skins/kenter/` beside the executable when present (installed builds).
- Otherwise, in a development build, from the source tree.
- **A `packaged` build has no fallback.** The source-tree path is the build
  machine's; on a user's machine an ordinary user can often create it, and
  skins define what the screens say. An installed wallet reads skins only
  from beside itself and refuses to start if they are missing.

## Limits

- Rendering is CPU only. The `Ui` model and skins are independent of the
  present path, so a GPU presenter could replace softbuffer without changing
  them.
- Deposit makes one note per run; a batch is a loop plus partial-failure
  display, not yet built.
- Settings is mostly a status page; the RPC server is the one editable field.

`API.md` in this directory lists the public items and the skin inventory;
`README.md` is the run guide.
