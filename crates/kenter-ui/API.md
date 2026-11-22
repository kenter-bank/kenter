# kenter-ui: API

The desktop wallet. The `kenter_ui` library holds the screen model, the
renderer and the flows; the `kenter-ui` binary (`src/main.rs`) is the shell
that runs them in a window. The library is public so the binaries, examples
and tests can drive it. It is not meant as a stable API for other crates.

How it works: a `Screen` is plain data. `Ui::build_screen` turns it into a
Taffy layout tree with a skin per element and an `Action` per button.
`Ui::render*` composites the skins to premultiplied RGBA on the CPU.
Input goes through `Ui::hit_test` and `Ui::action_at`, and the shell maps the
`Action` to work that produces the next `Screen`.

## Constants and re-exports

| Item | Value | Notes |
|------|-------|-------|
| `W`, `H` | `u32` = `960`, `620` | The fixed logical window size. |
| `NAV` | `[&str; 5]` = `["Billfold", "Account", "Deposit", "Accept", "Settings"]` | Sidebar entries, in order. |
| `NodeId` | `pub use taffy::NodeId` | Handle for a laid-out element. |

## `Ui`

| Fn / field | Signature | Notes |
|------------|-----------|-------|
| `Ui::build` | `() -> Ui` | The wallet page with sample data. |
| `Ui::build_with` | `(view: &WalletView) -> Ui` | The wallet page with real data. |
| `Ui::build_screen` | `(screen: &Screen) -> Ui` | Any screen. Lays out at `W×H`; skins rasterize lazily on first paint. |
| `Ui::rebuild` | `(&mut self, screen: &Screen)` | Swap in a new screen, keeping the raster cache, so a keystroke re-renders one label. |
| `Ui::purge_cache` | `(&self)` | Drop every cached layer. |
| `Ui::render` | `(&self, it: &Interaction) -> Vec<u8>` | Logical `W×H`, premultiplied RGBA. |
| `Ui::render_scaled` | `(&self, it: &Interaction, out_w: u32, out_h: u32) -> Vec<u8>` | Physical size, layout scaled uniformly (hi-DPI). |
| `Ui::render_live` | `(&self, it: &Interaction, out_w: u32, out_h: u32, live: Option<&LiveFrame>) -> Vec<u8>` | As `render_scaled`, with a camera frame painted into the viewfinder after the scene (not cached). |
| `Ui::hit_test` | `(&self, x: f32, y: f32) -> Option<NodeId>` | Topmost interactive element under a logical point. A button scrolled out of the viewport hits nothing. |
| `Ui::hit_test_with` | `(&self, x, y, it: &Interaction) -> Option<NodeId>` | At a given scroll position. |
| `Ui::action_at` | `(&self, node: NodeId) -> Option<Action>` | What clicking the node means. |
| `Ui::has_animation` | `(&self) -> bool` | The shell frame-paces only while this is true, so an idle client is idle. |
| `Ui::scroll_max` / `scrollable` / `clamp_scroll` | `-> f32` / `-> bool` / `(f32) -> f32` | The page's scroll range. |
| `Ui::nav_ids` | `pub Vec<NodeId>` | Sidebar nodes, in `NAV` order. |

Layers are cached by node, layer, state, physical size and a hash of the
content, so hover re-renders one element rather than the scene.

## Screen model

- `enum Screen { Wallet(WalletView), Receive(ReceiveView), Settings(SettingsView), Account(AccountView), Deposit(DepositView), Pay(PayView), Redeem(RedeemView), Setup(SetupView), Locked(LockedView), Reset(ResetView), Paper(PaperView), Prompt { view: PromptView, under: usize } }`.
  `nav_index() -> usize` derives the lit sidebar entry from the screen, so
  the highlight cannot disagree with the page. `Setup`, `Locked` and `Reset`
  show no navigation: nothing else is reachable from them. `Prompt` is an
  authorization prompt over whichever page asked; `under` keeps that page's
  entry lit. `Paper` is its own screen because its import half has partial
  success as the normal outcome.
- `enum Action`: what a button means (about fifty variants, one per intent:
  `Receive`, `Unlock`, `NewWallet`, `Deposit…`, `Pay…`, `Redeem…`,
  `Restore…`, card setup steps, paper steps, and so on). Carried on the
  element, so rearranging a page cannot rewire a button.
- `struct Interaction { hovered: Option<NodeId>, pressed: Option<NodeId>, selected_nav: usize, scroll: f32, frame: u32 }`:
  live input state, applied at render time.
- `struct LiveFrame<'a> { width: u32, height: u32, luma: &'a [u8] }`: a camera
  frame for `render_live`.
- `enum Anchor { Start, Middle, End }`: horizontal label placement.
- Views (plain structs and enums, `Debug, Clone`): `WalletView`
  (`sample()`, `loading()`, `locked()`, `empty(hint)`), `DenomTab`,
  `NoteCard`, `NoteState` (`is_actionable`, `is_wrong`, `label`, `is_live`,
  `is_done`), `AccountView`, `LockedView`, `ResetView`, `CardGate`,
  `StalledPrint`, `SettingsView`, `RpcEdit`, `RestoreSource`, `PaperView`,
  `PaperItem`, `PaperState`, `CameraView`, `ReceiveView` (`idle`, `failed`),
  `ReceiveState`, `RedeemView`, `RedeemQuote` (`elsewhere`), `RedeemState`,
  `PayView`, `PayableRow`, `PayState`, `DepositView`, `DepositState`,
  `DepositPreview`, `SetupView`, `SetupState`, `PromptView`, `Clip`.
- `struct SessionCreds { owner: Zeroizing<Vec<u8>>, account: Zeroizing<Vec<u8>> }`:
  `owner` opens owner-key operations (the passphrase, or the card PIN);
  `account` opens the vault holding the fee-paying account (the passphrase,
  or BIP85 child 2 on a card wallet). Named fields so the two cannot be
  swapped silently.
- `type GuiWallet = kenter_wallet::TokenWallet<kenter_client::WalletChain, kenter_wallet::FileStore, vault::GuiVault>`.

## Free functions

| Fn | Signature | Notes |
|----|-----------|-------|
| `check_skins` | `() -> Result<(), String>` | In a `packaged` build, fails if `skins/kenter/` is missing beside the executable. Always `Ok` in a development build. |
| `save_png` | `(canvas: &[u8], w: u32, h: u32, path: &str) -> Result<(), pelt::PeltError>` | Encode a canvas to PNG. |
| `canvas_to_argb` | `(canvas: &[u8], out: &mut [u32])` | Premultiplied RGBA to softbuffer's `0x00RRGGBB`. |

## Modules

Each module is a flow or a piece of one. Fallible functions return
`Result<_, String>` with a message meant for the holder.

| Module | Main items |
|---|---|
| `wallet` | `Network` (the resolved network: `name`, `rpc`, `passphrase`, `contract`, `roster`, `horizon`, `rpc_is_custom`; `init()`, `current()`, `rpc_client()`); `default_wallet_dir`, `home_dir`, `short`; `load`, `local_view`, `load_local` build a `WalletView` from the store. |
| `vault` | `GuiVault { Soft(SoftVault), Card(Box<StellarKeycard<Transport>>) }`, implementing `DerivingVault` by delegation; `GuiVault::open(custody, soft)` (a card wallet connects with `connect_expecting` at open); `session_credentials`. |
| `setup` | First run: `new_phrase`, `challenge`, `check`, `validate_phrase`, `create`, `create_as`, `create_at`, `phrase_matches`, `phrase_opens_paper`, `inspect_backup`, `Activation` / `activation`. |
| `card` | `Readiness` / `readiness()` (is there a usable card); `Presence` / `presence(expected_identity)`; `PINNED_CAS`; `PIN_LEN` = 6, `PUK_LEN` = 12, `PIN_RETRIES` = 5 (set explicitly; the applet default is 3); `check_pin`, `check_duress`, `generate_puk`, `group_puk`, `puk_matches`. |
| `card_setup` | `init_card`, `generate_phrase`, `load_phrase`, `restore_to_card`, `provision` → `CardWallet`, `write_working_copy`, `erase`, `unlock`, `account_credential`. |
| `receive` | `UiEvent` (worker results posted to the event loop), `Report`, `Ask`, `Standing`; `spawn`, `spawn_standing`, `spawn_unlock_with`, `spawn_card_unlock`, `unlock`, `watch`, `reserve_and_derive`, `readiness`, `can_unlock`, `default_vault_path`, `inbox_dir`, `copy_into_inbox`. |
| `deposit` | `ASSUMED_NODE_FEE` = 25,000 stroops; `fees_for(pairs, fee)` = `fee × 2 × (pairs − 2)` (interior pairs only); `redemption_value`, `floor`, `parse_amount`; `run` → `Deposited`. |
| `pay` | `payable` → `Vec<Payable>`, `is_spend_mode`, `repoint` (spend-mode transfer), `export`, `stage`, `promote`, `outbox_dir`, `held_token`. |
| `redemption` | `quote` → `Quote`, `redeem`, `redeemable`. |
| `account` | `Account` (`usable`, `has_trustline`, `asset_balance`, `blocked_by`); `MIN_XLM`; `read`; `Stalled` / `stalled_prints`; `cancel(net, credential, slot_id)`. |
| `settings` | `local`, `with_backup`, `with_account_status`, `verified_address`, `escrow_asset`. |
| `backup` | `EXT` = `"kbk"`; `file_name`, `working_copy_path`, `seed_source`, `save`, `refresh_working_copy`, `coverage`, `inspect_file`, `restore_file`, `adopt`, `open`, `when`, `now`. |
| `reset` | `Plan` / `plan(vault, store, now)`, `perform`, `CONFIRM_WORD` = `"RESET"`, `confirmed`. |
| `sheet` | A4 page geometry (`PAGE_W`, `PAGE_H`, `MARGIN`), `module_mm()` (0.30 mm; `KENTER_PAPER_MODULE_MM` overrides, clamped to 0.15–2.0), `slots`, `per_page`, `layout` → `Page` / `Placed`, `heading_lines`, `pages` (SVG). |
| `pdf` | `render(chunks, fingerprint, created) -> Result<Vec<u8>, String>`: a self-contained PDF writer. |
| `qr` | `QUIET` = 4; `svg`, `svg_with`, `svg_bytes`, `byte_mode_bits`. |
| `scan` | `WANTED_WIDTH` = 3000; `Found`; `read_image`, `read_dynamic`, `read_luma`, `read_frame`, `read_page`, `read_all`. Runs two QR decoders and merges their results. |
| `camera` | `Capture` (`start`, `start_on`, `grab`), `Event`, `cameras`, `remembered`, `remember`, `pixels_per_module`, `good_enough`. Decodes the full-resolution capture, never the preview. |

## Binaries

| Binary | Command | Does |
|--------|---------|------|
| `kenter-ui` | `cargo run -p kenter-ui --bin kenter-ui` | The wallet: a winit window presenting the canvas through softbuffer at the window's physical size. |
| `kenter-ui-mock` | `cargo run -p kenter-ui --bin kenter-ui-mock -- [screen] [scale] [frame]` | Renders one screen against fabricated data (no wallet, chain or card) to `crates/kenter-ui/kenter-ui-mock-<screen>.png` and prints cold and warm render times. Defaults: `wallet`, `1`, `0`. The fast loop for editing a skin. |

Feature `packaged` (set by the installers): skins are read only from
`skins/kenter/` beside the executable, and a missing folder stops the wallet.
Without it, a development build falls back to the source tree. Skins define
what the screens say, so an installed wallet must not read them from a path
an ordinary user might be able to create.

## Skins

Skins are SVG files in `skins/kenter/`, rendered by the `pelt` crate through
`usvg`/`resvg`. A skin carries its own states (`data-pelt-state`), theme
tokens and 9-slice scaling, and declares the text styles labels are drawn
with. The SVG is the source of truth: it must look in Inkscape as it looks in
the app, and the code applies no styling of its own.

## Tests

Screen tests live inline in `lib.rs`: build a `Screen`, assert on the text
and actions it offers. `tests/backup_recovery.rs` covers backup and restore.
`tests/card_ceremony.rs` and `tests/replacement_card.rs` provision and
restore real cards; they are destructive and gated twice: `#[ignore]` and
`KENTER_CARD_DESTRUCTIVE=1`.
