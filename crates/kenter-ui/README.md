# kenter-ui

The Kenter desktop wallet, built on the **pelt** SVG-skin engine. **Taffy**
lays out structure; each element's pelt (an SVG under `skins/kenter/`) paints
its look; a thin content layer draws text on top. Rendering is CPU: pelts
rasterize to premultiplied RGBA and alpha-composite into a canvas that is
presented in a window or saved as a PNG.

See `ARCHITECTURE.md` for how the crate is put together and `API.md` for its
public items.

## Building

`pelt` is an external crate. `Cargo.toml` takes it as a path dependency, so a
checkout of pelt must sit next to the Kenter repository directory
(`../pelt` relative to the repository root).

Installers build with `--features packaged`, which makes the wallet read
skins only from `skins/kenter/` beside the executable. Development builds
leave it off and fall back to the source tree.

## Run it

Two front-ends share one model (`src/lib.rs`).

### Interactive window

```sh
cargo run -p kenter-ui --bin kenter-ui
```

Opens a 960×620 window. It renders at the window's physical inner size, so it
is crisp on hi-DPI screens. On first run it walks through creating a wallet
(software custody behind a passphrase, or a keycard).

Where it keeps things:

| Variable | Default | Meaning |
|---|---|---|
| `KENTER_WALLET_DIR` | `~/.kenter/wallet` | The note store, shared with the `kenter` CLI. Received files go in its `inbox/`. |
| `KENTER_VAULT` | `~/.kenter/vault.json` | The vault (encrypted seed, or the card wallet's record). |
| `KENTER_CAMERA` | first camera | Camera for reading paper backups, by number or part of its name. |

The network (contract IDs, RPC, Horizon) is fixed per build by
`kenter-client`'s network profile; the RPC server can be overridden on the
Settings page.

Input:

- **move the cursor**: hover feedback on buttons and nav items
- **press the mouse**: button press state
- **click a nav item**: go to that page
- **scroll the wheel**: move a long list inside its panel
- **press R**: re-read the wallet and reconcile against the ledger

### PNG mock: the styling loop

```sh
cargo run -p kenter-ui --bin kenter-ui-mock [screen] [scale] [frame]
```

Renders one screen with sample content to
`crates/kenter-ui/kenter-ui-mock-<screen>.png` (gitignored) and prints the
path with cold and warm render times. No wallet, vault or ledger is needed.
`screen` defaults to `wallet`; others include `wallet-open`, `locked`,
`setup`, `phrase`, `done`, `deposit`, `pay`, `receive`, `prompt`, `address`,
`paid`, `failed`, `settings`, `account-busy`, `gate` and the `card-*` setup
steps (see `screen()` in `src/mock.rs`). `scale` is a hi-DPI factor;
`frame` picks a frame of an animated skin.

This is the fast loop for styling: open any file under `skins/kenter/` in
Inkscape (or any SVG editor), save, re-run, look at the PNG. No code changes.

## How it fits together

```
skins/kenter/*.svg   pelt art (appearance): the Inkscape restyle surface
      │
src/lib.rs           Ui: Taffy layout tree + skins + content labels + hit-test
      │              Ui::render_scaled(&Interaction) → premultiplied-RGBA canvas
      ├── src/mock.rs   → save_png()                   (bin: kenter-ui-mock)
      └── src/main.rs   → winit + softbuffer + workers (bin: kenter-ui)
```

- **Appearance is drawn, not coded.** A skin is a normal SVG with the small
  `pelt:` convention set: theme tokens (`var(--pelt-<name>, fallback)`), state
  variants (`data-pelt-state="default|hover|active|…"`), and 9-slice scaling
  (`pelt:scale="9-slice"` + `<pelt:slices>`). The SVG must look the same in
  Inkscape as in the app.
- **Text is content, not skin.** Labels and amounts are drawn as one-off
  `<text>` pelts over each element box, so skins stay reusable. Each label's
  style comes from a labelled sample text in the skin, so type is set in the
  SVG too.
- **State is applied at render time.** The Taffy tree never mutates; the
  renderer takes an `Interaction` and picks each element's state variant.
- **Rasterized layers are cached** by node, state, size and content, so a
  hover re-renders only the element whose state changed. The workspace
  `Cargo.toml` optimizes the render path in dev builds, so `cargo run` is
  smooth; `--release` is faster still.

## Examples and tests

`examples/` holds tools for the paper-backup path (sheet rendering, density
and calibration sheets, reading a sheet back from an image or camera) and a
skin preview. `tests/backup_recovery.rs` restores a wallet from its phrase
and backup with no card. `tests/card_ceremony.rs` and
`tests/replacement_card.rs` run first-run card setup and a restore onto a
replacement card against a real card in a reader. They wipe the card, so they
are `#[ignore]`d and also need `KENTER_CARD_DESTRUCTIVE=1`:

```sh
KENTER_CARD_DESTRUCTIVE=1 cargo test -p kenter-ui --test card_ceremony \
  -- --ignored --test-threads=1 --nocapture
```
