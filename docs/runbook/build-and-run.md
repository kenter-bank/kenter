# Build and run

## The binaries

| Command | Crate | What it is |
|---|---|---|
| `cargo run -p kenter-ui --bin kenter-ui` | `kenter-ui` | **The desktop client.** The primary surface. |
| `cargo run -p kenter-ui --bin kenter-ui-mock` | `kenter-ui` | The GUI against mock data — no wallet, no chain, no card. |
| `cargo run -p kenter-desktop --bin kenter` | `kenter-desktop` | The CLI: `print-net`, `import`, `held`, `balance`, `redeem`, `backup` and more (`kenter help`). |
| `cargo run -p kenter-node` | `kenter-node` | A pair node (`kenter-node --help`). |
| `cargo run -p kenter-tunnler` | `kenter-tunnler` | The relay. |
| `cargo run -p kenter-systest` | `kenter-systest` | The guided local system test. |

## Running the client

The client needs to know where its wallet lives. Both paths can come from the
environment, which is how you keep several test wallets side by side:

```bash
KENTER_VAULT=/path/to/vault.json \
KENTER_WALLET_DIR=/path/to/wallet \
cargo run -p kenter-ui --bin kenter-ui
```

With neither set it falls back to a default location — the same one the CLI
uses, so the two open the same wallet.

::: tip Skip the rebuild check when iterating
`cargo run` re-checks the whole dependency graph before it starts. When you
are opening and closing the window repeatedly, build once and run the binary
directly:

```bash
cargo build -p kenter-ui --bin kenter-ui
./target/debug/kenter-ui
```
:::

### The mock client

`kenter-ui-mock` renders every screen against fabricated data. It needs no
wallet, no network and no card, so it is the fastest way to look at a layout
change — and the only way to see screens that are hard to reach for real,
like a half-failed restore.

## Build gotchas

**Do not set `CARGO_PROFILE_*` environment variables.** Any profile change is
a new cache key, so a flag intended to make a build cheaper triggers a full
rebuild of the entire dependency graph — and another when you remove it. Use
`-j N` to limit parallelism instead; that is cache-safe.

**`kenter-ui` dominates build time.** It is one large crate whose link step
takes about 1.7 GB resident and minutes of wall clock. If a machine is short
on memory, that link is what gets killed. `-j 2` helps.

**A running binary holds its own `.exe`.** On Windows, rebuilding while the
client or a harness is open fails with `LNK1104: cannot open file`. Close the
window first; that is all it means.

**`target/` grows without limit.** On a long-lived checkout it reaches
hundreds of gigabytes and hundreds of thousands of files. Cargo stats every
one of them on every invocation, so a periodic `cargo clean` — or
`cargo-sweep` for the gentler version — pays for itself.

## Examples

Examples are how most of the hardware and paper work gets driven. They build
with `cargo build -p <crate> --examples` and run with `cargo run -p <crate>
--example <name>`.

### `kenter-ui`

| Example | What it does |
|---|---|
| `paper_sheet` | Render a paper backup sheet |
| `calibration_sheet` | A page of QR symbols at descending densities, for measuring what a capture chain can read |
| `read_back` | Read images and report which symbols came back |
| `paper_lab` | **A live viewfinder.** Camera, per-item progress strip, console reporting. |
| `bakeoff` | Run every QR reader over the same images and compare |
| `density_sweep` | Which densities survive which capture resolutions, headless |
| `camera_probe` | What raw formats this machine's cameras offer |
| `camera_grab` | Open the camera, take frames, prove pixels arrive |
| `demo_restore` | A restore against fixture data |
| `paper_density` | Which QR version a backup's symbols land at, and the pixels per module that leaves |
| `paper_sweep` | Whether capping symbol density makes a printed sheet more readable |
| `paper_versions` | The QR version of each symbol on the calibration sheet |
| `paper_which` | Which symbol on a rendered sheet fails to read, by name |
| `skin_preview` | Render one skin at a chosen size (`-- logo 192 out.png`) |

See [Paper and camera](/testing/paper) for how these fit together.

### `stellar-keycard`

| Example | What it does |
|---|---|
| `detect`, `probe_card`, `probe_select`, `probe_v2`, `probe_eddsa` | Non-destructive inspection of a card |
| `probe_cert`, `probe_identity` | Dump the card's identity certificate, and check it against the pinned CA. Spend no PIN attempt |
| `probe_pin_carryover` | Check that a new secure channel does not inherit a verified PIN. Needs `KENTER_CARD_PIN` |
| `card_inventory` | What is on the card |
| `card_sign` | Sign with a key on the card |
| `init_and_open` | Initialise a card and open a secure channel |
| `keycard_keyvault` | Drive the `KeyVault` implementation against hardware |
| `card_wipe` | **Destructive.** Wipes the card. |
| `stellar_sim` | Against a simulator rather than a reader |

::: danger Card examples can destroy a card
Read [Keycard hardware](/testing/keycard) before running any of these with a
card on the reader. Some are irreversible, and a card with a real wallet on it
should never be near them.
:::

## Contracts

The Soroban contracts live in `contracts/kenter-mint` and
`contracts/kenter-roster`. Each is its own cargo workspace with its own
lockfile, outside the main workspace. Build them with the `stellar` CLI:

```bash
cd contracts/kenter-mint
stellar contract build
```

`stellar contract build` adds contract metadata that a plain
`cargo build --target wasm32v1-none --release` does not, and its output is
what a deployed contract's hash is checked against. Use it for anything you
deploy or verify. The pinned toolchain in `rust-toolchain.toml` applies here
too.

The contract tests run with `cargo test` inside each contract directory.
Deploying is covered in [Deployment](/DEPLOY). The testnet contract ids are
in the `TESTNET` profile in `crates/kenter-client/src/network.rs`. The
authoritative interface description is `contracts/kenter-mint/API.md`.
