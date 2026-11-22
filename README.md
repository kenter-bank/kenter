# kenter

Non-custodial **bearer notes** on Stellar. A note is a file: whoever holds it
can redeem it, with no account required and no issuer able to freeze or
reverse it. Value is escrowed in an immutable, adminless Soroban contract and
released only against a cryptographic proof the holder carries with them.

Each note is registered in one of two modes, because the trade-off is real
and has no single right answer:

- **Pure bearer**: like cash. Handing it over leaves no trace: no
  transaction, no record of who held it. If someone copies the file, they can
  spend it first.
- **Spend mode**: like a registered instrument. Only the owner can spend it,
  because spending needs a key only they hold. The cost is that every change
  of hands is on the ledger.

Neither hides the ends: the ledger always shows which account deposited a
note and which account finally redeemed it. Pure bearer hides the path
between them.

## Status

**Testnet only. No independent security review. Do not put real money in
it.**

The protocol, the contracts, the printing network and a desktop wallet are
built. The whole loop (deposit, print across live nodes, hand over, accept
through the receive gates, redeem) runs end to end against Stellar testnet,
with home nodes on Linux, Windows and a Raspberry Pi.

Nobody chooses the nodes that print a note. The depositor names only its own
two end pairs; a future drand round, verified on chain, seeds the print;
registered node pairs claim its interior positions; and the lowest scores
win. The wallet has no node list and no relay setting.

Not built: a mobile client (the wallet core compiles to WebAssembly, but only
as a spike), hardware custody on production card silicon, and a combiner for
node-assisted (Path A) redemption.

## Layout

| Crate | What |
|---|---|
| `kenter-crypto` | Note construction, the n-of-n additive shard chain, spend-mode primitives |
| `kenter-wallet` | Wallet core: sealed store, receive gates G1–G4, owner-key association. No I/O |
| `kenter-client` | Soroban RPC, transaction build/sign/submit, typed mint and roster clients, the drand beacon |
| `kenter-network` | The printing protocol over a relay |
| `kenter-node` | A printing node: claims positions in prints, serves its links; tray, CLI, MSI and `.deb` |
| `kenter-tunnler` | The WebSocket relay nodes are reached through |
| `kenter-vault` | Key custody behind a port: the software vault, and the traits the card vault implements |
| `kenter-ui` | The desktop wallet (winit + Taffy + SVG skins) |
| `kenter-desktop` | The same wallet as a CLI |
| `kenter-systest` | System test against live testnet: interactive phases, `--skip-test`, `--remote` |
| `kenter-print` | Drives a print to completion across the selected nodes |
| `kenter-wallet-wasm` | The wallet core compiled for the browser (spike) |
| `stellar-keycard` | Smartcard client: secure channel, PIN, signing |
| `contracts/` | `kenter-mint` (immutable, adminless) and `kenter-roster` (adminless) |

The on-card side of hardware custody is a separate repository,
**kenter-keycard**: a fork of Status's Keycard applet that derives and signs
Stellar Ed25519 keys on the card.

## Build

```sh
cargo build --workspace
cargo test  --workspace
```

Contracts build separately under `contracts/`; see `docs/DEPLOY.md`. To run a
node, see "Running a node on testnet" in `docs/TESTNET.md`.

The system test drives real testnet contracts and two real wallet windows, so
it needs a funded account and a person for the half that exercises the GUI:

```sh
export KENTER_SYSTEST_FUNDER_SECRET=S...      # never passed on argv
cargo run -p kenter-systest -- --from 8       # the phase that needs nobody
cargo run -p kenter-systest -- --skip-test    # unattended: a selected node dies
```

`docs/SYSTEM_TEST.md` explains the phases.

## Documentation

The documentation is a VitePress site under `docs/` (`cd docs && npm install
&& npm run dev`). Start with:

- `docs/index.md`: what Kenter is and what is built
- `docs/reading-guide.md`: what to read, depending on what you are doing
- `docs/architecture/overview.md`: how the pieces fit
- `docs/architecture/node-selection.md`: how a print gets its nodes
- `docs/architecture/spend-mode.md`: bearer and spend mode, owner keys
- `docs/architecture/security-model.md`: what each component trusts, and what
  stops the main attacks
- `docs/bearer-token-format.md`: the note's cryptography and byte layout
- `contracts/kenter-mint/API.md`: the mint's entry points

Each crate also has an `ARCHITECTURE.md` and, for most, an `API.md`.

## Cross-language byte layouts

The card applet must reproduce Kenter's spend-mode messages byte for byte, or
its signatures will not verify on chain. Those layouts are pinned in
`tests/vectors/spend_vectors.json`, generated from `kenter-crypto`. Change a
layout and the test fails and names what to update:

```sh
cargo test -p kenter-crypto --test spend_vectors
KENTER_BLESS_VECTORS=1 cargo test -p kenter-crypto --test spend_vectors  # deliberate change
```

## Licence

Apache-2.0.
