# Supporting crates

Six smaller crates: two services, the printing library, the CLI, a test
harness and a browser spike.

## `kenter-node`: a pair node

A library (`kenter_node`) and two binaries: `kenter-node` (CLI and headless
service) and `kenter-node-tray` (desktop tray, feature `tray`). The CLI, the
service and the tray all run the same library code.

**One install is one pair.** `PartialToken::extend` dual-signs a link, so
whoever builds a pair's link can also compute its shard. The pair, not the
node, is the unit of trust, and a daemon hosting several pairs would look
like several parties while being one.

| Module | Holds |
|---|---|
| `home` | Where an install keeps its files: one directory per network (`%LOCALAPPDATA%\kenter-node\<network>` on Windows, `$XDG_DATA_HOME/kenter-node/<network>` or `~/.local/share/kenter-node/<network>` elsewhere). `KENTER_NODE_HOME` replaces the whole path |
| `config` | `node.json`: name, relays, terms. No secrets |
| `keys` | The pair's two keys, both derived from one node-only BIP-39 phrase at SLIP-10 accounts far from the indexes wallets use. The phrase can live in a file or the OS keystore (feature `keystore`) |
| `chain` | The node's own calls: join, reactivate, record its endpoint, heartbeat, claim, leave, withdraw; and the reads behind `status` |
| `daemon` | Prepare (wait for funding, join the roster), serve with relay fallback, leave selection on a clean stop |
| `select` | Register the pair for selection, watch the mint for slots, seed slots whose drand round is out, claim positions the pair might win. Spending is bounded by a daily XLM allowance |
| `slot_cache` | The slots extend requests name, held about a ledger, so the check before an extend costs a few RPC reads per burst instead of two per request. A refusal a later ledger could overturn is checked again on a fresh read, at most once a second per slot |
| `status` | What the daemon reports, and the lock that says one is running |
| `tray` | Tray icon and a separate settings process (Windows and macOS) |

Commands:

```text
kenter-node init [--name <n>] [--relay <host>]... [--insecure] [--volunteer] [--restore] [--keystore]
kenter-node addresses     # the two addresses and the XLM each needs to join
kenter-node run           # serve (the default when the home has a node)
kenter-node status | stop | claim | leave | withdraw | show-phrase
kenter-node keystore [status|enable|disable|wipe-file]
```

`claim`, `leave` and `withdraw` refuse while the node is running. The RPC
comes from `node.json`, else `KENTER_RPC`, else the build's default.

Each node serves three endpoints through the relay:

| Endpoint | Purpose |
|---|---|
| `/kenter/health` | Liveness, and the pair's addresses |
| `/kenter/extend` | Printing. Extends a partial token with one dual-signed link, then confirms the link on-chain |

The handlers live in `kenter-network`; this crate runs them.

For development and `kenter-systest` there is a flag form that takes the
pair's secrets from the environment (never from argv):

```bash
KENTER_NODE_SECRET=S… KENTER_NODE_PARTNER_SECRET=S… \
cargo run -p kenter-node -- --tunnel 127.0.0.1:8080 --insecure
```

The development help option of `kenter-node` lists these flags (`--roster`, `--mint`, `--rpc`,
`--no-roster`, `--volunteer`, `--no-confirm`, `--secret-file`,
`--partner-secret-file`, …).

## `kenter-tunnler`: the relay

Nodes connect over WebSocket and authenticate with a Stellar-signed JWT; the
relay checks the **on-chain roster** before admitting a node, and proxies
HTTP requests through the tunnel to it.

A node that authenticates and is then refused is almost always not on the
roster.

- `crates/kenter-tunnler/API.md` for configuration and endpoints
- [Relay API](/tunnler-api)
- [Relay deployment](/DEPLOY)

## `kenter-print`: networked printing

Walks a partial token around the nodes the network chose. Both clients print
through it: the CLI's `print-net` and the GUI's Deposit.

The depositor holds the first and the last pair. Pair 0 needs both of its
keys for `PartialToken::initiate`, and `assemble_bearer_token` closes the
chain with the requestor's own pair, which guarantees one honest pair in
every chain. A print with `k` network nodes is therefore `k + 2` pairs. The
depositor names only its two end pairs, which are exempt from the roster
check; the interior pairs claim their positions after a drand round seeds the
slot, so the depositor cannot choose them and the wallet needs no node list.
See [Node selection](/architecture/node-selection).

It is a crate of its own because the CLI and the GUI are sibling binaries
that cannot reach into each other, `kenter-client` has no business walking a
network, and `kenter-wallet` must stay wasm-safe.

## `kenter-desktop`: the CLI

Binary name **`kenter`**. The reference client and integration testbed,
sharing the wallet core, store and chain adapter with the GUI.

| Command | What it does |
|---|---|
| `print` | Build a note in process with random keys. Offline, not redeemable; for exercising the format |
| `print-net` | Print a real note across the node network |
| `inspect` | Verify a container and show its metadata |
| `import`, `held`, `forget` | Manage held notes locally |
| `balance`, `sync` | Reconcile held notes against the mint |
| `receive new / complete / list` | The receive flow and its gates |
| `redeem` | Redeem by chain, pure bearer or spend mode |
| `backup export / restore / inspect` | `.kbk` backups |
| `seed`, `keygen`, `keys` | The vault's seed and account keys |
| `keycard status / generate / sign` | Card diagnostics |

`inspect` is the fastest way to find out what a `.symtoken` actually
contains when something looks wrong. Full flags are in
`crates/kenter-desktop/API.md`.

## `kenter-systest`: the guided system test

Brings up a relay and real node daemons on this machine, points GUI clients
at them, and checks the ledger after each step the operator takes. It does
**not** drive the GUI, on purpose: there are no automation hooks, and adding
some would mostly test the hooks. An assertion is a ledger-visible
consequence (escrow moved, links confirmed by the nodes, an owner pointer
moved, a payout landed), not a screen that advanced.

[Full page](/testing/systest) · [Procedure](/SYSTEM_TEST)

## `kenter-wallet-wasm`: the browser spike

Deliberately minimal. It answers one question: **does the Rust crypto
compile to `wasm32-unknown-unknown`, load in a browser, and run a real note
loop at an acceptable bundle size?** Depending on `kenter-crypto` at all
forces its whole dependency tree to build for wasm, which is the real test.

It exposes keypair generation (driving `rand`/`getrandom` across the wasm
boundary), a sign/verify round trip, and a self-test that builds, serializes
and verifies a 3-pair note inside wasm. The bundle is about 105 KB gzipped.
Full surface: `crates/kenter-wallet-wasm/API.md`.

::: warning This is a spike, not a product
Do not grow it into a browser wallet. A browser wallet would consume
`kenter-wallet` through its port traits, with a `fetch`-based chain reader
and an IndexedDB store.
:::
