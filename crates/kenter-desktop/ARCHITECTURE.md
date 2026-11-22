# kenter-desktop — Architecture

**Role.** The reference command-line client, a native binary named `kenter`.
It drives the whole note lifecycle from a terminal: print a note through the
live node network, hold it in a local wallet, receive and verify notes from
others, reconcile against the mint, back up, and redeem. It also keeps an
offline path (`print`, `inspect`) for exercising the container format with no
network. It is a client, not the mint: it composes protocol pieces and holds
no escrow and no monetary policy.

The CLI and the desktop GUI (`kenter-ui`) are two shells over the same core,
store and chain adapter, so they agree about what a wallet holds and a store
written by one is read by the other.

## Boundaries

- **Depends on:** `kenter-crypto` (token construction, containers, chain
  hashes, spend authorization), `kenter-vault` (`SoftVault`: seed and keys
  under a passphrase), `stellar-keycard` (`KeycardVault`, card access over
  PC/SC), `kenter-wallet` with `fs` (held-note model, receive gates,
  reconciliation, the encrypted `FileStore`), `kenter-client` with `wallet`
  (`MintClient`, `RosterClient`, `WalletChain`, the network profile),
  `kenter-network` and `kenter-print` (the networked print walk), `tokio`.
- **Composes, does not own:** each command is argument parsing and display
  over those crates. Protocol rules, including the receive gates, live in
  the wallet core so that no shell can skip one.
- **Surface:** native only; one `kenter` binary with a flat subcommand table.
  `API.md` in this directory documents every command and flag.

## Structure

Everything is in `src/main.rs`. `main` matches `args[1]` to a `cmd_*`
handler, and each handler parses its own flags.

| Group | Commands | Network |
|---|---|---|
| Offline testbed | `print`, `inspect` | none |
| Keys | `seed generate/restore/status`, `keygen`, `keys`, `keycard status/generate/sign` | none (keycard uses the reader) |
| Wallet store | `import`, `held`, `forget`, `backup export/restore/inspect` | none |
| Ledger | `balance`, `sync`, `receive new/complete/list`, `redeem` | Soroban RPC |
| Printing | `print-net` | RPC + relays + node daemons |

`register` and `spend-demo` remain in the table only to print an error that
points at `print-net`.

## How the commands work

**`print` (offline).** Mints a note in-process, with one machine playing
every node role, and writes a `.symtoken`. It is a testbed for the container
format and cannot reach the ledger: the mint rejects a print whose pairs
repeat an address (`NodesNotDistinct`), so a single-key note can never be
registered.

**`print-net` (the real print).** Escrows the deposit with `request_print`;
the network then chooses the middle pairs through a drand-seeded draw that
node daemons claim into (see `docs/architecture/node-selection.md`). The CLI
reaches each selected node through the relay its roster record names, each
node extends the chain and confirms its own link on-chain, and the CLI
registers the note. The depositor opens and closes the chain with its own
pairs, so a print with `k` network nodes has `k + 2` pairs. Closing with the
depositor's own pair keeps the finished note out of reach of any coalition of
nodes. The depositor's pairs need no roster membership and no stake.
`--relay` overrides the relay only for a local test rig.

**The wallet store.** `import`, `held`, `forget`, `balance`, `sync`,
`receive` and `redeem` work on a persistent store: `--wallet <dir>`, else
`KENTER_WALLET_DIR`, else `~/.kenter/wallet`, one record per note written
atomically. The store is **encrypted** under credentials derived from the
vault's seed, because a pure-bearer note is redeemable from its bytes alone
and plaintext records would be money readable on disk. So a seed is
mandatory to hold anything, and each command that reads the store asks for
the vault passphrase once.

- `import` verifies each file offline (container parse, chain integrity) and
  refuses duplicates.
- `forget` deletes local bytes only. An unredeemed note that is not backed up
  is lost with them; a bearer note cannot be reissued.
- `balance` reconciles every held note against `kenter-mint`. Kenter has no
  balance query: a balance is the held notes partitioned by on-chain status
  (spendable, redeemed, unverified).
- `sync` repairs ownership: it binds a note whose receive crashed before it
  was recorded, and flags a note that has been paid away. The second matters
  because a paid-away spend-mode note is still `Active` on the ledger, and
  an unflagged one would count as spendable. It needs no vault,
  because the owner commitment is stored on the record at bind time.

**`receive`.** `new` derives a fresh owner commitment from the vault's seed
and records the pending receive. `complete <file>` runs the gates against
the bytes the payer sent: G1 structure, G2 active on the ledger with the
right amount, G3 ownership moved to us, G4 persist. Until `complete`
succeeds the holder has not been paid, whatever bytes they hold.

**`backup`.** A recovery phrase restores owner keys but not notes, which
cannot be found from the ledger. The backup file holds the note records,
sealed under a key derived from the seed, so restoring needs the phrase and
the file and not the vault file, which is the thing a backup must survive
losing. It has to be refreshed after every receive.

**`redeem`.** Uses `redeem_by_chain` (pure bearer) or `redeem_by_chain_owned`
(spend mode). The holder presents the chain data from the stored note; the
mint checks it against the `chain_hash` committed at registration and pays
`amount − node_fee × 2 × pairs` from escrow. No node is involved. A pure
bearer redemption also carries a signature from the note's claim key over
the contract and recipient, so a chain revealed by a failed transaction is
not enough for someone else to redeem. In spend mode the current owner key
is derived from the vault using the owner index recorded at receive, so it
never leaves the vault; an owner key from `KENTER_OWNER_SECRET` or
`--owner-secret-file` is the fallback for a key held elsewhere. `--to` pays the escrow to any account in the same transaction.
`--dry-run` runs the contract through `simulateTransaction` and reports the
cost without submitting. The cost of node-free redemption is publicity: the
whole construction chain is written on-chain. See
`docs/architecture/spend-mode.md`.

**`keycard`.** `status` reports whether the card is initialized and its
secure-channel key; `generate` creates a key on the card after pairing and
PIN entry; `sign` signs a message with it.

## Invariants

- **Offline verification before the network.** Every command that touches a
  note runs container parsing and `verify_chain_integrity` first, so a
  malformed or unsigned note never reaches an RPC call.
- **One implementation of the receive gates.** They live in `kenter-wallet`;
  this binary only calls them.
- **Funded secrets are not taken from the command line by preference.** A
  funded Stellar secret is read from the environment first
  (`KENTER_DEPOSITOR_SECRET` for `print-net`, `KENTER_REDEEM_SECRET` for
  `redeem`), then `--secret-file`, then `--secret`. A command line is visible
  to other processes and lands in shell history.
- **Network fixed per build.** RPC, contract IDs and passphrase come from the
  `kenter-client` network profile (testnet unless built for mainnet), with
  environment overrides. `--rpc` may change the endpoint; on a mainnet build
  a flag never changes the contracts.
- **Reads need no funded account.** Ledger reads go through
  `getLedgerEntries` or simulation and do not touch a source account. Only
  `print-net` and `redeem` need a funded key.
