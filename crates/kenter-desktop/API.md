# kenter-desktop — API

The `kenter` command-line client: a reference shell over `kenter-wallet`,
`kenter-client` and `kenter-print`. Each subcommand parses its own flags;
an unknown `--flag` is an error. Flags may appear in any order; positional
arguments (files, ids) are collected. Passphrases and PINs are read from
**stdin**, one line, unmasked; they are never taken from argv or the
environment. Amounts are in stroops (10⁷ stroops = 1 unit of the escrowed
asset) and print as `$1.2500000`.

## Commands

| Cmd | Arguments | Behaviour |
|-----|-----------|-----------|
| `print` | `--out <file>` (required), `--denom <stroops>` (default `1000000`), `--pairs <n>` (default `3`, min `2`) | Build a note **in process**, with fresh random keys playing every node, and write the SYMTOKEN container. Offline; nothing is escrowed or registered, so the note is not redeemable. For exercising the format. |
| `print-net` | `--out <file>` (required), depositor secret (below), `--pairs <n>` (default `3`, min `3`), `--denom <stroops>` (default `1000000`), `--rpc`, `--contract`, `--roster`, `--relay <host>`, `--insecure` | Print a real note across the node network. The depositor holds both end pairs; the interior pairs are nodes chosen by the mint's drand-seeded draw, each reached through the relay its roster endpoint names (restricted to the build's relay list). `--relay` fixes one relay instead, for a local rig; `--insecure` uses plain HTTP to it. Prints in pure-bearer mode. Deposits `--denom`, out of which the interior nodes' fees are paid. See [node selection](../../docs/architecture/node-selection.md). |
| `inspect` | `<file>` | Check the SYMTOKEN magic, chain integrity (link signatures and hash chain) and the container signature (against node A of the final link). Prints the metadata. Exits non-zero if either check fails. |
| `import` | `<file>...` (at least one), `--wallet <dir>` | Verify each container offline (parse plus chain integrity) and store it. A file already held is reported as skipped. Exits non-zero if any file failed. |
| `held` | `--wallet <dir>` | List held notes: id, face amount, import time. Offline: face values only, no redemption state. |
| `forget` | `<id-or-prefix>`, `--yes`, `--wallet <dir>` | Delete a note's record. Without `--yes` it shows whether a mint has confirmed the note and asks you to type the amount in stroops to confirm. Local only; if it was the only copy of an unredeemed note, the value is lost. |
| `balance` | `--wallet <dir>`, `--rpc <url>`, `--contract <id>` | Reconcile every held note against the mint. Prints a status table and spendable / redeemed / unverified / spent-away / total held. |
| `sync` | `--wallet <dir>`, `--rpc <url>`, `--contract <id>` | `TokenWallet::sync`: binds a note whose receive crashed before binding, and flags notes paid away. Run it after paying someone, or the paid note still counts as spendable. Needs no vault. |
| `receive new` | `--vault <file>` (required), `--wallet <dir>`, `--rpc`, `--contract` | Reserve a fresh owner index, derive its commitment from the vault seed, record the pending receive, and print the pay tag for the payer. |
| `receive complete` | `<file>`, `--wait <secs>` (default `0`), `--wallet <dir>`, `--rpc`, `--contract` | Run the receive gates (G1 structure, G2 ledger, G3 ownership, G4 store) against the bytes the payer sent. Retries every 3 s until `--wait` expires, but only while the failure is marked retryable. The owner index comes from the ledger, matched against every commitment the wallet can open. Refuses if the wallet has no pay tag. **You are not paid until this succeeds.** |
| `receive list` | `--wallet <dir>` | Outstanding pending receives: index, commitment, creation time. |
| `redeem` | `<id-or-prefix>`, payout secret (below), `--to <G...>`, `--vault <file>` or `--owner-secret-file <path>`, `--dry-run`, `--wallet <dir>`, `--rpc`, `--contract` | Redeem by chain. Verifies the stored bytes offline, checks the record is `Active`, then calls `redeem_by_chain` (pure bearer, with a claim signature over the recipient) or `redeem_by_chain_owned` (spend mode, with an owner proof). The escrow goes to `--to`, or to the submitting account. In spend mode the owner key is derived from `--vault` at the note's recorded owner index; an owner key from `KENTER_OWNER_SECRET` or `--owner-secret-file` is for a key held outside the wallet and is checked against the live commitment before submitting. `--dry-run` simulates against the live ledger and prints instructions and footprint instead of submitting. The record is kept, so `balance` shows it as redeemed. |
| `backup export` | `<file>`, `--vault <file>` (required), `--wallet <dir>` | Seal every note, pending receive and the owner-index counter into a `.kbk` file under a key derived from the seed. Re-export after every receive. |
| `backup restore` | `<file>`, `--vault <file>` (required), `--wallet <dir>` | Open a backup and merge it with `backup::restore`: additive, never overwrites a held note, refuses notes that fail `backup::check`, moves the counter forward only. Then run `sync`. |
| `backup inspect` | `<file>` | Print the cleartext header (wallet fingerprint, note count, version, seed origin, BIP85 path, content digest). Needs no wallet or vault. |
| `seed generate` | `--vault <file>` (required) | Create the BIP-39 seed that owner keys derive from (`m/44'/148'/n'`). Asks for the vault passphrase twice and prints the 24-word phrase once. Refuses if the vault already has a seed. |
| `seed restore` | `--vault <file>` (required) | Read a phrase from stdin into a vault with no seed, and print the standing pay-tag commitment (index 0) to compare with the old wallet. |
| `seed status` | `--vault <file>` (required) | Whether a seed is present and, if so, the standing pay-tag commitment. |
| `keygen` | `--vault <file>` (required), `--label <name>` (default `default`) | Generate an Ed25519 Stellar account key in the `SoftVault`. On an empty vault the passphrase is asked twice. |
| `keys` | `--vault <file>` (required) | List vault keys: slot, label, address. No passphrase. |
| `keycard status` | — | Over the PC/SC reader: whether the card is initialized, and its secure-channel public key. |
| `keycard generate` | — | Pair with the default pairing password, read the PIN, generate the card's key, print its key UID. |
| `keycard sign` | `--message <text>` | Pair, read the PIN, and sign SHA-256(message) with the card's secp256k1 key; prints hash, public key and DER signature. A card diagnostic, not part of the note flow. |
| `help`, `--help`, `-h`, none | — | Print usage. |

`register` and `spend-demo` are recognised only to exit with an error
pointing to `print-net`: a note can only be escrowed by a print whose
interior pairs are distinct roster nodes.

### Funded secrets

`print-net` (depositor) and `redeem` (submitter and default payout account)
need a funded Stellar secret. It is taken from the environment
(`KENTER_DEPOSITOR_SECRET` for `print-net`, `KENTER_REDEEM_SECRET` for
`redeem`), else from `--secret-file <path>`. Secrets are never accepted on
the command line, where other processes and the shell history would see
them: `--secret` and `--owner-secret` are refused with an error naming the
alternatives.

### Balance statuses

`balance` maps `kenter_wallet::TokenStatus` to: `active (spendable)`,
`redeemed`, `not on chain`, `unknown`, `DISPUTED - the ledger's record is not
this note` (`Counterfeit`), `another mint - not checked here` (`OtherMint`),
`unconfirmed - no mint has vouched for these bytes` (`Unbound`), `owned by
someone else - the ledger names another owner` (`NotOurs`).

## The wallet store

The wallet commands share one `kenter_wallet::FileStore`, found at:

1. `--wallet <dir>`
2. `$KENTER_WALLET_DIR`
3. `~/.kenter/wallet` (`%USERPROFILE%\.kenter\wallet` on Windows)

The store is encrypted under keys derived from the vault seed, so every
command that opens it needs a vault with a seed and asks for its
passphrase. The store's vault is found at `$KENTER_VAULT`, else
`~/.kenter/vault.json`. This lookup is separate from `--vault`: a command
that takes `--vault` for signing or sealing (`receive new`, `redeem`,
`backup`) still unlocks the store through the default vault path, so keep
the two the same or set `KENTER_VAULT`.

The on-disk layout (sealed records under keyed filenames, atomic writes, the
advisory write lock shared with the desktop app) is described in
[`kenter-wallet/API.md`](../kenter-wallet/API.md#filestore-feature-fs).
The CLI and the desktop app can use the same directory at the same time.

## Network

Defaults come from the network profile compiled into `kenter-client`
(`crates/kenter-client/src/network.rs`): testnet, unless `kenter-client` is
built with its `mainnet` feature. The environment can override the endpoint
(`KENTER_RPC`) and, on testnet only, the contracts (`KENTER_MINT`,
`KENTER_ROSTER`). The `--rpc`, `--contract` and `--roster` flags override
those again under the same rule: a mainnet build accepts a contract flag
only if it names the contract the build was made with.

## Behaviour notes

- **Verify before network.** `import` verifies offline and makes no RPC
  call unless the id collides with a held note, in which case the ledger
  decides which copy is genuine.
- **Redemption is by chain.** `redeem` publishes the note's construction
  chain on-chain; it needs no node network and no shard secrets.
- **The CLI has no transport.** Notes move between people as files:
  `receive new` prints a pay tag, the payer spends to it and sends the
  container, and `receive complete` checks it.
- **Owner keys stay in the vault.** Spend-mode redemption derives the key
  from the seed at the recorded owner index; nothing is written to disk.
