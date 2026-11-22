# kenter-wallet — Architecture

**Role.** The wallet core shared by every wallet shell. It holds notes locally,
reconciles each against its on-chain record, runs the receive gates that decide
whether a payee has been paid, signs owner authorizations for spend-mode notes,
and writes and restores backups. The `kenter` CLI (`kenter-desktop`) and the
desktop GUI (`kenter-ui`) both use it, and it compiles to `wasm32` so a browser
shell can use it too.

**Ports, not engines (the load-bearing property).** The core depends on port
traits — [`ChainRead`], [`Store`], the `kenter-vault` custody traits and the
[`Authorizer`] — never on a concrete transport, storage engine or card reader.
It pulls in only wasm-safe crates (`kenter-crypto`, `kenter-vault`, pure-Rust
AEAD and compression) and deliberately **no** `kenter-client`,
`kenter-network`, `reqwest` or full `tokio`. Each shell implements the ports
with its own engine. That inversion is what lets one implementation of the
protocol-critical checks serve native and browser shells alike.

## Boundaries

- **Depends on:** `kenter-crypto` (token model, container codec, offline
  verification, spend-mode digests); `kenter-vault` (`KeyVault`,
  `DerivingVault`, `StoreCredentials`, re-exported so shells name custody from
  one place); `crypto_secretbox`, `hmac`, `sha2`, `miniz_oxide`, `serde`.
  `tokio` only behind the `fs` feature.
- **Depended on by:** `kenter-desktop` and `kenter-ui` (with `fs`);
  `kenter-client`, whose `wallet` feature implements `ChainRead` as
  `WalletChain` over Soroban RPC. Rust's orphan rule puts that impl next to the
  client type, so both desktop shells share one chain adapter.
- **Features:** `fs` adds [`FileStore`], the filesystem `Store`. `testing` adds
  real, cryptographically valid note fixtures (`testing.rs`) for downstream
  tests and demos; they are not registered on any ledger.

## Modules

| Module | Purpose |
|---|---|
| `ports` | `ChainRead` and `Store` traits, `StoreGuard` |
| `models` | `HeldToken`, `TokenStatus`, `Balance`, pending receives, export log |
| `wallet` | `TokenWallet<C, S, V>`: import, reconcile, balance, sync, receive gates, ownership checks |
| `owner` | Owner-key commitments and spend/redeem authorizations from a `DerivingVault` |
| `authz` | `Authorizer`, `Prompter`, `AuthAction`, the two security tiers |
| `sealed` | Encryption and opaque naming for records at rest |
| `fsstore` | `FileStore` (feature `fs`) |
| `store` | `MemoryStore` for tests and ephemeral sessions |
| `backup` | Encrypted `.kbk` export and restore |
| `paper` | The same backup as printable QR symbols |
| `uri` | The `KENTER:RECV/` receive address |

## Core model: held notes, reconciliation, balance

Kenter has no account-balance query. Value lives in per-note ledger records,
so a holder's balance is computed client-side: enumerate locally held notes,
read each one's record, sum by status.

1. **`import`** takes container bytes plus a host-supplied time. It
   deserializes the container, verifies it offline (chain integrity and key
   consistency), and stores a [`HeldToken`]. The container bytes are kept
   verbatim so the signed note round-trips byte-identical. A note's id is its
   ephemeral Stellar address.
2. **`reconcile`** reads each note's record by its print slot
   (`ChainRead::token_status(slot_id)`) and pairs it with a [`TokenStatus`].
   The slot, not the ephemeral key, is the lookup key, because the mint keys
   records by slot. Reconciliation also checks that the ledger's record
   describes *these bytes*: the chain commitment and the claim key must both
   match, or the note is `Counterfeit`.
3. **`balance`** reduces the reconciliation to a [`Balance`]: `spendable`
   (Active and ours), `redeemed`, `unverified` (NotFound or Unknown),
   `spent_away` (still Active but owned by someone else), a `disputed` count,
   and `total_held`, a diagnostic sum over every record that is not a balance.
4. **`sync`** repairs ownership: it binds a note whose live owner commitment
   matches a pending receive (recovering a receive interrupted between showing
   a commitment and storing the note), and flags notes whose live commitment no
   longer matches the one recorded (paid away).

`TokenStatus` also has `OtherMint` (the note names a different mint, so it is
not read against this ledger at all), `Unbound` (no mint binding and nothing in
the ledger's answer could supply one) and `NotOurs` (live, but owned by a
commitment this wallet cannot open). These exist so the wallet never reports a
live note as redeemed, which is what would invite a holder to delete it.

## Receiving into spend mode

A spend-mode payee hands the payer an **owner commitment**, encoded as
`KENTER:RECV/<64 uppercase hex>` (`uri.rs`). Uppercase hex stays inside QR
alphanumeric mode, which packs denser than byte mode. The parser accepts either
case, with or without the prefix. The derivation index never travels: it would
link a payee's receipts to each other.

`start_receive` reserves the next fresh owner index, derives its commitment
and records a pending receive **before** the commitment is shown, so a crash
cannot lose an inbound payment. Indices are monotonic and never reused; index 0
is reserved for the opt-in static receive address, which trades linkability for
being reusable.

`complete_receive` runs the gates. The caller owns the polling loop.

- **G1, structure:** the container parses and its chain verifies offline.
  Never retryable.
- **G2, ledger:** the record exists, is Active, is worth what the bytes claim,
  names this note's key, and carries the chain commitment and claim key of these
  bytes. Already-redeemed is final; not-found may just mean the payer's
  transaction has not landed.
- **G3, ownership:** the live owner commitment is one this wallet can open.
  The contract moves the pointer only when the previous owner opens their
  commitment, so this gate is self-certifying against an honest ledger source.
  It is the gate worth waiting on. A pure-bearer note fails here by design:
  ownership cannot be proven, and first to redeem wins.
- **G4, bind:** store the note bound to the owning index. The owner key needs
  no separate backup; it re-derives from the seed and the index.

The gate reads are one endpoint's word. `ChainRead::ledger_source` names that
endpoint so the shell can show the payee what it trusted. See
[spend mode](../../docs/architecture/spend-mode.md) for the on-chain side.

## Owner authorizations and custody

`TokenWallet<C, S, V>` threads the vault through the core. The receive gates
and the owner-digest rule are protocol: a client that skips a gate or signs the
wrong bytes is unsafe, so they are implemented once here. A wallet built with
`TokenWallet::new` has no vault (`NoVault`) and simply lacks the signing
operations, which makes misuse a compile error.

`owner.rs` derives commitments and signs spend and redeem authorizations from
any `DerivingVault`: software (`SoftVault`) on both targets, or a keycard
(native, in `stellar-keycard`). Signatures cover `SHA-256(message)` so card and
software signatures are interchangeable. The current spend nonce is read from
the ledger immediately before signing and never cached. `verify_ownership`
re-derives each claimed owner key and strips a claim the vault cannot
reproduce, keeping the note.

## Authorization tiers

Every vault call takes a credential. `authz.rs` decides where it comes from and
how often a human is asked. A [`Prompter`] receives a described [`AuthAction`]
(`Receive`, `Spend`, `Redeem`, `Backup`, and so on), never a bare password
request, because a password box proves presence, not consent to *this*
transfer. `AuthAction` is deliberately not `#[non_exhaustive]`, so a new kind of
signature cannot ship without every shell writing down what it says.

- `Policy::Session` (default): one unlock covers the session.
- `Policy::PerAction`: every value-moving action is proved again. With a card
  that is a tap, which is both low-friction and a real intent proof.

Which actions move value is `AuthAction::moves_value`, so shells cannot
disagree about what may go unprompted. A card in a desktop reader shows its
prompt through the host, which a compromised host could falsify; a device with
its own screen cannot be lied through in the same way.

## Storage

- **`Store` port.** Async (browser backends are async), used through generic
  bounds so `async fn` in traits needs no boxing. It persists notes, the owner
  index counter, pending receives and the last-backup record.
  `advance_owner_index` only moves forward, so restoring an older backup can
  never hand out an index already in use.
- **Write lock.** `Store::lock` returns a `StoreGuard` held across a
  read-modify-write. `FileStore` implements it with an OS file lock on
  `.write-lock`, so several stores in one process and the CLI and GUI sharing a
  directory are serialized; the lock dies with the process, so there is nothing
  stale to recover. It is **not re-entrant**: exactly one method per call path
  takes it. Network reads run outside the lock, and writes go through a
  compare-and-commit against the snapshot that was read.
- **Sealed records.** For a pure-bearer note the container bytes are the money,
  so `FileStore` cannot be opened without `StoreCredentials`. Each record is
  `KNST1 || nonce(24) || XSalsa20-Poly1305(ciphertext)`, and its filename is a
  keyed hash of its id, so a directory listing does not reveal which notes (and
  therefore which public ledger amounts) are held. A plaintext file in the
  store is reported, never read.
- **Layout.** One file per note under `tokens/`, one per pending receive under
  `pending/`, and `state.json` for the counter (guarded by its own
  `.state-lock`). Writes go to a temporary sibling and are renamed into place,
  so a reader never sees a half-written record.

## Backup and restore

A recovery phrase restores authorization, not value: notes cannot be
enumerated from the ledger, so a complete backup is the phrase plus the note
bytes. `backup.rs` writes the note half as a `.kbk` file carrying the notes,
their owner indices, the index counter and pending receives, sealed with
XSalsa20-Poly1305 under a key derived from the HD seed. A restore therefore
needs the phrase and the file and nothing else. When the vault seed is a BIP85
child of a root held elsewhere (for example on a card), the cleartext header
records the child index, because the payload is sealed under the key that index
is needed to derive. `restore` merges into a store; `coverage` tells a shell
which held notes the last landed backup does not include. A backup is recorded
only after it has been written.

`paper.rs` prints the same material as QR symbols, with the wallet state and
each note as separate sealed items. One unreadable symbol then loses only the
item it belongs to, and a new note is a new sheet rather than a reprint. Each
symbol carries `"KPB2" | wallet(8) | kind | item | items | index | total |
digest | payload`. Symbols are printed at error-correction level M, which keeps
them at a QR version a camera reads reliably; the level is not part of the
format, so a reader decodes any level. A paper backup is sealed under the seed,
so it is a backup, not cash.

## Reference

`API.md` in this directory lists the public surface.
