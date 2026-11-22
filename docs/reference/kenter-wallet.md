# `kenter-wallet`

The wallet core: what a holder owns, how it reconciles against the chain,
and what the protocol requires before value moves. Shared by the desktop
client and the PWA.

::: danger This crate must stay wasm-safe
No `reqwest`, no sockets, no card readers, and no filesystem outside the
optional `fs` feature (which native shells enable for `FileStore` and the
wasm build leaves off). Everything outside comes in through a port trait.
The wasm target depends on this holding.
:::

## Modules

| Module | Holds |
|---|---|
| `wallet` | `TokenWallet`, the orchestrator |
| `ports` | `ChainRead`, `Store` |
| `models` | Held tokens, balances, reconciliation |
| `backup` | `.kbk` files, restore, coverage |
| `paper` | The `KPB2` paper format |
| `authz` | Authorization policy and prompting |
| `owner` | Owner commitments and authorizations |
| `store`, `fsstore`, `sealed` | `MemoryStore`; `FileStore` (feature `fs`); record sealing |
| `uri` | Receive addresses (`KENTER:RECV/…`) |
| `testing` | Fixtures, behind the `testing` feature |

## `TokenWallet<C, S, V>`

The orchestrator. Generic over a chain reader, a store, and optionally a
vault, so the same core can serve native and wasm shells.

```rust
let mut w = TokenWallet::with_vault(chain, store, vault);
```

| Method | Does |
|---|---|
| `new`, `with_vault` | Construct |
| `store()`, `chain()`, `vault()` | Borrow the parts |
| `import(bytes, at)` | Verify a `.symtoken` offline and store it |
| `held()` | Everything held |
| `forget(id)` | Delete a note's record. The ledger is untouched, but if this was the only copy of an unredeemed note, its value is lost |
| `reconcile()` | Compare held notes against the chain |
| `balance()` | Reconcile, then reduce to a `Balance` |
| `sync()` | Repair ownership: bind crashed receives, flag notes paid away (and returned) |
| `begin_receive(…)`, `start_receive(…)` | Open a receive |
| `reserve_owner_index()` | Claim the next fresh index |
| `record_pending(…)`, `pending()`, `forget_pending(index)` | Receives in flight |
| `complete_receive(bytes, now)` | Run the receive gates and store the note bound to its owner index |
| `known_owners()` | Owner commitments this wallet can open |
| `record_owner_commitment(id, c)` | Record the commitment on a self-printed note |
| `owner_commitment_for(index, credential)` | Compute one |
| `bind_owner(id, index)` | Attach an owner index to a note |
| `verify_ownership(credential)` | Re-derive and check — returns `OwnershipReport` |
| `record_export(id, kind)` | Log that bytes left the wallet |
| `mark_spent(id, spent)` | Local spent flag |
| `authorize_redeem(…)`, `authorize_spend(…)` | Owner authorizations; read the mint address and live spend nonce first |

### `OwnershipReport`

Returned by `verify_ownership`. Three-way: derived versus stored versus
live. It corrects or strips a commitment but **keeps the note** — and
`is_clean()` distinguishes "checked and fine" from "could not ask", because
a failure to ask is not an answer.

## `ports` — the seams

**`ChainRead`** — read-only chain access: `token_status(slot_id)`,
`mint_contract_xdr()`, `mint_id()`, `ledger_source()`. Implemented
natively by `kenter_client::WalletChain`. No browser implementation exists
yet.

**`Store`** — the note store. Implemented by `FileStore` (filesystem) and
`MemoryStore` (tests). Beyond holding notes it owns:

- `lock()` — the write lock for a read-modify-write. Not re-entrant.
- `allocate_owner_index()` — the next fresh index, never reused, never 0.
- `advance_owner_index(to)` — forward-only. `to = 0` is a read. Mirrors the
  card's `ADVANCE INDEX`, so software and hardware behave identically.
- `last_backup()` / `record_backup()` — what the backup warnings read.

::: warning `advance_owner_index` must never go backwards
Reusing an owner index links two notes to one key. Forward-only is why the
signature takes a target rather than a delta.
:::

## `models` — what a holder owns

| Item | Purpose |
|---|---|
| `HeldToken` | A note in the wallet, with its metadata |
| `ExportLog` / `ExportKind` | Every time bytes left, and how |
| `STATIC_RECEIVE_INDEX` = 0 | The standing pay tag |
| `FIRST_FRESH_INDEX` = 1 | Where per-note indices begin |
| `BackupRecord` | What a backup covered, and when. `covers()` answers staleness |
| `PendingReceive` | A receive in flight |
| `KnownOwner` | An owner key this wallet knows |
| `TokenStatus` | `Active`, `Redeemed`, `NotFound`, `Unknown`, `OtherMint`, `Unbound`, `Counterfeit`, `NotOurs` |
| `OnChainToken` | What the chain says |
| `ReconciledToken` | Held and chain views together. `trusted_amount()`, `claim_disputed()` |
| `SyncReport` | What a sync changed |
| `Balance` | Totals, including `disputed` |
| `DEFAULT_SYMBOL`, `fmt_stroops`, `fmt_amount` | Display |

`ReconciledToken::trusted_amount()` exists because a held note and the chain
can disagree, and showing the held figure as fact would be a lie. Disputed
value is surfaced separately rather than averaged in.

## `backup` — files and restore

| Item | Purpose |
|---|---|
| `encode(key, seed, tokens, pending, next_index, now)` | Write a `.kbk` |
| `export(store, key, seed, now)` | `encode` over everything a store holds |
| `decode(key, fingerprint, bytes)` | Read one |
| `inspect(bytes)` | Read the **cleartext header only** — what a restorer is asked, before any key |
| `BackupFile`, `BackupContents`, `SeedSource`, `SeedOrigin`, `Bip85Derivation` | The file and its header |
| `restore(store, contents)` | **Additive.** Never overwrites a held note |
| `RestoreReport` | Added versus already held. `is_empty()` |
| `check(token)` | Parse, verify chain integrity, confirm the id derives from the blob |
| `content_digest(tokens)`, `digest_of_ids(ids)` | Domain-tagged digests |
| `coverage(file, fingerprint, tokens)` | What a backup covers |
| `coverage_of_record(record, tokens)` | Same, from a record |
| `Coverage` | The answer |
| `record_for(tokens, at, whence)` | Build a `BackupRecord` |
| `seal_item(key, plain)` / `open_item(key, sealed)` | Per-item sealing for paper |

::: tip Restore is additive, and that is a feature
Scanning your own backup into a live wallet adds nothing and changes
nothing — so it is a safe way to *verify* a backup. `RestoreReport`
distinguishes "nothing new" from "nothing worked".
:::

::: danger `seal_item` uses a per-item nonce
A repeated nonce under one key leaks the XOR of two plaintexts. Each item
gets its own.
:::

## `paper` — the `KPB2` format

| Item | Purpose |
|---|---|
| `SYMBOL_CAPACITY` = 2331 | Version-40 symbol at EC M |
| `CHUNK_PAYLOAD` = 2306 | The format's ceiling, after the 25-byte header |
| `DEFAULT_CHUNK_PAYLOAD` = 850, `chunk_payload()` | What symbols are actually filled to (QR version 23 or below); `KENTER_PAPER_CHUNK_PAYLOAD` overrides |
| `Kind` | Wallet record, or note |
| `Chunk` | One symbol's bytes plus its position |
| `encode(wallet, tokens, pending, next_index, seal)` | Everything, as symbols |
| `read_symbol(bytes)` | Parse one symbol's header and payload |
| `Scanned` | A parsed symbol |
| `Sheet` | Accumulates symbols. Order-independent, idempotent. `finish` returns whatever is complete |
| `Recovered` | What a scan recovered; `into_contents` feeds `backup::restore` |
| `Progress` | Complete, partial, absent — per item |
| `calibration_symbol(…)` | A symbol of chosen size, for measuring capture chains |

Format and the reasoning behind each header field are in
[Data formats](/architecture/data-formats).

## `authz` — who is asked, and when

| Item | Purpose |
|---|---|
| `AuthAction` | What is being authorized, described |
| `Why` | Why the holder is being asked |
| `Policy` | How often to ask |
| `Authorization` / `PreAuthorized` | A credential, `Zeroizing` |
| `Prompter` | Asks a human. Handed a described action, **never just asked for a password** |
| `Authorizer` | Supplies credentials under a policy |
| `SessionAuthorizer<P>` | Over any `Prompter`, under `Policy::Session` (one unlock) or `Policy::PerAction` (fresh proof per value-moving action) |
| `NoAuthorizer` | Always refuses: a shell with no prompt must not sign |

The distinction between tiers — one session unlock versus a card tap per
value-moving action — lives here so both shells answer it the same way.

## `owner` — spend mode

| Function | Purpose |
|---|---|
| `commitment_for(vault, …)` | The owner commitment recorded on a note |
| `authorize_redeem(vault, …)` | Owner authorization to redeem |
| `authorize_spend(vault, …)` | Owner authorization to spend |

These refuse locally when the index does not open the live commitment,
and sign the 32-byte digest from `kenter_crypto::spend`, never a raw
message, so software and card signatures are interchangeable. See
[Spend mode](/architecture/spend-mode).

## `sealed` and `FileStore` — the store on disk

`FileStore::open(dir, creds)` takes `StoreCredentials` from the vault;
there is no way to open a store without them. Each record is JSON sealed
with XSalsa20-Poly1305 (`KNST1 || nonce || ciphertext`) and stored under an
HMAC-derived filename, so neither a note's bytes nor its id is visible in
the directory. Writes are atomic (temp file plus rename), and an OS
advisory lock on `<dir>/.write-lock` serialises writers across threads and
processes.

## `testing`

Behind the `testing` feature: real-note fixtures (`note`, `spend_note`,
`fabricated`). The crate is its own dev-dependency with the feature on, so
integration tests get them and shipped binaries never do.

`fabricated` builds a note that *looks* right but is not, which is how the
counterfeit-detection paths are tested.
