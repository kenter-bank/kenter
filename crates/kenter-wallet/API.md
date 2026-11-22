# kenter-wallet — API

Rust crate. Public surface only. The wallet core shared by every client
shell: the held-note model, reconciliation against the mint, the receive
gates, owner authorizations, backups (file and paper), and the
authorization port.

The crate is wasm-safe. It never opens a socket, a file or a card reader;
everything outside comes in through a port trait (`ChainRead`, `Store`,
`Prompter`/`Authorizer`, and the `kenter-vault` custody traits). The one
exception is `FileStore`, behind the `fs` feature, which native shells turn
on and the wasm build leaves off. Every async method is used through
generic bounds, so `async fn` in traits needs no boxing.

Kenter has no balance query. A balance is the sum of the notes a holder
keeps locally, each reconciled against its on-chain record. The wallet
therefore stores note bytes and reads the chain only for status.

## Features

| Feature | Adds |
|---|---|
| `fs` | `FileStore`, the filesystem `Store` (pulls in `tokio`). Off for wasm. |
| `testing` | The `testing` module: real-note fixtures for tests and demos. |

## `TokenWallet<C: ChainRead, S: Store, V = NoVault>`

The orchestrator. Composes a chain reader, a store and, optionally, a
custody backend.

### Construction and access

| Fn | Signature | Notes |
|----|-----------|-------|
| `new` | `(chain: C, store: S) -> TokenWallet<C, S, NoVault>` | No custody backend. Import, reconcile, sync and balance work; owner-key operations do not exist on this type. |
| `with_vault` | `(chain: C, store: S, vault: V) -> Self` | With a custody backend. |
| `store` / `chain` / `vault` | `(&self) -> &S` / `&C` / `&V` | Borrow a part. |

### Holdings

| Fn | Signature | Notes |
|----|-----------|-------|
| `import` | `async (&mut self, container_bytes: Vec<u8>, imported_at: i64) -> Result<HeldToken>` | Parse, `verify_chain_integrity` (offline), persist the bytes verbatim. `imported_at` is host-supplied: the core has no clock. Errors `Codec`, `InvalidToken`, `Duplicate`. See *Id collisions* below. |
| `held` | `async (&self) -> Result<Vec<HeldToken>>` | Every record. Local only. |
| `forget` | `async (&mut self, id: &str) -> Result<()>` | Delete a record. No-op if absent. For a bearer note this deletes the only copy of the value. |
| `record_export` | `async (&mut self, id: &str, kind: ExportKind) -> Result<HeldToken>` | Count a copy of the note leaving the client. Local only; never written into the container, where it would link copies of one note. Errors `NotHeld`. |
| `mark_spent` | `async (&mut self, id: &str, spent: bool) -> Result<HeldToken>` | The holder's own assertion that a note is gone (or not). Reversible, keeps the bytes. Errors `NotHeld`. |
| `reconcile` | `async (&mut self) -> Result<Vec<ReconciledToken>>` | One `ChainRead::token_status` per note. A failed read is an `Err`. Binds a note to the configured mint the first time that ledger confirms the note's content. |
| `balance` | `async (&mut self) -> Result<Balance>` | `reconcile`, then `Balance::from_reconciled`. |
| `sync` | `async (&mut self) -> Result<SyncReport>` | Ownership repair, no vault needed. Auto-binds a held note whose live owner commitment matches a pending receive (a receive that crashed before binding). Flags a note `spent_away` when its live commitment no longer equals the one recorded at bind time, and clears the flag when the ledger says it is ours again. |

### Receiving

| Fn | Signature | Notes |
|----|-----------|-------|
| `begin_receive` | `async (&mut self, commitment: [u8;32], now: i64) -> Result<PendingReceive>` | Reserve the next owner index and record the pending receive. The shell derives `commitment` from its vault. |
| `reserve_owner_index` | `async (&mut self) -> Result<u32>` | Reserve an index without recording it, for a caller that needs the index to derive the commitment. Pair with `record_pending`. |
| `record_pending` | `async (&mut self, pending: PendingReceive) -> Result<()>` | Record a pending receive for a reserved index. |
| `pending` | `async (&self) -> Result<Vec<PendingReceive>>` | Outstanding pending receives, lowest index first. |
| `forget_pending` | `async (&mut self, index: u32) -> Result<()>` | Stop watching one index. Nothing is cancelled on-chain: the mint still accepts a payment to that commitment, and the commitment can be re-derived from the seed. |
| `known_owners` | `async (&self) -> Result<Vec<KnownOwner>>` | Every owner commitment this wallet can open: the pending receives plus the `owner_commitment` recorded on each bound note. Needs no vault. The second source keeps a pay tag recognisable after its first payment, so one tag can be handed to several payers. |
| `complete_receive` | `async (&mut self, container_bytes: Vec<u8>, now: i64) -> Result<HeldToken>` | Runs the receive gates (below) and stores the note bound to the owner index the ledger names. It is not told which receive to complete: the live owner commitment is matched against `known_owners`. Errors `ReceiveGate { .. }` or `Duplicate`. |
| `bind_owner` | `async (&mut self, id: &str, owner_index: u32) -> Result<HeldToken>` | Tie a held note to the owner index that owns it, consuming the matching pending record and copying its commitment. Without this association the owner key cannot be re-derived and a spend-mode note can be neither spent nor redeemed. Errors `NotHeld`. |
| `record_owner_commitment` | `async (&mut self, id: &str, commitment: [u8;32]) -> Result<()>` | Record the commitment on a note already bound to an index. For a note this holder printed, which never had a pending receive to copy a commitment from. |

### Vault methods (`V: DerivingVault`)

Present only on a wallet built with `with_vault`.

| Fn | Signature | Notes |
|----|-----------|-------|
| `owner_commitment_for` | `(&mut self, index: u32, credential: &[u8]) -> Result<[u8;32]>` | The commitment a payer spends to for this index. |
| `start_receive` | `async (&mut self, credential: &[u8], now: i64) -> Result<PendingReceive>` | Reserve a fresh index, derive its commitment, record the pending receive. The record is written **before** the commitment is shown, so a crash cannot lose which index was promised. |
| `authorize_redeem` | `async (&mut self, index: u32, slot_id: u32, ephemeral_key: &[u8;32], live_owner_commitment: &[u8;32], recipient_xdr: &[u8], credential: &[u8]) -> Result<RedeemOwnerProof>` | Owner proof for `redeem_by_chain_owned`. Reads the mint's address XDR and the live spend nonce from the chain reader immediately before signing; neither is cached or caller-supplied. |
| `authorize_spend` | `async (&mut self, index: u32, slot_id: u32, ephemeral_key: &[u8;32], live_owner_commitment: &[u8;32], new_owner_commitment: &[u8;32], credential: &[u8]) -> Result<SpendAuthorization>` | Authorization to move a spend-mode note to `new_owner_commitment`. Same nonce rule. |
| `verify_ownership` | `async (&mut self, credential: &[u8]) -> Result<OwnershipReport>` | Check every spend note's local claim (`owner_index`, `owner_commitment`) against the derived key and the live commitment. Run where untrusted records enter, typically after a restore: each note costs a key derivation, which on a card is an NFC round trip. |

`verify_ownership` decides per note:

| derived vs stored | derived vs live | outcome |
|---|---|---|
| same | — | `confirmed` |
| differs | same | stored commitment corrected (`corrected`) |
| differs | differs | claim stripped, note kept (`disowned`) |

A note whose vault or ledger read fails is left untouched and counted as
`unchecked`. `OwnershipReport { confirmed: usize, corrected: Vec<(String, u32)>, disowned: Vec<(String, String)>, unchecked: usize }`;
`is_clean()` is true only when nothing changed and nothing went unchecked.

### The receive gates

`complete_receive` is the only way a spend-mode payment becomes held. Every
gate must pass; until G3 the payee has not been paid.

| Gate | `Gate` | Checks | Retryable |
|---|---|---|---|
| G1 | `Structure` | The container parses and its chain verifies offline. | no |
| G2 | `Ledger` | The record for the note's slot is `Active` (`Redeemed` is final; other states may mean the payer's spend has not landed). The recorded amount equals the container's. The recorded chain hash equals the container chain's hash. The record names this note's ephemeral key. The record's event id equals the chain's, and its participant count is even and equals twice the chain's link count. A record missing any of these fields fails. | only the not-yet-`Active` case |
| G3 | `Ownership` | The note is in spend mode and its live owner commitment is one of `known_owners`. For a pure-bearer note the record's claim key must be the container's (a mismatch fails as G2); the note then fails G3 because bearer ownership cannot be proven. | only "commitment not ours" |
| G4 | — | Store the note with `owner_index`, `owner_commitment` and `mint` set, and consume the pending record. Index 0, the standing pay tag, is never consumed. A note already held is `Duplicate`, unless it was marked `spent_away`, in which case the record is replaced (the note has come back). | — |

Everything except the chain hash can be rebuilt from public ledger data, so
the chain-hash comparison is what stops a payer with no note from handing
over a convincing container. The event-id and participant checks catch a
chain that hashes correctly but that `verify_chain` would refuse at
redemption.

A polling caller must branch on `retryable`, never on the message text.

### Id collisions

A note's id is `note_id(ephemeral_address, slot_id)`. When `import` meets an
id it already holds:

- byte-identical containers are `Duplicate`;
- a held note bound to a different mint is never replaced (`Duplicate`);
- otherwise the ledger is asked about each container's slot. The incoming
  note replaces the held one only if the ledger says the held one is not
  the registered note and the incoming one is, and only if the held record
  has not changed in the meantime. Every other outcome, including an
  unreadable ledger, keeps the held note and returns `Duplicate`.

### Locking

Read-modify-write paths read without the store lock, do the slow part (RPC,
card derivation), then take the lock to re-read and write only if the record
is unchanged. A slow ledger or an NFC tap never blocks other writers.

## `owner` module

The owner-key authorizations as free functions over a `DerivingVault`, with
no chain or store. `TokenWallet` delegates to them; a caller holding only a
vault uses them directly. They take the mint address XDR and the spend nonce
as parameters because they are chainless.

| Fn | Signature |
|----|-----------|
| `commitment_for` | `(vault: &mut V, index: u32, credential: &[u8]) -> Result<[u8;32]>` |
| `authorize_redeem` | `(vault: &mut V, index: u32, contract_xdr: &[u8], slot_id: u32, ephemeral_key: &[u8;32], live_owner_commitment: &[u8;32], spend_nonce: u32, recipient_xdr: &[u8], credential: &[u8]) -> Result<RedeemOwnerProof>` |
| `authorize_spend` | `(vault: &mut V, index: u32, contract_xdr: &[u8], slot_id: u32, ephemeral_key: &[u8;32], live_owner_commitment: &[u8;32], new_owner_commitment: &[u8;32], spend_nonce: u32, credential: &[u8]) -> Result<SpendAuthorization>` |

The commitment is `SHA-256(SPEND_OWNER_COMMIT || owner_pubkey)`. Both
authorizations derive the key at `index`, refuse locally if its commitment
is not `live_owner_commitment` (instead of letting the mint revert), and
sign the 32-byte digest from `kenter_crypto::spend` (`redeem_owner_digest`,
`spend_auth_digest`), never a raw message. Signing the digest is what makes
software and card signatures interchangeable. The digests cover the mint's
address, so a signature cannot be replayed against another deployment, and
the spend nonce, so it authorizes exactly one transfer. A vault
`BadCredential` maps to `WalletError::BadCredential`. See
[spend mode](../../docs/architecture/spend-mode.md).

## `NoVault`

Unit type for "no custody backend". It does not implement `DerivingVault`,
so a wallet built with `TokenWallet::new` has no owner-key methods: misuse
is a compile error, not a runtime one.

## Ports (`ports`)

### `ChainRead`

Read-only chain view. Implemented natively by `kenter_client::WalletChain`
(feature `wallet`), over Soroban RPC.

| Method | Notes |
|---|---|
| `async token_status(&self, slot_id: u32) -> Result<OnChainToken>` | Look up a note's record by its print slot. The mint keys records by slot, not by ephemeral key: the key is public once a print completes, so two slots can name the same key. |
| `mint_contract_xdr(&self) -> Vec<u8>` | The mint's address XDR, as the mint hashes it. Owner digests cover it. Belongs to the reader so it cannot disagree with the mint the answers came from. |
| `mint_id(&self) -> String` | The mint's contract id. Slot ids restart at zero per deployment, so notes are bound to the mint that confirmed them. |
| `ledger_source(&self) -> String` | Where answers come from, fit to show a holder (the gates trust this source). Must not contain a credential. |

### `Store`

Local persistence, keyed by `HeldToken::id`.

| Method | Notes |
|---|---|
| `lock(&self) -> Result<StoreGuard>` | Write lock for a read-modify-write, held until the guard drops. Default: a guard that holds nothing (single-owner stores). `FileStore` overrides it. **Not re-entrant**: taking it twice on one thread deadlocks, so exactly one method per call path takes it. |
| `async put(&mut self, token: HeldToken) -> Result<()>` | Insert or overwrite. The wallet checks for duplicates first. |
| `async get(&self, id: &str) -> Result<Option<HeldToken>>` | |
| `async all(&self) -> Result<Vec<HeldToken>>` | |
| `async remove(&mut self, id: &str) -> Result<()>` | No-op if absent. |
| `async allocate_owner_index(&mut self) -> Result<u32>` | Reserve the next fresh owner index and persist the advance. Monotonic, never reused, never returns `STATIC_RECEIVE_INDEX`. An abandoned receive burns an index, which is harmless; reuse would link two payments to one commitment. |
| `async advance_owner_index(&mut self, to: u32) -> Result<u32>` | Raise the counter to at least `to` and return where it is. Never moves backwards, so `to = 0` is a read. Same contract as the card's `ADVANCE INDEX`. Restore uses it so an older backup cannot roll the counter back. |
| `async put_pending(&mut self, p: PendingReceive) -> Result<()>` | |
| `async pending(&self) -> Result<Vec<PendingReceive>>` | |
| `async remove_pending(&mut self, index: u32) -> Result<()>` | No-op if absent. |
| `async last_backup(&self) -> Result<Option<BackupRecord>>` | What the backup warnings read. |
| `async record_backup(&mut self, record: BackupRecord) -> Result<()>` | Call only after the backup has been written and landed. |

`StoreGuard` is opaque; dropping it releases the lock.

## Authorization (`authz`)

Every vault call takes a `credential`. This port decides where it comes from
and how often a person is asked, which is the difference between the
standard tier (one unlock per session) and the maximum-security tier (a
fresh proof, typically a card tap, per value-moving action). Both shells use
it so they cannot disagree.

| Item | Notes |
|------|-------|
| `AuthAction` | `Receive { index: u32 }`, `Spend { token_id: String, amount: u64, to_commitment: [u8;32] }`, `Redeem { token_id: String, amount: u64, to_account: String }`, `Backup { seal: bool }`. Not `#[non_exhaustive]`: a new variant breaks every shell until its prompt text is written. |
| `AuthAction::summary(&self) -> String` / `rows(&self) -> Vec<(&'static str, String)>` | The text a prompt must show. A shell may lay the rows out as it likes but may not hide them. |
| `AuthAction::moves_value(&self) -> bool` | `Spend`, `Redeem` and `Backup { seal: true }` move value; `Receive` and restore do not. |
| `Why` | `Unlock`, `PerAction`, `Retry`: why the person is being asked now, so the wording differs. |
| `Prompter` | `async prompt(&mut self, action: &AuthAction, why: Why) -> Result<Zeroizing<Vec<u8>>>`. Implemented by shells. Return `WalletError::Declined` when the person refuses. |
| `Authorizer` | `async authorize(&mut self, action: &AuthAction) -> Result<Authorization>`, `lock(&mut self)` (forget the cache), `rejected(&mut self)` (the vault refused the last credential: forget it and make the next prompt a `Retry`). |
| `Policy` | `Session` (default) or `PerAction`. |
| `SessionAuthorizer<P: Prompter>` | `new(prompter, policy)`, `policy()`, `set_policy(policy)`, `into_prompter()`, `is_unlocked()`. Caches the credential under both policies; under `PerAction` the cache is not consulted for value-moving actions. That matches a card: the PIN may be cached, the tap is the proof. |
| `PreAuthorized` | `new(credential)`. A credential obtained elsewhere (a terminal prompt, a test). Never prompts. |
| `NoAuthorizer` | Always fails with `PromptFailed`. For a shell with no prompt: a screen that cannot ask must not sign. |
| `Authorization` | `new(Zeroizing<Vec<u8>>)`, `credential() -> &[u8]`. Owns its credential so it is wiped at the end of the operation. `Debug` prints the length only. |

A prompt is handed a described action rather than asked for a bare
password, because a password box proves presence, not consent to this
transfer. What the holder sees is still only as trustworthy as the display:
a card with its own screen cannot be lied through by the host, a bare card
in a desktop reader can.

## Receive addresses (`uri`)

| Item | Notes |
|----|-------|
| `RECEIVE_PREFIX: &str = "KENTER:RECV/"` | |
| `receive_uri(commitment: &[u8;32]) -> String` | `KENTER:RECV/<64 uppercase hex>`. |
| `parse_receive_uri(s: &str) -> Result<[u8;32]>` | Either case, with or without the scheme, or bare hex. A URI with another scheme fails by name (`Codec`). |

Uppercase keeps all 76 characters inside QR alphanumeric mode, which packs
denser than byte mode; a test pins the character set. Only the commitment
travels, never the derivation index, which would link a payee's receipts.

## Backups (`backup`)

A recovery phrase restores owner keys, not notes: notes cannot be found from
the ledger. A complete backup is the phrase plus the note bytes. This module
writes and reads the bytes as a `.kbk` file, sealed with XSalsa20-Poly1305
under a key derived from the wallet seed (`SoftVault::backup_credentials`),
so a restore needs the phrase and the file and nothing else.

| Item | Notes |
|---|---|
| `encode(key: &[u8;32], seed: &SeedSource, tokens: &[HeldToken], pending: &[PendingReceive], next_owner_index: Option<u32>, now: i64) -> Result<Vec<u8>>` | Write a file. |
| `export<S: Store>(store: &mut S, key: &[u8;32], seed: &SeedSource, now: i64) -> Result<Vec<u8>>` | `encode` over everything a store holds; reads the counter with `advance_owner_index(0)`. |
| `inspect(bytes: &[u8]) -> Result<BackupFile>` | Read the cleartext header, no key. Enforces that `bip85` is present exactly when the origin is `Bip85Child`. |
| `decode(key: &[u8;32], fingerprint: &str, bytes: &[u8]) -> Result<BackupContents>` | Open a file. The fingerprint is checked before decryption, so another wallet's file says so instead of failing like a wrong passphrase. |
| `restore<S: Store>(store: &mut S, contents: &BackupContents) -> Result<RestoreReport>` | Merge into a store. **Strictly additive**: an entry the store already has is never overwritten, so a past state cannot roll a live note back (for example un-flag `spent_away`). Each note is `check`ed; failures are reported in `rejected` and not stored. The counter moves to the highest of the store's, the file's, and one past every restored index. Takes the store lock; the caller must not hold it. |
| `check(token: &HeldToken) -> Result<()>` | Offline: the blob parses, the chain verifies, and the id derives from the blob. Amount is not checked (only the ledger can). |
| `content_digest(tokens: &[HeldToken]) -> String` / `digest_of_ids(ids) -> String` | SHA-256 over sorted ids under the tag `kenter_v1:backup:contents`, hex. |
| `coverage(file: Option<&[u8]>, fingerprint: &str, tokens: &[HeldToken]) -> Coverage` | Whether a file covers what is held. No key needed. Compares id sets. |
| `coverage_of_record(record: Option<&BackupRecord>, tokens: &[HeldToken]) -> Coverage` | The same from the wallet's own record, for when the file is not to hand. Returns only `Missing`, `Covered`, `Stale`. |
| `record_for(tokens: &[HeldToken], at: i64, whence: Option<String>) -> BackupRecord` | The record to store once a backup has landed. |
| `seal_item(key: &[u8;32], plain: &[u8]) -> Result<Vec<u8>>` / `open_item(key, sealed) -> Result<Vec<u8>>` | Per-item sealing for paper. A fresh nonce per item: a repeated nonce under one key would leak the XOR of two notes. |

Types:

- `BackupFile { kind, version, seed_fingerprint, created_at, token_count, seed_origin: Option<SeedOrigin>, bip85: Option<Bip85Derivation>, content_digest: Option<String>, .. }`,
  the cleartext header. `origin()` returns `Software` for a version-1 file,
  which has no origin field. This build writes version 2.
- `SeedOrigin`: `Software` (the phrase is the vault seed), `Card` (the card
  holds the seed), `Bip85Child` (the vault seed is a BIP85 child of a root
  held elsewhere).
- `Bip85Derivation { index: u32, words: u8, root_fingerprint: Option<String> }`,
  the child at `m/83696968'/39'/0'/{words}'/{index}'`. Kept in the cleartext
  header because the index is needed to derive the key that opens the
  payload. `root_fingerprint` is optional because two files carrying it are
  visibly from one root.
- `SeedSource { fingerprint, origin, bip85 }`, passed to `encode`;
  `SeedSource::software(fingerprint)` for a software wallet.
- `BackupContents { tokens, pending, next_owner_index: Option<u32>, created_at }`.
- `RestoreReport { tokens_added, tokens_kept, pending_added, pending_kept, owner_index_before, owner_index_after, rejected: Vec<(String, String)> }`;
  `is_empty()` when nothing in the file was new.
- `Coverage`: `Missing`, `OtherWallet { fingerprint }`, `Unreadable { why }`,
  `Unknown { created_at }` (a version-1 file, no digest), `Covered { created_at, notes }`,
  `Stale { created_at, in_file, held }`. `is_covered()` is true only for
  `Covered`; `needs_refresh()` is its negation.

## Paper backups (`paper`)

The same backup as independent QR items: one item for the wallet state (the
owner-index counter and pending receives) and one per note, each sealed
separately through a caller-supplied closure, so this module never holds a
key and a damaged symbol costs one item rather than everything. Sealed
under the seed, so a sheet is a backup, not a spendable note.

Symbol layout:

```text
"KPB2" | wallet [u8;8] | kind u8 | item u16 | items u16 | index u16 | total u16 | digest u32 | payload
```

`wallet` is the seed fingerprint, so a scan can name the wrong sheet before
anything is decrypted. `items` (the backup's item count) is in clear so a
scan can report a note whose every symbol is missing. `digest` is a CRC-32
of the whole item, repeated in each chunk, so chunks from two sheets cannot
be combined. Sheets render at error correction M; readers decode any level.

| Item | Notes |
|---|---|
| `SYMBOL_CAPACITY: usize = 2331` | Bytes in a version-40 symbol at EC M. |
| `CHUNK_PAYLOAD: usize = 2306` | The format's per-symbol payload ceiling (capacity less the 25-byte header). |
| `DEFAULT_CHUNK_PAYLOAD: usize = 850` | What symbols are filled to, keeping every item at QR version 23 or below so phone cameras read it. |
| `chunk_payload() -> usize` | `DEFAULT_CHUNK_PAYLOAD`, or `KENTER_PAPER_CHUNK_PAYLOAD` if set and within 100..=`CHUNK_PAYLOAD`. |
| `Kind` | `Wallet`, `Note`; `label()`. |
| `Chunk { wallet, kind, item, items, index, total, bytes }` | One symbol to render; `label()` names the item and position. |
| `encode<F>(wallet: &str, tokens: &[HeldToken], pending: &[PendingReceive], next_owner_index: Option<u32>, seal: F) -> Result<Vec<Chunk>>` | `F: FnMut(&[u8]) -> Result<Vec<u8>>`, normally `backup::seal_item` under the backup key. |
| `read_symbol(bytes: &[u8]) -> Result<Scanned>` | Parse and sanity-check one symbol. |
| `Scanned { wallet, kind, item, items, index, total, .. }` | |
| `Sheet` | `new()`, `add(Scanned)` (order-independent, idempotent, refuses symbols from another wallet or sheet), `is_empty()`, `wallet()`, `progress() -> Progress`, `finish(open) -> Result<Recovered>`. `finish` returns whatever is complete; an item that will not open is reported and skipped. |
| `Progress { complete, partial, absent, wallet }` | `has_anything()`, `is_complete()`, `describe()`. |
| `Recovered { tokens, pending, next_owner_index, failed: Vec<(u16, String)> }` | `into_contents(created_at) -> BackupContents`, so paper restores through `backup::restore`. |
| `calibration_symbol(wallet: &str, item: u16, items: u16, payload: &[u8]) -> Chunk` | A valid single-symbol item of chosen size, for measuring print and capture chains. |

## Sealed records (`sealed`)

Encryption for records on disk. A pure-bearer note's container is the
money, so a store of plaintext records would expose it.

| Item | Notes |
|---|---|
| `MAGIC: &[u8;5] = b"KNST1"` | Record prefix; the digit is the format version. |
| `seal(creds: &StoreCredentials, plaintext: &[u8]) -> Result<Vec<u8>>` | `MAGIC || nonce(24) || XSalsa20-Poly1305(creds.aead, nonce, plaintext)`. |
| `unseal(creds, bytes) -> Result<Zeroizing<Vec<u8>>>` | One error for wrong key and tampering: the AEAD cannot tell them apart. |
| `is_sealed(bytes) -> bool` | |
| `record_name(creds, kind: &str, id: &str) -> String` | HMAC-SHA256 under `creds.name` over `kind || 0x00 || id`, first 16 bytes as hex. Deterministic, so a lookup is one `open`, and one-way, so a directory listing reveals no ids. |

## `FileStore` (feature `fs`)

The filesystem `Store`.

| Fn | Notes |
|----|-------|
| `open(dir: impl AsRef<Path>, creds: StoreCredentials) -> Result<Self>` | Creates `<dir>/tokens/` and `<dir>/pending/` and sweeps stale temp files. There is no way to open a store without keys. |

Layout:

```text
<dir>/tokens/<record_name>.rec    one sealed record per note
<dir>/pending/<record_name>.rec   one sealed record per pending receive
<dir>/state.json                  sealed: owner-index counter, last backup record
<dir>/.write-lock                 the store lock (empty, never read)
<dir>/.state-lock                 the state file's own lock
```

- Records are JSON with byte fields hex-encoded, sealed with `sealed::seal`
  and named with `record_name`, so neither contents nor ids are visible.
- Writes go to a `.tmp` sibling and are renamed into place, so a reader
  never sees a partial record.
- The counter advances before an index is returned: a crash can burn an
  index, never hand one out twice.
- A record that will not decrypt or parse is reported, never skipped, and a
  stray plaintext file is reported rather than read.
- `lock()` uses an OS advisory lock (`std::fs::File::lock`) on
  `.write-lock`. It is per open handle, so it excludes two threads of one
  process as well as two processes. The OS releases it when the process
  dies, so there is no stale lock to clean up. Waits rather than fails.

## `MemoryStore`

In-memory `Store` for tests and ephemeral sessions: `new()`, `len()`,
`is_empty()`. Uses the default no-op lock.

## Re-exports

`DerivingVault`, `KeyVault`, `StoreCredentials` from `kenter-vault`, so
shells name the custody ports from one place.

## Types (`models`)

- `HeldToken`, a note the wallet holds:

  | Field | Notes |
  |---|---|
  | `id: String` | `note_id(ephemeral_address, slot_id)`, `G…-<slot>`. Unique per record. |
  | `slot_id: u32` | The print slot the mint keys the record by. |
  | `ephemeral_public_key: [u8;32]` | The note's key; signatures are made under it. |
  | `event_id: [u8;32]` | SHA-256 of the print-request event. |
  | `amount: u64` | Face amount from the container header, stroops (0 if unset). A local claim; the ledger's figure wins. |
  | `blob: Vec<u8>` | The container bytes, verbatim. |
  | `imported_at: i64` | Host-supplied Unix seconds. |
  | `mint: Option<String>` | The mint whose ledger confirmed this note's content. Set only from the wallet's own configured mint, by a passing receive or an `Active` reconciliation that matches the bytes; never from the container. |
  | `label: Option<String>` | |
  | `owner_index: Option<u32>` | Derivation index of the owner key (`m/44'/148'/index'`). `None` for pure bearer or a note owned by someone else. The key is never stored. |
  | `owner_commitment: Option<[u8;32]>` | Recorded at bind time, so paid-away detection needs no vault. |
  | `spent_away: bool` | The ledger's live owner moved away from us. |
  | `exports: ExportLog` | Copies that left the client. |
  | `marked_spent: bool` | The holder's assertion that the note is gone. |

  `to_bearer(&self) -> Result<BearerToken>` re-parses the blob.
- `note_id(ephemeral_address: &str, slot_id: u32) -> String`;
  `short_note_id(id: &str) -> String` (`GD7MDB…CLHR-3`; the slot is never
  elided).
- `ExportLog { backup: u32, to_card: u32, handover: u32 }`: `record(kind)`,
  `exposure()` (handovers plus card exports; backups are the holder's own),
  `is_empty()`. `ExportKind`: `Backup`, `ToCard`, `Handover`.
- `TokenStatus`: `Active`, `Redeemed`, `NotFound`, `Unknown` (read failed or
  unchecked), `OtherMint` (bound to a different mint; not read here),
  `Unbound` (no mint has confirmed it and this answer cannot),
  `Counterfeit` (a live record exists for the slot but its chain hash or
  claim key does not match the bytes), `NotOurs` (live spend-mode record
  owned by a commitment this wallet cannot open).
- `OnChainToken { status, amount: Option<i128>, chain_hash, event_id, participants_len: Option<u32>, owner_commitment, spend_nonce: Option<u32>, claim_pubkey, ephemeral_key }`,
  what `ChainRead` returns; the `[u8;32]` fields are `Option`, `None` when
  there is no record (and `owner_commitment` is `None` for pure bearer).
- `ReconciledToken { held, status, on_chain_amount: Option<i128> }`.
  `trusted_amount()` is the ledger's amount when there is a record (0 for a
  `Counterfeit`, 0 for a value outside `u64`), otherwise the local claim.
  `claim_disputed()` is true when the ledger has an amount and it differs
  from the local claim.
- `SyncReport { bound: Vec<(String, u32)>, spent_away: Vec<String>, returned: Vec<String> }`; `is_empty()`.
- `Balance { spendable, redeemed, unverified, spent_away, total_held: u64, disputed: u32 }`,
  stroops, from `trusted_amount`. Notes flagged `spent_away` or
  `marked_spent`, and `NotOurs`, count as `spent_away`. `Counterfeit`,
  `NotFound`, `Unknown`, `OtherMint` and `Unbound` count as `unverified`.
  `still_held()` (`spendable + unverified`) is the figure to show a person.
  `gone()` is `redeemed + spent_away`. `total_held` sums every record,
  including gone ones, and is a diagnostic, not a balance.
  `from_reconciled(&[ReconciledToken]) -> Balance` is pure.
- `PendingReceive { index: u32, commitment: [u8;32], created_at: i64 }`, an
  owner index promised to a payer before the note exists. Consumed when the
  note is bound.
- `KnownOwner { index: u32, commitment: [u8;32] }`.
- `BackupRecord { at: i64, ids: Vec<String>, whence: Option<String> }`, what
  the wallet remembers of its last backup (sorted ids, so it answers both
  "is the wallet covered" and "is this note covered"). `notes()`,
  `covers(id)`.
- `STATIC_RECEIVE_INDEX: u32 = 0`, the reusable standing pay tag (every
  payment to it is linkable to the others); `FIRST_FRESH_INDEX: u32 = 1`.
- `DEFAULT_SYMBOL: &str = "$"`; `fmt_stroops(u64) -> String`
  (`$1.2500000`, always seven places); `fmt_amount(stroops, symbol)`. There
  is no Kenter currency ticker: a note is a claim on whatever asset the mint
  escrows. Formatting lives here so every prompt renders an amount the same
  way.

## Errors

`WalletError` (`thiserror`), with `type Result<T> = std::result::Result<T, WalletError>`:

| Variant | Meaning |
|---|---|
| `InvalidToken(String)` | Offline verification failed on import. |
| `Codec(String)` | Container or URI (de)serialization failed. |
| `Store(String)` / `Chain(String)` | A port implementation failed. |
| `Duplicate(String)` | That id is already held. |
| `NotHeld(String)` | No held note with that id. |
| `ReceiveGate { gate: Gate, detail: String, retryable: bool }` | A receive gate failed; the payee is not paid. Branch on `retryable`. |
| `Vault(String)` | The custody backend failed, or an owner index does not open the live commitment. |
| `BadCredential` | Wrong passphrase or PIN: the one vault failure to answer by asking again. |
| `Backup(String)` | Backup export, restore or paper decode failed. |
| `Declined` | The person refused. Stop cleanly; do not retry. |
| `PromptFailed(String)` | No way to ask (no prompt wired, reader gone). A bug worth surfacing. |

`Gate`: `Structure` (G1), `Ledger` (G2), `Ownership` (G3).

## `testing` (feature `testing`)

Real-note fixtures: `note(seed: u8, amount: u64) -> HeldToken`,
`spend_note(seed, amount, owner_index: u32) -> HeldToken`,
`fabricated(seed, amount) -> HeldToken` (well-formed but not the registered
note, for counterfeit paths). The crate lists itself as a dev-dependency
with the feature on, so integration tests get the fixtures and shipped
builds do not.

## Not in this crate

- **No write path.** Submitting a spend or a redemption is the shell's job
  (natively through `kenter-client`); the core produces the authorizations.
- **No browser adapters.** No `fetch` `ChainRead` or IndexedDB `Store`
  exists yet; the wasm build compiles the core but nothing wraps it.
