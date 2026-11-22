# kenter-client: API

Native Soroban RPC client. Async (`tokio`); every method returns
`Result<T, ClientError>`. State-changing calls submit through
`TxBuilder::invoke` (or `invoke_cosigned` where a pair must both sign, or
`invoke_widened` where a call must declare storage its simulation did not
see); reads use `simulate_invoke`, `simulate_invoke_ro` or
`getLedgerEntries`. Which network and which contracts a build talks to is
fixed per build (`network`), never per call.

Re-exported at the crate root: `Asset`, `AssetClient`, `Beacon`,
`ClientError`, `ClaimInfo`, `MintClient`, `SelectionInfo`, `SlotInfo`,
`TokenInfo`, `TokenMode`, `TokenState`, `selection_score`,
`selection_seed`, `NetworkConfig`, `Overrides`, `Profile`, `NodeInfo`,
`RosterClient`, `Holdings`, `SorobanRpcClient`, `TxBuilder`, and
`WalletChain` with the `wallet` feature.

Cargo features: `wallet` (the `ChainRead` adapter, off by default) and
`mainnet` (build for mainnet instead of testnet).

## `TxBuilder` (`tx`)

The invoke engine. Wraps one `SorobanRpcClient` and a source
`StellarKeypair`.

| Fn | Sig | Notes |
|----|-----|-------|
| `new` | `(rpc, source_keypair) -> Self` | Caches `source_address`; the sequence starts at 0 (unknown). |
| `read_only` | `(rpc, source_address:&str) -> Self` | No key: simulates as that address, refuses to sign. For reads while the signing key is locked away. |
| `with_max_resource_fee` / `max_resource_fee` | `(self, stroops:u64) -> Self` / `(&self) -> u64` | Ceiling on the resource fee it will sign. |
| `rpc` / `source_address` | `(&self)` | |
| `refresh_sequence` | `(&mut self) -> Result<()>` | Fetches the sequence from Horizon. |
| `simulate_invoke` | `(&mut self, contract, fn, args) -> Result<Option<ScVal>>` | Dry run; no submit, no fee. |
| `simulate_invoke_ro` | `(&self, contract, fn, args) -> Result<Option<ScVal>>` | Same without the sequence refresh. Sees through archival (the host restores before running). |
| `simulate_resources` | `(&self, contract, fn, args) -> Result<SimResources>` | What a call would cost on this network: instructions, read/write bytes, entry counts, `min_resource_fee`. |
| `invoke` | `(&mut self, contract, fn, args) -> Result<InvokeResult>` | build, simulate, assemble, sign, send, poll. Refuses any auth entry for an address other than the source. |
| `invoke_widened` | `(&mut self, contract, fn, args, widen:&(dyn Fn(&LedgerFootprint) -> Vec<LedgerKey> + Sync)) -> Result<InvokeResult>` | `invoke`, with the keys `widen` returns added to the read-write footprint. Each added key raises the declared instructions, write bytes and fee by `EXTRA_KEY_*`. |
| `invoke_cosigned` | `(&mut self, contract, fn, args, cosigner:&StellarKeypair, margin:ContentionMargin) -> Result<InvokeResult>` | The one exception to the source-only rule (below). |
| `has_trustline` | `(&self, code, issuer) -> Result<bool>` | `getLedgerEntries`. |
| `change_trust` | `(&mut self, code, issuer, limit:i64) -> Result<String>` | Classic op, no simulation. |
| `send_xlm` | `(&mut self, destination, stroops:i64, create:bool) -> Result<String>` | `CreateAccount` when `create`, else a native `Payment`. |

**Sequence handling.** On any submission error the cached sequence is
reset to 0, so the next call reads it from the ledger. A transaction that
was included and failed, or that landed after the poll gave up, still
consumes a sequence number; re-reading is right in every case.

**Instruction slack.** Every ordinary call declares
`INSTRUCTION_SLACK_PCT` (10%) more instructions than simulation reported,
capped at the network's 400,000,000 per-transaction limit, with the fee
raised to match. A call whose path depends on the clock can take a longer
branch when it applies than when it was simulated.

**`invoke_cosigned`.** Used by calls that need both members of a node pair
(`register_pair`, `claim_position`). Rules:

- Exactly one `Address` auth entry beyond the source's, and it must be the
  co-signer's. Any other entry, or a second one, is refused.
- Its root invocation must be exactly the call being made (contract,
  function, arguments) with nothing beneath it, so the co-signer
  authorizes this one call and no transfer.
- The signature expires `COSIGN_LEDGERS` (60, about five minutes) after the
  simulation's ledger.
- The transaction is simulated again with the signed entry in place before
  sending, which runs the network's own authorization check.

`InvokeResult { tx_hash: String, return_value: Option<ScVal>, ledger: Option<u64> }`.

**`ContentionMargin { extra_bytes, extra_instructions }`.** Declared room
for claims that land between a claim's simulation and its application.
Several pairs claim on one slot within moments; when another claim lands
first, the slot's claim list is longer than simulated and an undeclared
write fails with `resource_limit_exceeded`. A claim simulated against
`seen` claims can apply after up to `2k - seen` more have landed (`k` the
number of interior positions). `ContentionMargin::for_claims(n)` is room
for `n` entries plus slack; the default (zero) sends the simulation
unchanged. When a margin applies, the resource fee is raised by
`CONTESTED_FEE_PCT` percent plus `CONTESTED_FEE_FLAT`; the network refunds
the unused part.

| Constant | Value | Meaning |
|---|---|---|
| `BASE_FEE` | 100 | Inclusion fee, stroops |
| `COSIGN_LEDGERS` | 60 | Life of a co-signer's auth entry |
| `CLAIM_ENTRY_BYTES` (pub) | 300 | Bytes per claim entry (260 measured, rounded up) |
| `CLAIM_ENTRY_INSTRUCTIONS` (pub) | 40,000 | Instructions per entry already in the list (about 34,000 measured) |
| `CONTESTED_SLACK_BYTES` / `_INSTRUCTIONS` | 512 / 100,000 | Slack on top of a margin |
| `CONTESTED_FEE_PCT` / `CONTESTED_FEE_FLAT` | 50 / 20,000 | Fee raise for a margin |
| `EXTRA_KEY_FEE` (pub) | 3,000 | Stroops per key added by `invoke_widened` |
| `EXTRA_KEY_INSTRUCTIONS` (pub) | 150,000 | Instructions per added key (an entry that exists at apply time is read and decoded) |
| `EXTRA_KEY_WRITE_BYTES` (pub) | 1,000 | Write bytes per added key (every existing read-write entry counts as written) |
| `INSTRUCTION_SLACK_PCT` (pub) | 10 | Instruction slack on every ordinary call |
| `DEFAULT_MAX_RESOURCE_FEE` (pub) | 50,000,000 | 5 XLM; above it, `FeeTooHigh` |
| `TX_TIMEOUT` | 60 s | Poll limit (every 2 s) |

The resource-fee ceiling exists because the fee comes from the RPC's
simulation: without it, a lying endpoint could name any figure and the
client would sign it. Legitimate calls cost a small fraction of it.

**`SimResources { instructions, disk_read_bytes, write_bytes,
read_only_entries, read_write_entries, min_resource_fee }`.** A
simulation's figures are the authoritative cost. The contract test suite
meters a different host and reads lower (a 3-pair chain redemption: about
9.9M instructions in the test suite, about 13.1M on testnet), because cost
parameters are a ledger entry that differs per network. Compare against
the target network's `tx_max_instructions`, not a compiled-in constant.

**ScVal helpers** (free fns). Encoders: `address_to_scval` (detects a `C…`
contract vs a `G…` account), `address_xdr`, `bytes32_to_scval`,
`bytes64_to_scval`, `bytes_to_scval`, `i128_to_scval`, `u32_to_scval`,
`string_to_scval`, `bool_to_scval`, `option_to_scval` (Soroban `Option` =
value or `Void`), `pair_entry_to_scval(node_a, node_b)`. Decoders:
`scval_to_address`, `scval_to_u32`, `scval_to_i128`, `scval_to_bool`,
`scval_to_bytes32`, `decode_scval` (base64 XDR).

## `MintClient` (`mint`)

Wraps a `TxBuilder` for the kenter-mint contract. `new(tx, contract_id)`;
`tx()`, `tx_mut()`, `contract_id()`. Where the contract takes a
`caller`/`holder`/`node`, the client passes `source_address`. Every token
and slot read is keyed by `slot_id`. The contract interface itself is in
[`contracts/kenter-mint/API.md`](../../contracts/kenter-mint/API.md); the
print lifecycle is described in
[node selection](../../docs/architecture/node-selection.md).

**Printing and selection** (submit):

| Fn | Sig | Returns |
|----|-----|---------|
| `request_print` | `(&mut, event_id:[u8;32], amount:i128, total_pairs:u32, first_pair:(&str,&str), last_pair:(&str,&str))` | `u32` slot_id. Names only the depositor's end pairs. Submitted with `invoke_widened` over `neighbour_slot_keys`; resent once (after a fresh simulation) if it fails on chain. |
| `seed_print` | `(&mut, slot_id, signature:[u8;96])` | `[u8;32]` seed. Anyone may call. |
| `register_pair` | `(&mut, partner:&StellarKeypair)` | `u32` registration ledger. Source is `node_a`, `partner` is `node_b`; cosigned, no margin. A pair may claim on prints requested after it registered. |
| `unpair` | `(&mut)` | `String` former partner |
| `claim_position` | `(&mut, slot_id, partner:&StellarKeypair, may_land_first:u32)` | `u32` rank (0 lowest). Cosigned with `ContentionMargin::for_claims(may_land_first)`. |
| `skip_position` | `(&mut, slot_id)` | `u32` position skipped. Depositor pays `2 * node_fee`, burned. Allowed once the current position has not confirmed within `serve_timeout`. |
| `confirm_link` | `(&mut, slot_id, link_index:u32, partial_public_key:[u8;32])` | `u32` links completed. Called by the assigned pair. |
| `cancel_print` | `(&mut, slot_id)` | `i128` refund. Depositor only. |
| `clear_expired_slot` | `(&mut, slot_id)` | `i128` refund. Anyone may call once `max_print_ledgers` has passed. |
| `register_token` | `(&mut, slot_id, ephemeral_key, chain_hash, mode:TokenMode, initial_owner_commitment, claim_pubkey)` | `bool`. Depositor only, after every link is confirmed. `initial_owner_commitment` is ignored (pass zeros) for `PureBearer`. Registering the wrong `claim_pubkey` makes the note unredeemable by chain. |

**Value** (submit):

| Fn | Sig | Returns |
|----|-----|---------|
| `spend` | `(&mut, slot_id, current_owner_pubkey, new_owner_commitment, signature:[u8;64])` | `()` |
| `redeem_by_key` | `(&mut, recipient:&str, slot_id, signature:[u8;64], claim_signature:[u8;64])` | `i128` payout |
| `redeem_by_key_owned` | `(&mut, recipient, slot_id, signature, owner_pubkey, owner_signature)` | `i128` payout |
| `redeem_by_chain` | `(&mut, recipient, slot_id, chain_data:Vec<u8>, claim_signature)` | `i128` payout |
| `redeem_by_chain_owned` | `(&mut, recipient, slot_id, chain_data, owner_pubkey, owner_signature)` | `i128` payout |
| `claim_fees` | `(&mut)` | `i128` claimed; contract error `NothingToClaim` on a zero balance |

The signatures these take:

- `spend`: the current owner's Ed25519 signature
  (`kenter_crypto::spend::authorize_spend`) over
  `SHA-256(SPEND_AUTH ‖ contract_xdr ‖ slot_id (u32 BE) ‖ ephemeral_key ‖
  current_commitment ‖ new_owner_commitment ‖ spend_nonce (u32 BE))`.
- `redeem_by_key` `signature`: Ed25519 by the composed ephemeral secret
  over `SHA-256(domain_tag ‖ contract_xdr ‖ slot_id (u32 BE) ‖
  ephemeral_key ‖ recipient_xdr)`. It proves the note was constructed.
  `claim_signature` is by the note's claim key and proves it is held. Both
  are needed, because each shard is derivable by either node of its pair,
  so colluding nodes (or one node of a one-pair print) can compose the
  ephemeral secret without holding the note.
- `redeem_by_chain`: `chain_data` is the canonical blob from
  `kenter_crypto::chain_data::serialize_chain_data`; its SHA-256 must equal
  the `chain_hash` registered. `claim_signature`
  (`BearerToken::sign_claim`) binds the redemption to `recipient`, so a
  chain read from any transaction, including a failed one, cannot be
  replayed to another address.
- `*_owned`: add the current owner's proof
  (`kenter_crypto::spend::authorize_redeem`) over
  `SHA-256(SPEND_REDEEM ‖ contract_xdr ‖ slot_id (u32 BE) ‖ ephemeral_key ‖
  owner_commitment ‖ spend_nonce (u32 BE) ‖ recipient_xdr)`.

See [spend mode](../../docs/architecture/spend-mode.md) for owner keys and
commitments.

`simulate_redeem_by_chain` and `simulate_redeem_by_chain_owned` take the
same arguments as their submitting forms (`&self`) and return
`SimResources` without submitting. The contract runs for real inside the
simulation, so a note that could not be redeemed errors here too, and the
slot stays live. Fees accrue to the construction participants and are
claimed with `claim_fees`, except a volunteer's and a forfeit's, which are
burned.

**Reads:**

| Fn | Sig | Path |
|----|-----|------|
| `node_fee` / `min_pairs` / `max_pairs` | `(&mut) -> u32` | simulate |
| `max_print_ledgers` | `(&self) -> u32` | simulate (ro) |
| `pay_token` | `(&mut) -> String` (SAC id) | simulate. Immutable: a mint escrows one asset for life. |
| `selection` | `(&mut) -> SelectionInfo` | simulate |
| `pair_of` | `(&mut, node:&str) -> Option<(String, u32)>` (partner, registered_at) | simulate |
| `accrued_fees` | `(&mut, node:&str) -> i128` | simulate |
| `is_redeemed` | `(&mut, slot_id) -> bool` | simulate |
| `get_token_state` | `(&self, slot_id) -> Option<TokenState>` | simulate (ro); authoritative through archival |
| `get_token` | `(&self, slot_id) -> Option<TokenInfo>` | `getLedgerEntries` |
| `token_or_marker` | `(&self, slot_id) -> SlotRecord` | `Token` and `Redeemed` keys in one call; falls back to `get_token_state` when both are absent |
| `get_slot` | `(&self, slot_id) -> Option<SlotInfo>` | `getLedgerEntries`, two keys |
| `get_slots` | `(&self, ids:&[u32]) -> HashMap<u32, SlotInfo>` | `getLedgerEntries`, 100 slots (200 keys) per call |
| `next_slot_id` | `(&self) -> u32` | `getLedgerEntries`; 0 on a mint that never printed |

`token_or_marker` exists because redemption removes `Token(slot_id)` and
writes `Redeemed(slot_id)`: reading only the token reports a paid-out note
as a slot that never existed. Both keys go in one call so the answers come
from the same ledger. An absent pair may also mean the record archived, so
that case is settled by simulation, which restores archived entries.

**A slot is two entries.** `DataKey::Slot(id)` is persistent (the core)
and `DataKey::Draw(id)` is temporary (beacon seed, claims, partial keys).
`get_slot` and `get_slots` read both in the same round trip and assemble
one `SlotInfo`. A core with no draw comes back with `lapsed = true`. Every
direct read checks that each returned entry belongs to this contract, is a
key that was asked for, and has the durability asked for
(`WrongLedgerEntry` otherwise), so an RPC cannot answer a question about
one note with another note's record.

**`NEIGHBOUR_SLOTS` (4) and `neighbour_slot_keys(fp, n) -> Vec<LedgerKey>`.**
The `Slot` and `Draw` keys of the `n` slot ids after the one a simulated
footprint writes (none if it writes no slot). Two `request_print` calls
simulated against the same `next_slot_id` declare the same keys, and the
one applied second would write keys it never declared; declaring the next
four ids lets that many other requests land in the same ledger first.

**Selection helpers** (free fns, same arithmetic as the mint; the mint
never takes their output):

- `selection_seed(mint_id, slot_id, signature:&[u8;96]) -> [u8;32]`:
  `sha256("kenter:select:v1" ‖ mint ScVal XDR ‖ slot_id BE ‖ sha256(sig))`,
  exactly as `seed_print` computes it. A daemon computes it from the beacon
  round before the slot is seeded, so it can tell whether it would claim.
- `selection_score(seed, a, b) -> [u8;32]`: `sha256(seed ‖ lo ‖ hi)` over
  the two addresses' ScVal XDR in bytewise order. Lowest scores win.

## `Beacon` (`beacon`)

Fetches drand quicknet rounds for `seed_print`. Nothing here is trusted:
the mint verifies the signature, so a lying mirror costs a failed
simulation, not a bad seed.

| Item | Notes |
|---|---|
| `Beacon::quicknet()` | `QUICKNET` chain hash through `MIRRORS` |
| `Beacon::new(chain, mirrors:Vec<String>)` | 10 s HTTP timeout per request |
| `signature(&self, round:u64) -> [u8;96]` | Tries each mirror in order; returns the G1 point **uncompressed**, as `seed_print` takes it |
| `g1_uncompressed(&[u8;48]) -> [u8;96]` | Free fn |
| `QUICKNET` | `52db9ba7…c84e971`, the chain the mint's beacon key belongs to |
| `MIRRORS` | `api.drand.sh`, `drand.cloudflare.com`, `api2.drand.sh`, `api3.drand.sh` |

## `RosterClient` (`roster`)

Wraps a `TxBuilder` for the kenter-roster contract. `new(tx, contract_id)`;
`tx()`, `tx_mut()`.

| Fn | Sig | Returns | Path |
|----|-----|---------|------|
| `join` | `(&mut, name:&str, tunnel_endpoint:&str)` | `ScVal` node. Pays `min_stake`; no fee. | submit |
| `volunteer` | `(&mut, name:&str, tunnel_endpoint:&str)` | `ScVal` node. Same bond; the mint burns this node's fees. Permanent for the address; a paid node converts in place. | submit |
| `leave` | `(&mut)` | `u32` | submit |
| `withdraw_stake` | `(&mut)` | `i128` | submit |
| `heartbeat` | `(&mut)` | `u32` ledger | submit |
| `update_node` | `(&mut, name:Option<&str>, tunnel_endpoint:Option<&str>, active:Option<bool>)` | `ScVal`; `None` = unchanged | submit |
| `is_node` | `(&mut, address)` | `bool` | simulate |
| `node_terms` | `(&mut, address)` | `Option<bool>`: `None` off the pool, else `Some(volunteer)` | simulate |
| `lookup` | `(&mut, address)` | `Option<String>` endpoint | simulate |
| `get_node` | `(&mut, address)` | `Option<NodeInfo>` | simulate |
| `get_node_count` | `(&mut)` | `u32` | simulate |
| `min_stake` | `(&mut)` | `i128` | simulate |

`NodeInfo { name, tunnel_endpoint, staked:i128, joined_at, last_heartbeat,
active, unbonding_at:Option<u32>, volunteer }`; `selectable()` = active and
not unbonding.

## `AssetClient` (`asset`)

`Asset { contract_id, code, issuer:Option<String>, decimals }`.
`needs_trustline()` is true for a classic asset (a payout cannot reach an
account without one). `symbol()` is `$` for a USD stablecoin, `XLM ` for
native, otherwise the asset's code. `AssetClient::new(tx, contract_id)`,
`describe(&mut) -> Asset`. Free fn `sac_contract_id(passphrase, code,
issuer:Option<&str>) -> String` derives the Stellar Asset Contract address
locally (nothing is asked of an endpoint).

## `network`

Which network a build talks to. Fixed at build time by the `mainnet`
feature: nothing set at runtime can turn a mainnet build into a testnet
client, or the reverse.

- `Profile { name, passphrase, rpc, horizon, mint:Option, roster:Option,
  contracts_overridable, relays }`. `relays` is the built-in list of relay
  hosts a wallet may reach a selected node through. A node names its relay
  in its roster endpoint; without the list an operator could name a host
  of its own and learn every depositor's IP. An empty list means a wallet
  reaches no node and fails closed.
- `TESTNET` and `MAINNET` profiles; `TESTNET_PASSPHRASE`,
  `MAINNET_PASSPHRASE`. The testnet profile carries the development
  deployment's contract ids and relay. The mainnet profile takes its mint
  and roster from `KENTER_MAINNET_MINT` and `KENTER_MAINNET_ROSTER` at
  build time, and its relay list is empty until mainnet relays are listed
  in the code. The mainnet default RPC is a public keyless endpoint; every
  holder trusts that one endpoint's answers, so it is overridable (see
  [security model](../../docs/architecture/security-model.md)).
- `built() -> &'static Profile`.
- `Overrides { rpc, horizon, mint, roster }`, `from_env()` (`KENTER_RPC`,
  `KENTER_HORIZON`, `KENTER_MINT`, `KENTER_ROSTER`; blank counts as unset),
  `or(fallback)`.
- `NetworkConfig { profile, rpc, horizon, mint, roster }`:
  `resolve(profile, overrides) -> Result<Self, String>` refuses a contract
  override on a profile that does not allow one (mainnet) and a build with
  no baked-in ids; `from_env()`, `passphrase()`, `rpc_client()` (Horizon
  set explicitly).
- `check_endpoint(profile, rpc_url) -> Result<(), String>`: refuses an RPC
  whose `getNetwork` passphrase is not the profile's.

## `WalletChain` (`wallet`), feature-gated

Behind `[features] wallet = ["dep:kenter-wallet"]`; off by default. Adapts
`MintClient` to `kenter_wallet::ports::ChainRead`. It lives here rather
than in a shell because the orphan rule bars a shell from implementing a
foreign trait for a foreign type; both desktop shells enable
`kenter-client/wallet` and share it.

- `WalletChain::new(mint)`, `mint(&self)`, `into_inner(self)`.
- `impl ChainRead`: `token_status(&self, slot_id:u32)`, backed by
  `token_or_marker`, so a redeemed note reads as `Redeemed` rather than as
  a slot that never existed (which the wallet would count as still held).

## `SorobanRpcClient` (`rpc`)

Thin JSON-RPC client. `new(rpc_url, network_passphrase)`;
`with_horizon(url)` (otherwise SDF's public Horizon, testnet's if the RPC
URL contains "testnet"),
`allowing_plaintext()` (a non-loopback `http://` URL is otherwise refused
with `InsecureRpcUrl`), `host_only()`, `network_passphrase()`.

- `get_network_passphrase`: `getNetwork`.
- `get_account_sequence(address) -> i64` and
  `get_holdings(address) -> Option<Holdings>`, via **Horizon**.
  `Holdings { native, assets:Vec<(code, issuer, stroops)>, subentries }`,
  with `reserve()` (`(2 + subentries) × 0.5 XLM`), `spendable_native()`,
  `asset(code, issuer) -> Option<i128>` (`None` = no trustline).
- `simulate(tx_xdr_b64) -> SimulateResult { transaction_data,
  min_resource_fee, auth, return_value, latest_ledger }`.
- `send_transaction -> SendResult { hash, status }`; `ERROR` becomes
  `TransactionFailed`.
- `get_transaction` / `poll_transaction(hash, timeout)` return
  `GetTransactionResult { status, return_value, ledger, result_xdr }`.
  `return_value` prefers the top-level `returnValue` and falls back to
  `resultMetaXdr`.
- `get_latest_ledger() -> u32`.
- `get_ledger_entries(keys:&[String]) -> Vec<Value>`; keys are base64
  `LedgerKey` XDR.

## Types

- `TokenInfo { amount, node_fee, slot_id, state, mode, chain_hash,
  event_id, participants_len, owner_commitment, spend_nonce, claim_pubkey,
  ephemeral_key }`: the `TokenRecord` fields the payee gates use. A payee
  compares `chain_hash`, `claim_pubkey` and `ephemeral_key` against the
  container it was handed, since each is a field the depositor chose and a
  record can carry one note's values beside another's. `spend_nonce` must
  be read fresh before signing an owner authorization.
- `TokenState`: `Printing | Active | Redeemed | Cancelled | Unknown(u32)`.
- `TokenMode`: `PureBearer = 0 | Spend = 1`. An unknown discriminant is an
  `XdrDecode` error, never a guess: misreading a spend-mode record as pure
  bearer would skip the ownership check.
- `SlotRecord`: `Token(Box<TokenInfo>) | Redeemed(Option<u32>) | Archived |
  NotFound`.
- `SlotInfo`: `slot_id, depositor, amount, total_pairs, pairs,
  completed_links, state, event_id, partial_keys, beacon_round, seed,
  claim_deadline, claims, closed, last_progress, created_at, filled,
  volunteers, lapsed`. `volunteers` is a bitmask: bit `2i` is pair `i`'s
  `node_a`, bit `2i+1` its `node_b`. Methods:
  - `positions()`: interior positions, `total_pairs − 2`.
  - `positions_fixed(ledger)`: selection has closed, or the claim window
    has passed with every position claimed.
  - `chain(ledger) -> Option<Vec<(String, String)>>`: the full chain once
    positions are fixed, read from the claims until selection closes.
  - `admits_next(me, event_id, prior_links, ledger) -> Result<(), String>`:
    the check a node runs before extending a print. The slot must be
    printing, for that event id, with exactly the chain's links confirmed,
    each signed by the pair the slot assigns it, and naming `me` next.
    `prior_links` is `(partial_public_key, node_a_public, node_b_public)`
    per link. The signer check matters because event ids and partial keys
    are public once confirmed.
  - `participants()`: every pair member, in order.
- `ClaimInfo { score, pair, volunteer_a, volunteer_b }`.
- `SelectionInfo { beacon_genesis, beacon_period, beacon_lead,
  claim_window, serve_timeout, min_node_age }`; `round_time(round)` is the
  unix time the round is published.
- `SimResources`, `InvokeResult`, `ContentionMargin`: see `tx` above.

## `ClientError` (`error`)

`thiserror` enum: `RpcTransport(reqwest::Error)`, `RpcError { code, message }`,
`SimulationFailed(String)`, `TransactionFailed { status, detail }`,
`TransactionTimeout(Duration)`, `XdrEncode(String)`, `XdrDecode(String)`,
`ContractError(u32)`, `InvalidAddress(String)`, `MissingReturnValue`,
`WrongLedgerEntry(String)`, `FeeTooHigh { asked, cap }`,
`InsecureRpcUrl(String)`, `Other(String)`.
