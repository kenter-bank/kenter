# kenter-client — Architecture

**Role.** The native Soroban RPC engine. It builds, simulates, assembles, signs,
and submits contract invocations against **kenter-mint** and **kenter-roster** over
raw JSON-RPC + `stellar-xdr` — **no Soroban SDK**. It also does direct storage
reads via `getLedgerEntries`, fetches drand beacon rounds for print selection,
and fixes which network a build talks to. Everything the wallets and the node
daemon do on-ledger goes through here.

**No SDK (the load-bearing choice).** The Soroban SDK is `no_std`, built for
*in-contract* code. Client-side submission instead hand-assembles XDR envelopes
(`stellar-xdr`) and speaks JSON-RPC over `reqwest`. Return values are decoded
from `ScVal` XDR by hand (`tx::decode_scval` + typed helpers).

## Boundaries

- **Native-only.** `reqwest` + `tokio`; **not** wasm-targetable. A browser wallet
  cannot link this crate — it is the desktop/server engine, not the browser one.
- **Depends on:** `kenter-crypto` (the `StellarKeypair` that signs transactions);
  `stellar-xdr` / `stellar-strkey` (envelope + address encoding); `ark-bls12-381`
  (beacon point decompression). Optionally `kenter-wallet` behind the `wallet`
  feature.
- **Depended on by:** `kenter-ui` and `kenter-desktop` (with `wallet`),
  `kenter-print`, `kenter-node`, `kenter-systest`.
- **Network fixed per build** (`network.rs`). The `mainnet` feature picks the
  `Profile`: passphrase, default RPC and Horizon, contract ids, and the relays
  a wallet may reach nodes through. A runtime switch would let a missing or
  wrong setting put someone's money on the wrong network, so there is none.
  Only the endpoints change at runtime (a Settings field, `KENTER_RPC`,
  `KENTER_HORIZON`), and a custom RPC is checked against the build's
  passphrase (`check_endpoint`) before it is trusted. Testnet contract ids may
  be overridden from the environment (`KENTER_MINT`, `KENTER_ROSTER`). Mainnet
  ids are baked in at build time from `KENTER_MAINNET_MINT` and
  `KENTER_MAINNET_ROSTER` and cannot be overridden, because a wallet pointed
  at somebody else's mint deposits into it; a mainnet build made without them
  refuses to start.
- **`wallet` feature → `WalletChain`.** When enabled, `MintClient` is wrapped to
  satisfy `kenter_wallet::ChainRead`. The adapter lives *here*, not in a shell,
  because orphan rules bar a shell from implementing a foreign trait (`ChainRead`)
  for a foreign type (`MintClient`). Both desktop shells (CLI and GUI) reuse it.
  Off by default, since it pulls in the wallet core.

## Modules

| Module | Contents |
|---|---|
| `rpc` | `SorobanRpcClient`: JSON-RPC calls, `getLedgerEntries`, return-value extraction |
| `tx` | `TxBuilder`: the invoke lifecycle, co-signed calls, `ScVal` decoding |
| `mint` | `MintClient`: typed calls and direct reads for kenter-mint; selection arithmetic; `SlotInfo` |
| `roster` | `RosterClient`: typed calls for kenter-roster |
| `asset` | reads the mint's `pay_token` (symbol, and whether a trustline is needed) |
| `beacon` | `Beacon`: drand quicknet rounds |
| `network` | build-time network `Profile` and runtime endpoint resolution |
| `wallet` | `WalletChain`, the `ChainRead` adapter (feature `wallet`) |
| `error` | the crate's error type |

**The pay token is read, not assumed.** A note is a claim on the mint's
`pay_token`, which is immutable constructor config. `asset` asks the Stellar
Asset Contract: `symbol()` gives the display code, and `name()` gives
`CODE:ISSUER` for a classic asset or `native` for XLM, which is also the test
for whether a holder needs a trustline before depositing or being paid.

## Core model: the invoke lifecycle

`TxBuilder` owns the source keypair (or only an address, `read_only`), its
cached sequence number, a resource-fee ceiling, and one `SorobanRpcClient`. A
state-changing call runs six steps:

1. **build** — assemble an `InvokeHostFunctionOp` (contract id + function symbol +
   `ScVal` args) into an unsigned `Transaction` at `seq + 1`, base fee 100.
2. **simulate** — `simulateTransaction` returns the footprint, `minResourceFee`,
   and the authorization entries.
3. **assemble** — check every auth entry (only the source's own are accepted),
   attach `sorobanTransactionData`, and set the fee to `base + resource`. A
   resource fee above the ceiling (`DEFAULT_MAX_RESOURCE_FEE`, 5 XLM, unless
   the caller set another) is refused with `FeeTooHigh`.
4. **sign** — hash `SHA256(network_id ‖ ENVELOPE_TYPE_TX ‖ tx_xdr)`, Ed25519-sign,
   attach the decorated signature.
5. **send** — `sendTransaction`; `ERROR` fails fast with the `errorResultXdr`.
6. **poll** — `getTransaction` every 2 s until `SUCCESS`/`FAILED` or a 60 s
   timeout, then `sequence += 1`.

Read paths skip 3–6: `simulate_invoke`/`simulate_invoke_ro` stop after step 2;
`MintClient`'s token and slot reads bypass invocation and read
`getLedgerEntries` directly.

### Co-signed calls

`register_pair` and `claim_position` need both members of a node pair to
sign. `invoke_cosigned` is the single exception to "only the source signs":
it accepts exactly one `Address` auth entry, which must be the co-signer's
and rooted at exactly the call being made with no sub-invocations, signs it
with an expiry `COSIGN_LEDGERS` (60) after the simulation's ledger, and
re-simulates with the signed entry in place so the network checks the
signature before anything is sent.

### Contested writes

Several pairs claim on one slot within moments. A claim simulated against the
list as it stood fails with `resource_limit_exceeded` if other claims land
first, because the slot's draw entry has grown since the simulation.
`ContentionMargin` declares room for up to `2k − seen` more claim entries (the
most the list can hold) and raises the resource fee to match; the network
refunds what is not used. Constants are in `API.md`.

### Slots are read as two entries

A print slot is a persistent core (`DataKey::Slot`) and a temporary draw
(`DataKey::Draw`); the split keeps growing data out of persistent rent (see
`contracts/kenter-mint/ARCHITECTURE.md`). `get_slots` builds both keys per
slot, at their own durabilities, and reads up to 100 slots per
`getLedgerEntries` call (the RPC's limit is 200 keys). `SlotInfo` is
assembled from both; a core with no draw is reported `lapsed`, and then only
cancel or clear works on it. This is the read a node daemon polls with,
alongside `next_slot_id`, so a node does not depend on how long an RPC
provider retains events.

### Selection arithmetic, mirrored

`selection_seed` and `selection_score` compute exactly what the mint computes,
so a daemon can score its own pair from a beacon round before the slot is
seeded, and seed only slots it would claim. The mint never accepts these
values from a caller; it computes its own. `SlotInfo::admits_next` is the check
a node runs before extending a chain it was handed: right slot, right event
id, exactly the confirmed links each signed by the pair the slot assigns, and
this node next. It lives here so a node and any harness standing in for one
run the same check. The selection rules themselves are described in
[node selection](../../docs/architecture/node-selection.md).

### The beacon

`Beacon` fetches drand quicknet rounds from public mirrors in order and returns
the G1 signature uncompressed, as `seed_print` takes it. It is untrusted by
design: the mint verifies the BLS signature, so a bad mirror costs one failed
simulation, not a bad seed.

## Return-value extraction

`TxBuilder::invoke` needs the contract's return value, but protocol 23 RPCs
(`TransactionMeta::V4`) omit the top-level `returnValue` field — the result
lives inside `resultMetaXdr`. `rpc::return_value_from_meta` decodes the meta,
pulls `soroban_meta.return_value`, and re-encodes it to the base64 `ScVal`
shape `decode_scval` expects. The code prefers the top-level field and falls
back to the meta, so it works on either RPC version.

## Invariants

- **Only the source signs, except `invoke_cosigned`.** `invoke` refuses an auth
  entry for any other address. The source's signature covers its own
  sub-invocations (the SAC `transfer` during `request_print`).
- **Sequence discipline.** Fetched lazily from Horizon (`sequence == 0`); bumped
  on success; **reset to 0 on any error**, because a transaction that was
  included and failed, or landed after the poll gave up, consumed a number too.
- **Reads never submit.** No read costs fees or a sequence number.
- **A direct read checks what came back.** Each entry must be this contract's,
  for a key that was asked for, at the durability asked for, or the read fails
  with `WrongLedgerEntry`.
- **Absence is not "false".** `getLedgerEntries` omits keys with no entry and
  also archived ones. `token_or_marker` reads `Token` and `Redeemed` together
  and, when both are absent, settles it by simulating `get_token_state`, which
  restores archived entries. Reading the marker matters because redemption
  removes the record: without it a paid-out note would look like one that
  never existed.

## Reference

This file and `API.md` in this directory are the per-crate reference; the
contract interface is `contracts/kenter-mint/API.md`. The mainnet profile
lists no relays yet, so a mainnet build reaches no node until relay hosts
are configured in `network.rs`.
