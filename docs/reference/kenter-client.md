# `kenter-client`

Native chain access: Soroban RPC, the contracts, transaction building, and
XDR conversion. This is the crate that makes `kenter-wallet`'s `ChainRead`
port concrete on desktop.

## Modules

| Module | Holds |
|---|---|
| `rpc` | Soroban RPC |
| `mint` | The mint contract, and the selection arithmetic |
| `roster` | The roster contract |
| `asset` | Assets and trustlines |
| `beacon` | drand quicknet rounds, which seed a print's draw |
| `network` | Which network a build talks to, and through which relays |
| `tx` | Transaction building and XDR conversion |
| `wallet` | `WalletChain` — the `ChainRead` implementation |
| `error` | `ClientError` |

## `wallet` — the port implementation

| Item | Purpose |
|---|---|
| `WalletChain` | Implements `kenter_wallet::ChainRead` over Soroban RPC |

This is the join between the wasm-safe core and the native world. The
browser build supplies its own implementation of the same trait.

## `rpc`

| Item | Purpose |
|---|---|
| `SorobanRpcClient` | The RPC client |
| `SimulateResult` | A simulated invocation |
| `SendResult` | A submitted transaction |
| `GetTransactionResult` | Its outcome |
| `Holdings` | What an account holds |

Soroban requires simulate-then-send: simulation computes the footprint and
resource fees that the real submission needs.

## `mint` — the mint contract

| Item | Purpose |
|---|---|
| `MintClient` | Calls the contract |
| `TokenMode` | Pure bearer, or spend mode |
| `TokenState` | What the chain says about a note |
| `TokenInfo` | A token record |
| `SlotRecord` | A token, a redemption marker, archived, or nothing |
| `SlotInfo` | A print slot, assembled from its two ledger entries |
| `ClaimInfo` | One pair's claim on a slot |
| `SelectionInfo` | The mint's beacon and timing parameters |
| `selection_seed`, `selection_score` | The mint's seed and score, computed locally |

`TokenState` is the authority on whether a note is still live. A held note
that the chain reports as redeemed is the disputed case — see
`ReconciledToken::trusted_amount()` in `kenter-wallet`.

Every token and slot is keyed by `slot_id`. Reads that matter for money
(`get_token`, `token_or_marker`, `get_slot`, `get_slots`, `next_slot_id`)
go straight to `getLedgerEntries` and check that each entry returned is the
one asked for.

### Selection

The depositor names only its own two end pairs in `request_print`; the
interior pairs select themselves by a drand-seeded draw (see
[node selection](/architecture/node-selection)). The calls that drive it:

| Call | Who | What |
|---|---|---|
| `request_print` | depositor | Escrows, names the end pairs, fixes a beacon round. Declares the next few slot ids' storage too (`neighbour_slot_keys`), so concurrent requests in one ledger do not collide |
| `seed_print` | anyone | Posts the round's signature; the mint derives the seed |
| `register_pair` / `unpair` | a pair | Fixes the pairing before any draw it claims in |
| `claim_position` | a pair | Claims a position; lowest scores win |
| `skip_position` | depositor | Replaces a pair that did not serve, at a burned fee |
| `confirm_link` | the assigned pair | Records each link, in order |
| `clear_expired_slot` | anyone | Settles an expired slot |

`register_pair` and `claim_position` need both members' signatures and go
through `TxBuilder::invoke_cosigned`. A claim also declares a
`ContentionMargin`, room for claims that land between its simulation and
its application.

**A slot is two entries**: a persistent core and a temporary draw (seed,
claims, partial keys), so the draw's storage expires on its own once a
print is done or abandoned. `get_slot` and `get_slots` read
both and return one `SlotInfo`. `filled` says whether the claim list ever
reached one claim per position; `volunteers` is a bitmask of which
participants' fees are burned; `lapsed` means the draw is gone and only
cancel or clear still work. Use `SlotInfo::chain(ledger)` for the selected
chain and `SlotInfo::admits_next` for the check a node runs before
extending.

`max_print_ledgers()` reads how long a slot stays open before anyone may
clear it.

## `roster` and `asset`

| Item | Purpose |
|---|---|
| `RosterClient` | Node registry: join, volunteer, heartbeat, leave, lookups |
| `Asset` | An asset, by code and issuer |
| `AssetClient` | Reads what a SAC is: code, issuer, decimals |
| `sac_contract_id` | Derives a Stellar Asset Contract address locally |

A client cannot be paid in an asset it has no trustline for, which is why
the settings page can offer to add one.

## `beacon` and `network`

| Item | Purpose |
|---|---|
| `Beacon` | Fetches a drand quicknet round from public mirrors, uncompressed for `seed_print` |
| `Profile` | A network as compiled in: passphrase, default endpoints, contracts, relays |
| `NetworkConfig` | The build's profile plus runtime endpoint overrides |
| `Overrides` | `KENTER_RPC`, `KENTER_HORIZON`, and on testnet `KENTER_MINT`, `KENTER_ROSTER` |

The network is fixed when the binary is built (the `mainnet` feature);
only endpoints change at runtime, and a custom RPC is refused unless it
serves the build's passphrase (`check_endpoint`).

`Profile::relays` is the list of relays a wallet will reach a selected node
through. A node names its relay in its roster endpoint, and a node whose
relay is not on the list is treated as one that does not serve; otherwise
a node operator could name a relay of its own and learn every depositor's
IP. The mainnet list is empty until mainnet relays are listed in the code,
so a mainnet wallet reaches no node and fails closed.

The beacon is untrusted: the mint verifies the signature, so a wrong
mirror costs one failed simulation, not a bad seed.

## `tx` — transactions and XDR

| Item | Purpose |
|---|---|
| `TxBuilder` | Builds and signs |
| `InvokeResult` | A contract invocation's result |
| `ContentionMargin` | Extra declared resources for a contested write |
| `invoke_widened` | `invoke`, with extra read-write keys added to the simulated footprint |
| `SimResources` | What a simulated call would cost on this network |

`invoke` signs only for the source account and refuses any other
authorization entry. `invoke_cosigned` is the one exception, for calls a
pair makes together: exactly one entry, the co-signer's, for exactly this
call, expiring 60 ledgers after simulation. A `TxBuilder` also refuses a
resource fee above its ceiling (5 XLM by default,
`with_max_resource_fee` to change it), and `read_only` builds one that can
simulate as an address but never sign.

And the XDR conversion helpers, which you will use constantly when adding a
contract call:

| To `ScVal` | From `ScVal` |
|---|---|
| `address_to_scval`, `address_xdr` | `scval_to_address` |
| `bytes32_to_scval`, `bytes64_to_scval`, `bytes_to_scval` | `scval_to_bytes32` |
| `i128_to_scval` | `scval_to_i128` |
| `u32_to_scval` | `scval_to_u32` |
| `bool_to_scval` | `scval_to_bool` |
| `string_to_scval` | |
| `option_to_scval` | |
| `pair_entry_to_scval` | |
| | `decode_scval` |

::: warning Argument order and types must match the contract exactly
Soroban will not tell you that you passed a `u32` where it wanted an `i128`
in a useful way — the failure surfaces as an opaque simulation error. When
adding a call, read the contract's signature in `contracts/kenter-mint/`
rather than inferring it.
:::

## Network tests

Several tests are `#[ignore = "network"]`: they need a live network and
funded accounts.

```bash
cargo test -p kenter-client -- --ignored
```

`tests/vectors_recipient.rs` runs offline and checks `address_xdr` for
account and contract addresses against golden vectors.

The full per-function reference, with signatures and constants, is
`crates/kenter-client/API.md` in the repository.
