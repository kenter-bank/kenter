# kenter-roster — API

Soroban contract interface. The roster is the registry of node operators
the mint draws from. State-changing functions take the acting `caller` as
an explicit `Address` and call `require_auth()` on it.

The roster has **no admin and takes no fee**. Nothing can remove a node,
confiscate a bond or withdraw funds on anyone's behalf. Node misbehaviour
(failing to serve a shard, reconstructing a key off-chain) leaves no
on-chain evidence, so there is nothing a contract could punish on. The
Sybil price is cost to enter and time to exit: `min_stake` is locked from
`join` until `unbonding_ledgers` have passed after `leave`.

Deployed contract IDs come from the network profile in
`crates/kenter-client/src/network.rs` or from the deploy output
([Deploy](../../docs/DEPLOY.md)). See also the
[security model](../../docs/architecture/security-model.md).

## Constructor

| Fn | Args |
|----|------|
| `__constructor` | `min_stake:i128, pay_token:Address, unbonding_ledgers:u32` |

Writes `Config` and `NodeCount = 0`. `symbol` is `KNTRROST`,
`start_ledger` is the deploy ledger.

- `min_stake` is the bond in stroops of `pay_token`. It panics if negative.
  Zero is legal; the bond then costs only a transaction fee.
- `unbonding_ledgers` is how long a stake stays locked after `leave`. It is
  not validated: zero makes exit immediate, and `u32::MAX` makes it
  effectively permanent (the release ledger saturates rather than
  overflowing).

The configuration is immutable.

## Node lifecycle

| Fn | Args | Returns | Auth | Notes |
|----|------|---------|------|-------|
| `join` | `caller:Address, name:String, tunnel_endpoint:String` | `Node` | `caller` | Registers a node and transfers `min_stake` to the roster (skipped if zero). An address that has ever volunteered joins as a volunteer here too. Increments `NodeCount`. Panics if already registered (`"already registered"`) or if either string exceeds `MAX_STRING_LENGTH` (256). |
| `volunteer` | `caller:Address, name:String, tunnel_endpoint:String` | `Node` | `caller` | Joins as, or converts a registered node into, a **volunteer**: a node whose fees the mint burns instead of crediting. A depositor pays the same either way, so volunteers neither undercut nor profit. Open to anyone. **Permanent**: writes `Volunteer(caller)`, which is never removed, so a later `leave`, `withdraw_stake` and `join` comes back as a volunteer. On conversion only the flag changes; `name` and `tunnel_endpoint` are used only for a new enrollment. Panics on a node that already volunteers (`"already volunteering"`) or on over-long strings. |
| `update_node` | `caller:Address, name:Option<String>, tunnel_endpoint:Option<String>, active:Option<bool>` | `Node` | `caller` | `None` fields are unchanged. Toggling `active` moves `NodeCount` with it; an unbonding node is already outside the count and is not moved again. Panics if not registered or a string is too long. |
| `heartbeat` | `caller:Address` | `ledger:u32` | `caller` | Sets `last_heartbeat` to the current ledger and extends the node's record (and its volunteer marker). This is the call that keeps an otherwise idle node's record from archiving. Panics if not registered. |
| `leave` | `caller:Address` | `unbonding_at:u32` | `caller` | **Starts unbonding; pays nothing.** Sets `active = false` and `unbonding_at = now + unbonding_ledgers`, so `is_node` turns false at once, and decrements `NodeCount` if the node was counted. Extends the node record to outlive the unbonding period. Returns the ledger from which `withdraw_stake` succeeds. Panics if not registered or already unbonding. |
| `withdraw_stake` | `caller:Address` | `i128` | `caller` | Once `now >= unbonding_at`, transfers the node's `staked` back to it and deletes its record. This is the contract's only outflow, and only the node's own key opens it. A node that loses its key strands its bond: there is no admin to rescue it. Panics if not registered, not unbonding, or still unbonding. |

## Queries (read-only)

| Fn | Args | Returns | Notes |
|----|------|---------|-------|
| `is_node` | `address:Address` | `bool` | Whether the address is in the **selectable** pool: a record exists, `active` is true and the node is not unbonding. Not a presence check. |
| `node_terms` | `address:Address` | `Option<bool>` | `None` if not selectable, else `Some(volunteer)`. The mint calls this when a pair registers and claims, and records the answer with the print, so redemption never consults the roster. |
| `is_volunteer` | `address:Address` | `bool` | Whether the address has ever volunteered, registered or not. |
| `get_node` | `address:Address` | `Option<Node>` | The full record, including inactive and unbonding nodes. |
| `get_node_count` | — | `u32` | Size of the selectable pool: the number of nodes for which `is_node` is true. Not the number of records. |
| `lookup` | `address:Address` | `Option<String>` | The node's `tunnel_endpoint`. |
| `get_config` | — | `RosterConfig` | |
| `symbol` | — | `Symbol` | `KNTRROST`. |
| `min_stake` | — | `i128` | |

Reads never extend TTLs: the mint calls `node_terms` and `is_node` from
other users' transactions, and a read that wrote would bill them.

## Storage rent

| Fn | Args | Returns | Auth | Notes |
|----|------|---------|------|-------|
| `bump` | — | `live_until:u32` | **none** | Extends the contract instance (and with it the code), `Config` and `NodeCount` to the full extension (120 days, or the network's `max_entry_ttl` if lower), whatever their remaining life. Takes no auth: paying rent harms nobody, and gating it would make a dormant roster rescuable only by a key-holder. Node records are not included; `heartbeat` carries those. |

Every mutating call also extends those entries lazily, once they are within
30 days of archival. Without a keeper, that top-up lands as one large fee on
whichever transaction crosses the threshold; a keeper calling `bump`
regularly pays for the elapsed time instead.

## Types

- `Node { address: Address, name: String, tunnel_endpoint: String,
  staked: i128, joined_at: u32, last_heartbeat: u32, active: bool,
  unbonding_at: Option<u32>, volunteer: bool }`. `staked` is the bond the
  node posted at join. `unbonding_at` is `None` when not
  unbonding (an `Option`, because with a zero delay at a low ledger the
  release ledger can itself be 0). `volunteer` only ever goes from false to
  true.
- `RosterConfig { symbol: Symbol, pay_token: Address, min_stake: i128,
  start_ledger: u32, unbonding_ledgers: u32 }`.
- `MAX_STRING_LENGTH = 256`, applied to `name` and `tunnel_endpoint`.

### Storage keys (`DataKey`)

| Key | Holds |
|-----|-------|
| `Config` | `RosterConfig` |
| `NodeCount` | `u32`, the selectable-pool size |
| `Node(Address)` | `Node`, deleted by `withdraw_stake` |
| `Volunteer(Address)` | `true`; written once by `volunteer`, never removed. It outlives the `Node` record so an address cannot volunteer, leave and return as a paid node. Extended by `join` and `heartbeat`; if it archives, `join` lists it and protocol 23 restores it, so the rule holds. |

All are persistent.

## Invariants

- **Solvency.** The roster holds exactly the bonds of its registered nodes:
  `balance(pay_token) == sum(Node.staked)` over all records. There is no
  fee, forfeit or other inflow or outflow.
- **Count.** `NodeCount` equals the number of records with `active` true
  and `unbonding_at` none. Every path that changes that predicate moves the
  count with it, and only those paths.

## Events

| Topics | Data |
|--------|------|
| `(JOIN, node)` | `NodeJoinEvent { node, name, tunnel_endpoint, staked: i128, volunteer: bool }` |
| `(VOLUNTEER, node)` | `NodeVolunteerEvent { node }`: a registered paid node converted. |
| `(UPDATE, node)` | `NodeUpdateEvent { node, tunnel_endpoint, active }` |
| `(UNBOND, node)` | `NodeUnbondEvent { node, staked: i128, unbonding_at: u32 }` |
| `(LEAVE, node)` | `NodeLeaveEvent { node, stake_returned: i128 }`, emitted by `withdraw_stake`. |

Amounts in these events are `i128`. An indexer that decodes them as `u32`
compiles and fails at runtime, because the type checker does not cross the
contract boundary.
