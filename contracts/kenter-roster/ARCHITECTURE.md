# kenter-roster — Architecture

**Role.** The node registry. A node joins to become eligible to print notes
and to be admitted to the relay network; the mint contract and the relay
(`kenter-tunnler`) both consult it. The roster holds no note escrow. What it
holds is each node's bond, and only that node can take its bond back.

**Adminless.** There is no admin, no fee and no upgrade path. Every parameter
(`min_stake`, `pay_token`, `unbonding_ledgers`) is set once in the
constructor. Nobody can remove a node, confiscate a bond or redirect funds.
The reasons:

- **There is nothing provable to punish.** Failing to serve a shard leaves no
  on-chain evidence, and reconstructing a key off-chain leaves no trace. A
  removal power would be confiscation on someone's say-so, not punishment.
- **The mint depends on the roster.** `confirm_link` requires live roster
  membership for interior links, so a power to remove a node mid-print would
  let one key stall prints in an otherwise adminless mint.
- **An entity that can redirect funds is what the design avoids.** The mint
  has no admin over money; a roster with one would undo that claim.

What remains as the Sybil price is **cost to enter and time to exit**:
`min_stake` is locked for `unbonding_ledgers` after `leave`. A stake returned
on demand would be a deposit, not a barrier: an attacker could register many
identities, use them, and withdraw at once. A delay turns it into capital at
risk for a period, which needs no fraud proofs.

## Boundaries

- **Depends on:** the `pay_token` SAC, only when `min_stake > 0` (a roster
  with `min_stake = 0` moves no funds, and anyone can join for the price of
  the transaction).
- **Depended on by:**
  - **kenter-mint**: `node_terms` (selectable, and volunteer or not) when a
    pair registers and when it claims a position; `get_node` for `joined_at`
    when the mint enforces a minimum node age; `is_node` when an interior link
    is confirmed. Redemption never consults the roster; the terms are copied
    into the print.
  - **kenter-tunnler**: admits only active members to the relay (reads via
    `getLedgerEntries`, cached).
  - `crates/kenter-client` `RosterClient`, and the node daemon's join and
    heartbeat logic.

## Source layout

| File | Contents |
|---|---|
| `src/lib.rs` | the contract: constructor, lifecycle, queries, rent helpers |
| `src/types.rs` | `DataKey`, `RosterConfig`, `Node`, events |
| `src/test.rs` | unit tests, including a roster that stakes native XLM |

## Storage

All persistent, keyed by `DataKey`:

| Key | Holds |
|---|---|
| `Config` | `RosterConfig`: symbol, `pay_token`, `min_stake`, `start_ledger`, `unbonding_ledgers` |
| `NodeCount` | how many nodes `is_node` would accept |
| `Node(addr)` | the node record |
| `Volunteer(addr)` | marks that this address has volunteered; written once, never removed |

## Model

A `Node` record carries identity (`name`, `tunnel_endpoint`), the bond
(`staked`), liveness (`joined_at`, `last_heartbeat`, `active`), the unbonding
deadline (`unbonding_at`, `None` when not unbonding) and the `volunteer` flag.

Lifecycle:

1. **`join`** takes `min_stake` and registers the caller as a paid node.
   **`volunteer`** does the same as a volunteer, or converts a registered
   paid node in place (only the flag changes; name and endpoint are left as
   they are).
2. **`heartbeat`** and **`update_node`** while running. `update_node` can
   change name, endpoint and `active`.
3. **`leave`** starts unbonding: the node stops counting at once, and
   `unbonding_at = now + unbonding_ledgers` (saturating, so `u32::MAX` means
   "effectively permanent" rather than a trap).
4. **`withdraw_stake`**, once `unbonding_at` has passed, returns the whole
   bond and deletes the record.

**Volunteers.** Every interior node is paid `node_fee` by the mint on
redemption. A volunteer serves without pay: the mint burns its fees instead
of crediting them. The depositor pays the same either way, so volunteers do
not undercut paid operators and cannot profit. Volunteering is open to
anyone, so the flag says "takes no fees", not whose node it is. It is
permanent: the `Volunteer(addr)` marker outlives the record, and `join` reads
it, so an address cannot volunteer, leave, and return as a paid node.
`is_volunteer` answers for any address, registered or not.

## Invariants

- **Membership is one predicate.** `is_node(addr)` is `counted(record)`:
  active and not unbonding. A record that is inactive or unbonding exists but
  is not a member, so a departing operator cannot be named in a fresh print.
  `NodeCount` is defined as the number of records for which `counted` is
  true, and every path that changes the answer (`join`, `volunteer`,
  `update_node` toggling `active`, `leave`) moves the count with it, exactly
  once.
- **Solvency is a single line.** `balance == sum(staked)`. The contract's only
  outflow is `withdraw_stake`, opened only by the node's own signature. A node
  that loses its key strands its bond permanently; there is no entry point
  that could rescue it.
- **A negative bond is refused** at construction. Zero is a legal, deliberate
  configuration.
- **An unbonding record survives its own deadline.** `leave` extends the
  record's TTL to at least `unbonding_ledgers` plus a day (clamped to the
  network maximum), so a node never pays to restore its record to collect its
  own stake.

## Rent and TTL

Entries are bumped lazily: once within 30 days of archival, out to 120 days,
clamped to the network's `max_entry_ttl`. Reads never bump, because `is_node`
and `node_terms` are called by the mint and a read that wrote would bill that
caller. `heartbeat` keeps a node's record (and its volunteer marker) alive.

The lazy threshold has a cost: when it is crossed, the whole top-up lands on
the next transaction, and the instance bump carries the contract's code
entry. `bump()` is the other half. It takes no auth, names no caller, and
tops the core entries up whatever their remaining life, so a keeper calling
it regularly pays rent in proportion to elapsed time and no node ever meets
the lump.

## Queries

`is_node`, `node_terms`, `is_volunteer`, `get_node`, `lookup` (the tunnel
endpoint), `get_node_count`, `get_config`, `symbol`, `min_stake`. There is no
on-chain enumeration of the active pool; an off-chain reader can build one
from the `JOIN`, `UNBOND`, `UPDATE` and `LEAVE` events. See `API.md` for signatures, and
[security model](../../docs/architecture/security-model.md) for how the
roster fits the wider trust picture.
