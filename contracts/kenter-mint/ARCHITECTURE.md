# kenter-mint — Architecture

**Role.** The autonomous escrow, print-coordination and redemption contract. It
holds the deposited value for every bearer note, runs the draw that chooses the
nodes who print it, coordinates the multi-pair "printing" of the note's chain,
records the finished note on-ledger, and pays out on redemption. It is the only
place value enters or leaves the protocol.

**Autonomy (the load-bearing property).** No admin keys touch money. Every
parameter (`node_fee`, `min_pairs`, `max_pairs`, `pay_token`, `roster`,
`max_print_ledgers`, and the `SelectionConfig`: beacon key, genesis, period,
lead, claim window, serve timeout, `min_node_age`) is set once in the
constructor and is immutable. There is no upgrade path and no withdrawal
function. Value leaves **only** through redemption, cancellation, slot expiry,
`claim_fees`, and burns. Nobody, including the deployer, can move escrowed
funds outside those rules. Changing a parameter means deploying a new contract
and repointing clients.

The constructor refuses (`InvalidConfig`) any configuration that would make
printing unreachable forever: `min_pairs < 3`, `max_pairs > 12`
(`MAX_REDEEMABLE_PAIRS`), `max_print_ledgers = 0`, a zero beacon period, lead,
claim window or serve timeout, a claim window not shorter than
`max_print_ledgers`, and a beacon key that is the identity or not in the G2
subgroup. The `max_pairs` ceiling exists because redemption verifies the whole
chain in one transaction, and a longer chain would not fit the budget. Details
in `API.md`, "Constructor".

## Boundaries

- **Depends on:**
  - the `pay_token` SAC for escrow transfers and burns. The testnet mint uses
    the testnet USDC SAC; `scripts/deploy_testnet.sh` refuses an XLM pay token,
    because the SAC refuses `burn` on native XLM.
  - the **kenter-roster** contract: `node_terms` (selectable, and volunteer or
    not) when a pair registers and when it claims; `get_node` for `joined_at`
    when `min_node_age > 0`; `is_node` when an interior link is confirmed.
    Redemption and `claim_fees` never consult the roster.
  - **drand quicknet**, but only as data. The contract makes no network calls;
    it verifies a round signature someone else posts, against the beacon key
    in its config. Redemption never touches the beacon.
- **Depended on by:** `crates/kenter-client` (`MintClient` builds, simulates
  and submits invocations; `Beacon` fetches drand rounds), `crates/kenter-print`
  (drives a print through selection and the walk), `crates/kenter-node`
  (`select.rs`: registers the pair, seeds, claims, clears expired slots it
  worked on), and the `kenter-wallet` `ChainRead` adapter. Nodes and relays
  read its events.

## Source layout

| File | Contents |
|---|---|
| `src/lib.rs` | the contract: constructor, selection, print walk, settlement, redemption, spend, rent helpers |
| `src/types.rs` | `DataKey`, `MintConfig`, `SelectionConfig`, `SlotCore`, `SlotDraw`, `PrintSlot`, `TokenRecord`, events, errors |
| `src/verify.rs` | on-chain chain verification for chain-based redemption (signatures and hash links) |
| `src/test.rs` | unit tests, including the BLS beacon check and budget measurements |

## Storage

All keys are `DataKey` variants. Nothing is kept in instance storage beyond
the instance itself.

| Key | Storage | Holds | Life |
|---|---|---|---|
| `Config` | persistent | `MintConfig`, including `SelectionConfig` | forever; kept by a keeper via `bump` |
| `NextSlotId` | persistent | the slot counter, never reused | forever; `bump` |
| `Slot(id)` | persistent | `SlotCore`: escrow and every fixed-size fact of a print | fixed end (below), then deleted |
| `Draw(id)` | **temporary** | `SlotDraw`: `pairs`, `seed`, `claims`, `partial_keys`, `confirmers` | same fixed end, then deleted |
| `Token(id)` | persistent | `TokenRecord`, keyed by slot id | 7-day floor at registration; the holder extends with `bump_token` |
| `Redeemed(id)` | persistent | the ledger a note was redeemed on | not bumped; left to archive |
| `EventIdUsed(h)` | persistent | marks an `event_id` as spent | not bumped; never removed |
| `Accrued(addr)` | persistent | a node's claimable fee balance | 7-day floor; removed by `claim_fees` |
| `PairOf(addr)` | persistent | `RegisteredPair { partner, registered_at }` | bumped when registered and when it claims; removed by `unpair` |

**A print slot is two entries.** `SlotCore` is written at `request_print` and
rewritten at the same size after, so no later call pays persistent rent on
growth. Everything that grows with claims and links is in `SlotDraw`, in
temporary storage. The reason: on mainnet a persistent entry lives at least
120 days whatever the contract asks, and growth is charged rent for the
entry's whole remaining life, so a growing persistent slot would make every
claim and link pay 120 days of rent on its bytes. Temporary storage has no
such minimum. Measured costs are in `docs/LEDGER_COSTS.md`.

Both entries live to one **fixed end**, `created_at + max_print_ledgers + 1
day`, clamped to the network's `max_entry_ttl` (`slot_ttl` in `lib.rs`). Later
writes do not move it. `get_slot` assembles both into `PrintSlot`, so readers
see one record; a client reading ledger entries directly reads both
`Slot(id)` and `Draw(id)`. If the draw is gone, `lapsed` is true, `pairs`
holds only the end pairs, the working lists are empty, and every live call
refuses with `DrawLapsed`. That can happen only on a mint whose window is
longer than `max_entry_ttl`, after that long with no write.

## Lifecycle of a print

With `k = total_pairs − 2` interior positions. The end pairs (links `0` and
`total_pairs − 1`) are the depositor's own; every interior pair is chosen by
the draw. The full selection design is in
[node selection](../../docs/architecture/node-selection.md).

0. **`register_pair(a, b)`**, once per node pair, both signing. Both must be
   selectable on the roster and at least `min_node_age` old; each address is
   in at most one pair. Only a pair registered in a ledger strictly before a
   slot's request may claim on it, so pairings are fixed before the seed can
   be known and nobody can grind a pairing against a known seed. `unpair`
   dissolves it.
1. **`request_print(caller, event_id, amount, total_pairs, first_pair,
   last_pair)`.** Transfers `amount` into escrow and opens a `Printing` slot.
   The depositor names only the two end pairs. They are exempt from the
   roster and distinctness checks, because they are the depositor's own
   machines and earn nothing. Requires `amount > 2·node_fee·k` and an unused
   `event_id`. Fixes the beacon round `R = round_at(now) + beacon_lead`, a
   round that has not been published yet.
2. **`seed_print(slot, sig)`**, callable by anyone. The contract verifies
   `sig` as quicknet's BLS12-381 signature for round `R` with a pairing check,
   derives `seed = sha256("kenter:select:v1" ‖ mint ‖ slot_id ‖ sha256(sig))`,
   and opens a claim window of `claim_window` ledgers. A BLS signature is
   unique for its round, so whoever posts it chooses nothing. If nobody has
   posted the round `fallback_delay` seconds after it was due,
   **`seed_fallback(slot)`** seeds with
   `sha256("kenter:select:fallback:v1" ‖ mint ‖ slot_id ‖ R)` instead, so
   issuance survives the beacon stopping.
3. **`claim_position(slot, a, b)`**, both signing. The contract computes
   `score = sha256(seed ‖ lower ‖ higher)` over the two addresses' XDR and
   inserts the claim in score order, keeping the lowest `2k`: `k` positions
   and one runner-up per position. A later, lower score displaces a higher
   one, so arriving first earns nothing. Each claim records both members'
   volunteer terms from the roster. After the deadline, claims are taken only
   while fewer than `k` exist, so a thin network can still fill a print.
4. **Selection closes lazily**, at the first interior `confirm_link` (or the
   first `skip_position`), once the window has passed with at least `k`
   claims. Positions `1..=k` are the `k` lowest scores; the rest become the
   ordered runner-up list. The positions are readable from `get_slot` before
   that: once the deadline has passed with `k` claims, `claims[0..k]` is the
   order.
5. **`confirm_link`**, strictly in order. Link 0 is the depositor's and may be
   confirmed before selection closes. The confirmer of an interior link must
   still be on the roster. Each confirmation records the partial public key
   and the confirming address, and starts the next position's serve clock.
6. **`skip_position`**, by the depositor, when the next interior position has
   not confirmed within `serve_timeout` ledgers. The best runner-up takes its
   place. The depositor pays `2·node_fee`, transferred in and burned. It does
   not come from the escrow, which stays equal to the note's face, and the
   cost makes re-rolling the draw by skipping unattractive.
7. **`register_token`**, by the depositor, once every link is confirmed and
   the slot has not expired. Stores the `TokenRecord` under the slot id, with
   the participant list, the volunteer bits, `chain_hash` and `claim_pubkey`,
   and deletes both slot entries. One record per slot, ever.

The depositor's client carries the partial note to each selected pair through
the relay and checks every extension. The closing link never leaves the
depositor's machine, so no single node ever holds enough to redeem.
`kenter-print` drives this side.

## Settlement paths

| Path | Who | Pays out |
|---|---|---|
| `redeem_by_key` / `redeem_by_chain` (and `_owned` forms) | holder | `amount − fees` to a named `recipient`; one `node_fee` per interior participant, credited to `Accrued` or burned for a volunteer |
| `cancel_print` | depositor, while `Printing` | refund = deposit − confirmed-link fees − forfeit |
| `clear_expired_slot` | anyone, after `max_print_ledgers` | as cancel, except a slot never seeded refunds in full |
| `claim_fees` | node | its whole `Accrued` balance |

**Redemption** removes the `Token` record and writes `Redeemed(id)`. A second
attempt finds no record and is refused; the marker only lets the contract
answer `AlreadyRedeemed` instead of `TokenNotFound`.

- **By key.** The holder proves knowledge of the composed ephemeral secret by
  signing `sha256(tag ‖ contract ‖ slot_id ‖ ephemeral_key ‖ recipient)`. The
  recipient is in the digest because `require_auth()` binds only the
  submitter; without it the signature would be a reusable credential.
- **By chain.** For a note whose printing nodes are offline, the holder
  presents the chain itself. See "Invariants" for how it is bound.
- **Spend mode.** A note in spend mode also needs the current owner to open
  the live `owner_commitment` and sign over the recipient and the spend
  nonce (`_owned` forms); `spend` rotates the commitment. A pure-bearer note
  refuses an owner proof and a spend-mode note refuses redemption without
  one. See [spend mode](../../docs/architecture/spend-mode.md).

**Abandoned slots.** Confirmed interior links are paid one `node_fee` each, to
the address that confirmed, not to its partner, so a node that did the work
is the one paid. End links are not paid. Then the **forfeit**: `2·node_fee`
per interior position not yet confirmed, burned, once round `R`'s publication
time has passed, seeded or not. The forfeit makes cancelling after the seed is
known (to discard an unwanted draw) cost the depositor. There is no forfeit
before round `R` is due, after a seeded window (beacon or fallback) that
closed short of `k` claims, or on an unseeded slot that expires (the beacon
stalled and nobody used the fallback), because in
those cases the depositor learned nothing to exploit. Settlement plus forfeit
never exceeds `2·node_fee·k`, the reserve `request_print` took.

If the draw has lapsed, the confirmers cannot be identified, so their fees are
**burned** instead of paid (`FEE lapsed` event). The depositor's refund is
unchanged, so letting the draw lapse gains a depositor nothing.

`PrintCancelledEvent` and `SlotExpiredEvent` carry `refund`, `earned`,
`burned` and `forfeited`, which together are the whole deposit.

## Fees, volunteers and burns

- **`node_fee` is per interior participant**, two per interior pair. The
  depositor's end pairs are neither charged nor credited.
- **Paid nodes accrue.** Fees are credited to `Accrued(node)` and claimed with
  `claim_fees` whenever the node is next online. A node therefore earns for a
  print even if it is offline when the note is redeemed, which matters most
  for chain-based redemption. The on-ledger `participants` list is the work
  receipt.
- **Volunteers are burned.** A roster node that joined with `volunteer` has
  its fees destroyed with the SAC's `burn`, with a `FEE burned` event per
  volunteer. The holder's payout is the same either way. Terms are taken from
  the roster at claim time and fixed in the slot's `volunteers` bitmask, then
  copied to the token.
- **Burns in the mint:** volunteer fees, skip fees, forfeits, and lapsed-draw
  confirmer fees. If the pay token refuses a burn, the amount stays in the
  mint's balance, where no entry point can move it, and a `FEE locked` event
  says so. A burn that trapped would revert the whole settlement and lock the
  escrow for good.

## Rent and TTL policy

The rule every call site follows is **bump what you read, for as long as it
has to be readable**.

- **Contract state** (instance and code, `Config`, `NextSlotId`): internal
  bumps are lazy, at 30 days remaining, to 120 days (clamped to
  `max_entry_ttl`). A keeper calling `bump()` tops them up whatever their
  remaining life, so no ordinary caller meets the lump.
- **Slot and draw:** the fixed end above. On mainnet the persistent core gets
  the network's 120-day minimum anyway, paid once by the depositor at request.
- **Notes:** a 7-day floor at `register_token` and `spend`; the holder buys
  more with `bump_token(slot_id, ledgers)`, which also carries the contract's
  own entries.
- **`Accrued`:** a 7-day floor at redemption credit.
- **`Redeemed`, `EventIdUsed`:** not bumped. Protocol 23 restores an archived
  persistent entry when a transaction names it, so the refusals they back stay
  correct.

On mainnet every new persistent entry is prepaid about 120 days
(`min_persistent_ttl`), so the 7-day floors only bite on testnet. See
`docs/LEDGER_COSTS.md`.

## Invariants

- **n-of-n additive custody.** A note's ephemeral key is the sum of every
  pair's partial key; all pairs are required. The contract never sees or
  reconstructs a secret. It publishes the partial public keys for observers
  but does not sum them (Soroban has no Curve25519 point addition).
- **Nobody chooses the interior.** The depositor names only the end pairs, and
  claims fill only interior positions. The seed comes from a beacon round not
  yet published at request, and pairs are fixed before the request.
- **Escrow conservation.** Every deposit fully disburses: on redemption as
  holder payout + credited fees + burned fees; on cancel or expiry as refund +
  earned + burned + forfeited. Skip fees come from the depositor, not the
  escrow. No admin drain.
- **Chain redemption cannot be forged.** The ephemeral key, `event_id` and
  pair count are public, so a chain that is merely internally valid could be
  built by anyone. `redeem_by_chain` therefore first requires
  `sha256(chain_data) == token.chain_hash`, the commitment fixed at
  `register_token`, then verifies the chain, then a signature from the note's
  `claim_pubkey` over the recipient. The chain is a preimage, so presenting
  it publishes it; a failed attempt (say, a recipient without a trustline)
  would leave it readable while the note is still live. The claim signature
  closes that: the claim secret travels inside the note file, and what
  reaches the ledger is a signature useful only for this recipient.
- **Single redemption.** Slot ids are never reused and redemption deletes the
  record, so absence refuses a second attempt.

See also [security model](../../docs/architecture/security-model.md). This
file and `API.md` are the per-contract reference; the deployed address comes
from the network profile in `crates/kenter-client/src/network.rs` or the
deploy output (`docs/DEPLOY.md`).
