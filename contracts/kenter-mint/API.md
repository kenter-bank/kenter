# kenter-mint — API

Soroban contract interface. Types are `soroban_sdk` types. Every
state-changing function that acts for someone takes that party as an
explicit `Address` (`caller`, `holder`, `node`) and calls `require_auth()`
on it. Functions marked **none** under Auth take no signature at all.

The mint has no admin, no upgrade path and no withdrawal entry point. Every
parameter is fixed at construction. Deployed contract IDs come from the
network profile in `crates/kenter-client/src/network.rs` or from the deploy
output ([Deploy](../../docs/DEPLOY.md)).

Background: [node selection](../../docs/architecture/node-selection.md),
[spend mode](../../docs/architecture/spend-mode.md),
[security model](../../docs/architecture/security-model.md).

## Constructor

| Fn | Args |
|----|------|
| `__constructor` | `node_fee:u32, min_pairs:u32, max_pairs:u32, pay_token:Address, roster:Address, max_print_ledgers:u32, selection:SelectionConfig` |

The constructor panics with `InvalidConfig` on any configuration that would
make printing unreachable. A mint cannot be corrected after deployment, so
these are refused here rather than at `request_print`:

- `min_pairs < 3`, or `max_pairs < min_pairs`. Three is the floor because a
  print is the depositor's opening pair, at least one node pair, and the
  depositor's closing pair. The two end pairs are exempt from the
  distinctness and roster checks, so a shorter print would contain no
  checked pair at all.
- `max_pairs > 12` (`MAX_REDEEMABLE_PAIRS`). The ceiling is set by what a
  holder can carry: at 12 pairs a note's container is 4172 bytes (17 of a
  keycard's 217 storage blocks) and its sealed paper form is 5 QR symbols
  with no redundancy between them. Path B verification costs roughly
  `1.6M + 3.81M · pairs` instructions, so 12 pairs is about 12% of the
  network's 400M per-transaction budget. More pairs do not strengthen a
  note against the node network: the depositor holds the first and last
  pair at any count, so no coalition of interior nodes can compose the
  secret.
- `max_print_ledgers == 0`.
- A zero `beacon_period`, `beacon_lead`, `claim_window` or `serve_timeout`,
  or `claim_window >= max_print_ledgers`.
- `beacon_pk` equal to the G2 identity (every round's signature would
  verify under it, so anyone could seed any slot), or not in the G2
  subgroup. A key that is not on the curve traps.

**Where fees go.** Fees accrue to the interior nodes that earned them, as
claimable balances. A volunteer node's fees, skip fees and forfeits are
burned: the mint calls the pay token's `burn` on its own balance. If the
token refuses the burn (the native XLM asset does), the amount stays in the
mint's balance where no entry point can move it, and a `(FEE, locked)`
event records that. There is no burn address.

## Printing

A print's interior pairs are chosen by a drand-seeded draw, not by the
depositor. With `k = total_pairs − 2` interior positions:

0. Each node pair registers once with `register_pair`. This fixes who is
   paired with whom before any draw the pair can claim in.
1. `request_print` escrows the deposit and names only the depositor's two
   end pairs. It fixes the beacon round `R`, which has not been published
   yet.
2. `seed_print` posts round `R`'s drand signature and opens a claim window
   of `claim_window` ledgers.
3. Registered pairs `claim_position`. Lowest scores win; the list keeps the
   best `2k`.
4. After the window, with at least `k` claims, the first interior
   `confirm_link` closes selection. Positions `1..=k` are the `k` lowest
   scores; the rest are runners-up.
5. `skip_position` replaces a selected pair that has not confirmed within
   `serve_timeout` ledgers.
6. When all `total_pairs` links are confirmed, the depositor calls
   `register_token`.

| Fn | Args | Returns | Auth | Notes |
|----|------|---------|------|-------|
| `request_print` | `caller:Address, event_id:BytesN<32>, amount:i128, total_pairs:u32, first_pair:PairEntry, last_pair:PairEntry` | `slot_id:u32` | `caller` | Transfers `amount` to escrow and opens a `Printing` slot whose `pairs` is `[first_pair, last_pair]` until selection closes. **The end pairs are the depositor's and are exempt** from the roster and distinctness checks; one key may fill all four places. The exemption is positional, and safe because the depositor names the end pairs and nothing else: no caller can place anyone at an interior position, and no claim can reach an end one. Fixes `beacon_round = round_at(ledger timestamp) + beacon_lead`. The `event_id` must never have been used (`EventIdInUse`); it is how every off-chain party names a print, and it is never released, not even by cancelling. Errors: `InvalidPairCount` (outside `[min_pairs, max_pairs]`), `InvalidAmount` (`amount ≤ 0` or `amount ≤ 2·node_fee·k`), `EventIdInUse`, `PayoutToSelf` (an end pair names the mint). |
| `seed_print` | `slot_id:u32, signature:BytesN<96>` | `seed:BytesN<32>` | **none** | Verifies `signature` (G1, uncompressed) as the beacon's for `beacon_round`: `e(sig, −g₂)·e(H(sha256(R as u64 BE)), pk) = 1`, with drand quicknet's DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`. Sets `seed = sha256("kenter:select:v1" ‖ mint address XDR ‖ slot_id (u32 BE) ‖ sha256(sig))` and `claim_deadline = now + claim_window`. Anyone may call it: a BLS signature is unique, so the poster chooses nothing. About 28M instructions. Errors: `SlotNotFound`, `SlotNotPrinting`, `SlotExpired`, `DrawLapsed`, `AlreadySeeded`, `BadBeacon`. A point off the curve or outside the subgroup traps. |
| `register_pair` | `node_a:Address, node_b:Address` | `registered_at:u32` | `node_a` **and** `node_b` | Fixes the pair for prints requested in later ledgers. Both members must be selectable on the roster and at least `min_node_age` ledgers past their `joined_at`. Each address is in at most one registered pair, so a set of addresses cannot be recombined per draw. Errors: `NodesNotDistinct`, `PayoutToSelf`, `NodeNotOnRoster`, `NodeTooNew`, `AlreadyPaired`. |
| `unpair` | `caller:Address` | `partner:Address` | `caller` | Either member dissolves the pair; both records are removed, so registering again writes a new ledger. Errors: `NotPaired`. |
| `claim_position` | `slot_id:u32, node_a:Address, node_b:Address` | `rank:u32` | `node_a` **and** `node_b` | The two must be registered with each other in a ledger **strictly before** the slot's request (`PairNotRegistered`). The round is fixed at request, so the pairing is set before anyone can know the seed. Scores the pair `sha256(seed ‖ lo ‖ hi)`, where `lo`/`hi` are the two addresses' XDR in bytewise order, and inserts it in score order (ties go to the earlier claim), keeping the lowest `2k`. A later, lower claim displaces a higher one, so arriving first earns nothing. Both members must be selectable on the roster (their `node_terms`, i.e. volunteer status, are recorded in the claim) and distinct from each other, from the end pairs and from every pair in the list. After the deadline, claims are taken only while fewer than `k` exist. Returns the rank, 0 being the lowest score so far. Errors: `NodesNotDistinct`, `SlotNotFound`, `SlotNotPrinting`, `SlotExpired`, `DrawLapsed`, `NotSeeded`, `ClaimsClosed`, `PayoutToSelf`, `NodeNotOnRoster`, `NodeTooNew`, `PairNotRegistered`, `ClaimNotCompetitive` (list full and this score not lower than its last). |
| `confirm_link` | `caller:Address, slot_id:u32, link_index:u32, partial_public_key:BytesN<32>` | `completed:u32` | `caller`, a member of `pairs[link_index]` | Strictly in order (`link_index == completed_links`). Every link after link 0 waits for selection to close; the first interior one closes it. The caller of an interior link must **still** be selectable on the roster: a bond is what backs membership. A node that leaves the roster mid-print stalls the slot at its link, and the depositor skips it or cancels. Records `partial_public_key` and the confirming address, and starts the next position's serve clock. Errors: `SlotNotFound`, `SlotNotPrinting`, `SlotExpired`, `DrawLapsed`, `LinkOutOfOrder`, `PrintAlreadyComplete`, `NotSeeded`, `SelectionNotReady` (window open, or fewer than `k` claims), `NotAssignedPair`, `NodeNotOnRoster`. |
| `skip_position` | `caller:Address, slot_id:u32` | `position:u32` | depositor | Replaces the pair at the next interior position with the best runner-up, once more than `serve_timeout` ledgers have passed since that position became current. **The depositor pays `2·node_fee`, burned.** The contract cannot tell a dead node from a depositor who never sent the extend request, so a skip must cost something or it would be a free way to steer positions. It is charged to the depositor, not the escrow, so the escrow stays equal to the note's face. The skipped pair earns nothing. Errors: `SlotNotFound`, `SlotNotPrinting`, `SlotExpired`, `DrawLapsed`, `NotDepositor`, `NotSeeded`, `SelectionNotReady`, `NotSkippable` (the next link is not interior), `ServeTimeoutNotReached`, `NoBackup`. |
| `register_token` | `caller:Address, slot_id:u32, ephemeral_key:BytesN<32>, chain_hash:BytesN<32>, mode:TokenMode, initial_owner_commitment:BytesN<32>, claim_pubkey:BytesN<32>` | `bool` | depositor | Requires all links confirmed and the slot **not expired**, so a race with `clear_expired_slot` never settles whether a note exists. Stores a `TokenRecord` with `participants` (every pair's two addresses, in order), `chain_hash` (SHA-256 of the canonical `chain_data`) and `claim_pubkey`, in state `Active`. Deletes the slot. **One record per slot, ever.** The record is keyed by `slot_id`, which the contract issues, not by `ephemeral_key`, which is computable by anyone from the published partial keys before registration; two slots naming the same key are two independent records. Errors: `SlotNotFound`, `SlotNotPrinting`, `NotDepositor`, `PrintNotComplete`, `SlotExpired`, `DrawLapsed`, `TokenExists` (a defensive check; the state checks refuse a second registration first). |
| `cancel_print` | `caller:Address, slot_id:u32` | `refund:i128` | depositor | Only while the slot exists and is `Printing`. Refunds the deposit less the settlement and the forfeit (see [Abandoning a print](#abandoning-a-print)), and deletes the slot. Errors: `SlotNotFound`, `SlotNotPrinting`, `NotDepositor`. |
| `clear_expired_slot` | `slot_id:u32` | `refund:i128` | **none** | After `created_at + max_print_ledgers`. Settles exactly as `cancel_print` does, except that a slot **never seeded** refunds in full (the beacon stalled). Pays the refund to the depositor. Errors: `SlotNotFound`, `SlotNotPrinting`, `SlotNotExpired`. |

### Abandoning a print

`cancel_print` and `clear_expired_slot` settle the same way, so letting the
clock run out is never cheaper than cancelling.

- **Settlement.** Each confirmed interior link pays one `node_fee` to the
  address that confirmed it (only one member of a pair signs, and that is
  what is provable). A volunteer's fee is burned instead. The end links are
  not paid. If the draw entry has lapsed, the confirmers cannot be read, so
  their fees are burned (`(FEE, lapsed)` event) and the refund is unchanged.
- **Forfeit.** Once a draw exists, `2·node_fee` is burned for every interior
  position not yet confirmed. A draw exists from round `R`'s publication
  time, seeded or not: anyone can fetch the round and compute every score,
  so cancelling then would re-roll a known draw. No forfeit applies before
  `R` is published, after a seeded window that closed short of `k` claims,
  or when an unseeded slot expires.
- Settlement plus forfeit never exceeds `2·node_fee·k`, the reserve
  `request_print` required the deposit to exceed.

## Redemption

Every redemption pays `amount − node_fees` to a `recipient` the holder
names, and credits `node_fee` to each **interior** participant as a
claimable balance (or burns it, for a volunteer). The depositor's end pairs
are neither charged nor credited: they do no node work.

`recipient` is not authenticated. The paying side is this contract, and an
address cannot be harmed by receiving an asset it already trusts. It may
not be the mint itself (`PayoutToSelf`), which would consume the note and
strand the escrow. The recipient is inside every redemption digest, so a
signature taken from a failed transaction is useless for any other payout.

**Redemption removes the token record** and writes `Redeemed(slot_id)`
holding the ledger it happened on. A second attempt finds no record; slot
IDs come from a monotonic counter and are never reused, so absence is what
refuses it. The marker lets the contract answer `AlreadyRedeemed` rather
than `TokenNotFound`. It is not bumped: an on-chain read restores it, while
`is_redeemed` stops answering once it archives.

All digests below are SHA-256, and the Ed25519 signature is over the
32-byte digest, not the preimage. `contract` is the mint's address XDR,
`slot_id` is u32 big-endian, `recipient` is the address XDR.

| Fn | Args | Returns | Auth | Notes |
|----|------|---------|------|-------|
| `redeem_by_key` | `holder:Address, recipient:Address, slot_id:u32, signature:BytesN<64>, claim_signature:BytesN<64>` | `payout:i128` | `holder` | **Path A, pure bearer.** `signature` is by the composed ephemeral key over `SHA-256("kntr_v1:redeem:key" ‖ contract ‖ slot_id ‖ ephemeral_key ‖ recipient)`; it proves the note was **constructed**. `claim_signature` is by `claim_pubkey` over `SHA-256("kntr_v1:redeem:claim" ‖ contract ‖ slot_id ‖ ephemeral_key ‖ recipient)`; it proves the note is **held**. Both are needed because the composed secret is not held only by the note: each shard is derivable by either node of its pair, so colluding nodes could compose it, and the shard-release handler serves anyone who asks. |
| `redeem_by_chain` | `holder:Address, recipient:Address, slot_id:u32, chain_data:Bytes, claim_signature:BytesN<64>` | `payout:i128` | `holder` | **Path B**, no nodes needed. Requires `sha256(chain_data) == chain_hash`, a valid chain (see [Chain format](#chain-format)), and the same claim signature as Path A. The chain alone is not a proof: presenting it publishes it, and a transaction that fails on-chain publishes it while the note stays `Active`. Errors: `ChainVerificationFailed`. |
| `redeem_by_key_owned` | `holder:Address, recipient:Address, slot_id:u32, signature:BytesN<64>, owner_pubkey:BytesN<32>, owner_signature:BytesN<64>` | `payout:i128` | `holder` | Path A for a spend-mode note. No claim signature: the owner proof is the possession proof. |
| `redeem_by_chain_owned` | `holder:Address, recipient:Address, slot_id:u32, chain_data:Bytes, owner_pubkey:BytesN<32>, owner_signature:BytesN<64>` | `payout:i128` | `holder` | Path B for a spend-mode note. No claim signature, as above. |

**Owner proof.** For the `_owned` forms, `owner_pubkey` must open the live
commitment, `SHA-256("kntr_v1:spend:owner" ‖ owner_pubkey) ==
owner_commitment` (`OwnerCommitmentMismatch`), and `owner_signature` is over
`SHA-256("kntr_v1:spend:redeem" ‖ contract ‖ slot_id ‖ ephemeral_key ‖
owner_commitment ‖ spend_nonce (u32 BE) ‖ recipient)`.

**Mode and path must agree.** A spend-mode note on a plain path fails with
`SpendModeRequiresOwner`; a pure-bearer note on an `_owned` path fails with
`NotSpendMode`.

Errors common to all four: `PayoutToSelf`, `TokenNotFound`,
`AlreadyRedeemed`, `TokenNotActive`. A bad Ed25519 signature traps (the
transaction reverts) rather than returning an error.

### Chain format

`chain_data` is `event_id (32) ‖ link_count (u16 LE) ‖ links`, each link 290
bytes: `node_a_public (32) ‖ node_b_public (32) ‖ partial_public_key (32) ‖
shard_commitment (32) ‖ prev_link_hash (32) ‖ link_index (u16 LE) ‖
signature_a (64) ‖ signature_b (64)`.

On-chain verification checks that `event_id` matches the record, that
`link_count` equals `participants.len() / 2` and the length is exact, that
link indices run `0, 1, …`, and that `prev_link_hash` chains (zero for the
first link). Both signatures on each link are verified over
`"kntr_v1:chain:link" ‖ the first 160 bytes of the link ‖ link_index (u16 LE)
‖ event_id`, and the next link's `prev_link_hash` is
`SHA-256(signable ‖ signature_a ‖ signature_b)`. The signatures are checked
against keys inside the chain, so it is `chain_hash` and the claim signature
that bind a chain to its note, not this check.

## Spend

| Fn | Args | Returns | Auth | Notes |
|----|------|---------|------|-------|
| `spend` | `caller:Address, slot_id:u32, current_owner_pubkey:BytesN<32>, new_owner_commitment:BytesN<32>, signature:BytesN<64>` | `()` | `caller` (fee payer only) | Moves a spend-mode note to a new owner without redeeming it. Ownership is proven by the owner-key signature, not by `caller`, so any funded account may relay a spend. The key must open the live commitment (`OwnerCommitmentMismatch`). The signature is over `SHA-256("kntr_v1:spend:auth" ‖ contract ‖ slot_id ‖ ephemeral_key ‖ current_commitment ‖ new_commitment ‖ spend_nonce (u32 BE))`. Then `owner_commitment = new_owner_commitment` and `spend_nonce += 1`. The nonce makes a signature good for exactly one transfer, even when a note returns to a commitment it held before. Leaves the record with at least 7 days of life. Errors: `TokenNotFound`, `AlreadyRedeemed`, `NotSpendMode`, `TokenNotActive`, `OwnerCommitmentMismatch`; a bad signature traps. |

## Node fees

| Fn | Args | Returns | Auth | Notes |
|----|------|---------|------|-------|
| `claim_fees` | `node:Address` | `amount:i128` | `node` | Pays out and clears the node's accrued balance. Neither this nor redemption consults the roster, so a node that has left still collects. Errors: `NothingToClaim`. |
| `accrued_fees` | `node:Address` | `i128` | read | Unclaimed balance, 0 if none. |

## Queries (read-only)

All are keyed by `slot_id`, not by `ephemeral_key`.

| Fn | Returns | Notes |
|----|---------|-------|
| `get_slot(slot_id)` | `Option<PrintSlot>` | A print in progress, assembled from its two entries. |
| `get_token(slot_id)` | `Option<TokenRecord>` | `None` for a redeemed note as well as an unknown one. |
| `get_token_state(slot_id)` | `Option<TokenState>` | `Redeemed` if the record is gone but the marker remains. |
| `is_redeemed(slot_id)` | `bool` | Informational; lapses when the marker archives. |
| `redeemed_at(slot_id)` | `Option<u32>` | The redemption ledger, while the marker is live. |
| `is_slot_expired(slot_id)` | `bool` | False for a missing or non-printing slot. |
| `pair_of(node)` | `Option<RegisteredPair>` | The pair `node` is registered in. |
| `node_fee()`, `min_pairs()`, `max_pairs()`, `max_print_ledgers()` | `u32` | Config. |
| `pay_token()`, `roster()` | `Address` | Config. |
| `selection()` | `SelectionConfig` | Beacon and selection timings. |

**Positions can be read before selection closes.** Once the deadline has
passed with at least `k` claims, no claim is accepted, so `claims[0..k]` of
`get_slot` are the positions in order. That is how a depositor knows whom
to send each extend request to, and how a node learns it was chosen.

**A slot's record does not outlive the slot.** `register_token`,
`cancel_print` and `clear_expired_slot` delete it, so `get_slot` answers
`None` for anything but a print in progress. To tell a redeemed note from an
unknown one, read `get_token_state` or `is_redeemed`; both lapse when the
marker archives. A client that must be certain simulates
`get_token_state`, since simulation restores archived entries.

**A slot is two entries.** `DataKey::Slot(id)` is persistent and holds the
escrow and every fixed-size fact (`SlotCore`). It never changes size after
`request_print`, so no later call pays persistent rent on growth.
`DataKey::Draw(id)` is **temporary** and holds what grows (`SlotDraw`:
pairs, seed, claims, partial keys, confirmers). Both live to one fixed end,
`created_at + max_print_ledgers + 17,280` ledgers (one day), clamped to the
network's `max_entry_ttl`; later writes do not move it. A client reading
entries directly reads both keys, `Draw` at temporary durability. If the
draw has lapsed, `PrintSlot.lapsed` is true, `pairs` holds only the end
pairs, the working lists are empty, and every call that works on the slot
answers `DrawLapsed`. Cancel and clear still settle.

## Storage rent

| Fn | Args | Returns | Auth | Notes |
|----|------|---------|------|-------|
| `bump` | — | `live_until:u32` | **none** | Extends the contract instance (and with it the code), `Config` and `NextSlotId` to the full extension (120 days, or the network's `max_entry_ttl` if lower). Tops up whatever the remaining life, so a keeper pays for the time since it last called. |
| `bump_token` | `slot_id:u32, ledgers:u32` | `found:bool` | **none** | Extends a note's record to `ledgers`, clamped to `max_entry_ttl`. Asking for less than the record already has is a no-op, so it is safe to call on a schedule. Also extends the contract's own entries, since a live record inside an archived contract is not redeemable. For a print in progress it extends the slot entries to their fixed end only. Returns false for a slot holding neither a print nor a token. |

Neither takes auth. Paying an entry's rent harms nobody, gating it would
make a dormant contract rescuable only by a key-holder, and a bearer note
has no address to authenticate from.

Calls that touch the contract extend its own entries lazily, once they are
within 30 days of archival. `register_token` and `spend` leave a note's
record with a 7-day floor rather than 120 days: how long a note stays
current is the holder's choice (`bump_token`). Accrued fee balances also get
a 7-day floor. `EventIdUsed` and `Redeemed` entries are never bumped;
protocol 23 restores an archived entry automatically when a transaction
reads it, so their on-chain checks hold. See
[Ledger costs](../../docs/LEDGER_COSTS.md).

## Types

- `PairEntry { node_a: Address, node_b: Address }`: one link's two nodes.
- `TokenMode` (repr u32): `PureBearer = 0`, `Spend = 1`.
- `TokenState` (repr u32): `Printing = 0`, `Active = 1`, `Redeemed = 2`,
  `Cancelled = 3`. A stored record is only ever `Active`; `Redeemed` is
  reported from the marker; `Cancelled` is not produced (an abandoned slot
  is deleted).
- `PrintSlot { slot_id, depositor, event_id, amount, total_pairs, pairs,
  completed_links, partial_keys, confirmers, volunteers, state, created_at,
  beacon_round, seed: Option<BytesN<32>>, claim_deadline, claims, closed,
  last_progress, filled, lapsed }`: the view `get_slot` assembles from
  `SlotCore` and `SlotDraw`. `pairs` is `[first, last]` until `closed`,
  then the whole chain. `claims` is every competitive claim, lowest score
  first, until `closed`, then the runners-up only. `confirmers[i]` is the
  address that called `confirm_link` for link `i`. `volunteers` is a
  bitmask: bit `2i` is pair `i`'s `node_a`, bit `2i + 1` its `node_b`.
  `claim_deadline` is 0 until seeded. `filled`: the claim list has held `k`
  claims. `last_progress`: the ledger the current position's serve clock
  started. `lapsed`: the draw entry is gone.
- `SlotCore { slot_id, depositor, event_id, amount, total_pairs, first_pair,
  last_pair, completed_links, volunteers, state, created_at, beacon_round,
  claim_deadline, filled, closed, last_progress }`: the persistent entry.
- `SlotDraw { pairs, seed, claims, partial_keys, confirmers }`: the
  temporary entry.
- `Claim { score: BytesN<32>, pair: PairEntry, volunteer_a: bool,
  volunteer_b: bool }`.
- `RegisteredPair { partner: Address, registered_at: u32 }`, stored per
  address under `DataKey::PairOf`.
- `SelectionConfig { beacon_pk: BytesN<192>, beacon_genesis: u64,
  beacon_period: u64, beacon_lead: u64, claim_window: u32,
  serve_timeout: u32, min_node_age: u32 }`. `beacon_pk` is an uncompressed
  G2 point; genesis and period are unix seconds; round 1 is at genesis.
- `MintConfig { symbol, node_fee, min_pairs, max_pairs, pay_token, roster,
  max_print_ledgers, start_ledger, selection }`. `symbol` is `KNTRMINT`.
- `TokenRecord { ephemeral_key, event_id, chain_hash, slot_id, amount,
  node_fee, participants, volunteers, state, created_at, redeemed_at, mode,
  owner_commitment, spend_nonce, claim_pubkey }`. `volunteers` is copied
  from the slot. `redeemed_at` is always 0 on a stored record.
- `RosterNode`: the roster's `Node`, mirrored field for field so the
  roster's `get_node` decodes. The mint reads only `joined_at`.

### Storage keys (`DataKey`)

| Key | Durability | Holds |
|-----|-----------|-------|
| `Config` | persistent | `MintConfig` |
| `NextSlotId` | persistent | next `u32` slot ID |
| `Slot(u32)` | persistent | `SlotCore` |
| `Draw(u32)` | temporary | `SlotDraw` |
| `Token(u32)` | persistent | `TokenRecord` |
| `Redeemed(u32)` | persistent | redemption ledger `u32` |
| `EventIdUsed(BytesN<32>)` | persistent | the slot ID that used it |
| `Accrued(Address)` | persistent | unclaimed fees `i128` |
| `PairOf(Address)` | persistent | `RegisteredPair` |

## Events

| Topics | Data |
|--------|------|
| `(PRINT, request)` | `PrintRequestEvent { slot_id, event_id, amount, total_pairs, first_pair, last_pair, depositor, beacon_round }` |
| `(PRINT, seeded)` | `PrintSeededEvent { slot_id, beacon_round, seed, claim_deadline, positions }` |
| `(PRINT, claim)` | `ClaimEvent { slot_id, pair, score, rank }` |
| `(PRINT, selected)` | `PrintSelectedEvent { slot_id, pairs }` |
| `(PRINT, skip)` | `SkipEvent { slot_id, position, skipped, replacement, fee }` |
| `(PRINT, forfeit)` | `ForfeitEvent { slot_id, positions, amount }` |
| `(PRINT, cancel)` | `PrintCancelledEvent { slot_id, event_id, refund, earned, burned, forfeited }` |
| `(SLOT, expired)` | `SlotExpiredEvent { slot_id, event_id, refund, depositor, earned, burned, forfeited }` |
| `(PAIR, register)`, `(PAIR, unpair)` | `PairEvent { node_a, node_b, registered }` |
| `(LINK, confirm)` | `LinkConfirmedEvent { slot_id, link_index, completed_links, confirmer, partial_public_key }` |
| `(TOKEN, active)` | `TokenActiveEvent { slot_id, event_id, ephemeral_key, amount, depositor, mode, chain_hash, claim_pubkey }` |
| `(SPEND, owner)` | `SpendEvent { slot_id, ephemeral_key, new_owner_commitment, spend_nonce }` |
| `(REDEEM, key)` | `RedeemByKeyEvent { slot_id, ephemeral_key, holder, recipient, amount, node_fees_accrued, node_fees_burned }` |
| `(REDEEM, chain)` | `RedeemByChainEvent { …same fields… }` |
| `(FEE, accrued)` | `FeeAccruedEvent { slot_id, node, amount }`: an abandoned print credited a confirmer. |
| `(FEE, burned)` | `FeeBurnedEvent { slot_id, node, amount }`: a volunteer's fee was burned. |
| `(FEE, lapsed)` | `FeeLockedEvent { slot_id, amount }`: an abandoned slot settled after its draw lapsed; confirmed interior fees were burned. |
| `(FEE, locked)` | `FeeLockedEvent { slot_id, amount }`: the pay token refused a burn; the amount stays unreachable in the mint. |
| `(FEES, claim)` | `FeesClaimedEvent { node, amount }` |

### What an indexer can reconstruct from events alone

- `TokenActiveEvent` carries `depositor`, `mode`, `chain_hash` and
  `claim_pubkey` beside the slot and key. Records are keyed by slot, so two
  of them may name the same `ephemeral_key`; the chain hash tells them
  apart.
- `SpendEvent` and both `Redeem*` events carry `slot_id` for the same
  reason. `SpendEvent.spend_nonce` is the value **after** the transfer,
  the one the next authorization must use.
- `PrintCancelledEvent` and `SlotExpiredEvent` carry `earned`, `burned` and
  `forfeited` beside `refund`; together they account for the whole deposit.
- `PrintSeededEvent` carries the seed, so a node daemon can score its pair
  without reading the slot.
- `LinkConfirmedEvent` is the only lasting record of `partial_public_key`
  once the slot is deleted.

`TokenActiveEvent.amount` is the **gross** escrow, while the `Redeem*`
events report the net paid out, with `node_fees_accrued` and
`node_fees_burned` alongside.

## Error codes

| Code | Name | Code | Name |
|------|------|------|------|
| 20 | `InvalidPairCount` | 40 | `TokenNotFound` |
| 21 | `NodeNotOnRoster` | 41 | `TokenNotActive` |
| 22 | `SlotNotFound` | 42 | `AlreadyRedeemed` |
| 23 | `SlotNotPrinting` | 43 | `InvalidSignature` (not returned; bad signatures trap) |
| 24 | `SlotExpired` | 44 | `ChainVerificationFailed` |
| 25 | `NotAssignedPair` | 45 | `NothingToClaim` |
| 26 | `LinkOutOfOrder` | 46 | `NotSpendMode` |
| 27 | `PrintAlreadyComplete` | 47 | `SpendModeRequiresOwner` |
| 28 | `NotDepositor` | 48 | `OwnerCommitmentMismatch` |
| 29 | `PrintNotComplete` | 49 | `TokenExists` |
| 30 | `SlotNotExpired` | 50 | `PayoutToSelf` |
| 31 | `NodesNotDistinct` | 51 | `InvalidAmount` |
| 32 | `EventIdInUse` | 52 | `InvalidConfig` |
| 33 | `NotSeeded` | 53 | `ServeTimeoutNotReached` |
| 34 | `AlreadySeeded` | 54 | `NotSkippable` |
| 35 | `BadBeacon` | 55 | `NodeTooNew` |
| 36 | `ClaimsClosed` | 56 | `AlreadyPaired` |
| 37 | `ClaimNotCompetitive` | 57 | `NotPaired` |
| 38 | `SelectionNotReady` | 58 | `PairNotRegistered` |
| 39 | `NoBackup` | 59 | `DrawLapsed` |
