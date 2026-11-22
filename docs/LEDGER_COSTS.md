# Ledger costs: what Kenter pays Soroban, and who pays it

Soroban charges for two things, and they behave differently:

- **Transactions:** compute, I/O and bandwidth. A one-off, paid by whoever
  submits the transaction.
- **Storage rent:** bytes × ledgers on every live entry. It accrues against
  entries nobody is looking at, and falls on whichever transaction next
  extends an entry's TTL.

Every figure here is measured on testnet from real transactions, unless it is
marked as projected. Fees and rent rates are network parameters, not
properties of Kenter: they move with protocol upgrades and with the network's
total state size, so re-measure after an upgrade. Mainnet projections use
testnet's measured rates with mainnet's own TTL settings; the two networks'
fee settings otherwise match closely.

## Mainnet prepays 120 days per entry

Soroban gives every new persistent entry a minimum life, prepaid when the
entry is created and not refunded if it is deleted early. The two networks
differ in exactly that parameter:

| | `min_persistent_ttl` | |
|---|---:|---|
| testnet | 120,960 ledgers | ~7 days |
| **mainnet** | **2,073,600 ledgers** | **~120 days** |

So each persistent entry a note creates prepays 120 days on mainnet instead
of 7. Projected, per entry:

| Entry | Storage | Bytes | Prepaid on mainnet (XLM) |
|---|---|---:|---:|
| `Slot(id)` core | persistent | 868 | 0.145 |
| `Token(id)` | persistent | 908 | 0.159 |
| `EventIdUsed(h)` | persistent | 136 | 0.023 |
| `Redeemed(id)` | persistent | 92 | 0.016 |
| `Draw(id)` | temporary | ~500 (3 pairs) | 0.002 |

| Whole life of a note | XLM | at $0.15/XLM |
|---|---:|---:|
| testnet, measured | ~0.04 | ~$0.006 |
| **mainnet, projected** | **~0.35–0.4** | **~$0.055** |

Consequences:

- **Below about $6 face value, ledger cost exceeds 1% of the note** on
  mainnet, for a note held up to 120 days. Holding it longer costs nothing
  more until the 120 days run out.
- **A contract's TTL floor below 120 days has no effect on mainnet.** The
  contract's own floors (7 days for a note record) are below the network
  minimum there.
- **A deploy prepays 120 days of code rent**, estimated at about 59 XLM for
  the mint and 18 XLM for the roster at their current wasm sizes (see
  "Storage rent").
- **Measure after a mainnet deploy.** Run one `ExtendFootprintTtlOp` probe,
  as the testnet figures were measured, and replace these projections.

### What a print request creates

`request_print` creates three entries. Read from the transaction meta of a
testnet print request; the rent formula's total is within 5% of what was
charged:

| Entry | Storage | Bytes | Life | Rent, testnet (stroops) | Rent, mainnet (projected) |
|---|---|---:|---|---:|---:|
| `Slot(id)` core | persistent | 868 | network minimum | 86,775 | **1,446,667** (0.145 XLM) |
| `EventIdUsed(h)` | persistent | 136 | network minimum | 13,596 | 226,667 (0.023 XLM) |
| `Draw(id)` | temporary | 500 | window + 1 day | 24,233 | 23,566 (0.002 XLM) |

The `Draw(id)` figures are for `max_print_ledgers` = 100,000. With the
mainnet configuration of 17,280 (one day), the draw lives about 34,560
ledgers instead of 117,280, and its rent falls to about 30% of the figure
shown.

So a print request costs the depositor about **0.17 XLM on mainnet**
(≈ $0.025 at $0.15/XLM), almost all of it the persistent core's 120-day
minimum life, for a record that typically lives minutes. That is the cost
behind the ~$6 floor above. The first print on a new mint also creates the
mint's own USDC balance entry (224 B, about 0.037 XLM on mainnet), once.

The core is 868 bytes mostly because a `contracttype` struct is stored as a
map keyed by field-name symbols. A packed encoding, or a much smaller
persistent refund record with the rest of the core temporary, would reduce
it; both are contract changes.

## Transaction costs

Measured on testnet. The rent included in each fee is at testnet's 7-day
minimum.

| Call | Submitted by | Fee (XLM) |
|---|---|---:|
| `request_print` | depositor | 0.0148 |
| `seed_print` | depositor or node | 0.0017 |
| `claim_position` that adds to the claim list | node | 0.0028 |
| `claim_position` that replaces one | node | 0.0012 |
| `skip_position` | depositor | 0.0014 |
| `confirm_link` (end link, ×2) | depositor | 0.0013 |
| `confirm_link` (interior, after the first) | roster node | 0.0012 |
| `register_token` | depositor | 0.0098 |
| `redeem_by_chain` | holder | 0.0064 |
| `bump` (cold contract) | anyone | tens of XLM |
| `bump` (warm) | anyone | 0.0011 |
| `join` (warm roster) | node | 0.0794 |

On testnet a depositor spends roughly 0.03 XLM to mint a three-pair note and
a holder 0.0064 XLM to redeem it. On mainnet the depositor's figure is
dominated by `request_print`'s 0.17 XLM.

`cancel_print` and `clear_expired_slot` are not in the table; they have not
been measured under the current TTL policy.

### Selection calls on mainnet

Rent is charged when an entry **grows**, on the new bytes, for the entry's
whole remaining life. A claim adds about 266 bytes to the draw, a link about
83, the seed about 36. The rent formula reproduces the claim measurement
(266 B against the 260–268 B seen).

All of that growth lands on the temporary `Draw(id)`, whose life is set by
the contract (`created_at + max_print_ledgers + 1 day`), not by the
network's minimum. Temporary storage rents at about half the persistent
rate, and the two networks' rent rates differ by about 3%. So selection
calls cost about the same on mainnet as on testnet: a claim about
0.0028 XLM, a seed about 0.0017, a link about 0.0012. With
`max_print_ledgers` at 17,280 instead of 100,000, the rent part of each is
lower again:

| | Fee, testnet (XLM) | Rent part, at `max_print_ledgers` 100,000 (stroops) |
|---|---:|---:|
| `claim_position` that adds to the list | 0.0028 | 14,557 |
| `seed_print` | 0.0017 | 1,782 |
| interior `confirm_link` | 0.0012 | 4,156 |
| `skip_position` | 0.0014 | 0 |

## Storage rent

Measured with `ExtendFootprintTtlOp`: one entry, zero instructions, zero
reads, zero writes, so the whole fee is rent.

| Probe | Size | Ledgers | Fee (XLM) |
|---|---:|---:|---:|
| roster code entry | 20,509 B wasm | 526,830 | 5.0378 |
| mint code entry | 41,001 B wasm | 288,292 | 4.7528 |
| roster `Config` | 296 B | 526,852 | 0.0131 |

```
data   8.4178e-4 stroops per byte per ledger   (0.531 mXLM per byte-year)
code   26.33 + 3.3786e-3 × wasm_bytes, per ledger
```

**A code byte costs 4.0× a data byte**, and a code entry is not charged on
the size of its wasm file: there is a large fixed term plus roughly 4×
expansion, consistent with rent being charged on the parsed module.
Shrinking the wasm buys less than it looks.

The code fit has **two points**, at 20.5 KB and 41 KB. The current mint wasm
is about 77 KB, outside that range, so code-rent figures for it are
extrapolations.

### Live entry sizes

Read back from deployed contracts.

| Contract | Entry | Bytes |
|---|---|---:|
| roster | instance / `Config` / `NodeCount` | 96 / 296 / 88 |
| mint | instance / `Config` / `NextSlotId` | 96 / 380 / 88 |
| mint | `Slot(id)` core | 868 |
| mint | `Draw(id)`, three-pair print | ~500 |
| mint | `Token(id)` | 908 |
| mint | `EventIdUsed(h)` | 136 |
| mint | `Redeemed(id)` | 92 |
| mint | `Accrued(addr)` | 140 |

The `Slot(id)` core is fixed-size. `Draw(id)` grows with the pair count and
the claims: pairs, claims, partial keys and confirmers all live there.

### Annual cost

Computed from the fit at the current wasm sizes:

| | XLM/yr |
|---|---:|
| roster, ~18 KB wasm | ~56 |
| mint, ~77 KB wasm | ~181 (extrapolated) |
| core data entries | 0.63 |
| **system floor** | **~237** |
| per outstanding note kept current | 0.550 |

Code entries are over 99% of the fixed cost. **Every KB of wasm is
2.18 XLM/yr**, for as long as the contract is kept alive, so wasm size is a
recurring cost line.

## What is kept alive, and by whom

Rent is owed only while an entry is live, and what stays live is a choice per
entry.

| Entry | Life | Paid by |
|---|---|---|
| code, instance, `Config`, `NextSlotId` | always | a keeper, calling `bump()` |
| `Slot(id)` core, `Draw(id)` | until `created_at + max_print_ledgers + 1 day`; deleted when the note registers | the depositor |
| `Token(id)`, outstanding | a 7-day floor (the network minimum, 120 days, on mainnet), extended by `bump_token` | the holder |
| `Token(id)`, redeemed | deleted, replaced by a `Redeemed(id)` marker | — |
| `Redeemed(id)` | left to archive | — |
| `EventIdUsed(h)` | left to archive | — |
| `Accrued(addr)` | a 7-day floor (120 days on mainnet) | the node, when it claims |

An archived entry is **not lost**. Soroban restores a persistent entry
automatically when a transaction names it, so a double redemption stays
refused and a note stays redeemable. What rent buys is predictability:
without it, the restore fee falls on whoever next touches the record.

So the recurring bill is **0.550 XLM/yr × notes outstanding and kept
current**, not notes ever minted.

### The keeper

The contracts' internal bumps are lazy: they act only once an entry is within
30 days of archival, and then extend it to 120 days (or the network's
`max_entry_ttl`, if lower). That keeps rent off an ordinary caller's bill, at
the cost of making one arbitrary transaction pay the whole top-up: tens of
XLM on a cold contract, against 0.0011 XLM on a warm one.

`bump()` on each contract takes no auth and does nothing else. A keeper
calling it on a schedule tops the entries up whatever their remaining life,
so cost tracks cadence and the lazy threshold is never reached. The deploy
script calls it once right after deploying, so the first extension is paid
by the deployer rather than the first node to join. After that, the
threshold comes round again about every 90 days.

> **`bump` needs `--send=yes` from the stellar CLI.** It only extends TTLs,
> so its `read_write` footprint is empty and the CLI classifies the
> simulation as read-only, declining to submit with a zero exit and a
> plausible return value.

## Circulation

Outstanding notes follow Little's Law:

```
notes outstanding = mints per day × mean days held
```

Rent tracks the **float, not the throughput**. A note redeemed the same day
costs almost nothing however many are printed.

| mints/day | 7d held | 30d | 90d | 365d |
|---:|---:|---:|---:|---:|
| 10 | 39 | 165 | 495 | 2,008 |
| 100 | 385 | 1,650 | 4,950 | 20,076 |
| 1,000 | 3,850 | 16,501 | 49,504 | 200,765 |
| 10,000 | 38,503 | 165,012 | 495,037 | 2,007,648 |

*XLM/yr, if every outstanding note is kept live, at 0.550 XLM per note-year.*

## Denomination floor

**Testnet figures.** On mainnet the floor is about $6 at under 1%; see
"Mainnet prepays 120 days per entry".

At $0.30/XLM, the minimum face value for total cost (mint, fees, redeem,
rent) to stay under a given share of the note:

| held | <0.5% | <1% | <2% |
|---|---:|---:|---:|
| 7d | $3 | **$2** | $1 |
| 30d | $6 | $3 | $1 |
| 90d | $15 | **$7** | $4 |
| 365d | $40 | $20 | $10 |

Rent overtakes the cost of minting after about 22 days held, so short-lived
notes are priced by transactions and long-held ones by storage.

Per-note rent is charged per entry however the calls are packed, so batching
prints does not reduce it. What a TTL policy reaches is rent an entry would
prepay for a life it will not have: a print slot scoped to the print window,
and a note record left at a floor the holder extends.

## The fee structure

`node_fee` is a mint constructor parameter: a flat amount per participant,
in stroops of the pay token, charged only for **interior pairs**:

```
total fees = node_fee × 2 × (pairs − 2)
```

With `node_fee = 25000` (the deploy script's default) and three pairs, a note
deducts 0.005 USDC from the holder's payout, and all of it reaches roster
nodes. The depositor's end pairs are neither charged nor credited, on either
exit. A roster node placed at an end position works for free.

| | |
|---|---|
| An interior pair's revenue per print | 0.005 USDC |
| An interior pair's ledger cost per print | its claims, possibly a seed, and its `confirm_link` |
| Break-even for a winning pair, projected | XLM up to about $2.04 with `max_print_ledgers` 17,280 ($1.39 at 100,000) |
| Abandoned print | the forfeit covers the nodes' spend up to XLM at about $0.52–0.60 (one-day window) |

The fee is fixed in USDC for the life of a mint, while a node's costs are in
XLM, so the margin depends on the XLM price.

**The fee is flat because the costs are flat.** Rent is per entry and a node's
work is per print; neither scales with face value. A percentage fee would
make large notes subsidise the small ones that cause the cost. The pressure
toward consolidating notes comes from transaction fees, which no fee schedule
changes.

## Funding the floor

**Nothing in the fee structure funds the contracts' own rent.** Fees accrue to
node balances, not to a treasury, so the system floor is the deployer's
upkeep: whoever runs the keeper pays it.

A treasury would add contract surface, review area and wasm, and at
2.18 XLM/yr per KB, a 2 KB treasury spends part of its own take on rent
before anyone decides who may withdraw from it. The annual floor is **not**
an initialisation cost: TTLs decay and the bump threshold is crossed again
about every 90 days, so the keeper has to keep calling `bump()`.

Join fees do not fit: a join fee is one-off and rent is perpetual, so solvency
would depend on a continuous supply of new nodes. If the floor ever rose by an
order of magnitude, the shape that fits is a protocol slice of the existing
per-print fee, which scales with use and is a field on a fee that already
exists.

## Why these are measurements

The published formula (`rs-soroban-env/fees.rs`) is

```
fee = ceil(size × fee_per_rent_1kb × ledgers / (1024 × denominator))
```

with `fee_per_rent_1kb` interpolated from the network's total Soroban state
size and a documented ⅓ discount for code entries. Fed testnet's live config
(state 4.44 GB against a 7 GB target, which floors the rate at 1000,
denominator 1215), it predicts about 1 XLM for the roster code probe that
cost 5.04.

The formula as documented does not reproduce the ledger, so everything here
is measured, and projections are checked against the measurements rather
than against the formula.

## Caveats

- **Every figure is a lower bound.** Rent rises with the network's total
  Soroban state. The published curve says the rate is at its floor today and
  climbs about 10× at target, but that curve does not reproduce these
  measurements, so the real multiplier is unknown.
- **The code-entry fit has two points**, and the current mint is outside
  them. A third wasm size would make it safer to extrapolate.
- **Restore fees are not modelled.** They are what a holder pays for a note
  whose record archived.
- **Little's Law assumes a steady state.** A launch or a redemption rush moves
  the float faster than mean holding time suggests.
