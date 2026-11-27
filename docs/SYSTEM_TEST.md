# Local system test

`kenter-systest` runs Kenter end to end against Stellar testnet: real node
daemons, a relay, two GUI clients, and the live mint and roster. It
provisions accounts, starts the processes, and after every step checks what
changed on the ledger.

This page is the procedure: what the test needs, how to run each mode, and
what each phase asserts. For an overview of all the test tiers, see
[The harnesses](/testing/).

## What the test covers

| Choice | What the test does |
|---|---|
| Daemons | Real `kenter-node` processes, two by default, with keys generated for the run |
| Mint | A USDC mint, the asset mainnet uses |
| Clients | Two GUI wallets: a depositor and a receiver, so payment and acceptance are both reached |
| Assertions | Ledger-visible consequences only, all written to a results log |

### The daemons build links, not shards

The daemons in this test serve `/kenter/health` and `/kenter/extend`. They
build **links**.

Nodes do not serve shards: the GUI's Redeem and the CLI's `redeem` both use
`redeem_by_chain`, which needs no node and no secret. The shard scheme is
still exercised in process by `kenter-tunnler`'s `multi_node_test.rs`, which
turns shard service on for its own nodes.

### How many daemons

One daemon process is **one pair** and holds **two** Stellar keys. Extending a
chain dual-signs the link, so whoever can build a pair's link can also compute
its shard: the unit of trust is the pair.

A print across `k` daemons has `k + 2` pairs. The depositor opens the chain
(link 0) and closes it (link `n-1`); the closing pair is what guarantees at
least one honest pair in every chain.

| Daemons | Pairs | What it adds | Node accounts |
|---------|-------|--------------|---------------|
| 1 | 3 | the network path exists | 2 |
| **2** | **4** | **hop-to-hop walk, two independent confirmers, a mid-chain failure is testable** | **4** |
| 3 | 5 | little beyond 2 | 6 |

Two is the default. At two, node A's output becomes node B's input, and two
separate accounts submit `confirm_link` against the same slot. Nothing in the
test depends on the number, so `--nodes` changes it.

**The harness starts the daemons, but the draw picks the interior.** A print
names only the depositor's two end pairs. Registered pairs claim the interior
positions and the lowest scores win (see
[Node selection](/architecture/node-selection)). A print with `--nodes n`
asks for `n + 2` pairs, and any registered pair on the roster may win a
position, including another operator's. The assertions are written for
that: each interior pair must be a registered pair and appear once, not
node *i* at position *i*.

## Accounts

Roster stake is in **XLM** (`pay_token` is the native SAC; `min_stake` is
150 XLM per address at the default). Friendbot's 10 000 XLM covers it. The
mint escrows **USDC**. The two do not mix, which keeps node provisioning
cheap.

| Who | XLM | USDC trustline | USDC balance | Roster |
|-----|-----|----------------|--------------|--------|
| Each node's own + partner address | friendbot | yes, to claim fees | none | joins at daemon start |
| Client 1 (depositor) | sent by the operator during first run | yes | topped up to 5 | never |
| Client 2 (receiver) | sent by the operator during first run | yes, to redeem | none | never |

Node keys are generated for the run. The clients' accounts are derived from
their own vault seeds, so the harness cannot choose them.

`kenter-node` joins the roster with both of its keys at startup, then
registers the pair with the mint (`register_pair`), which makes it drawable.
Depositors do not join: their end pairs are exempt from the roster check, and
joining would lock `min_stake` for nothing.

**USDC comes from the funder**, a testnet account whose secret is in
`KENTER_SYSTEST_FUNDER_SECRET`. The harness tops client 1 up to 5 USDC when it
holds less than 4. Circle's faucet (`faucet.circle.com`) refills the funder;
see [Testnet](/TESTNET#getting-testnet-xlm-and-usdc).

## How the wallet prints over the network

`crates/kenter-print` holds the print walk, and both clients print through it
(`print_selected`). The wallet has **no node list and no relay setting**:

1. it requests the print, naming its own two end pairs;
2. it fetches the drand round the slot names and seeds the slot (a node may
   seed it first);
3. it waits out the claim window, then reads the positions off the slot;
4. it walks them, reaching each selected node through a relay listed in the
   build's network profile (`Profile::relays`), and skips a pair that does
   not serve within `serve_timeout`.

The deposit screen's pair dial offers 3, 4, 5 and 8. The CLI's
`kenter print-net` takes `--pairs`, and `--relay <host> [--insecure]` only for
a local rig. The harness's automatic modes print through the same code, with
the relay fixed to this run's (`Reach::Fixed`) or taken from each node's
roster endpoint (`Reach::Roster`, for `--remote`).

### Which relay the run's nodes use

The GUI wallet reaches a selected node only through a relay in its network
profile, so a node behind a relay on 127.0.0.1 is one it can never reach.
The interactive run therefore points its nodes at the profile's first relay
and starts no local relay. `--skip-test` and `--from 8` print through the
harness itself, which names its relay, so they default to a local one.
`--relay <host>` picks another public relay; `--relay local` forces a local
one. The clients get no node or relay setting.

## Topology

```
  profile relay (wss://)               or, for --skip-test / --from 8,
        |                              kenter-tunnler on 127.0.0.1:8000
        +-- kenter-node 1 .. n   (own + partner, USDC mint)
  kenter-ui #1    KENTER_WALLET_DIR / KENTER_VAULT = client1
  kenter-ui #2    KENTER_WALLET_DIR / KENTER_VAULT = client2
        |
   Soroban testnet (USDC mint, shared roster), drand quicknet
```

Everything is local except the ledger, the drand beacon and, in the
interactive run, the profile relay. `--remote` starts no relay and no node,
and reaches real installs through the relays named in their roster
endpoints.

A local relay gates connections on roster membership when
`ROSTER_CONTRACT_ID` is set, which the harness does. The order matters: a
node joins the roster, then connects. The daemon does it in that order.

## The harness

`crates/kenter-systest` is a Rust binary. Its assertions read Soroban
structures (`get_slot`, `get_token`, `accrued_fees`, the mint's events), and
its setup builds trustline and payment transactions; `kenter-client` already
does all of that.

It automates provisioning, process lifecycle and every assertion, and it
**launches both clients itself**, because a client started against the wrong
mint or wallet directory invalidates a run while looking normal. Each window
announces `kenter: mint … | roster …` at startup, and the harness checks the
IDs match the ones it passed. `--manual-clients` prints each client's
environment instead, for a client you want to restart mid-run or run under a
debugger.

The harness does **not** drive the GUI. There are no automation hooks, and
adding some to test the UI would mostly test the hooks. It pauses at each
manual step, says what to do in the window, and checks the ledger when you
continue.

Slots carry no index by depositor, so the harness notes the slot counter
(`next_slot_id`) or the current ledger before a manual step and reads what
appeared afterwards.

### Running it

```bash
cargo build --workspace
export KENTER_SYSTEST_FUNDER_SECRET=S...       # a testnet account holding USDC
cargo run -p kenter-systest -- --preflight     # check, provision nothing
cargo run -p kenter-systest                    # the full interactive run
cargo run -p kenter-systest -- --from 8        # the phase that needs nobody
cargo run -p kenter-systest -- --skip-test     # the unattended skip test
cargo run -p kenter-systest -- --burst 5       # five simultaneous print requests
cargo run -p kenter-systest -- --remote 4      # 4 pairs across installed nodes
```

`TUNNLER_SERVER_SECRET` (a local relay's identity, normally in `.env`) is
required only when the run starts a local relay.

`--preflight` checks that the funder exists, that the mint escrows USDC and,
for a local relay, that its secret is present. It reports the funder's USDC
and which relay the nodes will use, then stops. It is free and idempotent:
use it to catch a wrong mint before spending accounts and attention on a
run.

| Flag | Meaning |
|---|---|
| `--nodes <n>` | node daemons to run (default 2) |
| `--volunteers <k>` | the first `k` of them join as volunteers, whose fees the mint burns; Phase 8 checks the burn (default 0) |
| `--skip-test` | unattended: a local relay and at least three local nodes, a 4-pair print, the node drawn for position 1 killed as soon as positions are fixed (see "Skip test") |
| `--burst <n>` | unattended: `n` fresh depositors request a print at the same moment; starts no nodes (see "Burst test") |
| `--remote <pairs>` | print one note of `<pairs>` pairs (at least 3) across whatever nodes the network selects, starting nothing here; redeem it and check every fee (see "Remote print") |
| `--relay <host>` | the relay this run's nodes use: the profile relay for the interactive run, a local one for `--skip-test` and `--from 8`; `local` forces a local relay |
| `--port <p>` | local relay port on 127.0.0.1 (default 8000) |
| `--mint <id>` | mint contract (default `KENTER_SYSTEST_MINT`, else the testnet USDC mint the harness is built with) |
| `--roster <id>` | roster contract (default `KENTER_ROSTER`, else the harness's built-in testnet roster) |
| `--run-dir <path>` | where clients, logs and artifacts go (default `target/systest`) |
| `--stay-joined` | leave this run's nodes on the roster at the end; by default they leave, so they stop counting toward other daemons' estimate of the roster |
| `--keep-going` | do not stop at the first failed check |
| `--preflight` | check the environment and stop, provisioning nothing |
| `--manual-clients` | print the client environment instead of launching them |
| `--from <phase>` | skip to a phase (3, 3b, 4, 5, 6, 7, 8); earlier ones are assumed done. Provisioning and the network always run. `--from 8` needs no clients and no human |
| `--step-file <path>` | wait for this file at each manual step instead of stdin |
| `--fund <G...>` | fund a wallet the GUI just made, and exit (see [Testnet](/TESTNET#funding-a-wallet-for-a-ui-run)) |
| `--amount <usdc>` | how much `--fund` sends (default 5) |

The funder secret comes from the environment and is never accepted on argv.
Node keys are generated per run and live only in memory and in the daemons'
environment, never on argv or disk. The log records addresses.

### Results logs

A run writes `docs/systest-runs/<timestamp>.md` with every assertion and the
value observed, passed or failed, plus the client, daemon and relay logs.
That directory is gitignored. Each log names the accounts the run funded and
used, so read it locally and do not commit it.

## Runbook

### Phase 0: provision (automatic)

Generate two keys per node, fund every node account from friendbot, and add
a USDC trustline to each.

> Assert: two accounts per node pair.

### Phase 1: bring up the network (automatic)

Start the local relay if this run uses one (roster-gated), then each daemon,
pointed at the USDC mint and the run's relay. Each daemon joins the roster
and registers its pair with the mint by itself.

> Assert: each daemon logs `node is serving`; every node address is on the
> roster.

### Phase 2: first run and trustline (manual, both clients)

The harness starts both windows and checks that each announces the mint and
roster it was given. In each window, complete first run: passphrase, phrase,
account. The window shows an address and waits; send it at least 3 XLM. It
adds the USDC trustline itself once the XLM lands. The harness then reads
each account out of its vault and tops client 1 up with USDC.

> Assert: each client resolved the right mint and roster; its account was
> funded from outside; it has a USDC trustline; client 1 holds enough USDC
> to deposit.

### Phase 3: networked deposit (manual, client 1)

Deposit 1.00 USDC, pure bearer, with `nodes + 2` pairs on the dial. The
wallet requests, seeds, waits for claims and walks the selected pairs.

A registered print deletes its slot, so the harness reads the print from the
mint's events (`PRINT request`, `PRINT selected`, `PRINT skip`,
`TOKEN active`) since a ledger noted before the step, and the note from its
token record.

> Assert: exactly one print by client 1, of `nodes + 2` pairs, registered;
> the amount escrowed; the note live at its face value, naming twice as many
> participants as pairs; selection closed on a whole chain; **every interior
> pair is a pair registered with the mint, and appears once** (the log says
> whether it is this run's or another operator's); the depositor holds both
> ends of the chain; the mint's escrow grew by the deposit, and client 1
> paid it.

### Phase 3b: a selected node dies mid-print (manual, client 1)

Start another deposit of 1.00 USDC. The harness watches the slot and stops
the first node of this run that the draw selects. Touch nothing: the wallet
should skip the silent pair after `serve_timeout` and carry on with the
runner-up or, with none left, cancel for a refund. If no node of this run is
selected, none is stopped.

> Assert: the slot is retired on its own (registered through a runner-up, or
> cancelled); the escrow either holds the note's deposit or gave it back.
> The stopped node is restarted with the same identity.

### Phase 4: pay, bearer (manual, client 1)

Export a note to a file.

> Assert: the file parses as a container; the export log incremented; **no
> ledger change at all**. A bearer handover is off-chain, and a transaction
> here would mean the export is not what it claims.

### Phase 5: pay, spend mode (manual, both clients)

Deposit a note in spend mode. Client 2 shows a receive address; client 1 pays
to it.

> Assert: client 1's spend-mode print registered (read from the events and
> the token record, as in Phase 3); `spend` moved the owner pointer on-chain
> to client 2's commitment; client 2's Accept passes G1 (structure), G2
> (ledger) and G3 (ownership); the note lands in client 2's billfold;
> client 1's copy is marked paid away.

See [Spend mode](/architecture/spend-mode) for the owner pointer and the
acceptance gates.

### Phase 6: redeem (manual, client 2)

Redeem the received note.

> Assert: `is_redeemed` is true; the mint's escrow fell by the face; client
> 2's USDC rose by the face minus the note's fees, which are the `node_fee`
> recorded on the note times its interior participants; when Phase 5 ran in
> the same process, each of this run's node accounts accrued exactly one
> `node_fee` if the draw put it in the note's chain as a paid node, and
> nothing otherwise.

### Phase 7: a node claims its fees (automatic)

`claim_fees` from the first node account of this run that has accrued
anything. Skipped, with a note, if none has.

> Assert: it claimed what had accrued; its USDC balance rose by that; its
> claimable balance is zero.

### Phase 8: redeem to an address (automatic, no clients)

Print a note through the draw, reaching nodes through this run's relay, and
redeem it **to a third party**: an account that never authorised anything
and never held the note. Then have a node claim what the redemption earned
it. `--from 8` runs this phase alone and starts no client windows.

This phase reaches two things nothing else does:

- **Redeem to an address.** The GUI always pays the holder's own account, so
  only here does the payout land somewhere the redeemer does not control.
- **Claiming fees from a fresh print.** Node identities are generated per run
  and kept in memory, so fees accrued in an earlier run belong to keys that
  are gone once that run ends. Printing and claiming inside one phase makes them the same
  nodes.

It prints 0.10 USDC (`SMALL_DEPOSIT`), not the 1.00 the client phases use.
The payout goes to a freshly generated payee that nothing sweeps, so each run
spends the face value out of the funder permanently.

A node of another operator that wins a position and sits behind a different
relay cannot be reached through this run's relay, so it is skipped for a
runner-up, which this run's nodes are.

> Assert: the payee's USDC rose by the payout; the payout equals face minus
> one `node_fee` per interior participant; **the redeemer's balance does not
> move at all**; the mint's balance fell by the payout plus any volunteers'
> burn, with one `FEE burned` event per volunteer participant and no
> `FEE locked`; a volunteer of this run was credited nothing; a paid node of
> this run accrued its fee, claims exactly what accrued, is paid in USDC, and
> is left with zero claimable.

### Skip test (`--skip-test`, automatic)

Runs instead of the phases above. It provisions at least three nodes and
brings up the network as in Phases 0 and 1, then waits up to three minutes
for every local pair to be registered with the mint. It prints 4 pairs (two
interior positions, three claimants, so there is a runner-up) through the
wallet's own code and the local relay, and kills the local node drawn for
position 1 as soon as positions are fixed. It prints 0.10 USDC. Run it with
other operators' nodes offline if you can, so that the draw picks this
run's.

> Assert: every local pair registered; positions were final before the print
> finished; the node at position 1 was killed before it served; the print
> completed after the skip; the note is registered and active; a `PRINT skip`
> event replaced the pair at position 1; each skip cost the depositor one
> pair's fee (`2 x node_fee`); the skipped pair is not in the note's chain;
> the runner-up built position 1; the depositor paid the deposit plus the
> skip fees, nothing else.

### Burst test (`--burst <n>`, automatic)

Runs instead of the phases above, and starts no relay and no node. It funds
`n` fresh depositors (XLM, a USDC trustline, and 0.02 USDC each), then has
them all send `request_print` for 0.01 USDC and 3 pairs at the same moment,
so several land in one ledger. It then cancels each print before its beacon
round is out.

> Assert: every request landed; each got its own slot (the log records which
> ledgers they landed in); each cancel refunded the deposit in full, or less
> one position's fees if the beacon round came out before the cancel.

### Remote print (`--remote <pairs>`, automatic)

Runs instead of the phases above, and starts no relay and no node. It prints
one note of `<pairs>` pairs (at least 3) across whatever registered pairs the
draw selects, reaching each through the relay named in its roster endpoint,
then redeems it by chain to a freshly generated payee. It prints 0.10 USDC.

> Assert: the payee received the payout, which is face minus one `node_fee`
> per interior participant; the mint's balance fell by the payout plus any
> volunteers' burn; one `FEE burned` event per volunteer participant, none
> locked; each selected paid address was credited one fee, each volunteer
> nothing.

### Beacon outage (`KENTER_BEACON_MIRRORS=none`)

Not a separate mode: any run that prints through the draw (Phase 8,
`--remote`) can be made with the beacon turned off. Set
`KENTER_BEACON_MIRRORS=none` in the environment of the harness; the run's
own nodes inherit it. Other operators' nodes must be offline, or they will
seed from the beacon as usual.

With no beacon, nobody posts the round, so the print waits for the mint's
fallback to open (`fallback_delay`, 600 s after the round is due) and is
seeded by it. Expect each print to take about ten minutes longer.

Every print through the draw checks how it was seeded, with the beacon on or
off:

> Assert: with the beacon on, the slot was seeded from it and has no `PRINT
> fallback` event; with it off, the slot has one, and the print otherwise
> passes the same checks.

### Teardown (automatic)

Stop the clients, the daemons and the relay, and copy their logs into the
results log. Unless `--stay-joined` was given, each of this run's node
addresses leaves the roster. The accounts are left in place for inspection.
