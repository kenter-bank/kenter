# kenter-node — Architecture

**Role.** The runtime for one Kenter pair. It keeps the pair on the roster,
stays bound to a `kenter-tunnler` relay, serves `/kenter/health`,
`/kenter/shard` and `/kenter/extend`, confirms the links it builds, and takes
part in print selection: it registers its pair with the mint, seeds and
claims prints it may win, and clears abandoned prints it is owed for.
How print selection works on the contract side is described in
[node selection](../../docs/architecture/node-selection.md); what each
component trusts is in the [security model](../../docs/architecture/security-model.md).

## One process is one *pair*, not one node

`ExtendNodeContext` holds `own_keypair` **and** `partner_keypair`, because
`PartialToken::extend` dual-signs the link. The party that can produce a pair's
link can therefore also compute that pair's shard.

**The unit of trust is the pair.** A token built from 3 pairs stands behind 3
independent parties, not 6. The threshold property — no single party can
reconstruct the ephemeral key — holds *across* pairs only.

One process per pair keeps that visible. A multi-identity daemon would let
several pairs collapse into one trust domain: it would look like a 6-party
network and behave like a 1-party one. Splitting a pair across two hosts would
need a two-party protocol for the dual-signed link, which does not exist.

## Shape: a library and two binaries

`kenter_node` is a library so every way of running a node runs the same code.

| Binary | Feature | What it is |
|---|---|---|
| `kenter-node` | none | The CLI. `run` is the headless daemon (a Pi, a server, under systemd or a service manager); the other subcommands are `init`, `addresses`, `status`, `stop`, `claim`, `leave`, `withdraw`, `show-phrase`, `keystore`. |
| `kenter-node-tray` | `tray` | The desktop node, Windows and macOS. No arguments: the daemon in-process with a tray icon. `settings`: the settings window, a separate process the tray launches. Its own binary so a GUI started at login opens no console. |

The `tray` feature pulls `tray-icon`, `winit`, `eframe` and `qrcode`, and
implies `keystore` (the recovery phrase in the OS credential store). A
headless build leaves both off and carries no GUI dependencies. A Linux
desktop tray is not built; Linux runs `kenter-node run`.

| Module | Holds |
|---|---|
| `home` | The install's directory, one per network (`KENTER_NODE_HOME` overrides) |
| `config` | `node.json`: name, ordered relays, terms, endpoint overrides. No secrets. |
| `keys` | The pair's two keys, derived from one node-only recovery phrase |
| `chain` | The node's own on-chain calls and the reads behind `status` |
| `daemon` | Prepare, serve with relay fallback, stop; the link confirmer |
| `select` | Pair registration, seeding, claiming, clearing owed slots |
| `status` | `DaemonStatus`, mirrored to `status.json`; the daemon lock |
| `tray` | Tray menu, icon, autostart, settings window |

**The CLI and the tray talk to a running daemon through files in the home**,
which is owner-only: `stop.request` (`kenter-node stop`), `reload.request`
(settings saved; the tray restarts its node), `register.request` (Settings,
"Register now"). The daemon holds an OS lock on `daemon.lock` for its whole
life, and `claim`, `leave` and `withdraw` refuse while it runs, because two
submitters on one account race for the sequence number.

## What the daemon does (`daemon::run`)

1. **Prepare.** Wait until both addresses can pay to join (stake, reserve
   and `FEE_FLOAT`). The operator funds only the own address; the node
   creates and funds its partner from it, and tops the partner up later
   when it runs low, so the operator manages one balance. Then join (or
   volunteer) for both addresses, convert to volunteer if the config asks,
   and mark both records **active before binding any relay**, so a relay
   that gates on the roster admits the pair. (The bundled `kenter-tunnler`
   admits any address with a roster record, which exists exactly while its
   stake is locked.)
2. **Serve.** Bind to the first relay in `node.json` that answers; on a
   drop, start again from the top, with backoff while none answers. The
   endpoint the relay assigns is checked (`valid_endpoint`: `https://<own
   address>.<the relay's own host>`) before it is
   written to both roster records: at once on the first binding or the
   primary relay, after `FALLBACK_SETTLE` on a fallback, and never more
   than once per `ENDPOINT_RECORD_EVERY`. The check means a hostile relay
   cannot make the node advertise an endpoint that points somewhere else. Both records are heartbeated
   every `HEARTBEAT_EVERY`.
3. **Select.** Alongside serving, `select::run` (below).
4. **Stop.** On a clean stop, set both records inactive while still
   reachable, then close the tunnel. A crash skips this; a selected pair
   that goes silent is skipped by the depositor (`skip_position`).

**One account, one submitter at a time.** The own key signs `confirm_link`,
the roster calls and every selection transaction. `OwnKeyLock` serialises
them, and each submitter re-reads the sequence before sending.

### Serving a print

`ExtendRequest` carries the `slot_id`. Before extending, the node's
`LinkConfirmer::admits` reads the slot and runs `SlotInfo::admits_next`: the
chain must be for this slot's event id, carry exactly the links confirmed
on-chain, each signed by the pair the slot assigns it, and name this pair
next. A node therefore never signs a link for a chain that skips a pair,
reorders pairs or belongs to another print. After extending, the node submits `confirm_link`
itself — the mint accepts it only from a member of the assigned pair — and
**a failed confirmation fails the extend**, because an unconfirmed link can
never be registered. `KenterHandler` keeps the last `SERVED_KEEP` (64)
replies keyed by a hash of the exact request, so a depositor whose reply was
lost gets the same reply again without a second confirmation.

The chain call goes through the `LinkConfirmer` port, so `kenter-network`
stays chain-free and this crate supplies the Soroban implementation.

## Selection (`select::run`)

Every 5 s the loop reads `next_slot_id` and every slot it is still watching,
in one batched `get_slots` call (both of each slot's entries). It follows live
state, not events, so it does not depend on how long an RPC provider
retains events. Slot ids are sequential, so `next_slot_id` alone tells the
node which slots are new.

| On chain | When | Why |
|---|---|---|
| `register_pair` | Once, retried every 30 s until registered | Only a pair registered before a print's request may claim on it, so pairings are fixed before any seed is known and cannot be chosen to fit one. If the mint has either address paired with someone else, the node reports it and claims nothing; it never unpairs. |
| `seed_print` | A slot the pair is eligible for, beacon round out, after `SEED_GRACE`, and only if this pair would claim | The seed is computed locally from the round (`selection_seed`) and the pair scores itself first, so a node that would not claim pays for no seed. Among nodes that would claim, lower scores seed sooner, spread over `SEED_SPREAD`; the slot is re-read just before sending, so usually one node pays. |
| `claim_position` | Seeded, inside the window, and the sortition threshold says the pair might win; or after the window while positions are unfilled | Lowest scores win. Never sends a claim the mint would refuse as not competitive. Short-list claims after the window go in score order, a ledger or so apart, each re-reading the slot first, so a full slot stops further claims. |
| `clear_expired_slot` | A slot this node confirmed a link on, once expired | Abandoned-slot fees are paid to confirmers only while the draw still exists, about a day past expiry; after that the draw entry has lapsed, the confirmers are unknown, and the fees are burned. Skipped where settling would pay this node nothing (`paid_nothing`: a volunteer's fee, or no confirmed link still recorded). |

The owed-slot list is in memory: a node restarted across an abandoned print
relies on someone else to clear it.

Status reports `pair_registered`, `claims_made`, `claims_won` and
`links_confirmed`, plus a `detail` when registration or the allowance holds
the node back.

## Spending limits

A stranger can open as many slots as they like and make the node *consider*
them. What the node *spends* is bounded:

- **A daily allowance in XLM**: `DAILY_SHARE` of what the own address can
  spend above `LOW_BALANCE`, over a sliding 24 h window. A node at the floor
  spends nothing.
- **A reserve for short lists**: `SHORT_LIST_RESERVE` of the day's allowance
  is kept for claims after the window, so a flood cannot starve an honest
  print short of nodes.
- **The threshold tightens as the allowance drains**: the sortition
  probability is scaled by the share left, so what remains goes to the best
  scores.
- **The pair count is the live one, not the roster's** (`LivePairs`): the roster counts every pair that joined and
  never left, including machines that are off. The daemon estimates live
  pairs from each slot's `k`-th lowest claim score (about `k / (P + 1)`),
  over the last day (at most 50 slots), and uses the roster count only
  while it has fewer than three slots of evidence. Using the roster count would make
  each live pair's claim probability too low when many registered machines
  are off, and prints would run short. The lowest scores are claimed by
  every live pair whatever its allowance, so the throttle above still
  applies. Logged as `live pairs estimated`.
- **Charged at estimates, whether or not the transaction lands**: a sent
  transaction is charged; a failed simulation sends nothing and costs nothing.
- **Fee caps per submitter**: selection signs under `SELECTION_FEE_CAP`,
  clearing under `CLEAR_FEE_CAP`. Registration, once per pair, signs under the
  client's ordinary cap, since it prepays its records' rent.

| Constant | Value | Where |
|---|---|---|
| `DAILY_SHARE` | 0.2 | `select.rs` |
| `SHORT_LIST_RESERVE` | 0.25 | `select.rs` |
| `CLAIM_COST` | 60,000 stroops charged per claim | `select.rs` |
| `SEED_COST` | 30,000 stroops charged per seed | `select.rs` |
| `CLEAR_COST` | 400,000 stroops charged per clear (unmeasured, generous) | `select.rs` |
| `SELECTION_FEE_CAP` | 200,000 stroops (0.02 XLM) | `select.rs` |
| `CLEAR_FEE_CAP` | 500,000 stroops (0.05 XLM) | `select.rs` |
| `SEED_GRACE` / `SEED_SPREAD` | 8 s / 20 s | `select.rs` |
| `SHORT_LIST_MAX_WAIT` | 20 ledgers | `select.rs` |
| `LOW_BALANCE` | 2 XLM spendable | `chain.rs` |
| `FEE_FLOAT` | 5 XLM above reserve | `chain.rs` |
| `FALLBACK_SETTLE` / `ENDPOINT_RECORD_EVERY` | 10 min / 10 min | `daemon.rs` |
| `HEARTBEAT_EVERY` | 24 h | `daemon.rs` |

The real price of a flood is the mint's forfeit, paid by whoever opens the
slots. The allowance only makes sure a flood cannot empty the node.

## Boundaries

- **Depends on:** `kenter-network` (handlers + `TunnelClient`), `kenter-crypto`
  (keys), `kenter-client` (roster, mint, beacon, network profile), `tokio`,
  `tracing`.
- **Why `kenter-client` lives here and not in `kenter-network`:** the network
  crate stays chain-free so the protocol can be reasoned about as pure
  transport + crypto. This crate is where transport meets chain.
- **Secrets** come from the recovery phrase in the home (or the OS keystore),
  or, in the development form, from the environment or a file. Never argv: a
  process list is not a secret store.
- **Network** is the build's (`kenter_client::network`); `node.json` can
  override only the RPC and Horizon endpoints, not the contracts.

## The development form

`kenter-node` with flags and no subcommand (`legacy.rs`) is the form used for
development and by `kenter-systest`, which drive several nodes on one machine:
secrets in `KENTER_NODE_SECRET` / `KENTER_NODE_PARTNER_SECRET` (or
`--secret-file` / `--partner-secret-file`), one relay with no fallback, and no
deactivation on stop. It runs selection only when it both joins the roster and
confirms links.

```sh
# relay (roster gating off when the contract id is empty)
TUNNLER_SERVER_SECRET=S... TUNNLER_PORT=8080 cargo run -p kenter-tunnler

# one node per pair, each with two distinct keys
KENTER_NODE_SECRET=S... KENTER_NODE_PARTNER_SECRET=S... \
  cargo run -p kenter-node -- --tunnel 127.0.0.1:8080 --insecure
```

`--no-roster` skips roster registration and `--no-confirm` skips
`confirm_link`. Either is fine for transport testing, and either turns
selection off, so the node is never in a print.
