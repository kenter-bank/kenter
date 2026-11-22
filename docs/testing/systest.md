# System tests

`kenter-systest` brings up a relay and real node daemons on your machine,
points two GUI clients at them, and checks the testnet ledger after each step
an operator takes.

The full procedure, every flag and every phase's assertions are in
**[Local system test](/SYSTEM_TEST)**. This page is the orientation around
it.

## What it does, and does not

It provisions accounts, runs the daemons, launches the clients, and makes
every assertion. It **does not drive the GUI**.

There are no automation hooks in the client, and adding some to test the UI
would mostly test the hooks. So the harness stops at each manual step, says
what to do in the window, and reads the ledger when told to continue.

Several modes need no human at all:

| Mode | What it checks |
|---|---|
| `--preflight` | the funder, the mint's asset and the relay secret; provisions nothing |
| `--from 8` | print through the draw, redeem to a third party, a node claims its fee |
| `--skip-test` | a selected node is killed before it serves; the wallet skips it for a runner-up |
| `--burst <n>` | `n` print requests in the same ledger each get their own slot, and cancel for a refund |
| `--remote <pairs>` | a print across other operators' installed nodes, with every fee checked |

## What counts as an assertion

A **ledger-visible consequence**, never a screen that advanced:

- escrow moved
- a slot was allocated
- links were confirmed *by the nodes*
- a token record exists
- an owner pointer moved
- a payout landed

The observed value goes in the log whether the check passed or failed, so
one run can be compared with another. Many interesting failures show up as
differences between runs rather than as absolute values.

## Secrets

Node keys are generated per run and live only in memory and in the child
processes' environment: **never argv, never disk**. The log records
addresses only.

The one secret from outside is the funder's, read from
`KENTER_SYSTEST_FUNDER_SECRET`: a testnet account holding XLM and USDC.

```bash
export KENTER_SYSTEST_FUNDER_SECRET=S…
cargo run -p kenter-systest
```

::: danger Never pass a secret on the command line
argv is readable by every process on the machine and lands in shell history.
This is why the harness reads one variable and generates everything else.
:::

## Results logs

Runs write to `docs/systest-runs/`, which is **gitignored**. The logs contain
addresses and observed ledger values: useful when comparing two runs, and
not something to commit.

## Related

- [Testnet](/TESTNET): funding accounts, pointing clients at a deployment,
  deploying your own contracts
- [Relay deployment](/DEPLOY): running `kenter-tunnler` for real
- [A local network](/runbook/local-network): bringing the pieces up by hand
