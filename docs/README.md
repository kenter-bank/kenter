# Kenter documentation

A VitePress site covering how Kenter works and how to build, run, test and
deploy it.

## Running it

```bash
cd docs
npm install
npm run dev      # http://localhost:5173
```

```bash
npm run build    # static site into .vitepress/dist
npm run preview  # serve that build
```

Node 18 or later. Nothing in the Rust workspace needs any of this.

## What is here

| Path | Contents |
|---|---|
| `index.md`, `reading-guide.md` | Entry points |
| `architecture/` | How the system fits together: overview, workspace, custody, tokens, node selection, bearer and spend mode, network and contracts, security model, data formats, the desktop client |
| `bearer-token-format.md` | The note's cryptography and byte layout |
| `reference/` | One page per crate: every public type and its purpose |
| `testing/` | The test harnesses and what each is for |
| `runbook/` | Setup, build, run, test, troubleshoot |
| `SYSTEM_TEST.md`, `TESTNET.md`, `DEPLOY.md`, `tunnler-api.md` | Operational documents, kept at these paths because code cites them. `DEPLOY.md` covers the contracts and the relay; `TESTNET.md` the testnet parameters and running a node |
| `LEDGER_COSTS.md` | What Kenter pays Soroban in fees and storage rent, measured |

## Other documentation

| Where | What it is |
|---|---|
| `crates/*/ARCHITECTURE.md`, `crates/*/API.md` | Per-crate design and interface notes, next to the code |
| `contracts/*/API.md`, `contracts/*/ARCHITECTURE.md` | The contracts' entry points, arguments, auth and errors |
| Doc comments | The finest detail. `cargo doc --workspace --no-deps --open` |

Where a page and the code disagree, **the code is right** and the page should
be corrected.

## Keeping it accurate

This site describes what is true now. Two habits keep it that way:

- When you change a format, an invariant or a load-bearing constant, change
  the page that describes it in the same commit.
- When you find that something here is wrong, fix it rather than adding a
  caveat.
