# Reading guide

This site is written for a developer who has never seen the codebase and has
nobody to ask. It assumes working Rust, and no prior knowledge of Stellar,
Soroban, JavaCard or QR.

## If you have an hour

Read [System overview](/architecture/overview), then
[The workspace](/architecture/crates). Those two answer "what is this and
where does the code live". Then run it: [Setting up](/runbook/setup) and
[Build and run](/runbook/build-and-run).

## If you are fixing a bug

Find the crate in [the workspace map](/architecture/crates), then its page
under **Crate reference**. Each one lists every public type and what it is
for, so you can locate the seam you need without reading the whole crate.

Then read the comments around the code. This codebase comments *why*, and
often names the failure a rule prevents. The `ARCHITECTURE.md` beside each
crate explains its internal structure.

## If you are adding a feature

Three things are worth knowing before you write anything:

1. **The port traits are the architecture.** `kenter-wallet` depends on
   `ChainRead`, `Store`, `Authorizer`, `KeyVault` and `DerivingVault`, never
   on an implementation. That is what lets the same core serve a native
   desktop client and a browser build. If you find yourself reaching for a
   socket or a file inside `kenter-wallet`, you are in the wrong crate.
2. **Custody is pluggable and must stay so.** Software and hardware vaults
   implement the same traits. Code that assumes a seed is in memory will
   break on a card.
3. **Much of what looks redundant is load-bearing.** Before removing a check
   that seems belt-and-braces, read its comment and the
   [Security model](/architecture/security-model).

## If you are working on the protocol

Read [Bearer token format](/bearer-token-format) for the cryptography and
bytes, [Bearer and spend mode](/architecture/spend-mode) for owner keys and
the receive gates, and [Tokens and their lifecycle](/architecture/tokens) for
registration and redemption. The contract interface is
`contracts/kenter-mint/API.md`. Every attack the design answers, and every
limit it accepts, is in [Security model](/architecture/security-model).

## If you are working on printing or nodes

A print's interior pairs are not chosen by anyone. The depositor names only
its own two end pairs; a future drand round, verified on chain, seeds the
print; registered node pairs claim positions; the lowest scores win; and the
wallet walks the winners, skipping a pair that does not serve. Read
[Node selection](/architecture/node-selection) for that mechanism and its
parameters, and [Network and contracts](/architecture/network) for how a
wallet reaches a node. Running a node on testnet is in
[Testnet environment](/TESTNET). Deploying the contracts and the relay is
[Deployment](/DEPLOY); the end-to-end harness is
[System test](/SYSTEM_TEST).

## If you are working on backup or restore

Start with [Data formats](/architecture/data-formats) and
[Custody and keys](/architecture/custody), then
[Paper and camera](/testing/paper). This is the most fully tested part of the
system, and also the part where the consequences of a bug are worst: a backup
that cannot be read is indistinguishable from no backup at all, and the
holder finds out at the only moment it matters.

Where a page on this site and the code disagree, the code is right and the
page should be corrected.
