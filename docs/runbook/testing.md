# Running the tests

## The everyday command

```bash
cargo test --workspace
```

That runs tiers 1 and 2 — unit and integration tests. Everything that could
touch hardware, a network or real value is gated behind `#[ignore]` and does
not run.

## Narrowing

Almost always what you want while working, because the full workspace is
slow.

```bash
cargo test -p kenter-ui --lib               # one crate's unit tests
cargo test -p kenter-wallet --lib paper     # tests whose name contains "paper"
cargo test -p kenter-crypto --test bearer_token   # one integration test file
cargo test -p kenter-ui --lib -- --nocapture      # see println! output
```

## On a constrained machine

```bash
cargo test --workspace -j 2
```

`-j 2` caps how many compiles and links run at once. It is cache-safe.

::: danger Do not set CARGO_PROFILE_* to save memory
`CARGO_PROFILE_TEST_DEBUG=0` and friends change the build profile, which is
part of the cache key. The result is a full rebuild of every dependency —
and another when you remove the flag — so a flag meant to make one build
cheaper makes two builds maximally expensive.
:::

Linking `kenter-ui`'s test binary takes about 1.7 GB resident. On a
machine with a few GB free, that is what gets killed first, and the failure
looks like the tests dying for no reason.

## The gated tests

Nothing below runs by accident. Read [Keycard hardware](/testing/keycard)
before any of the card ones.

```bash
# All ignored tests in a crate — simulator and hardware alike
cargo test -p stellar-keycard -- --ignored --test-threads=1

# Network tests (testnet)
cargo test -p kenter-client -- --ignored

# Destructive card tests. WILL WIPE A CARD.
KENTER_CARD_DESTRUCTIVE=1 KENTER_CARD_PIN=… \
  cargo test -p kenter-ui --test card_ceremony -- --ignored --test-threads=1
```

`--test-threads=1` whenever hardware is involved: there is one reader.

## The contracts

The contracts are separate workspaces, so `cargo test --workspace` does not
reach them:

```bash
cargo test --manifest-path contracts/kenter-mint/Cargo.toml
cargo test --manifest-path contracts/kenter-roster/Cargo.toml
```

The redemption CPU budget checks run against a freshly built wasm, behind a
feature and `#[ignore]`. Build first with `stellar contract build` in
`contracts/kenter-mint`, then:

```bash
cargo test --manifest-path contracts/kenter-mint/Cargo.toml \
  --features wasm-bench bench_pathb_wasm -- --include-ignored
cargo test --manifest-path contracts/kenter-mint/Cargo.toml \
  --features wasm-bench pathb_owned_at_the_ceiling_fits_the_budget_wasm -- --include-ignored
```

Each must report `1 passed`. A filter that matches nothing also exits 0, so
read the result line. `scripts/deploy_testnet.sh` runs both before every
deploy.

## Golden vectors

Several suites compare against committed vectors:

| File | Covers |
|---|---|
| `crates/kenter-crypto/tests/spend_vectors.rs` | Spend-mode signing |
| `crates/kenter-vault/tests/owner_key_vectors.rs` | Owner key derivation |
| `crates/kenter-client/tests/vectors_recipient.rs` | Recipient derivation |
| `crates/kenter-crypto/tests/cross_language.rs` | Keys, ECDH and domain separation against vectors from an independent Python implementation |

To regenerate:

```bash
KENTER_BLESS_VECTORS=1 cargo test -p kenter-vault --test owner_key_vectors
```

::: warning Blessing accepts whatever the code currently produces
Bless only when you are sure the new output is correct, never to turn a red
suite green. A blessed-away regression in key derivation is unrecoverable for
anyone who already has a wallet.
:::

## Interpreting a failure

**Read the panic message, not just the count.** Tests in this codebase carry
messages built to explain, e.g. `3000px: 3 of 5 symbols read`.

**A test name is a claim.** Most are written as sentences —
`restore_never_overwrites_a_note_already_held`,
`an_items_symbols_are_evenly_sized`. If one fails, the claim in its name is
what stopped being true.

**Check the doc comment above it.** Many explain the failure the test
guards against. That is usually faster than reasoning from the assertion.

## Before you commit

```bash
cargo test --workspace
cargo build --workspace --examples   # examples are NOT built by cargo test
cargo clippy --workspace --all-targets
cargo fmt --check
```

::: warning `cargo test` does not build examples
Deleting a module and leaving an example referencing it passes the test suite
and breaks the build, which is why the examples line is part of this list.
:::
