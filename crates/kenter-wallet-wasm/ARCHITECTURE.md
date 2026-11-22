# kenter-wallet-wasm — Architecture

**Role.** The `wasm-bindgen` bridge that exposes `kenter-crypto` to a browser,
so a browser wallet can run the same Rust crypto as the desktop instead of a
JavaScript reimplementation. Today it is a thin crypto harness: it proves that
`kenter-crypto` compiles to `wasm32-unknown-unknown`, loads in a browser and
runs the full note loop at runtime. It does not yet bind the `kenter-wallet`
core.

## Boundaries

- **Depends on:** `kenter-crypto` and `wasm-bindgen`, plus `getrandom` with its
  `js` feature (see below).
- **Depended on by:** nothing native. The `wasm-bindgen --target web` output in
  `www/` is loaded by `www/index.html`, a test page that calls the exports and
  times them. The native client, node and desktop crates never use this crate.
- **Target:** `wasm32-unknown-unknown`. `crate-type = ["cdylib", "rlib"]`.

## Exports

A deliberately thin façade over `kenter-crypto` (full list in `API.md`):

- `generate_keypair` and `address_from_secret`: key material. Generating a key
  drives `rand` → `getrandom` → the browser's `crypto.getRandomValues`.
- `sign_verify_roundtrip`: Ed25519 sign then verify.
- `full_loop_selftest`: the heavy path. It builds a 3-pair daisy chain
  (initiate, extend, assemble), round-trips the SYMTOKEN container through
  serialize and deserialize, verifies chain integrity, re-composes the ephemeral
  key independently from the three shards, signs and verifies with the composed
  key, and checks the container version. It mirrors the native
  `test_full_daisy_chain_3_pairs` test but returns a structured `LoopResult`
  instead of asserting, so the browser page can display and time it. This is
  what makes the compiled artifact meaningful rather than a compile-only check.
- `version`: confirms the module loaded.

## Build constraints

- **`getrandom` needs its `js` feature on wasm.** `rand` inside `kenter-crypto`
  pulls in `getrandom`, which on `wasm32-unknown-unknown` must be told to use
  `crypto.getRandomValues`. Declaring `getrandom = { features = ["js"] }` in
  this crate unifies the feature across the dependency tree.
- **No `wasm-opt` in the release profile.** `wasm-opt = false` in the
  `wasm-pack` metadata keeps the raw output honest. Run `wasm-opt -Oz` by hand to
  measure the shipped size.

## Invariants

- **Wasm-clean dependencies only.** Nothing in the tree may pull in full
  `tokio`, `native-tls`, PC/SC or `reqwest`, none of which compile to wasm32.
  This is why a browser wallet binds `kenter-wallet` (which talks to the chain
  through its `ChainRead` port) and never `kenter-client` (a native engine). In a
  browser, `ChainRead` is implemented over `fetch`.
- **No wall clock.** Timestamps are passed in, never read from a clock that
  wasm does not have.
- **Software-only custody.** A browser has no secure element. `WalletKeypair`
  hands the secret to JavaScript as a plain `String`; protecting it at rest is
  the browser shell's job, not this crate's.

## Open items

- **Binding the wallet core.** The intended shape is this crate wrapping
  `kenter-wallet` (held tokens, reconciliation, receive gates) plus browser
  adapters for its `ChainRead` (`fetch`) and `Store` (IndexedDB) ports. Neither
  exists yet; today the crate binds `kenter-crypto` only.
- **Size and speed on real hardware.** The bundle size after `wasm-bindgen`,
  `wasm-opt -Oz` and gzip, and the loop's run time on a low-end ARM phone, are
  the figures that decide whether a browser wallet is practical. Measure them
  with the steps in `README.md`.
