# kenter-wallet-wasm

A `wasm-bindgen` bridge that runs `kenter-crypto` in a browser. It answers
whether the Rust crypto compiles to `wasm32-unknown-unknown`, loads in a
browser and runs a real note loop at an acceptable size and speed. It exposes
keypair generation, a sign/verify round-trip, secret-to-address derivation and
`full_loop_selftest`, which builds, serializes, parses and re-composes a 3-pair
note entirely inside wasm. See `ARCHITECTURE.md` for the design and `API.md`
for the exports.

## Requirements

- The `wasm32-unknown-unknown` Rust target:
  `rustup target add wasm32-unknown-unknown`.
- `wasm-bindgen-cli` at the **same version** as the `wasm-bindgen` crate in
  `Cargo.lock` (0.2.114). A mismatched CLI refuses the module.
- Optional: `wasm-opt` from Binaryen, to measure the optimized size.

## Build and run

```sh
# 1. Compile to wasm.
cargo build -p kenter-wallet-wasm --target wasm32-unknown-unknown --release

# 2. Generate browser bindings into www/.
wasm-bindgen target/wasm32-unknown-unknown/release/kenter_wallet_wasm.wasm \
  --out-dir crates/kenter-wallet-wasm/www --target web

# 3. Optional: shrink the module and measure it.
wasm-opt -Oz crates/kenter-wallet-wasm/www/kenter_wallet_wasm_bg.wasm \
  -o crates/kenter-wallet-wasm/www/kenter_wallet_wasm_bg.wasm
gzip -9 -k -c crates/kenter-wallet-wasm/www/kenter_wallet_wasm_bg.wasm | wc -c

# 4. Serve www/ over HTTP and open index.html.
python -m http.server -d crates/kenter-wallet-wasm/www 8000
```

`index.html` loads the module, calls each export and logs the results with
timings, including the `full_loop_selftest` run time. Only `index.html` is
tracked; the generated `.js`, `.d.ts` and `.wasm` files are build output.

## Build notes

- `getrandom` is declared with its `js` feature so randomness comes from the
  browser's `crypto.getRandomValues`. Without it the wasm build fails.
- The release profile sets `wasm-opt = false`, so step 3 is how you get the
  size a browser would actually download.

## Not yet covered

- Measured bundle size after `wasm-opt -Oz` and gzip, against a low-end-phone
  budget.
- Run time on real low-end ARM hardware rather than a development machine.
- Bindings for the `kenter-wallet` core and its browser adapters.
