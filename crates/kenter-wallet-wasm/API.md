# kenter-wallet-wasm — API

The `#[wasm_bindgen]` surface exported to the browser. A thin façade over
`kenter-crypto` that proves the crypto compiles to `wasm32-unknown-unknown`,
loads in a browser, and runs a full note loop at runtime. It does not wrap
`kenter-wallet`. Errors reach JavaScript as thrown exceptions (`JsError`).

`kenter-crypto` is built with `default-features = false`. `getrandom` is
built with its `js` feature, so randomness comes from the browser's
`crypto.getRandomValues`.

## Functions

| Fn | Args | Returns | Notes |
|----|------|---------|-------|
| `generate_keypair` | — | `WalletKeypair` | Fresh random Stellar keypair (`OsRng` → `getrandom` → `crypto.getRandomValues`). |
| `address_from_secret` | `secret: &str` (`S…`) | `Result<String, JsError>` | Decode the strkey secret, return its `G…` address. Throws on a bad strkey. |
| `sign_verify_roundtrip` | `secret: &str, message: &[u8]` | `Result<bool, JsError>` | Ed25519 sign then verify; returns whether it verified. Throws on a bad secret. |
| `full_loop_selftest` | — | `Result<LoopResult, JsError>` | The full 3-pair note loop inside wasm (below). Throws on any crypto error. |
| `version` | — | `String` | `CARGO_PKG_VERSION`: a probe that the module loaded and is callable. |

### `full_loop_selftest`

Mirrors the native `test_full_daisy_chain_3_pairs` integration test but
returns a structured result instead of asserting, so a browser harness can
display and time it:

1. Build a 3-pair chain: `PartialToken::initiate` → `extend` →
   `assemble_bearer_token`.
2. `serialize_bearer_token` → `deserialize_bearer_token` →
   `verify_chain_integrity`.
3. Re-compose the ephemeral keypair independently from the three
   `derive_shard` shards with `CompositionBuilder`.
4. Sign and verify a message with the composed keypair.
5. Check the parsed container version equals `SYMTOKEN_VERSION`, so a wasm
   build that diverges from native on the byte format is caught.

## Types

- **`WalletKeypair`** `{ address: String, secret: String }`
  (`getter_with_clone`), reaching JavaScript as `{ address, secret }`.
  `secret` is the plaintext `S…` key.
- **`LoopResult`** (`getter_with_clone`), the self-test report:
  - `container_bytes: usize`: size of the serialized container.
  - `chain_links: usize`: authenticated links (equal to pairs).
  - `ephemeral_address: String`: `G…` address of the note's ephemeral key.
  - `composed_key_matches: bool`: independent composition reproduced the
    ephemeral key.
  - `roundtrip_ok: bool`: serialize → deserialize preserved the ephemeral
    key and every link.
  - `sign_verify_ok: bool`: the composed keypair signs and verifies.
  - `version_ok: bool`: the container version is `SYMTOKEN_VERSION`.

## Build and use

```sh
# 1. compile to wasm
cargo build -p kenter-wallet-wasm --target wasm32-unknown-unknown --release

# 2. generate browser bindings (the CLI version must match the wasm-bindgen
#    crate version in Cargo.lock)
wasm-bindgen target/wasm32-unknown-unknown/release/kenter_wallet_wasm.wasm \
  --out-dir crates/kenter-wallet-wasm/www --target web

# 3. optional: shrink the _bg.wasm with wasm-opt -Oz
# 4. serve www/ over HTTP, import the module from JavaScript, call the
#    functions above
```

## Not in this crate

- **No wallet-core bindings.** No held-note, balance, `ChainRead` or `Store`
  exports; those live in `kenter-wallet`, which compiles to wasm but is not
  wrapped here.
- **No browser adapters.** No `fetch`-based `ChainRead` and no IndexedDB
  `Store`.
