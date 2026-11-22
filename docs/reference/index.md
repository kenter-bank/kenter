# Crate reference

One page per crate, listing every public type and what it is for, so you can
find the seam you need without reading the whole thing.

## How to use this

These pages are a **map**: what each crate is for and where its seams are.
Most crates, and both contracts, also have an `API.md` beside their `Cargo.toml`
listing every public item with its signature: `crates/<name>/API.md` and
`contracts/<name>/API.md`. The doc comments on the items carry the
reasoning; this codebase comments *why* a rule exists.

```bash
cargo doc --workspace --no-deps --open
```

will give you the generated API docs with all of it.

## The crates

| Crate | Page | What it is |
|---|---|---|
| `kenter-crypto` | [→](/reference/kenter-crypto) | The token container, chains, shards. No I/O. |
| `kenter-vault` | [→](/reference/kenter-vault) | Custody traits, software vault, key derivation. |
| `kenter-wallet` | [→](/reference/kenter-wallet) | The wallet core: holdings, backup, paper, policy. |
| `kenter-network` | [→](/reference/kenter-network) | Wire protocol, tunnel client, JWT auth. |
| `kenter-client` | [→](/reference/kenter-client) | Native chain access: Soroban RPC, contracts, XDR. |
| `kenter-ui` | [→](/reference/kenter-ui) | The desktop wallet (GUI). |
| `stellar-keycard` | [→](/reference/stellar-keycard) | Keycard custody over PC/SC, for the kenter-keycard applet. |
| others | [→](/reference/supporting) | `kenter-print`, `kenter-node`, `kenter-tunnler`, `kenter-desktop`, `kenter-systest`, `kenter-wallet-wasm`. |

The two Soroban contracts are documented in `contracts/kenter-mint/API.md`
and `contracts/kenter-roster/API.md`.

## Conventions worth knowing before you read any of them

**`Result` is per-crate.** Each crate defines its own error enum and a
`Result<T>` alias over it. They do not share one.

**Secrets are `Zeroizing`.** Anything holding key material is wrapped so it
is wiped on drop. If you add a type that holds a secret and it is not
`Zeroizing`, that is a bug.

**Ports are traits, implementations live elsewhere.** `kenter-wallet`
defines `ChainRead`, `Store`, `Authorizer`, `Prompter`; `kenter-vault`
defines `KeyVault`, `DerivingVault`, `Bip85`. Finding an implementation means
looking in a shell or an engine crate (`SoftVault`, `StellarKeycard`,
`WalletChain`, `FileStore`), never in the core.

**Indices and slots are not interchangeable.** A `SlotId` names a place in a
vault. A derivation index names a position in an HD tree and is recorded on
a note. A print slot id names a slot in the mint. Confusing them produces
keys or records that look fine and open nothing.

**Many constants are load-bearing.** `STORE_KEY_INDEX`,
`ACCOUNT_VAULT_KEY_INDEX`, `ACCOUNT_KEY_INDEX`, `SYMTOKEN_VERSION`,
`CHUNK_PAYLOAD`: changing one can make existing wallets or notes unopenable.
Each carries a comment saying so.
