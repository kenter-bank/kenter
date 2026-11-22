# `kenter-vault`

Pluggable key custody. Three port traits, one software implementation, and
the derivation stack beneath them. The hardware implementation,
`StellarKeycard`, is in [`stellar-keycard`](/reference/stellar-keycard). Full
signatures are in `crates/kenter-vault/API.md`.

The conceptual background is in [Custody and keys](/architecture/custody);
this page is the API.

## Modules

| Module | Holds |
|---|---|
| `lib` | The traits, credentials, errors |
| `soft` | `SoftVault`, `Custody` |
| `mnemonic` | BIP-39 phrases |
| `slip10` | SLIP-0010 Ed25519 HD derivation |
| `bip85` | BIP-85 child keys |
| `kdf` | Argon2id |

## The traits

### `KeyVault` — Stellar account keys by slot

| Method | Notes |
|---|---|
| `generate_key(label, credential) -> SlotId` | Fresh Ed25519, stored encrypted |
| `import_seed(&[u8;32], label, credential) -> SlotId` | **Hardware backends return `Unsupported`** — a card using SLIP-0010 with a 64-byte seed and on-card derivation cannot accept a raw 32-byte Ed25519 seed |
| `sign(slot, message, credential) -> [u8;64]` | Unwraps in memory, signs, zeroizes |
| `public_key(slot) -> [u8;32]` | No credential, so **unauthenticated**. Hardware may return a value cached at provision time, or `LockedMetadata` |
| `stellar_address(slot) -> String` | No credential, unauthenticated. Use `SoftVault::verified_stellar_address` before showing an address to fund |
| `list_keys() -> Vec<KeySlotInfo>` | |
| `remove_key(slot, credential)` | Credential required: irreversible |

### `DerivingVault` — owner keys by index

| Method | Notes |
|---|---|
| `derive_public(index, credential) -> [u8;32]` | The key at `m/44'/148'/index'`. Needs the credential: deriving needs the seed |
| `sign_derived(index, message, credential) -> [u8;64]` | **Pass the digest, not the preimage.** Owner authorizations sign `SHA-256(message)` so card and software signatures match; a card refuses anything but 32 bytes |

A held note records the derivation index, never the key, so the seed is the
whole backup of authorization and a card and a software wallet loaded from the
same seed derive the same keys.

### `Bip85`: secrets the seed can reproduce

| Method | Notes |
|---|---|
| `bip85_entropy(path, len, credential)` | BIP-85 entropy at an all-hardened path under `m/83696968'`, 1 to 64 bytes |

A port rather than a function over a seed, because a card never hands over
its seed: it runs the derivation on-chip and returns only the entropy.

::: tip Why signing and deriving take `&mut self`
A software backend does not need it. A card opens a secure channel and
exchanges APDUs to answer, which mutates its transport. Taking `&self` and
hiding that behind interior mutability would misdescribe the call, and would
panic rather than fail if re-entered.
:::

## Credentials and types

| Item | Purpose |
|---|---|
| `SlotId` | `u32`. Names a key's place in a vault |
| `KeySlotInfo` | Label, address, metadata for one slot |
| `StoreCredentials` | Opens the sealed note store |
| `BackupCredentials` | Key plus fingerprint, for backups and paper |
| `VaultError` / `Result<T>` | Including `Unsupported` and `LockedMetadata` |

## `soft` — the software vault

| Item | Purpose |
|---|---|
| `SoftVault` | Keys encrypted at rest under a passphrase; implements all three traits |
| `SoftVault::set_seed` / `set_seed_from_mnemonic` | Store the HD seed. Refuses to replace one |
| `SoftVault::set_custody` / `custody` | Write-once record of what opens the wallet |
| `SoftVault::keypair(slot, credential)` | Unwrap an account key for transaction signing (software only) |
| `SoftVault::verified_stellar_address(slot, credential)` | The address derived from the sealed secret, not read from the file |
| `SoftVault::store_credentials` / `backup_credentials` | Seed-hash credentials for a software wallet |
| `Custody` | `Software`, `Card { seed_fingerprint, card_identity }` or `RecoveredCard { seed_fingerprint }` |
| `backup_fingerprint(seed)` | Short hex identifying a wallet without revealing it |

The vault file is JSON (version 3): an Argon2id salt and cost triple, one
XSalsa20-Poly1305 entry per key, the sealed seed, the custody record, and an
HMAC over every field that is not ciphertext. The MAC is what stops someone
who can write the file from swapping the displayed account address or the
recorded card identity; a file holding secrets without one is refused. The
cost triple cannot be MAC-covered (the MAC needs a key derived with it), so
it is range-checked at open instead.

## `mnemonic` — BIP-39

| Item | Purpose |
|---|---|
| `DEFAULT_WORD_COUNT` | 24 words |
| `generate()` | A fresh phrase, `Zeroizing` |
| `validate(phrase)` | Wordlist and checksum |
| `wordlist_contains(word)` | For per-word input validation |
| `from_indexes(&[u16])` | Build from wordlist indices |
| `to_seed(phrase, passphrase)` | The 64-byte seed |
| `word_count(phrase)` | |

`wordlist_contains` exists so a UI can tell a holder a word is wrong as they
type it, rather than after twenty-four of them.

## `slip10` — HD derivation

| Item | Value / purpose |
|---|---|
| `HARDENED` | `0x8000_0000` |
| `PURPOSE` | 44 |
| `STELLAR_COIN_TYPE` | 148 |
| `ExtendedKey` | Key plus chain code |
| `master_from_seed(seed)` | SLIP-0010 master — HMAC key `"ed25519 seed"` |
| `derive_hardened(parent, index)` | One hardened step |
| `derive_path(seed, path)` | Full path |
| `stellar_account_secret(seed, account)` | `m/44'/148'/account'` |

## `bip85` — independent child keys

| Item | Purpose |
|---|---|
| `STORE_KEY_INDEX` = 0 | Sealed note store |
| `BACKUP_KEY_INDEX` = 1 | Backup files and paper |
| `ACCOUNT_VAULT_KEY_INDEX` = 2 | Opens the account vault on a card wallet |
| `ACCOUNT_KEY_INDEX` = 3 | **Is** the fee-paying account's secret |
| `Bip85` | The derivation trait |
| `entropy(seed, path, len)` | Raw BIP-85 entropy |
| `hex_key_path(index)` | The path for the HEX application |
| `hex_key(seed, index)` | A 32-byte child |
| `account_vault_credential(vault)` | Index 2, via the trait |
| `account_key(vault)` | Index 3, via the trait |
| `vault_bound_credentials(vault)` | Store and backup credentials together |
| `backup_fingerprint(child)` | Short hex identifier |

::: danger BIP-85 uses a different master
`bip85` derives through a **BIP-32** master whose HMAC key is `"Bitcoin
seed"`. `slip10` uses `"ed25519 seed"`. Same seed, different trees. The wrong
one produces valid-looking keys that open nothing.
:::

::: warning These indices are permanent
A wallet provisioned against index 2 cannot be opened by a build that
derives that credential elsewhere. Index 3 exists so the fee-paying account
is recoverable from the phrase alone: a random account is recoverable only
from phrase *plus vault file*, which strands redemption proceeds whenever that
file is gone. Do not renumber them.
:::

## `kdf`

| Item | Value |
|---|---|
| `KDF_NAME` | `"argon2id"` |
| `DEFAULT_M_COST` | 19,456 KiB |
| `DEFAULT_T_COST` | 2 |
| `DEFAULT_P_COST` | 1 |
| `MIN_*_COST` / `MAX_*_COST` | The range a vault file may ask for: floor = defaults, ceiling 1 GiB / 16 / 16 |
| `validate_params(m, t, p)` | Range-check a triple read from a file |
| `argon2id_kek(…)` | Derive a key-encryption key |

## Testing

`tests/owner_key_vectors.rs` holds golden vectors for owner key derivation,
generated from SEP-0005 test vector 1 — the same seed the Keycard applet
suite leaves on a card, so software and hardware can be compared directly.

`KENTER_BLESS_VECTORS=1` regenerates them. Think hard before you do: a
blessed-away derivation change is unrecoverable for anyone who already has a
wallet.
