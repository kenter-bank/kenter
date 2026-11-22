# kenter-vault: API

Key custody for Kenter. The public surface is:

- three port traits: `KeyVault` (slot-based Stellar **account** keys),
  `DerivingVault` (HD-derived spend-mode **owner** keys) and `Bip85`
  (independent secrets derived from the wallet seed);
- their software backend `SoftVault` (a passphrase-sealed JSON file);
- the `slip10`, `mnemonic`, `bip85` and `kdf` modules;
- the credential types `StoreCredentials` and `BackupCredentials`.

The hardware backend, `StellarKeycard`, lives in `stellar-keycard` and
implements the same traits.

`credential` is the unlock secret: the passphrase for `SoftVault`, the PIN
for a card. It is required for any operation that touches secret material,
never for read-only metadata. All fallible returns are
`Result<T> = std::result::Result<T, VaultError>`.

## `KeyVault` trait

| Fn | Args | Returns | Credential | Notes |
|----|------|---------|-----------|-------|
| `generate_key` | `&mut self, label:&str, credential:&[u8]` | `SlotId` | yes | Fresh Ed25519 key, stored encrypted. |
| `import_seed` | `&mut self, seed:&[u8;32], label:&str, credential:&[u8]` | `SlotId` | yes | Import a raw 32-byte Ed25519 secret. A card returns `Unsupported`. |
| `sign` | `&mut self, slot:SlotId, message:&[u8], credential:&[u8]` | `[u8;64]` | yes | Unwraps the secret in memory, signs, zeroizes. `&mut` because a card mutates secure-channel state. |
| `public_key` | `&self, slot:SlotId` | `[u8;32]` | no | The stored public key. **Unauthenticated**: with no credential there is nothing to check it against. |
| `stellar_address` | `&self, slot:SlotId` | `String` | no | `G…` address from the stored key. **Unauthenticated**, as above. Use `SoftVault::verified_stellar_address` before presenting an address as "fund this". |
| `list_keys` | `&self` | `Vec<KeySlotInfo>` | no | Enumerate stored keys. |
| `remove_key` | `&mut self, slot:SlotId, credential:&[u8]` | `()` | yes | Irreversible; the credential must open the target entry. |

## `DerivingVault` trait

One seed; an owner key derived per receipt at `m/44'/148'/n'`. A held note
records the **derivation index**, never the key. The key is re-derived when
needed, so the backup is the seed, once, rather than a new secret on every
receipt, and a card and a software wallet loaded from the same seed derive
identical keys and can take over each other's notes.

| Fn | Args | Returns | Credential | Notes |
|----|------|---------|-----------|-------|
| `derive_public` | `&mut self, index:u32, credential:&[u8]` | `[u8;32]` | **yes** | Public key of the owner key at `index`. Unlike `KeyVault::public_key` this needs the credential: deriving requires the seed, which is sealed at rest (PIN-gated on a card). `&mut` because a card answers over its secure channel. |
| `sign_derived` | `&mut self, index:u32, message:&[u8], credential:&[u8]` | `[u8;64]` | yes | Signs what it is given. Owner authorizations sign a 32-byte digest (`kenter_crypto::spend::*_digest`), so callers pass the digest, not the preimage. A card refuses any other length. |

## `Bip85` trait and `bip85` module

The wallet needs symmetric keys (for the sealed note store, the backup file
and a card wallet's account vault) that a card can produce **without
exporting its seed**, and that a `SoftVault` restored from the same phrase
reproduces bit for bit. BIP85 provides that: deterministic, no signing key
and no nonce involved, and a card exposes it as a PIN-gated command that
returns only the derived entropy.

BIP85 derives from the **BIP32 / secp256k1** master
(`HMAC-SHA512("Bitcoin seed", seed)`), a different tree from the SLIP-0010
owner keys (`HMAC-SHA512("ed25519 seed", seed)`). Both come from the same
BIP-39 seed. Correctness is pinned to the published BIP85 test vectors.

```rust
pub trait Bip85 {
    fn bip85_entropy(&mut self, path: &[u32], len: usize, credential: &[u8])
        -> Result<Zeroizing<Vec<u8>>>;   // all-hardened path under m/83696968', len 1..=64
}
```

All Kenter secrets use the HEX application, `m/83696968'/128169'/32'/{index}'`:

| Constant | Index | Secret |
|---|---|---|
| `STORE_KEY_INDEX` | 0 | Sealed note store keys (card wallets) |
| `BACKUP_KEY_INDEX` | 1 | Backup file key (card wallets) |
| `ACCOUNT_VAULT_KEY_INDEX` | 2 | Credential that opens a card wallet's account `SoftVault` |
| `ACCOUNT_KEY_INDEX` | 3 | The fee-paying Stellar account's Ed25519 secret (every custody) |

These indices are **permanent once a wallet exists**: a build that derives
elsewhere cannot open it.

- `ACCOUNT_KEY_INDEX` makes the account a function of the phrase alone.
  Redemption pays into this account, so it must come back from the words,
  not from a vault file. It is deliberately not an `m/44'/148'/n'` index:
  an account sharing a key with an owner would link fee payments to notes.
- `ACCOUNT_VAULT_KEY_INDEX` lets a card wallet seal its software account key
  with no passphrase: the card is the single unlock.

Functions:

| Item | Signature | Notes |
|------|-----------|-------|
| `entropy` | `(seed:&[u8], path:&[u32], len:usize) -> Result<Zeroizing<Vec<u8>>>` | Local BIP85: `HMAC-SHA512("bip-entropy-from-k", k)` of the derived node key, truncated. |
| `hex_key_path` | `(index:u32) -> [u32;4]` | `[83696968, 128169, 32, index]`. |
| `hex_key` | `(seed:&[u8], index:u32) -> Result<Zeroizing<[u8;32]>>` | 32-byte HEX-application secret, computed locally. |
| `account_vault_credential` | `<V: Bip85>(&mut V, credential) -> Result<Zeroizing<[u8;32]>>` | Index 2, used directly as a vault credential. |
| `account_key` | `<V: Bip85>(&mut V, credential) -> Result<Zeroizing<[u8;32]>>` | Index 3. |
| `vault_bound_credentials` | `<V: Bip85>(&mut V, credential) -> Result<(StoreCredentials, BackupCredentials)>` | Store keys split by tag (`kntr_v1:wallet:bip85:store:key` / `:name`) from child 0; backup key is child 1. |
| `backup_fingerprint` | `(child:&[u8;32]) -> String` | First 8 bytes, hex, of `SHA-256(kntr_v1:wallet:bip85:backup:fp ‖ child)`. |

These are **not** the values `SoftVault::store_credentials` and
`backup_credentials` produce for a software wallet: the two derivations
give different wallets from the same seed, and a backup header records which
one it used.

## Credential types

- `StoreCredentials { aead: Zeroizing<[u8;32]>, name: Zeroizing<[u8;32]> }`:
  `aead` seals note records; `name` is a MAC key that turns a record id into
  an opaque filename, so a directory listing does not reveal which notes are
  held.
- `BackupCredentials { key: Zeroizing<[u8;32]>, fingerprint: String }`:
  `key` seals the backup payload; `fingerprint` is a public tag naming which
  wallet a backup belongs to, so restoring the wrong file fails by name.

Both derive from the HD seed, so recovery is phrase plus files, with no vault
file required. The seed itself never leaves the vault.

## `mnemonic` module

BIP-39 recovery phrases, the human-holdable form of the wallet seed. English
only, because the card's wordlist is English.

| Item | Signature | Notes |
|------|-----------|-------|
| `DEFAULT_WORD_COUNT` | `pub const WordCount` | 24 words (256-bit entropy), as a Keycard generates. |
| `generate` | `() -> Result<Zeroizing<String>>` | Fresh phrase. The only copy of the wallet's authorization. |
| `validate` | `(phrase: &str) -> Result<()>` | Parse and checksum. `BadMnemonic` on failure. |
| `wordlist_contains` | `(word: &str) -> bool` | Lets a restore screen point at the word that is wrong. |
| `from_indexes` | `(indexes: &[u16]) -> Result<Zeroizing<String>>` | Build a phrase from BIP-39 word indexes, as a card's GENERATE MNEMONIC returns them. Re-verifies the checksum. |
| `to_seed` | `(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8;64]>>` | The 64 bytes `slip10` and `bip85` derive from. `passphrase` is BIP-39's optional extra word, **not** the vault credential. |
| `word_count` | `(phrase: &str) -> usize` | Unvalidated count, for UI hints. |

The phrase recovers **authorization**, not value: notes cannot be enumerated
from the chain, so a phrase without the note files or a backup redeems
nothing.

Two hazards the module tests rather than assumes away:

- **A phrase that parses is not proof it is the right phrase.** The checksum
  is 8 bits at 24 words, so about one single-word substitution in 256 still
  validates (one in 16 at 12 words) and silently derives a different wallet.
  The real confirmation of a restore is that a known address or commitment
  comes back.
- **A BIP-39 passphrase silently changes the wallet.** Forgetting one looks
  like "my words don't work" with no error to point at.

## `slip10` module

SLIP-0010 **ed25519** derivation, hardened only (Ed25519 has no public
derivation, so there is no watch-only receive). Master is
`HMAC-SHA512("ed25519 seed", seed)`; each step is
`HMAC-SHA512(chain_code, 0x00 ‖ key ‖ ser32(index | 0x80000000))`.

| Item | Signature | Notes |
|------|-----------|-------|
| `HARDENED` / `PURPOSE` / `STELLAR_COIN_TYPE` | `pub const u32` | `0x80000000`, `44`, `148`. |
| `ExtendedKey` | `{ key: [u8;32], chain_code: [u8;32] }` | Zeroized on drop. |
| `master_from_seed` | `(seed:&[u8]) -> Result<ExtendedKey>` | Seed must be 16..=64 bytes; a BIP-39 seed is 64. |
| `derive_hardened` | `(parent:&ExtendedKey, index:u32) -> Result<ExtendedKey>` | `index` is the unhardened number; one that already carries the bit is an error. |
| `derive_path` | `(seed:&[u8], path:&[u32]) -> Result<ExtendedKey>` | Every element hardened. |
| `stellar_account_secret` | `(seed:&[u8], account:u32) -> Result<[u8;32]>` | `m/44'/148'/account'`. The 32 bytes are an Ed25519 secret (RFC 8032 seed), as `StellarKeypair::from_raw_secret` and the card both take. |

Correctness is pinned to **SEP-0005 test vector 1**, the same vector the
kenter-keycard applet's tests reproduce on-card, and to
`tests/vectors/owner_key_vectors.json`. That equality is the card/software
interoperability guarantee. A divergence would not fail loudly: it would
produce keys that cannot open the wallet's own commitments.

## `SoftVault` (impl `KeyVault`, `DerivingVault`, `Bip85`)

| Fn | Args | Returns | Notes |
|----|------|---------|-------|
| `open` | `path: impl AsRef<Path>` | `Result<SoftVault>` | Open a vault file, or prepare an empty one (random 16-byte salt) if none exists. Nothing is written until the first mutating call. Errors `UnsupportedVersion`, `Corrupt`, `Io`, `BadKdfParams`, `Tampered`. |
| `has_seed` | `&self` | `bool` | Public metadata, no credential. |
| `set_seed` | `&mut self, seed:&[u8], credential:&[u8]` | `Result<()>` | Store the HD seed, sealed like a key entry. **Refuses to replace an existing seed**: that would orphan every note owned by a key derived from it, and a note cannot be reissued. |
| `set_seed_from_mnemonic` | `&mut self, phrase:&str, bip39_passphrase:&str, credential:&[u8]` | `Result<()>` | Validate a phrase and store its seed. Same no-replace rule. |
| `set_custody` | `&mut self, custody:Custody, credential:&[u8]` | `Result<()>` | Record what opens this wallet. Write-once. Needs the credential because the record is inside the authenticated header. |
| `custody` | `&self` | `Option<&Custody>` | `None` means "not recorded", never "software". |
| `keypair` | `&self, slot:SlotId, credential:&[u8]` | `Result<StellarKeypair>` | Unwrap a slot's key for transaction signing. Checks the unwrapped key against the entry's public key (`Tampered` on mismatch). Software custody only. |
| `verified_stellar_address` | `&self, slot:SlotId, credential:&[u8]` | `Result<String>` | The address derived from the sealed secret, not read from the file. Costs one Argon2 derivation. |
| `store_credentials` | `&self, credential:&[u8]` | `Result<StoreCredentials>` | `SHA-256(kntr_v1:wallet:store:key ‖ seed)` and `SHA-256(kntr_v1:wallet:store:name ‖ seed)`. |
| `backup_credentials` | `&self, credential:&[u8]` | `Result<BackupCredentials>` | `SHA-256(kntr_v1:wallet:backup:key ‖ seed)`; fingerprint below. |

Free function `soft::backup_fingerprint(seed:&[u8]) -> String` (re-exported
as `soft_backup_fingerprint`): first 8 bytes, hex, of
`SHA-256(kntr_v1:wallet:backup:fp ‖ seed)`. Computable from a phrase before
any vault exists.

`Bip85` on `SoftVault` runs `bip85::entropy` over the unwrapped seed, so a
phrase-restored software wallet reproduces a card's BIP85 values.

### `Custody`

Serialized with `#[serde(tag = "mode", rename_all = "lowercase")]`.

- `Software`: the seed is in this file, behind a passphrase.
- `Card { seed_fingerprint: String, card_identity: String }`: the seed is on
  a card. This file holds only the fee-paying account key, opened with the
  card-derived `account_vault_credential`. `seed_fingerprint` (the BIP85
  backup fingerprint) answers "is this the same wallet" and survives card
  replacement; `card_identity` (hex identity key from the card's SELECT
  certificate) answers "is this the same physical card" with no PIN.
- `RecoveredCard { seed_fingerprint: String }`: a card wallet's seed,
  recovered into this file because the card is gone. Distinct from
  `Software` because a card wallet's store and backup keys are BIP85
  children, not seed hashes; reading it as `Software` would make the
  wallet's own notes and backups unopenable.

Custody is recorded, not inferred, because "has no seed" is true of both a
card wallet and an empty machine.

### On-disk format (JSON, `version = 3`)

`kdf = "argon2id"`, the Argon2id cost triple (`kdf_m_cost`, `kdf_t_cost`,
`kdf_p_cost`), hex `kdf_salt` (16 bytes), monotonic `next_slot`, one entry
per key, an optional `seed` object, an optional `custody` record, and `mac`.

Each entry seals a 32-byte secret with XSalsa20-Poly1305 (24-byte nonce)
under the Argon2id key-encryption key; ciphertext is 48 bytes. The seed entry
is sealed the same way. A wrong passphrase or altered ciphertext fails the
Poly1305 tag and returns `BadCredential`.

**`mac` is HMAC-SHA256 over everything that is not ciphertext**: version,
KDF triple and salt, `next_slot`, each entry's slot, label, public key, nonce
and ciphertext, the seed entry and the custody record. It is keyed by a
derivative of the same key-encryption key under `kntr_v1:vault:header-mac`.
The AEAD protects only the sealed secrets; without the MAC, anyone who could
write the file could swap an entry's `public_key` (the address the UI shows
as the account to fund) or `custody.card_identity` with no error anywhere.

Rules that follow:

- Every credentialed operation verifies the MAC before acting, reads
  included; every mutation recomputes it.
- A file with entries or a seed and **no** `mac` is refused at `open`
  (`Tampered`); otherwise deleting the field would turn the check off.
- **One vault, one passphrase.** A write offered a different credential fails
  rather than sealing an entry nobody can open.
- The KDF triple is range-checked at `open` instead of being MAC-covered: the
  MAC cannot be verified without first deriving a key with those parameters.

Other versions are refused with `UnsupportedVersion`.

## Types

- `type SlotId = u32`: opaque handle to a stored key; monotonic, never reused.
- `KeySlotInfo { slot: SlotId, label: String, stellar_address: String, created_at: i64 }`:
  public slot description. `Debug, Clone, PartialEq, Eq`.
- `type Result<T> = std::result::Result<T, VaultError>`.
- `VaultError` (`thiserror`): `Io(String)`, `Serde(String)`, `Corrupt(String)`,
  `UnsupportedVersion(u8)`, `SlotNotFound(SlotId)`, `BadCredential` (wrong
  credential or altered ciphertext), `Tampered` (header MAC absent or wrong:
  the file's public fields were edited), `BadKdfParams(String)` (cost triple
  out of range), `Crypto`, `Crypto2(String)` (crypto failure with a reason),
  `BadMnemonic(String)`, `LockedMetadata` (hardware metadata not available
  without prior authentication), `Unsupported(String)` (operation not offered
  by this backend), `Hardware(String)` (transport, secure channel or card
  status). `SoftVault` never returns `LockedMetadata` or `Hardware`.

## `kdf` module

| Fn / const | Signature | Notes |
|----|------|-------|
| `KDF_NAME` | `&str = "argon2id"` | Written into the vault file. |
| `DEFAULT_M_COST` / `DEFAULT_T_COST` / `DEFAULT_P_COST` | `u32` | 19456 KiB, 2 passes, 1 lane (OWASP guidance). |
| `MIN_*_COST` / `MAX_*_COST` | `u32` | The range `open` accepts. Floor = the defaults; ceiling = 1 GiB / 16 / 16. Too weak would let a planted file make later seals cheap to crack; too strong is a denial of service. |
| `validate_params` | `(m_cost:u32, t_cost:u32, p_cost:u32) -> Result<(), String>` | Range-check a triple read from a file. |
| `argon2id_kek` | `(password:&[u8], salt:&[u8], m_cost:u32, t_cost:u32, p_cost:u32) -> Result<[u8;32], String>` | 32-byte key via Argon2id. Salt must be at least 8 bytes. |
