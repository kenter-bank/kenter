# kenter-vault — Architecture

**Role.** The custody abstraction. It defines the port traits every client
codes against and ships `SoftVault`, their software implementation: a
passphrase-encrypted JSON file. The card backend (`StellarKeycard` in
`stellar-keycard`) implements the same traits, so a client chooses custody
once and the rest of the code does not care which it got.

It also owns the key-derivation scheme the whole wallet depends on: BIP-39
phrase to seed, SLIP-0010 owner keys, and BIP85 children for symmetric keys
and the fee-paying account. The crate is pure Rust with no PC/SC and no OS
keystore, so it builds for `wasm32` as well as native.

## Boundaries

- **Depends on:** `kenter-crypto` (`StellarKeypair`), `stellar-strkey`,
  `crypto_secretbox` (XSalsa20-Poly1305), `argon2` (Argon2id), `hmac` +
  `sha2` (SLIP-0010, BIP32, header MAC), `k256` (BIP32 secp256k1 scalar
  arithmetic for BIP85), `bip39`, `subtle`, `zeroize`, `rand`, `serde`.
- **Depended on by:** `kenter-wallet`, `kenter-ui`, `kenter-desktop`,
  `stellar-keycard` (implements the traits), `kenter-node`, `kenter-systest`.

## Structure

| Module | What it does |
|---|---|
| `lib.rs` | The traits `KeyVault` and `DerivingVault`, `StoreCredentials`, `BackupCredentials`, `SlotId`, `KeySlotInfo`, `VaultError`. |
| `soft.rs` | `SoftVault`: the on-disk format, encryption, header MAC, custody record, seed, credential derivation. |
| `kdf.rs` | Argon2id with a parameter floor and ceiling. |
| `mnemonic.rs` | BIP-39: generate, validate, words from card indexes, phrase to 64-byte seed. |
| `slip10.rs` | SLIP-0010 Ed25519 derivation; owner keys at `m/44'/148'/n'`. |
| `bip85.rs` | BIP85 over the BIP32 secp256k1 tree, the `Bip85` port, and the wallet's fixed BIP85 indexes. |

## Two traits for two roles

- **`KeyVault`** custodies individual Ed25519 Stellar **account** keys by
  slot: `generate_key`, `import_seed`, `sign(slot, msg, credential)`,
  `public_key`, `stellar_address`, `list_keys`, `remove_key`. Slots are a
  monotonic `u32` and never reused.
- **`DerivingVault`** custodies one HD seed and derives spend-mode **owner**
  keys from it: `derive_public(index, credential)` and
  `sign_derived(index, digest, credential)`, at `m/44'/148'/index'`.

They are separate because an owner key is identified by a **derivation index
recorded on the held note**, not a slot, and it is never stored: it is
re-derived when needed. Folding that into `KeyVault` would make one
identifier mean two things. The split also gives the property the owner-key
model rests on: the backup is the seed, once, instead of a new secret on
every receipt, and a card and a software wallet restored from the same
phrase can take over each other's notes. See
`docs/architecture/spend-mode.md`.

**The credential** is a passphrase for `SoftVault` and a PIN for a card. It
is required for anything that touches secret material and never for
read-only metadata. Deriving takes it because it needs the seed itself.
Methods take `&mut self` because a card backend opens a secure channel and
exchanges APDUs, which mutates its transport.

Everything is Ed25519, because the mint verifies owner proofs with
`ed25519_verify`. Owner authorizations sign a 32-byte digest; callers pass
the digest, not the preimage.

## Seeds and derivation

- **BIP-39 phrase.** The wallet seed is the 64-byte PBKDF2 output of a
  BIP-39 mnemonic. BIP-39 specifically because the Keycard applet is loaded
  with a BIP-39 seed and computes its masters from the same 64 bytes; any
  other format would make a card and a software wallet restored from "the
  same" backup derive different owner keys. The optional BIP-39 passphrase
  is a different secret from the vault passphrase; a forgotten one silently
  yields a different wallet, so it defaults to empty.
- **A phrase recovers authorization, not value.** Notes cannot be found from
  the ledger, so a phrase with no note records redeems nothing. Recovery is
  phrase plus backup file; neither alone is enough.
- **Two trees from one seed**, not interchangeable:

  | Tree | Master | Used for |
  |---|---|---|
  | SLIP-0010 / Ed25519 | `HMAC-SHA512("ed25519 seed", seed)` | owner keys at `m/44'/148'/n'` |
  | BIP32 / secp256k1 | `HMAC-SHA512("Bitcoin seed", seed)` | BIP85 |

- **BIP85 children** (HEX application, `m/83696968'/128169'/32'/index'`):

  | Index | Use |
  |---|---|
  | 0 | note store keys (record AEAD key, filename MAC key) |
  | 1 | backup file key |
  | 2 | credential that opens a card wallet's account vault |
  | 3 | the fee-paying Stellar account's secret key |

  BIP85 is exposed as the `Bip85` port, not a function over a seed, because
  a card never hands over its seed: it runs the derivation and returns the
  entropy. Children are independent by construction, so one leaking says
  nothing about another. The account key is derived from the seed so the
  same phrase always names the same account; redemptions pay into it, so it
  has to come back from the words alone. It is not an `m/44'/148'/n'` index,
  because an account sharing a key with an owner would link fee payments to
  the note being paid for. These indexes are permanent once a wallet exists.
  BIP85 is used instead of a key derived from a deterministic signature over
  a fixed challenge, because re-signing the same message on every unlock is
  the fault-injection setting that leaks a signing key, and key derivation
  must not depend on a signing-nonce policy.
- **Software store and backup keys.** For a software wallet,
  `store_credentials` and `backup_credentials` hash the seed under separate
  `kntr_v1:wallet:*` domain tags. These are different values from the BIP85
  ones a card wallet uses; a backup's header records which derivation it
  used, so a restore never guesses. The backup fingerprint, written in the
  clear, is a hash under its own tag and reveals nothing about the key.
- **The store needs two keys.** Encrypting records is half the job: files
  named after note IDs would say exactly which notes are held, and every ID
  can be looked up on the ledger for its amount. So the second key MACs each
  record ID into an opaque filename.

## SoftVault on disk

One JSON file (format version 3):

- `kdf` and the Argon2id cost triple (`m = 19456 KiB, t = 2, p = 1` by
  default) and a random 16-byte salt for the whole file.
- `entries`: one per account key, holding slot, label, public key, a fresh
  24-byte nonce and the 32-byte Ed25519 secret sealed with
  XSalsa20-Poly1305 (`crypto_secretbox`) under the passphrase-derived KEK.
- `seed`: the BIP-39 seed sealed the same way.
- `custody`: what opens this wallet, recorded rather than inferred.
  `Software` (the seed is here behind a passphrase); `Card` (the seed is on a
  card, this file holds only the fee-paying account key, opened with a
  BIP85-derived credential; records the seed fingerprint and the card's
  identity key); `RecoveredCard` (a card wallet's seed restored into this
  file after the card was lost; it keeps the card wallet's BIP85 derivation
  and fingerprint, so the notes and backups still open).
- `mac`: HMAC-SHA256 over every field that is not ciphertext (version, KDF
  triple and salt, `next_slot`, every entry's metadata, the seed entry, the
  custody record), keyed by a `kntr_v1:vault:header-mac` derivative of the
  same KEK.

The KEK is derived fresh per operation and zeroized after use; there is no
intermediate master key. XSalsa20-Poly1305 is a 256-bit stream cipher with a
24-byte nonce and Poly1305 tag, equivalent in strength to
XChaCha20-Poly1305.

## Invariants

- **Secrets encrypted at rest.** Seeds and keys reach disk only sealed. The
  clear parts of the file are labels, public keys, timestamps and the
  custody record.
- **Credential never stored.** The passphrase is passed per call as `&[u8]`
  and never kept on the struct or on disk. The KEK and any unwrapped secret
  are zeroized immediately.
- **Tamper is an auth failure.** A wrong passphrase or altered ciphertext
  fails the Poly1305 tag as `VaultError::BadCredential`.
- **The plaintext around the secrets is authenticated too.** The AEAD does
  not cover the displayed `public_key` (the address the UI shows as the
  account to fund) or the card identity a launch check compares against.
  Every credentialed operation verifies the header MAC before acting, reads
  included, and every mutation recomputes it. A file holding secrets with no
  `mac` is refused, so deleting the field is not a way around it.
- **One vault, one passphrase.** The MAC verifies only under the key the
  file was sealed with, so a write offered a different passphrase fails
  instead of sealing an entry under a credential the owner does not have.
- **Credential-free reads are unauthenticated**, necessarily.
  `public_key` and `stellar_address` have no key to check against; code
  about to present an address as "fund this" uses
  `verified_stellar_address`, which derives it from the sealed secret.
- **KDF parameters are range-checked.** The cost triple is the one input
  that cannot be MAC-checked, since the MAC key is derived with it. Without a
  floor, someone able to write the file could plant a cheap KDF and make a
  short passphrase brute-forceable; without a ceiling, a cost nobody can
  compute. The floor is the default (OWASP guidance); the ceiling is 1 GiB
  memory and 16 iterations.
- **Seeds are never overwritten.** `set_seed` refuses to replace a seed,
  because replacing one orphans every note owned by a key derived from it.
- **Metadata writes need the credential.** `set_custody` takes one, because
  it re-tags the file.
- **Removing a key proves the passphrase** by decrypting the target entry
  first, which also catches a wrong-vault mistake.

Derivation is pinned by published vectors (SLIP-0010, BIP85) and by
`owner_key_vectors.json`, which `stellar-keycard` uses to check that a card
derives the same owner keys.
