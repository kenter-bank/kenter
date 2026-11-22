# stellar-keycard: API

The hardware-custody engine. It drives a Keycard JavaCard applet over PC/SC,
or the applet's jcardsim simulator over TCP. Native only.

Two backends live here:

- **`StellarKeycard<T: CardTransport>`**: the Ed25519 / Stellar backend. It
  speaks Secure Channel V2 to the **kenter-keycard** applet, a fork of
  Status's Keycard applet that adds on-card SLIP-0010 Ed25519 derivation,
  RFC 8032 signing, BIP85 export and a note-index counter. It implements
  `kenter_vault::KeyVault`, `DerivingVault` and `Bip85`. This is the backend
  Kenter uses.
- **`KeycardVault`**: a secp256k1 ECDSA signer for the stock Status applet
  over Secure Channel V1. It implements no `kenter-vault` trait and plays no
  part in note custody; the mint verifies owner authorizations with
  `ed25519_verify`, which a secp256k1 key cannot satisfy. It remains as a
  working V1 transport and lifecycle client.

PINs and PUKs are passed in by the caller and must be read interactively,
never from argv or the environment (the dev examples and the on-metal test
read `KENTER_CARD_PIN` for throwaway test cards only).

## `StellarKeycard<T: CardTransport>`

`T` is any `CardTransport`: `Transport` (PC/SC) or `SimTransport`. All
methods return `kenter_vault::Result<T>`; card failures arrive as
`VaultError::Hardware(String)`.

### Connecting

| Fn | Sig | Notes |
|----|-----|-------|
| `connect` | `(t: T) -> Result<Self>` | SELECT and read the identity key. **Checks nothing**: no CA signature, no pinning across later SELECTs. For probes only; never on a path that sends a PIN. |
| `connect_certified` | `(t: T, cas: &[CaPublicKey]) -> Result<Self>` | Provisioning: the identity certificate must be signed by one of `cas`. The identity read here is what the wallet records. |
| `connect_expecting` | `(t: T, expected_id: &[u8], cas: &[CaPublicKey]) -> Result<Self>` | Normal use: CA-signed **and** equal to the identity recorded at provisioning, read on this connection. |

Every PIN-bearing operation re-SELECTs (which resets the secure channel) and,
for a handle opened with `connect_expecting`, re-checks the identity before
the PIN is sent. A PIN never crosses a channel whose far end was identified
on another connection.

### Provisioning and PIN management

| Fn | Sig | Notes |
|----|-----|-------|
| `init` | `(&mut self, params: &InitParams) -> Result<()>` | INIT a blank card with PIN, PUK, duress PIN and retry limits. Best effort: an already-initialized card is not an error. |
| `generate_mnemonic` | `(&mut self, words: u8) -> Result<Vec<u16>>` | The card draws entropy and returns BIP-39 word indexes (12, 15, 18, 21 or 24 words). It keeps nothing; the host shows the words, then loads the seed. Needs an initialized card, not a verified PIN. |
| `load_bip39_seed` | `(&mut self, seed: &[u8;64], pin: &[u8]) -> Result<()>` | LOAD KEY with a 64-byte BIP-39 seed. The card computes both the SLIP-0010 and BIP32 masters from it. Caches account 0. |
| `change_pin` | `(&mut self, current: &[u8], new: &[u8]) -> Result<()>` | The applet refuses a new PIN equal to the duress PIN. |
| `change_puk` | `(&mut self, pin: &[u8], new_puk: &[u8]) -> Result<()>` | Needs the PIN, not the old PUK. |
| `unblock_pin` | `(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<()>` | Only on a blocked card; the applet answers `6985` while attempts remain. |
| `factory_reset` | `(&mut self, pin: Option<&[u8]>) -> Result<()>` | Wipes keys, notes, PIN, PUK and pairing. Sent in plain, outside the secure channel. Allowed on a never-initialized card, with a verified PIN (main or duress), or with PIN and PUK both exhausted. No undo. |
| `application_info` | `(&mut self) -> Result<ApplicationInfo>` | Re-SELECT and parse; chiefly "is it initialized". Works over any transport. |
| `identity_pubkey` | `(&self) -> &[u8]` | The card's identity key (compressed secp256k1, 33 bytes) from the SELECT certificate. |

`InitParams<'a> { pin: &[u8], puk: &[u8], duress: DuressPin, pin_retries: Option<u8>, puk_retries: Option<u8> }`,
built with `InitParams::new(pin, puk, duress)` (default retry limits).
`PIN_LEN = 6`, `PUK_LEN = 12` (ASCII digits); `PIN_RETRIES = 2..=10`
(default 3), `PUK_RETRIES = 3..=12` (default 5). Values the card would refuse
are refused locally with a readable message, plus one check the applet does
not make: a chosen duress PIN must be digits.

`enum DuressPin<'a> { Chosen(&[u8]), PukPrefix }`. There is no "no duress
PIN": with none chosen, the applet uses the PUK's first six digits. The enum
makes the caller name that choice. The duress PIN verifies with `9000` and
switches the card to a decoy tree (empty note list, unrelated keys, its own
index counter), so callers must only ever send the main PIN.

### Owner-index counter

The card is the sole allocator of owner indices for a card-backed wallet.

| Fn | Sig | Notes |
|----|-----|-------|
| `next_owner_index` | `(&mut self, pin: &[u8]) -> Result<u32>` | **Allocates**: returns the next index and advances. Call only when an index is being assigned to a receive. |
| `owner_index` | `(&mut self, pin: &[u8]) -> Result<u32>` | Read without allocating. |
| `advance_owner_index` | `(&mut self, to: u32, pin: &[u8]) -> Result<u32>` | Raise the counter to at least `to`; returns where it ended. The restore path. |

The counter survives factory reset and duress, so a re-seeded card never
hands out an index the holder already used. Only reinstalling the applet's
store package resets it; a restore then advances it past every index the
backup and the held notes mention, plus a margin.

### Stellar transaction signing

| Fn | Sig | Notes |
|----|-----|-------|
| `sign_stellar_tx` | `(&mut self, account: u32, tx_hash: &[u8;32], pin: &[u8]) -> Result<DecoratedSignature>` | Sign a transaction hash with the key at `m/44'/148'/account'`. The host builds the transaction and the hash. |

### Trait implementations

A `KeyVault` slot *n* and a `DerivingVault` index *n* are the **same key** on
the card (both `m/44'/148'/n'`), unlike `SoftVault`, where account keys are
independent. Kenter uses only `DerivingVault` and `Bip85` on a card; the
fee-paying account stays a software key, so neither key alone moves a note
and the account never sits at owner index 0.

`DerivingVault` (credential = PIN):

| Fn | Behaviour |
|----|-----------|
| `derive_public(index, pin)` | Exports the Ed25519 public key at `m/44'/148'/index'`. Not cached. |
| `sign_derived(index, message, pin)` | `message` must be 32 bytes (a digest) else `Unsupported`. Verifies the returned signature under the returned key before handing it back, so a derivation mismatch fails locally rather than as an on-chain revert. |

`Bip85` (credential = PIN): `bip85_entropy(path, len, pin)` runs the BIP85
derivation on the card from its BIP32/secp256k1 master and returns only the
entropy (`len` in 1..=64). A card whose master was not loaded from a BIP-39
seed has values no phrase can reproduce.

`KeyVault` (credential = PIN):

| Fn | Behaviour |
|----|-----------|
| `generate_key(label, pin)` | INIT with a fixed all-zero PUK, GENERATE KEY, cache account 0, return slot `0`. For tests and examples only. |
| `import_seed(seed32, ..)` | `VaultError::Unsupported`: use `load_bip39_seed`. |
| `sign(slot, message, pin)` | `message` must be 32 bytes else `Unsupported`. |
| `public_key(slot)` / `stellar_address(slot)` | From the cache, no credential; `LockedMetadata` if this handle has not provisioned or signed with the slot yet. |
| `list_keys()` | Cached slots, `label = "stellar/{slot}"`. |
| `remove_key(slot, pin)` | REMOVE KEY wipes the seed, so every account goes; clears the cache. |

### PIN errors

A wrong PIN (`63Cx` with attempts left) maps to `VaultError::BadCredential`,
which prompt loops re-ask on. A blocked PIN (`63C0`) and an exhausted PUK
(`6983`) map to `VaultError::Hardware` with a message, so the loop stops
instead of spinning.

## Free functions

- `stellar_path(n: u32) -> [u8;12]`: `m/44'/148'/n'` as three 4-byte
  big-endian hardened elements.
- `network_id(passphrase: &str) -> [u8;32]`: `SHA-256(passphrase)`.
- `transaction_hash(network_id: &[u8;32], tx_xdr: &[u8]) -> [u8;32]`:
  `SHA-256(network_id || ENVELOPE_TYPE_TX (2, u32 BE) || tx_xdr)`. The caller
  supplies the XDR.
- `verify_ed25519(pubkey: &[u8;32], hash: &[u8;32], sig: &[u8;64]) -> bool`.

## Identity certificates (`secure_channel_v2`)

- `type CaPublicKey = [u8; 33]` (compressed secp256k1).
- `DEV_CA_PUBLIC_KEY: CaPublicKey`: the development CA used by the simulator
  and dev cards. Its private key is public in the applet repository, so it
  proves only that a card came from a development bench. A release build
  must pin its own CA keys instead.
- `card_identity_pubkey(select_resp) -> Result<Vec<u8>>`: the key the card
  claims, unverified (probes and display only).
- `card_identity_certificate(select_resp) -> Result<Vec<u8>>`: the `0x8A`
  certificate, identity key followed by the CA signature.
- `verify_identity_certificate(cert, ca: &CaPublicKey) -> Result<Vec<u8>>` ·
  `verify_identity_certificate_any(cert, cas: &[CaPublicKey]) -> Result<Vec<u8>>`:
  return the identity key if a pinned CA signed it. Pinning several keys lets
  a CA be retired without stranding its cards; an empty set accepts nothing.
- `SecureChannelV2<'a, T>`: `open(t: &mut T, id_pubkey: &[u8]) -> Result<Self>` ·
  `send(&mut self, cla, ins, p1, p2, data: &[u8]) -> Result<Vec<u8>>`.

## `KeycardVault` (secp256k1, stock applet)

| Fn | Sig | Notes |
|----|-----|-------|
| `connect` | `() -> Result<Self>` | First card on any reader; SELECT the applet. |
| `is_initialized` | `(&self) -> bool` | |
| `card_public_key` | `(&self) -> &[u8]` | Static secure-channel key (secp256k1, 65 bytes uncompressed). |
| `init` | `(&mut self, pin, puk, pairing_password: &str) -> Result<()>` | INIT a blank card. Undone only by factory reset. |
| `ensure_paired` | `(&mut self, pairing_password: &str) -> Result<()>` | Pair once and cache the `Pairing`. Idempotent. |
| `generate_key` | `(&mut self, pin: &str) -> Result<Vec<u8>>` | On-card secp256k1 master; returns the key UID. |
| `sign_ecdsa` | `(&mut self, pin: &str, hash: &[u8;32]) -> Result<CardSignature>` | ECDSA (DER) over the hash. |

Each `generate_key` / `sign_ecdsa` opens a fresh V1 channel (re-SELECT, OPEN,
MUTUALLY AUTHENTICATE, VERIFY PIN). These return this crate's own
`Result<T, KeycardError>`.

## Constants

- `DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"` (the stock applet's),
  `PAIRING_PASSWORD_SALT = b"Keycard Pairing Password Salt"`,
  `PAIRING_PBKDF2_ITERATIONS = 50_000`.
- `DEFAULT_SIM_ADDR = "127.0.0.1:21345"`: where the applet's jcardsim
  `SimServer` listens.
- `apdu`: `KEYCARD_AID` (`A0 00 00 08 04 00 01 01 01`), the stock `INS_*`
  codes, `SW_*` status words, and APDU builders.

## Types

- `DecoratedSignature { hint: [u8;4], signature: [u8;64] }`: `to_xdr() -> Vec<u8>`
  (72 bytes: hint, length 64 as u32 BE, signature) · `to_base64() -> String`.
- `CardSignature { public_key: Vec<u8>, der: Vec<u8> }`: a parsed secp256k1
  SIGN response; `parse_signature_template(resp)`.
- `Pairing { index: u8, key: [u8;32] }`: V1 pairing material, zeroized on drop.
- `ApplicationInfo { initialized, instance_uid, secure_channel_public_key, app_version, remaining_pairing_slots, key_initialized, pin_retries: Option<u8> }`:
  parsed SELECT. `pin_retries` is `None` on a card that does not report it.
- `KeycardError` / `Result<T>`: `PcscContext`, `NoReader`, `NoCard`,
  `CardComm`, `Apdu { sw }`, `NotKeycard`, `NotInitialized`,
  `AlreadyInitialized`, `NoSecureChannel`, `SecureChannel`, `PairingFailed`,
  `AuthFailed`, `PinRequired`, `WrongPin { attempts_remaining }`,
  `CardBlocked`, `SlotNotFound(u8)`, `StorageFull`, `WrapError`,
  `InvalidSlotData`, `Crypto`. `From<pcsc::Error>`.

## Lower-level surface (also `pub`)

- Transport: `CardTransport` trait (`transmit(&mut self, apdu) -> Result<Vec<u8>>`);
  `Transport` (PC/SC: `connect`, `connect_to`, `list_readers`, `transmit`,
  `transmit_ok`, `select_keycard`); `SimTransport` (`connect(addr)`, `reset`).
  The simulator wire protocol is a `u16` big-endian length followed by the
  APDU, each way; a zero length resets the card.
- Secure channel V1: `SecureChannel` (`open`, `send_encrypted`, `verify_pin`,
  `generate_key`, `sign_ecdsa`, `sign_eddsa`), `init_card`, `pair`,
  `pairing_secret_from_password`. On the stock applet `sign_eddsa` returns an
  ECDSA signature; Ed25519 needs the kenter-keycard applet over V2.

## Testing

`tests/owner_keys.rs` checks the derivation path against
`tests/vectors/owner_key_vectors.json` without a card, and (ignored) the keys
the simulator returns. `tests/provisioning.rs` (ignored, simulator,
destructive) covers the provisioning commands. `tests/on_metal.rs` (ignored)
needs a real card seeded with SEP-0005 test vector 1 and PIN `000000`; its
destructive parts also need `KENTER_CARD_DESTRUCTIVE=1`. Run hardware tests
with `--test-threads=1`.
