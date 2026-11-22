# `stellar-keycard`

Keycard custody over PC/SC. `StellarKeycard` implements the `kenter-vault`
traits against a JavaCard secure element, so the wallet core never learns
whether custody is software or hardware. Full signatures are in
`crates/stellar-keycard/API.md`.

::: danger Operations here can destroy a card
Read [Keycard hardware](/testing/keycard) before running anything with a
card on a reader.
:::

## Modules

| Module | Holds |
|---|---|
| `apdu` | The Keycard command set |
| `transport` | PC/SC |
| `secure_channel` / `secure_channel_v2` | Encrypted sessions |
| `stellar` | `StellarKeycard`: the `KeyVault` / `DerivingVault` / `Bip85` implementation, provisioning, the owner-index counter |
| `vault` | `KeycardVault`: a secp256k1 signer for the stock applet (not used for notes) |
| `sim` | Talking to the applet's simulator |
| `error` | Errors |

## The fork

Status's stock Keycard applet is **secp256k1**. Kenter needs **Ed25519**,
because the mint verifies owner authorizations with `ed25519_verify`.
`StellarKeycard` targets **kenter-keycard**, a fork of Status's applet that
adds on-card SLIP-0010 Ed25519 derivation and signing, BIP85 export and a
note-index counter, over Secure Channel V2.

A stock card will pair, open a channel and derive keys — and they will be
the wrong keys. `probe_eddsa` is how you check before concluding the code is
broken.

## `apdu` — the command set

`KEYCARD_AID` selects the applet:
`A0 00 00 08 04 00 01 01 01`.

| Constant | `INS` | Command |
|---|---|---|
| `INS_SELECT` | `A4` | Select applet |
| `INS_INIT` | `FE` | Initialise |
| `INS_OPEN_SECURE_CHANNEL` | `10` | Open channel |
| `INS_MUTUALLY_AUTHENTICATE` | `11` | Mutual auth |
| `INS_PAIR` / `INS_UNPAIR` | `12` / `13` | Pairing |
| `INS_GET_STATUS` | `F2` | Status |
| `INS_VERIFY_PIN` | `20` | Verify PIN |
| `INS_CHANGE_PIN` / `INS_UNBLOCK_PIN` | `21` / `22` | PIN management |
| `INS_GENERATE_KEY` | `D4` | Generate on card |
| `INS_DERIVE_KEY` | `D1` | Derive |
| `INS_EXPORT_KEY` | `C2` | Export |
| `INS_LOAD_KEY` / `INS_REMOVE_KEY` | `D0` / `D3` | Load, remove |
| `INS_SIGN` | `C0` | Sign |
| `INS_STORE_DATA` / `INS_GET_DATA` | `E2` / `CA` | Card storage |
| `INS_IDENTIFY` | `14` | Identify |

Status words worth recognising:

| Word | Meaning |
|---|---|
| `SW_OK` `9000` | Success |
| `SW_SECURITY_NOT_SATISFIED` `6982` | PIN not verified |
| `SW_AUTHENTICATION_BLOCKED` `6983` | **Card blocked** |
| `SW_CONDITIONS_NOT_SATISFIED` `6985` | Wrong state |
| `SW_WRONG_DATA` `6A80` | Malformed |
| `SW_WRONG_P1P2` `6A86` | Bad parameters |
| `SW_INS_NOT_SUPPORTED` `6D00` | Not this applet — often a stock card |
| `SW_CLA_NOT_SUPPORTED` `6E00` | Wrong class |
| `SW_REFERENCED_DATA_NOT_FOUND` `6A88` | No such key or slot |

Helpers: `select_keycard`, `get_status`, `pair_step1`, `pair_step2`,
`open_secure_channel`, `mutually_authenticate`, `verify_pin`,
`generate_key`, `sign`, `store_data`, `get_data`, `init`.

`STORE_TAG_STELLAR_VAULT` tags the card-stored vault blob.

::: danger `9000` does not mean the right PIN
The duress PIN verifies successfully and switches the card to a decoy tree —
empty notes, unrelated keys, its own index counter. Every layer reports
success; only the keys are wrong. **Only the main PIN is ever sent.**
:::

## `stellar`: the implementation

`StellarKeycard<T: CardTransport>` implements `KeyVault`, `DerivingVault` and
`Bip85`. On the card a `KeyVault` slot and a `DerivingVault` index with the
same number are the same key (`m/44'/148'/n'`). Kenter uses only
`DerivingVault` (owner keys) and `Bip85` (store, backup and account
credentials) on a card; the fee-paying account stays in software.

Connect with `connect_certified` when provisioning and `connect_expecting`
afterwards: both check the card's identity certificate against pinned CA
keys, and `connect_expecting` also requires the identity recorded at
provisioning. Plain `connect` checks nothing and is for probes.

Differences from `SoftVault` that callers must tolerate:

- **`import_seed` returns `Unsupported`.** A card using SLIP-0010 with a
  64-byte seed and on-card derivation cannot take a raw 32-byte Ed25519
  seed. Use the native seed loader.
- **`public_key` may return `LockedMetadata`.** Export is gated behind the
  PIN, so the answer comes from a value cached at provision time — and there
  may not be one yet.

- **Owner signing takes a 32-byte digest.** Anything else is `Unsupported`.
- **A wrong PIN is `BadCredential`; a blocked card is `Hardware`.** Prompt
  loops re-ask on the first and stop on the second.

Signing and deriving take `&mut self` because a card mutates transport and
secure-channel state per call.

## `sim` — the simulator

`SimTransport::connect(addr)` talks to the applet's jcardsim `SimServer`
(`./gradlew simServer` in the kenter-keycard repository), by default
`DEFAULT_SIM_ADDR` = `127.0.0.1:21345`.

The simulator runs the applet's own code, but it is **not** the card's chip,
its RNG, or its NFC framing. Signature encoding, timing and radio dropouts
differ on real hardware, which is why hardware runs are a gate rather than a
formality.

## Examples

Read-only (no PIN attempt spent unless noted): `detect`, `probe_card`,
`probe_select`, `probe_v2`, `probe_cert`, `probe_identity`, `probe_eddsa`,
`card_inventory`, `probe_pin_carryover` (spends an attempt only if the PIN is
wrong).

Simulator: `keycard_keyvault`, `stellar_sim`.

Changes card state: `init_and_open` (INITs a blank card with dev PINs; undone
only by a wipe), `card_sign` (generates a key on the stock applet),
**`card_wipe`** (factory reset). Examples that need a PIN read
`KENTER_CARD_PIN`; use them only with throwaway test cards.

## Tests

| File | Needs |
|---|---|
| `tests/owner_keys.rs` | Nothing for the path check; the simulator for the ignored key check |
| `tests/on_metal.rs` | A real card; destructive parts also need `KENTER_CARD_DESTRUCTIVE=1` |
| `tests/provisioning.rs` | The simulator; destructive |

Hardware tests want a card seeded with **SEP-0005 test vector 1** — what the
applet suite leaves behind, and what the owner-key golden vectors are
generated from, so software and hardware are compared against the same
truth.

Always `--test-threads=1`: there is one reader.
