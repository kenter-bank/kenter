# stellar-keycard — Architecture

**Role.** The hardware-custody engine. It drives a Keycard smart card over an
APDU transport (a PC/SC reader, or the applet's jcardsim simulator over TCP)
and exposes the card as a `kenter-vault` backend, so the wallet can keep its
seed on a secure element instead of in a passphrase-encrypted file.

The card runs **kenter-keycard**, a fork of Status's Keycard applet. Status's
applet is the upstream: this crate's secure channels, lifecycle and most
commands follow it. The fork adds what Stellar needs and stock Keycard lacks:
Ed25519 signing and public-key export along SLIP-0010 paths, BIP85 export,
and an owner-index counter for spend-mode notes. A stock Keycard signs only
secp256k1 and cannot serve as a Kenter wallet.

The crate is native-only: it needs a card on a reader, or the simulator.

## Boundaries

- **Depends on:** `pcsc` (reader access), `k256` (secp256k1 ECDH and ECDSA
  for both secure channels), `aes`/`cbc` (channel V1), `ccm` (channel V2),
  `hkdf`/`hmac`/`sha2`, `ed25519-dalek` (verifying card signatures),
  `stellar-strkey`/`base64` (addresses, XDR), `zeroize`, and `kenter-vault`
  (the `KeyVault` and `DerivingVault` traits).
- **Depended on by:** `kenter-ui` (card custody in the desktop wallet: first
  run, unlock, owner-key derivation, PIN management, reset) and
  `kenter-desktop` (the `keycard` command).

## Structure

| Module | What it does |
|---|---|
| `transport.rs` | `CardTransport` trait (`transmit(apdu) -> data‖SW`) and `Transport`, the PC/SC implementation; `select_keycard`, `ApplicationInfo`. |
| `sim.rs` | `SimTransport`: the jcardsim TCP server (`127.0.0.1:21345`), framed as a `u16` length plus APDU; a zero-length frame resets the card. |
| `apdu.rs` | APDU building and status-word handling. |
| `secure_channel_v2.rs` | Secure Channel V2 and the card identity certificate check. |
| `stellar.rs` | `StellarKeycard<T>`: the Ed25519 backend Kenter uses. Provisioning, PIN/PUK management, owner keys, BIP85, the owner-index counter, Stellar transaction signing. |
| `secure_channel.rs`, `vault.rs` | Secure Channel V1 (pairing-based) and `KeycardVault`, a secp256k1 signer for a stock applet. Used by the CLI's `keycard` command and the probes. |
| `error.rs` | `KeycardError`. |

The transport seam means the same channel and command code runs on hardware
and in the simulator.

## StellarKeycard

### Secure Channel V2

ECDHE on secp256k1, HKDF-SHA256 (`"sc_v2_ccm"`), then AES-128-CCM with an
8-byte tag and a 13-byte counter nonce shared by a command and its response.
The card authenticates by an ECDSA signature over the key-exchange
transcript, verified against the identity key in its SELECT certificate
(tag `0x8A`: compressed identity key plus a CA signature). There is no
pairing step.

### Connecting and pinning the card

Three ways to connect, by how much is known:

- `connect` takes the card's word for its identity. It is for the probes
  only, never for a path that sends a PIN or trusts a derived key.
- `connect_certified` requires the identity certificate to be signed by a
  pinned CA. It is used at provisioning, where the identity read is the one
  written into the vault record; recording a substitute card here would make
  the substitution permanent, so the CA check matters most here.
- `connect_expecting` also requires the identity to equal the one recorded
  at provisioning.

A SELECT resets the secure channel, so every PIN-bearing operation
re-SELECTs, re-reads the identity, and re-checks it **on the same
connection that will carry the PIN**. Checking on a separate connection
would let a device answer honestly there and substitute itself here.

The CA key in the crate, `DEV_CA_PUBLIC_KEY`, is a development CA whose
private key is public in the applet repository's simulator. It proves only
that a card came from a development workbench. A build for real users must
pin a production CA whose private key stays offline.

### Provisioning

- **`init`** sets PIN (6 digits), PUK (12 digits), a duress PIN and retry
  limits. `InitParams` is a struct because transposing a PIN and a PUK makes
  a card nobody can unblock. Inputs are validated before sending so the
  caller gets a sentence instead of `6A80`; the digit check on a chosen
  duress PIN is ours alone, because the applet does not make it and a
  non-digit duress PIN could never be typed on a keypad.
- **There is no "no duress PIN".** The applet checks the duress PIN first on
  every unlock, and with none configured it is the PUK's first six digits.
  `DuressPin` is an enum (`Chosen` or `PukPrefix`) rather than an
  `Option`, so inheriting has to be named. The wallet asks the
  holder to choose one, because a credential they never picked is not one
  they can use under pressure. The duress PIN unlocks a decoy tree: unrelated
  keys, no notes, its own counter.
- **`generate_mnemonic`** has the card draw entropy and return BIP-39 word
  indexes. It stores nothing.
- **`load_bip39_seed`** (`LOAD KEY P1=SEED`) loads the 64-byte BIP-39 seed.
  Kenter always provisions this way, so the card holds a seed with a phrase
  behind it and the wallet is recoverable. A card set up with `GENERATE KEY`
  works but has no phrase and cannot be told apart over the wire, so this is
  controlled by provisioning rather than checked.
- **`factory_reset`** wipes the card. Notes are bearer instruments; nothing
  is kept.
- **Blank-card guard.** On an uninitialized card the applet answers most
  secured commands with an empty `9000` that did nothing. The client checks
  initialization before such commands rather than trusting the status word.

### Two key trees from one seed

`LOAD KEY P1=SEED` sets two masters, and they are not interchangeable:

| Tree | Master | Used for |
|---|---|---|
| SLIP-0010 / Ed25519 | `HMAC-SHA512("ed25519 seed", seed)` | owner keys at `m/44'/148'/n'` |
| BIP32 / secp256k1 | `HMAC-SHA512("Bitcoin seed", seed)` | BIP85 children |

`StellarKeycard` implements both `kenter-vault` traits:

- **`DerivingVault`**: spend-mode owner keys, `derive_public(index)` and
  `sign_derived(index, digest)`. The credential is the PIN. This is the role
  Kenter uses.
- **`KeyVault`**: slot *n* is `m/44'/148'/n'`, so on the card a slot and an
  owner index with the same number are the same key. Kenter does not use it:
  the fee-paying Stellar account stays a software key. Putting it on the
  card would place it at index 0, the standing pay tag's index, linking that
  tag to an account the ledger names as depositor and redeemer. A fee-paying
  hot key gains nothing from a secure element, and keeping it in software
  keeps the shape where neither key alone moves a note.

BIP85 export (`INS 0xC4`) gives the wallet its symmetric keys (note store,
backup file, account vault) without exporting the seed. A software vault
restored from the same phrase derives the same values, which is what lets a
holder recover after losing the card. BIP85 is used rather than a key
derived from a deterministic signature over a fixed challenge, because
re-signing the same message on every unlock is exactly the fault-injection
setting that leaks a signing key, and because key derivation must not depend
on a signing-nonce policy.

The owner-key path agreement with `kenter-vault` is pinned by
`tests/vectors/owner_key_vectors.json`, generated from `kenter-vault`. A card
that derived differently could not open commitments a software wallet
wrote, and the notes behind them would be unredeemable.

### The owner-index counter

For a card wallet the card is the sole allocator of owner indexes.

- `next_owner_index` **allocates**: call it only when an index is being
  assigned to a receive.
- `owner_index` reads the counter without spending one.
- `advance_owner_index(to)` raises the counter to at least `to`. It is the
  restore path: after the store package is reinstalled (the one event that
  resets the counter, and also loses the notes), the host advances past the
  larger of the backup's next index and one more than any held note's index,
  plus a margin of 20 for indexes that were issued and paid but whose note
  never arrived.

The counter survives `FACTORY_RESET` and duress, so a re-seeded card never
reissues an index the holder has used, which would relink their history.

### Stellar transaction signing

The host builds the transaction and computes
`transaction_hash = SHA256(network_id ‖ ENVELOPE_TYPE_TX ‖ tx_xdr)`; the card
signs the 32-byte hash, and the result is a `DecoratedSignature` (4-byte
hint, 64-byte signature) as XDR or base64. The crate does not build
envelopes.

## KeycardVault (stock applet)

A concrete secp256k1 ECDSA signer over Secure Channel V1, for a stock
Keycard: SELECT, INIT, PAIR once (pairing secret is
PBKDF2-HMAC-SHA256 over the pairing password), then per operation OPEN,
MUTUALLY AUTHENTICATE, VERIFY PIN and the command. V1 derives an
AES-256-CBC key and an AES-CBC-MAC key from
`SHA-512(ecdh ‖ pairing_key ‖ salt)`, and each message's MAC becomes the next
IV. It implements neither `kenter-vault` trait: the mint verifies owner
proofs with Ed25519, so a secp256k1 key cannot be an owner key. It remains
for the CLI's `keycard` command and for probing cards.

## Invariants

- **Keys never leave the card.** Only public keys and BIP85 children are
  exported; the seed stays in the secure element. Session keys and pairing
  keys are zeroized on drop.
- **Fresh channel per operation.** Every PIN-bearing operation re-SELECTs
  and opens a new secure channel; there is no long-lived session.
- **Identity checked on the PIN's own connection** whenever a recorded
  identity exists.
- **PINs are typed by the holder, never taken from argv or the environment** in
  shipping callers. Passing a passphrase where a PIN is expected burns one
  of very few attempts.
- **One seed, one set of owner keys.** Card and software vault derive the
  same owner keys and the same BIP85 values from the same phrase.

## Testing

- `tests/owner_keys.rs`: the path the client sends runs anywhere; the keys
  that come back need the simulator (`#[ignore]`).
- `tests/provisioning.rs`: provisioning commands against the simulator,
  `#[ignore]`d because several are destructive. Each test factory-resets on
  the way in, so a failed run leaves the card inspectable.
- `tests/on_metal.rs`: the owner-key claims against a real card seeded with
  SEP-0005 test vector 1. Only the main PIN is ever sent; falling back to the
  duress PIN would report wrong keys rather than fail.

Start the simulator from the kenter-keycard repository with
`./gradlew simServer` (JDK 11). See `docs/testing/keycard.md` for the full
procedure. `examples/` holds probes and card utilities (inventory, wipe,
identity and certificate probes).
