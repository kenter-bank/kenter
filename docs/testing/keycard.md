# Keycard hardware

Keycard custody is tested three ways: against a simulator, against a real
card, and, for the destructive paths, against a card you are prepared to
lose.

All of it targets the **kenter-keycard** applet, a fork of Status's Keycard
applet that adds Ed25519 (Stellar) signing on the card.

::: danger Read this before putting a card on a reader
Several operations here are **irreversible**. A card holding a real wallet
must never be on the reader while they run. Develop with two cards, so one
can be sacrificed.
:::

## The three levels

| Level | Gate | Needs |
|---|---|---|
| Simulator | `#[ignore]` | The applet's jcardsim `SimServer` on `127.0.0.1:21345` |
| Real card, read-only | `#[ignore]` | A seeded kenter-keycard card on a PC/SC reader |
| Real card, destructive | `#[ignore]` **and** `KENTER_CARD_DESTRUCTIVE=1` | A card you can afford to wipe |

The double gate on the last one is deliberate: neither `cargo test` nor
`cargo test -- --ignored` can fire it by accident.

## Why hardware at all

The simulator runs the applet's own code, but it is not the card's chip, its
RNG, or its NFC framing. A secure channel can pass review and every simulator
test and still fail on a real card, so a hardware run is a gate, not a
formality.

## Running them

```bash
# Simulator: start the applet's SimServer first (./gradlew simServer in the applet repo)
cargo test -p stellar-keycard --test owner_keys -- --ignored --test-threads=1

# Real card, read-only
cargo test -p stellar-keycard --test on_metal -- --ignored --test-threads=1

# Destructive: wipes the card
KENTER_CARD_DESTRUCTIVE=1 KENTER_CARD_PIN=… \
  cargo test -p stellar-keycard --test on_metal -- --ignored --test-threads=1
```

`--test-threads=1` is required. There is one reader and one card.

## Requirements for a real-card run

- **A card running the kenter-keycard applet.** Stock Keycard signs with
  secp256k1 and will not derive the right keys.
- **A steady reader position.** A contactless card at the edge of range drops
  the channel mid-command, and the failure reads like a protocol bug rather
  than a physical one. If results are erratic, move the card before you debug
  the code.
- **Seeded with SEP-0005 test vector 1**, which is what the applet's own test
  suite leaves behind, and what `tests/vectors/owner_key_vectors.json` is
  generated from.

## PINs

**Never hard-code a PIN.** Set `KENTER_CARD_PIN`. A card blocks permanently
after a fixed number of wrong PIN attempts, and a literal PIN in test code
spends one of those attempts every time it runs against a card with a
different PIN.

The applet suite's own value is in the header of
`crates/stellar-keycard/tests/on_metal.rs`, and is the default when
`KENTER_CARD_PIN` is unset.

**Only the main PIN is ever sent.** The duress PIN verifies successfully with
`9000` and switches the card to a decoy tree: empty notes, unrelated keys,
its own index counter. A test that fell back to it would not fail; it would
report that the card derives the wrong keys, which is far worse than an
error.

**Never generate a PUK that begins with the PIN.** Some flows compare
prefixes, and the result is a card that unlocks when it should not.

## Operational rules

::: danger Never run these with a wallet-bearing card on the reader
- **`./gradlew install`** or any card-target gradle test in the applet repo:
  reinstalls the applet and destroys everything on the card.
- **`./gradlew lock`**: irreversible.
:::

**If a GlobalPlatform run fails at "Opening a SecureChannel", stop.** Do not
retry in a loop. Repeated failed opens can exhaust attempt counters, and the
usual cause is physical (card position, reader power), not something a retry
fixes.

**`pkill` is unreliable on Windows.** Use `Stop-Process`, and check the
process is gone before touching the reader again.

## The test files

| File | What it covers |
|---|---|
| `stellar-keycard/tests/owner_keys.rs` | Owner key derivation, against the simulator |
| `stellar-keycard/tests/on_metal.rs` | The same claims against real hardware |
| `stellar-keycard/tests/provisioning.rs` | Provisioning a card from scratch |
| `kenter-ui/tests/card_ceremony.rs` | The full provisioning ceremony through the client |
| `kenter-ui/tests/replacement_card.rs` | Restoring a wallet onto a *replacement* card |

The last two prove the recovery story: a holder whose card is lost can
restore onto a new one from the recovery phrase plus a backup. Both are
destructive and both are double-gated.

## Inspection examples

Non-destructive, for working out what state a card is in:

```bash
cargo run -p stellar-keycard --example detect          # is there a reader, and a card
cargo run -p stellar-keycard --example probe_card      # what applet, what version
cargo run -p stellar-keycard --example probe_v2        # secure channel V2
cargo run -p stellar-keycard --example probe_eddsa     # does it have Ed25519 signing
cargo run -p stellar-keycard --example card_inventory  # what keys are on it
```

`card_wipe` is in the same directory and is left out of that list on
purpose: it erases the card.
