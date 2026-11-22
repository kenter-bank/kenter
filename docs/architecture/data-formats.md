# Data formats

Three containers carry value or the means to recover it. Get these wrong and
a holder loses money, so each is specified here rather than left to be read
out of the code.

## 1. The note — `SYMTOKEN` v6

A bearer token on disk, conventionally `.symtoken`. Little-endian throughout.
Defined in `kenter_crypto::container`; the byte-level layout and the
cryptography behind each field are in [Bearer token
format](/bearer-token-format).

| Section | Field | Bytes |
|---|---|---|
| Preamble | magic `SYMTOKEN` | 8 |
| | version (`6`) | 2 |
| | token type | 1 |
| | flags (reserved) | 1 |
| Header | event id | 32 |
| | print timestamp | 8 |
| | denomination present? | 1 |
| | denomination, if present | 8 |
| Slot | slot id | 4 |
| Mint binding | present? | 1 |
| | mint contract id, asset contract id, if present | 32 + 32 |
| Ephemeral key | ephemeral public key | 32 |
| Claim key | claim **secret** | 32 |
| Chain | total pairs | 2 |
| | required pairs | 2 |
| | links | `total_pairs` × 290 |
| Initiation proof | initiator public key | 32 |
| | VRF proof length | 2 |
| | VRF proof (reserved; always empty) | variable |
| Caveats | count | 2 |
| | caveats | variable |
| Signature | Ed25519 over everything above | 64 |

The signature is the requestor's, and it covers **magic through the last
caveat byte**, everything but itself. The slot, the mint binding and the
claim secret are all inside that range, so changing any of them breaks the
signature.

Only this version is read. An older note is neither readable by the current
code nor redeemable by the current mint; reprint it.

### The slot

The mint keys a note's record by the print slot it came from, because the
contract issues slot ids while the ephemeral key is a value the depositor
names. A note carries its slot so a redemption can name its record.

### The mint binding

The issuing mint's contract id and the contract id of the asset it escrows.
A payee handed a bare file learns from it which deployment to ask and what
the note pays out in. The asset matters: an issued asset whose issuer can
revoke authorization can have the escrow frozen, while native XLM cannot. A
note assembled without a mint (an offline test print) has no binding.

### The claim key

The one secret a note carries. Generated with independent randomness when
the requestor assembles the note, which is the only moment the whole note
exists (a partial token passes through every node while printing), and
**never transmitted**. Its public half is registered on chain; a
pure-bearer redemption presents a signature over
`SHA-256("kntr_v1:redeem:claim" ‖ contract ‖ slot_id ‖ ephemeral_key ‖ recipient)`.

It exists because the chain alone cannot be the proof. Presenting the chain
publishes it, and a transaction that *fails* on chain publishes it while the
note stays live. If the chain were enough, reading a failed transaction off
the ledger would be enough to take a note. A commit-reveal scheme would not
help: once the chain is public and the note is live, an attacker commits
their own and reveals a ledger later. So the proof is a signature naming the
recipient, from a key nobody but the holder has.

::: danger Never derive the claim secret from the chain
It is the obvious shortcut and it silently undoes the whole mechanism: the
chain is published by every redemption attempt, so a key derived from it goes
straight to the observer this exists to stop. Independent randomness, stored
in the file.
:::

The note stays bearer. The key lives in the file rather than with a person,
so copying the file copies the right to redeem, including photographing one
off paper. That is what distinguishes it from spend mode, where a thief
holding the file cannot redeem.

### Chain data

A chain link is `CHAIN_LINK_SIZE` = 290 bytes. `kenter_crypto::chain_data`
has the helpers (`chain_data_len`, `serialize_chain_data`, `chain_hash`) that
produce the canonical chain data (`event_id ‖ link count ‖ links`) and the
commitment `register_token` records.

`is_symtoken()` checks the magic, which is how the client tells a note from
any other file it is handed.

## 2. The backup file — `.kbk`

Produced by `kenter_wallet::backup::encode`. Unlike the other two, this is
**JSON with a cleartext header and a hex ciphertext body**, so a restorer can
be told what they are holding before anything is decrypted.

```json
{
  "kind": "kenter-wallet-backup",
  "version": 2,
  "seed_fingerprint": "5e1f0c2a9d4b7368",
  "created_at": 1761350400,
  "token_count": 2,
  "seed_origin": "card",
  "bip85": { "...": "derivation, only for a bip85-child backup" },
  "content_digest": "…",
  "nonce": "…24 bytes hex…",
  "ciphertext": "…"
}
```

The header earns its cleartext. `seed_origin` decides **what the restorer has
to be asked for** (a phrase, a card, or a root plus an index), and the client
answers that question before prompting the holder for anything.
`seed_fingerprint` lets a wrong file be named as the wrong file immediately.

Body: XSalsa20-Poly1305 under the BIP-85 backup key (index 1), 24-byte nonce.

`content_digest` is domain-tagged with `kenter_v1:backup:contents` so the
value cannot be confused with any other hash in the system.

**Invariant:** a backup with `seed_origin: bip85-child` must carry its
derivation, and only such a backup may. `encode` rejects either mismatch;
without it, a card-rooted file would record no way back to its own key.

Version 2 is written; `inspect` also reads version 1.

### Restoring is additive

`backup::restore` never overwrites a note the wallet already holds. That makes
restoring safe to repeat, safe to run against a live wallet, and usable as a
*verification* step: scanning your own backup back in proves it works and
changes nothing. `RestoreReport` distinguishes added from already-held.

## 3. Paper — `KPB2`

Defined in `kenter_wallet::paper`. A page of QR symbols, one set per
**item**, where an item is one note or the wallet's own record.

Each symbol carries this cleartext header, then its slice of the payload:

| Field | Bytes | Meaning |
|---|---|---|
| magic `KPB2` | 4 | |
| wallet fingerprint | 8 | the seed fingerprint, as bytes |
| kind | 1 | wallet record, or note |
| item | 2 | which item, 0-based |
| items | 2 | how many items the backup has |
| index | 2 | which symbol within this item, 0-based |
| total | 2 | how many symbols this item has |
| digest | 4 | of the whole item, repeated in every chunk |
| payload | … | deflate-compressed, sealed |

25 bytes of header. Symbols are rendered at error correction **M**.
`SYMBOL_CAPACITY` is 2331 bytes (a version-40 symbol at M), so the format
allows up to `CHUNK_PAYLOAD` = 2306 payload bytes per symbol. Sheets fill
each symbol to at most 850 payload bytes (`chunk_payload()`, overridable with
`KENTER_PAPER_CHUNK_PAYLOAD`), which keeps every symbol at QR version 23 or
below, inside what a camera reliably reads. A reader decodes any error
correction level, so the level is not part of the format.

Three parts of the header are there because the backup fails silently
without them:

**`wallet` is in the clear** so a sheet can say which wallet it belongs to
*before any key*. Otherwise the wrong sheets show up as "a backup where
nothing decrypts", which looks the same as a damaged one.

**`items` is in the clear** because otherwise a note whose every symbol is
missing is not missing, it is *invisible*. A holder who loses one sheet would
scan the rest, be told four notes came back when there were five, and never
learn otherwise. It reveals only how many notes a backup holds, which the
printed labels show anyway.

**`digest` is of the whole item and repeated in every chunk**, so symbols
from two different sheets cannot be combined into a plausible-looking item.

### Per item, not one blob

Each item has its own symbols, so an unreadable symbol costs one note, not
the whole backup. Within an item the chunks carry no redundancy between them:
every symbol of an item must read.

### Chunks are balanced

An item too large for one symbol is split into **evenly sized** chunks, not
filled to capacity with a short remainder.

This is not cosmetic. An item needs every one of its symbols, so its
readability is set by its densest symbol. Filling to capacity would make the
first symbol of every multi-symbol item the densest thing on the page and the
last one nearly empty, which maximises exactly the wrong thing. Balancing
costs nothing (same symbol count, same bytes), and the test
`an_items_symbols_are_evenly_sized` pins it.

### Geometry

| | Value |
|---|---|
| Module size | 0.30 mm (`KENTER_PAPER_MODULE_MM` overrides) |
| Symbol cell | 185 modules (177 + 8 quiet zone) = 55.5 mm square |
| Error correction | M |
| Page | A4; nine symbols at the default module size |

Module size governs *printing*; the QR **version** governs whether a camera
can read it. When a symbol fills the frame, physical module size cancels:
pixels per module is `frame_pixels / modules_per_symbol`.

See [Paper and camera](/testing/paper) for the measurements.
