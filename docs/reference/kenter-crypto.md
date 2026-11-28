# `kenter-crypto`

The bottom of the stack: what a note **is**, and the cryptography that makes
it one. It depends on no other Kenter crate, performs no I/O, and compiles to
`wasm32`. Full signatures are in `crates/kenter-crypto/API.md`.

Read `container.rs` and `chain_data.rs` first. They define the bytes
everything else manipulates.

## Modules

| Module | Holds |
|---|---|
| `container` | The `SYMTOKEN` note format |
| `token` | `BearerToken`, `PartialToken`, `MintBinding`, assembly |
| `chain_data` | The canonical chain blob and its hash |
| `shard` | `Shard`, `ChainLink`, shard derivation |
| `compose` | Building the ephemeral key additively |
| `spend` | Spend-mode owner commitments and authorizations |
| `redemption` | Redemption requests, encrypted shards, sessions |
| `keypair` | `StellarKeypair`, `VerifyOnlyKey` |
| `ecdh` | NaCl-box shared secrets |
| `encrypt` | Asymmetric and hybrid encryption |
| `caveats`, `kntr_file` | The `KNTRTOKN` data-file format (not used by a note) |
| `domain` | Domain separation tags |
| `error` | `CryptoError`, `Result` |

## `container`: the note format

| Item | Purpose |
|---|---|
| `SYMTOKEN_MAGIC` | `b"SYMTOKEN"`, 8 bytes |
| `SYMTOKEN_VERSION` | `6`. Any other version is refused |
| `is_symtoken(data)` | Magic check. How the client tells a note from any other file |
| `serialize_bearer_token(token, signer)` | To bytes, signed by the requestor |
| `deserialize_bearer_token(data)` | Back, verifying structure |
| `verify_bearer_signature(data, key)` | Check the signature alone |
| `serialize_partial_token` / `deserialize_partial_token` | A token mid-print. **No claim secret**: a partial token passes through every node, and the key must not |

The signature covers magic through the last caveat byte. The byte layout is
in [Data formats](/architecture/data-formats) and in the crate's `API.md`.

### What identifies a note

| Item | Purpose |
|---|---|
| `BearerToken::slot_id` | The print slot. The mint keys its records by slot |
| `BearerToken::mint_binding` | `MintBinding { mint, pay_token }`: which contract issued the note and which asset it escrows, as raw 32-byte contract ids |
| `BearerToken::ephemeral_public_key` | The composed key: the sum of every pair's partial public key |

A slot id is unique only within one mint, so the binding is what tells a
payee which deployment to ask. The binding is inside the signed range, so it
can't be changed without breaking the note's signature. Otherwise anyone
handling a note could point its payee at a contract they control. The
signature doesn't make the binding trustworthy on its own: whoever signs a
note chooses what it names. So a wallet asks only its own configured mint
about a note, and treats a note bound to any other mint as foreign.
`pay_token` also tells the payee whether the escrow can be frozen
(an issued asset with `auth_revocable` can be; native XLM cannot).

### The claim key

| Item | Purpose |
|---|---|
| `BearerToken::claim_secret` | The note's one secret. Generated at assembly, never transmitted |
| `BearerToken::claim_public_key()` | Recorded on-chain by `register_token` |
| `BearerToken::sign_claim(contract_xdr, recipient_xdr)` | The chain-redemption proof, bound to a recipient |
| `DomainSeparation::REDEEM_CLAIM` | Must byte-match the mint's `CLAIM_TAG` |

Redeeming by chain publishes the chain, and a transaction that fails on-chain
publishes it while the note is still live. So the chain cannot be the proof
of possession. The proof is a signature from the claim key, which the ledger
never sees, over a digest that names the recipient.

::: danger Never derive the claim secret from the chain
The chain is published by every redemption attempt, so a key derived from it
goes to the observer this exists to stop. Independent randomness, in the
file.
:::

## `chain_data`: the chain and its commitment

| Item | Purpose |
|---|---|
| `CHAIN_LINK_SIZE` | 290 bytes |
| `CHAIN_HEADER_SIZE` | 34 bytes (event id + `u16` link count) |
| `MAX_CHAIN_LINKS` | `u16::MAX` |
| `chain_data_len(n)` | Serialized size for `n` links |
| `serialize_chain_data(event_id, links)` | The canonical bytes |
| `chain_hash(event_id, links)` | The commitment `register_token` records |
| `serialize_token_chain_data(token)` | Same, from a whole token |
| `token_chain_hash(token)` | Same |

`chain_hash` binds a chain to its registration. At redemption the mint
re-hashes the submitted blob and refuses any mismatch, so a chain cannot be
swapped for another that sums to the same key. The layout must stay
byte-identical to the mint's `verify.rs`; a divergence makes honest
redemptions fail.

## `compose`: building the ephemeral key

An ephemeral Stellar account assembled additively, so no participant ever
holds the whole secret until every shard is combined at redemption.

| Item | Purpose |
|---|---|
| `CompositionBuilder` | Accumulates shards |
| `ComposedKeypair` | The assembled key; zeroized on drop |
| `compute_ephemeral_from_links(links)` | Derive the public key from a chain |
| `verify_chain_public_key(…)` | Does this chain produce this key? |
| `verify_chain_public_key_from_links(…)` | Same, from links alone |

Verification matters as much as construction: a note claiming an ephemeral
key its chain does not produce is a forgery.

## `spend`: owner commitments

| Item | Purpose |
|---|---|
| `owner_commitment(pubkey)` | `SHA-256(kntr_v1:spend:owner ‖ pubkey)`, the value on-chain |
| `opens_commitment(c, pubkey)` | Does this key open it? |
| `new_owner()` | Fresh owner key and its commitment |
| `spend_signable_bytes` / `spend_auth_digest` | The transfer message and the 32 bytes actually signed |
| `authorize_spend` / `verify_spend` | Produce and check a `SpendAuthorization` |
| `redeem_owner_signable_bytes` / `redeem_owner_digest` | The redeem message, with the recipient |
| `authorize_redeem` / `verify_redeem_owner` | Produce and check a `RedeemOwnerProof` |

Owner authorizations always sign `SHA-256(message)`. A Keycard signs a
32-byte hash, so this is what makes card and software signatures
interchangeable. See [spend mode](/architecture/spend-mode) for the model.

## `shard` and `redemption`

A shard is one pair's contribution to a note's key. The redemption types
serve redemption by key, which Kenter's clients do not use and nodes do not
serve; they remain because the mint has the entry points and the scheme is
tested.

| Item | Purpose |
|---|---|
| `Shard` | One pair's contribution; zeroized on drop |
| `ChainLink` | A pair's public record, signed by both nodes |
| `derive_shard(…)` | ECDH between the two nodes of a pair, salted by event id |
| `EncryptedShard` | A shard sealed to the combiner |
| `contribute_shard(…)` | One pair's shard, checked and sealed to a combiner |
| `RedemptionRequest` | A holder's request |
| `RedemptionSession` | State across a multi-pair redemption |
| `holder_signable_bytes(…)` | Exactly what the holder signs |
| `verify_holder_signature(…)` | Check it |
| `SHARD_REQUEST_MAX_AGE_SECS` | 300, the replay window |
| `SHARD_REQUEST_MAX_FUTURE_SECS` | 60, the clock skew tolerance |

The two time bounds are anti-replay. A request outside them is refused even
if correctly signed. The holder signs the combiner's key, so a relay cannot
substitute its own key to collect the shards.

## `keypair`

| Item | Purpose |
|---|---|
| `StellarKeypair` | Ed25519 keypair with Stellar address encoding and X25519 conversion |
| `VerifyOnlyKey` | A public key with no secret, for verifying without the ability to sign |

`VerifyOnlyKey` exists so verification paths cannot accidentally be given
signing power.

## `encrypt` and `ecdh`

| Item | Purpose |
|---|---|
| `SharedSecret` | A NaCl-box ECDH result |
| `asymmetric_encrypt` / `asymmetric_decrypt` | NaCl box to a public key |
| `hybrid_encrypt` / `hybrid_decrypt` | Box keys derived from a sender signature; decryption checks the signature |
| `encrypt_keypair` / `decrypt_keypair` | Seal a keypair for transmission |

## `domain`

`DomainSeparation` holds every tag, all `kntr_v1:*`. The crate's `API.md`
lists each tag and where it is used.

::: warning Domain separation is not decoration
Every hash in the system is domain-tagged so a value computed for one
purpose cannot be presented as another. If you add a hash, tag it.
:::

## `caveats` and `kntr_file`

A separate format for wrapping arbitrary files, distinct from `SYMTOKEN`.
Nothing in the money path uses it.

| Item | Value / purpose |
|---|---|
| `MAGIC` | `b"KNTRTOKN"` |
| `VERSION_MAJOR` / `VERSION_MINOR` | 1 / 0 |
| `MAX_FILE_SIZE` | 100 MiB |
| `WARN_FILE_SIZE` | 50 MiB |
| `CHUNK_SIZE` | 2 MiB streaming chunk |
| `KntrHeader` | The JSON header: version, timestamp, filename, size, SHA-256, type |
| `write_header` / `read_header` | Streaming I/O over `Write` / `Read` |
| `is_kntr_format(data)` | Magic check |
| `Caveat`, `CaveatVerifier` | Size, type and hash restrictions checked against a file |

`read_header` refuses a JSON header larger than 1 MiB before allocating it.
The file-size constants are exported for callers to enforce.

## Testing

| Test | Covers |
|---|---|
| `tests/bearer_token.rs` | Chain construction, container round trip, tamper detection |
| `tests/spend_vectors.rs` | Golden vectors for spend-mode signing |
| `tests/cross_language.rs` | Keys, ECDH, tags, `KNTRTOKN` header and encryption against fixed vectors from an independent implementation |

`cross_language.rs` is the one that catches format drift. If it fails, a
change has broken compatibility with the published vectors, which is a
format break, not a test problem.
