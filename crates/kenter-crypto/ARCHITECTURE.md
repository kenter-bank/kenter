# kenter-crypto — Architecture

**Role.** The pure-crypto layer of the bearer-note system. It derives the ECDH
shards, builds and verifies the dual-signed daisy chain, composes the ephemeral
Ed25519 key, serializes the SYMTOKEN container, and produces the owner
authorizations for spend-mode notes. It touches no network and no ledger: it
only produces and checks bytes. It builds for `wasm32` as well as native, so the
browser runs the same code as the desktop.

**Determinism (the load-bearing property).** Every secret is derived, never
stored. A shard is a deterministic function of a node pair's ECDH secret and the
note's `event_id`. The full ephemeral secret exists only for the duration of one
`RedemptionSession::compose_and_sign` call, which consumes the session and
zeroizes on drop. All secret-holding structs (`Shard`, `ComposedKeypair`,
`SharedSecret`, `StellarKeypair`) wrap their scalars in `Zeroizing`.

## Boundaries

- **Depends on:** `ed25519-dalek` (including `hazmat` for composed signing),
  `x25519-dalek` / `curve25519-dalek` (ECDH and Edwards point math),
  `crypto_box` / `salsa20` / `crypto_secretbox` (NaCl-compatible encryption),
  `sha2`, `hkdf`, `stellar-strkey`, `zeroize`, `subtle`, `serde`.
- **Depended on by:** the `kenter-mint` contract, which mirrors the
  `chain_data.rs` byte layout in its `verify::verify_chain` and the `spend.rs`
  message layouts in its spend checks; `kenter-client`, `kenter-wallet`,
  `kenter-node` and the desktop app, which use the token, keypair and container
  surface; `kenter-wallet-wasm`, which exposes it to the browser.
- **Modules:**

  | Module | Purpose |
  |---|---|
  | `shard` | ECDH shard derivation and the `ChainLink` record |
  | `compose` | Additive key composition and composed signing |
  | `token` | `PartialToken` / `BearerToken` lifecycle, claim key, `MintBinding` |
  | `container` | SYMTOKEN wire format (serialize, deserialize, verify signature) |
  | `chain_data` | Canonical chain blob and `chain_hash` committed on-chain |
  | `redemption` | Shard transport to a combiner and the `RedemptionSession` |
  | `spend` | Owner commitments and spend/redeem authorizations |
  | `keypair`, `ecdh`, `encrypt` | Stellar identity keys, X25519 conversion, NaCl box |
  | `domain` | The `kntr_v1:*` domain-separation tags |
  | `kntr_file`, `caveats` | The `kntr_file` data-file wrapper and its caveats |

## Model: print, assemble, redeem

1. **Initiate.** `PartialToken::initiate` derives shard 0 from the first node
   pair via ECDH, wraps it in a genesis `ChainLink` signed by both nodes, and
   seeds the running public point `P = P_0`.
2. **Extend.** Each intermediate pair calls `PartialToken::extend`. It
   re-verifies chain integrity, derives its shard, appends a hash-chained
   `ChainLink`, and adds `P_i` to the running point. No scalars are summed here.
3. **Assemble.** The requestor calls `assemble_bearer_token`. It derives the
   final shard, appends the final link, computes `ephemeral_public_key` from
   **public partial keys only** (`compute_ephemeral_from_links`), draws a fresh
   random `claim_secret`, and produces a `BearerToken`. `serialize_bearer_token`
   signs the container.
4. **Redeem by composition.** One node per pair re-derives its shard, encrypts
   the scalar to the combiner (NaCl box) and signs it (`contribute_shard`). The
   combiner's `RedemptionSession` decrypts each scalar, re-checks it against the
   link's commitment and partial key, sums them into a `ComposedKeypair`, checks
   that the composed public key equals the note's ephemeral key, signs, and drops
   the secret.
5. **Redeem by chain.** The holder presents the chain blob plus a signature from
   the note's claim key (`BearerToken::sign_claim`). The mint re-hashes the blob
   against the committed `chain_hash` and verifies the claim signature. No node
   is involved.

## Invariants

- **Additive n-of-n custody.** `s = shard_0 + … + shard_n (mod L)` and
  `P = P_0 + … + P_n` (Edwards addition). Every shard is required. There is no
  threshold and no subset reconstruction. Composition is order-independent.
  `ChainSection.required_pairs` is always equal to `total_pairs`.
- **ECDH shard derivation.** `scalar = SHA-512("kntr_v1:shard:derive" || raw_dh
  || event_id) mod L`, using **raw** X25519 DH (no HSalsa20, so it is distinct
  from the NaCl box key in `ecdh`/`encrypt`). The `event_id` salt makes shards
  unique per note: the same pair yields a different shard for every note.
- **Signature chain and hash chain.** Each `ChainLink` is signed by **both**
  nodes of its pair over `CHAIN_LINK || pubs || P_i || commitment ||
  prev_link_hash || link_index || event_id`. `link_hash = SHA-256(signable ||
  sig_a || sig_b)` becomes the next link's `prev_link_hash`. Inserting,
  reordering or changing any link breaks a signature or the hash chain.
  `event_id` is signed but not stored in the link, which blocks splicing links
  from one note into another.
- **`chain_data` canonical form.** `chain_data.rs` is the single source of truth
  for the chain blob: `event_id(32) || link_count(2 LE) || n × link(290)`, links
  in strictly sequential `link_index` order, `34 + 290·n` bytes in total. A link
  is `node_a_public(32) || node_b_public(32) || partial_public_key(32) ||
  shard_commitment(32) || prev_link_hash(32) || link_index(2 LE) ||
  signature_a(64) || signature_b(64)`. `chain_hash = SHA-256(chain_data)` is
  committed at `register_token`, and `kenter-mint` re-hashes the submitted bytes
  and rejects any mismatch. This layout must stay byte-for-byte in step with the
  contract's `verify.rs`, or legitimate chain redemptions fail.
- **Claim key.** The chain is published by every redemption attempt, including
  one that fails on-chain while the note is still live. So the chain alone
  cannot be the right to redeem. The note carries an independent random
  `claim_secret`; its public half is committed at registration and chain
  redemption requires a signature from it over `REDEEM_CLAIM || contract_xdr ||
  slot_id(BE) || ephemeral_key || recipient_xdr`. The secret is never derived
  from anything published, never travels in a `PartialToken`, and lives only in
  the finished container. The note stays bearer: copying the file copies the
  right to redeem.
- **SYMTOKEN container.** `container.rs` frames a note as magic `SYMTOKEN`,
  version `6`, type and flags bytes, then the header (`event_id`, print
  timestamp, optional denomination), `slot_id`, an optional `MintBinding`, the
  ephemeral key, the claim secret, the chain section (290-byte links), the
  initiation proof and the caveats, trailed by a 64-byte Ed25519 signature over
  all preceding bytes by the requestor key. `deserialize_bearer_token` checks
  magic, version and type. A container with a different version is rejected,
  not migrated.
- **Mint binding.** `slot_id` is unique only within one mint, so a note names its
  issuing contract and the asset it escrows (`MintBinding`, raw 32-byte contract
  ids). Both sit inside the signed range, so they cannot be rewritten to point a
  payee at another contract. A payee learns from the signed bytes alone which
  deployment to ask and what the note pays out in, including whether the asset
  has an issuer that could freeze the escrow. The crate keeps raw bytes rather
  than strkeys so it stays wasm-friendly; callers encode at the edges.
- **No identity in a note.** The container holds no account address of the
  requestor or any holder. The initiation proof carries the initiator's node
  key and an opaque `vrf_proof` field that is empty; node selection happens on
  the mint, not here.
- **Redemption binding.** A holder's `RedemptionRequest` signs the
  `combiner_public_key` into its payload (so a relay cannot substitute its own
  combiner), plus a nonce and a timestamp. `contribute_shard` enforces a
  freshness window of 60 s into the future and 300 s into the past.
- **Spend-mode authorizations.** A spend-mode record stores
  `SHA-256(SPEND_OWNER_COMMIT || owner_pubkey)` instead of the owner key. A
  transfer is authorized by the current owner signing `SPEND_AUTH ||
  contract_xdr || slot_id || ephemeral_key || current_commitment ||
  new_commitment || spend_nonce`; a redemption by signing `SPEND_REDEEM ||
  contract_xdr || slot_id || ephemeral_key || owner_commitment || spend_nonce ||
  recipient_xdr`. Owners sign `SHA-256(message)` rather than the message, because
  the keycard signs 32-byte digests; hashing first makes card and software
  signatures interchangeable. The layouts are pinned by
  `tests/vectors/spend_vectors.json`. See
  [spend mode](../../docs/architecture/spend-mode.md).
- **Domain separation.** Every derivation and signature is prefixed by a
  `kntr_v1:*` tag from `domain.rs`. Changing a tag changes every signature and
  commitment made under it. `REDEEM_CLAIM` and the `SPEND_*` tags must
  byte-match the constants in the mint contract.

## Limits and loose ends

- **Not every tag is used.** `TOKEN_SECRET`, `TOKEN_COMPOSE`, `BEARER_TOKEN`,
  `HYBRID_ENCRYPT`, `ASYMMETRIC_ENCRYPT`, `DATA_FILE` and `JWT_SIGNING` are
  defined but not applied. The `encrypt` hybrid and asymmetric paths use the raw
  NaCl box key without their `*_ENCRYPT` tags.
- **Dead code in `ecdh.rs`.** `from_nacl_box` builds a `SalsaBox` and drops it,
  then computes the shared key with the standalone `hsalsa20`. Harmless.
- **`BearerToken.signature` in memory.** `assemble_bearer_token` leaves it
  `[0; 64]`. The real container signature is produced by
  `serialize_bearer_token` and filled in by `deserialize_bearer_token`. The field
  is not authoritative before serialization.
- **Data-file surface.** `kntr_file` (magic `KNTRTOKN`, a JSON header and file
  body) and `caveats` (file size, type, hash) implement a separate file-wrapping
  token. `TokenType::Data` is reserved for it. The bearer-note flow does not use
  them. They keep their own cross-language test vectors.
- **Token caveats.** `TokenCaveat` (`Expiration`, `MaxRedemptions`, `Custom`) is
  serialized in the container. Whether a note can be redeemed is the mint's
  call, not these caveats'.

## Reference

`API.md` in this directory lists the public surface.
[`docs/bearer-token-format.md`](../../docs/bearer-token-format.md) describes the
container byte by byte.
