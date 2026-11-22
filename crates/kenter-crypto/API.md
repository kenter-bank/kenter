# kenter-crypto: API

The public Rust surface, grouped by module. Every fallible function returns
`error::Result<T>` (= `Result<T, CryptoError>`). Values that hold secret key
material are zeroized on drop. The crate performs no I/O beyond the
`Read`/`Write` passed to `kntr_file`, depends on no other Kenter crate, and
builds for `wasm32`.

## keypair

One Ed25519 identity, usable as a Stellar account and as an X25519 key.

- `struct StellarKeypair` (wraps an Ed25519 `SigningKey`; `Clone`; zeroized on drop).
  - `random() -> Self` · `from_stellar_secret(&str) -> Result<Self>` ·
    `from_raw_secret(&[u8;32]) -> Self` ·
    `from_stellar_address(&str) -> Result<VerifyOnlyKey>` (assoc).
  - `stellar_address() -> String` · `stellar_secret() -> Zeroizing<String>` ·
    `raw_secret() -> Zeroizing<[u8;32]>` · `raw_public() -> [u8;32]` ·
    `verifying_key() -> VerifyingKey`.
  - `sign(&[u8]) -> Signature` ·
    `verify(&VerifyingKey, &[u8], &Signature) -> Result<()>` (assoc).
  - `to_x25519_secret() -> Zeroizing<StaticSecret>` · `to_x25519_public() -> X25519Public` ·
    `x25519_public_from_ed25519(&VerifyingKey) -> Result<X25519Public>` (assoc) ·
    `x25519_public_b64url() -> String`.
- `struct VerifyOnlyKey`: a public key with no secret.
  `verify(&[u8], &Signature) -> Result<()>`. Verification paths take this
  type so they cannot be handed signing power.

## shard

ECDH shard derivation and the authenticated chain link.

- `fn derive_shard(own: &StellarKeypair, partner: &VerifyingKey, event_id: &[u8;32]) -> Result<Shard>`.
- `fn derive_shard_from_x25519(own: &StaticSecret, partner: &X25519Public, event_id: &[u8;32]) -> Result<Shard>`.
  Raw X25519 Diffie-Hellman; the scalar is
  `SHA-512(kntr_v1:shard:derive || dh || event_id)` reduced mod L. Both nodes of a
  pair derive the same shard; the commitment is `SHA-256(scalar)`.
- `struct Shard` (scalar zeroized on drop): `scalar() -> &Scalar` ·
  `partial_public() -> &EdwardsPoint` · `partial_public_bytes() -> [u8;32]` ·
  `commitment() -> &[u8;32]` · `verify_commitment() -> bool` ·
  `verify_partial_public() -> bool` · `from_raw(Scalar, EdwardsPoint) -> Self`.
- `struct PairInfo { node_a_address: String, node_b_address: String, partial_public_key: [u8;32], shard_commitment: [u8;32] }`:
  `from_shard(&Shard, String, String) -> Self` ·
  `decompress_partial_public() -> Result<EdwardsPoint>`. `impl From<&ChainLink> for PairInfo`.
- `struct ChainLink { node_a_public, node_b_public, partial_public_key, shard_commitment, prev_link_hash: [u8;32], link_index: u16, signature_a, signature_b: [u8;64] }`:
  `create(&StellarKeypair, &StellarKeypair, &Shard, prev_link_hash: [u8;32], link_index: u16, event_id: &[u8;32]) -> Self` ·
  `signable_bytes(&[u8;32]) -> Vec<u8>` · `link_hash(&[u8;32]) -> [u8;32]` ·
  `verify_signatures(&[u8;32]) -> Result<()>` ·
  `decompress_partial_public() -> Result<EdwardsPoint>` ·
  `node_a_address() / node_b_address() -> String`.
  Both nodes sign `signable_bytes`, which is tagged `kntr_v1:chain:link` and
  includes the event id and the previous link's hash, so links cannot be
  reordered or moved between notes.

## compose

Additive key composition. The note's ephemeral key is the sum of every
pair's partial public key; its secret exists only when all shards are added
together at redemption.

- `struct CompositionBuilder` (`Default`): `new()` ·
  `add_shard(Shard, PairInfo) -> &mut Self` · `count() -> usize` ·
  `running_public_bytes() -> [u8;32]` · `pairs() -> &[PairInfo]` ·
  `verify_consistency() -> Result<()>` ·
  `build(self) -> Result<(ComposedKeypair, Vec<PairInfo>)>`.
- `struct ComposedKeypair` (secret zeroized on drop): `sign(&[u8]) -> Signature` ·
  `verifying_key() -> VerifyingKey` · `public_bytes() -> [u8;32]` ·
  `stellar_address() -> String` ·
  `verify_signature(&[u8;32], &[u8], &Signature) -> Result<()>` (assoc, strict verification).
- `fn verify_chain_public_key(&[PairInfo], expected: &[u8;32]) -> Result<()>`.
- `fn compute_ephemeral_from_links(&[ChainLink]) -> Result<[u8;32]>`.
- `fn verify_chain_public_key_from_links(&[ChainLink], expected: &[u8;32]) -> Result<()>`.

A note whose chain does not sum to its ephemeral key is a forgery; the
`verify_*` functions are the check.

## token

The note model and its assembly.

- `enum TokenType { Bearer = 0x01, Data = 0x02, Partial = 0x03 }`: `from_u8(u8) -> Result<Self>`.
- `struct TokenHeader { version: u16, token_type: TokenType, event_id: [u8;32], print_timestamp: i64, denomination: Option<u64> }`.
  `denomination` is in stroops.
- `struct ChainSection { links: Vec<ChainLink>, total_pairs: u16, required_pairs: u16 }`.
  Redemption is n-of-n: `required_pairs` always equals `total_pairs`.
- `struct InitiationProof { initiator_public_key: [u8;32], vrf_proof: Vec<u8> }`.
  `vrf_proof` is opaque bytes carried through; nothing in this crate generates
  or checks it. Node selection is done on-chain by the mint's drand-seeded
  draw instead.
- `enum TokenCaveat { Expiration(i64), MaxRedemptions(u32), Custom(String, String) }`:
  `type_byte() -> u8` (`0x01`, `0x02`, `0x03`).
- `struct MintBinding { mint: [u8;32], pay_token: [u8;32] }`: the issuing mint
  contract and the asset it escrows (its SAC contract id), both as raw 32-byte
  contract ids. Slot ids are only unique within one mint, so a payee needs
  the binding to know which deployment to ask. It also tells the payee
  whether the escrow can be frozen: an issued asset with `auth_revocable` can
  be, native XLM cannot. Encoding to and from `C…` strkeys is left to callers
  so this crate stays strkey-free.
- `struct BearerToken { header, mint_binding: Option<MintBinding>, slot_id: u32, ephemeral_public_key: [u8;32], claim_secret: [u8;32], chain: ChainSection, initiation_proof, caveats: Vec<TokenCaveat>, signature: [u8;64] }`.
  - `slot_id` is the print slot the note was registered under; the mint keys
    its records by slot.
  - `mint_binding` is `None` only for a note assembled without a mint (the
    offline `print` path).
  - `claim_secret` is the secret half of the note's claim key, generated from
    independent randomness at assembly. The public half is recorded on-chain
    at `register_token`. It must never be derived from the chain, which every
    redemption attempt publishes.
  - `signature` is `[0;64]` until `container::serialize_bearer_token` signs
    the bytes; deserializing fills it in.
  - Methods: `ephemeral_address() -> String` ·
    `claim_public_key() -> [u8;32]` ·
    `sign_claim(contract_xdr: &[u8], recipient_xdr: &[u8]) -> [u8;64]` ·
    `verify_chain() -> Result<()>` (key sum only) ·
    `verify_chain_integrity() -> Result<()>` (link signatures, hash chain,
    sequential indices, key sum).
  - `sign_claim` signs `SHA-256(kntr_v1:redeem:claim || contract_xdr || slot_id (u32 BE) || ephemeral_public_key || recipient_xdr)`
    with the claim key. This is the chain-redemption proof; the mint checks it
    against the claim public key it recorded, and the recipient in the digest
    stops anyone from redirecting the payout.
- `struct PartialToken { header, running_public_key: [u8;32], chain, initiation_proof, remaining_pairs: u16 }`.
  A note mid-print. It carries no claim secret, because it passes through
  every node.
  - `initiate(event_id: [u8;32], print_timestamp: i64, denomination: Option<u64>, total_pairs: u16, initiator: &StellarKeypair, partner: &StellarKeypair, vrf_proof: Vec<u8>) -> Result<(Self, Shard)>`.
  - `extend(&mut self, new_node: &StellarKeypair, partner: &StellarKeypair) -> Result<Shard>`.
  - `verify_chain_integrity() -> Result<()>`.
- `fn assemble_bearer_token(partial: &PartialToken, requestor: &StellarKeypair, partner: &StellarKeypair, slot_id: u32, expiration: Option<i64>) -> Result<BearerToken>`.
  Adds the final link (requires `remaining_pairs == 1`), computes the
  ephemeral key from public data only, adds `MaxRedemptions(1)` (and
  `Expiration` if given), and generates the claim secret. It leaves
  `mint_binding` as `None`; the caller that knows the deployment sets it.

## container

The `SYMTOKEN` binary format of a finished note. Little-endian throughout.

- `const SYMTOKEN_MAGIC: &[u8;8]` = `b"SYMTOKEN"` · `const SYMTOKEN_VERSION: u16` = `6`.
  A file with any other version is refused.
- `fn is_symtoken(&[u8]) -> bool`.
- `fn serialize_bearer_token(&BearerToken, signer: &StellarKeypair) -> Result<Vec<u8>>`.
- `fn deserialize_bearer_token(&[u8]) -> Result<BearerToken>`.
- `fn verify_bearer_signature(&[u8], signer_public_key: &[u8;32]) -> Result<()>`.
- `fn serialize_partial_token(&PartialToken) -> Result<Vec<u8>>` ·
  `fn deserialize_partial_token(&[u8]) -> Result<PartialToken>` (unsigned).

Bearer layout, in order:

```text
magic "SYMTOKEN"            8
version (u16)               2
token_type (u8)             1
flags (u8, reserved 0)      1
event_id                   32
print_timestamp (i64)       8
denomination flag (u8)      1   [+ 8: u64 if flag = 0x01]
slot_id (u32)               4
mint binding flag (u8)      1   [+ 32 mint + 32 pay_token if flag = 0x01]
ephemeral_public_key       32
claim_secret               32
total_pairs (u16)           2
required_pairs (u16)        2
links                     n × 290 (ChainLink, layout as in chain_data)
initiator_public_key       32
vrf_len (u16)               2   + vrf_proof
num_caveats (u16)           2   + caveats: type (u8), len (u16), data
signature                  64   Ed25519 by the requestor over every byte before it
```

## chain_data

The canonical chain blob and its `chain_hash` commitment. The mint parses
exactly these bytes when a note is redeemed by chain, so this layout must
stay byte-identical to `contracts/kenter-mint/src/verify.rs`.

- `const CHAIN_LINK_SIZE: usize` = `290` · `const CHAIN_HEADER_SIZE: usize` = `34` ·
  `const MAX_CHAIN_LINKS: usize` = `u16::MAX`.
- `fn chain_data_len(num_links: usize) -> usize` (= `34 + n·290`).
- `fn serialize_chain_data(event_id: &[u8;32], links: &[ChainLink]) -> Result<Vec<u8>>`.
  Rejects an empty chain, more than `MAX_CHAIN_LINKS`, and any `link_index`
  that is not its position (the mint enforces `link_index == i`).
- `fn chain_hash(&[u8;32], &[ChainLink]) -> Result<[u8;32]>` (= `SHA-256(serialize_chain_data(..))`).
- `fn serialize_token_chain_data(&BearerToken) -> Result<Vec<u8>>` ·
  `fn token_chain_hash(&BearerToken) -> Result<[u8;32]>` (the value passed to
  `register_token`).

```text
event_id            32
link_count (u16 LE)  2
per link (290):
  node_a_public 32 · node_b_public 32 · partial_public_key 32
  shard_commitment 32 · prev_link_hash 32 · link_index (u16 LE) 2
  signature_a 64 · signature_b 64
```

## spend

Spend-mode primitives (see [spend mode](../../docs/architecture/spend-mode.md)).
A spend-mode note's on-chain record holds a 32-byte commitment to its current
owner's Ed25519 key. A transfer opens that commitment, is signed by the
current owner, and replaces it with the next owner's commitment, so the payer's
retained copy cannot move or redeem the note any more.

Owner authorizations sign `M = SHA-256(message)`, never the message itself.
A Keycard signs a 32-byte hash, so hashing first makes card and software
signatures interchangeable. The `*_signable_bytes` helpers build the
preimage; the `*_digest` helpers return the 32 bytes handed to the signer.
The mint verifies over the same digest. The layouts are pinned by
`tests/vectors/spend_vectors.json`.

- `fn owner_commitment(owner_pubkey: &[u8;32]) -> [u8;32]` = `SHA-256(kntr_v1:spend:owner || owner_pubkey)`.
- `fn opens_commitment(commitment: &[u8;32], owner_pubkey: &[u8;32]) -> bool`.
- `fn new_owner() -> (StellarKeypair, [u8;32])`: a fresh owner key and its
  commitment. The key must be kept: a note cannot be reissued.
- Transfer:
  - `fn spend_signable_bytes(contract_xdr: &[u8], slot_id: u32, ephemeral_key: &[u8;32], current_owner_commitment: &[u8;32], new_owner_commitment: &[u8;32], spend_nonce: u32) -> Vec<u8>`
    = `kntr_v1:spend:auth || contract_xdr || slot_id (u32 BE) || ephemeral_key || current || new || spend_nonce (u32 BE)`.
  - `fn spend_auth_digest(..same args..) -> [u8;32]`.
  - `struct SpendAuthorization { current_owner_pubkey: [u8;32], new_owner_commitment: [u8;32], signature: [u8;64] }`.
  - `fn authorize_spend(current_owner: &StellarKeypair, contract_xdr, slot_id, ephemeral_key, current_owner_commitment, new_owner_commitment, spend_nonce) -> SpendAuthorization`.
  - `fn verify_spend(contract_xdr, slot_id, ephemeral_key, current_owner_commitment, spend_nonce, &SpendAuthorization) -> Result<()>`.
    Mirrors the mint's `spend` check.
- Redeem:
  - `fn redeem_owner_signable_bytes(contract_xdr: &[u8], slot_id: u32, ephemeral_key: &[u8;32], owner_commitment: &[u8;32], spend_nonce: u32, recipient_xdr: &[u8]) -> Vec<u8>`
    = `kntr_v1:spend:redeem || contract_xdr || slot_id (u32 BE) || ephemeral_key || owner_commitment || spend_nonce (u32 BE) || recipient_xdr`.
  - `fn redeem_owner_digest(..same args..) -> [u8;32]`.
  - `struct RedeemOwnerProof { owner_pubkey: [u8;32], signature: [u8;64] }`.
  - `fn authorize_redeem(current_owner: &StellarKeypair, ..same args..) -> RedeemOwnerProof`.
  - `fn verify_redeem_owner(..same args.., &RedeemOwnerProof) -> Result<()>`.

Why each field is bound: both commitments stop a signature being replayed
against a different state or redirected to another successor; `spend_nonce`
makes one authorization good for exactly one transfer even when a note
returns to an owner it had before; `contract_xdr` keeps a signature from
crossing deployments; `slot_id` is the record's key; `recipient_xdr` makes a
redeem signature mean "pay to this address". `contract_xdr` and
`recipient_xdr` are the XDR of the Soroban `Address` values; this crate takes
them as raw bytes and knows nothing about XDR.

## redemption

Encrypted shard transport and combination at redemption.

- `const SHARD_REQUEST_MAX_AGE_SECS: i64` = `300` ·
  `const SHARD_REQUEST_MAX_FUTURE_SECS: i64` = `60`. A shard request outside
  this window is refused even when correctly signed.
- `struct RedemptionRequest { token: BearerToken, token_hash: [u8;32], holder_address: String, holder_signature: [u8;64], combiner_public_key: [u8;32], nonce: [u8;32], timestamp: i64 }`:
  `new(token, token_hash, holder: &StellarKeypair, combiner_public_key: [u8;32], timestamp: i64) -> Self` ·
  `verify_holder_signature() -> Result<()>`.
- `fn holder_signable_bytes(token_hash: &[u8;32], holder_address: &str, combiner_public_key: &[u8;32], nonce: &[u8;32], timestamp: i64) -> Vec<u8>`
  = `kntr_v1:redemption:request || token_hash || holder_address (UTF-8) || combiner_public_key || nonce || timestamp (i64 LE)`.
  Binding the combiner key means a relay cannot substitute its own key to
  receive the shards.
- `fn verify_holder_signature(token_hash, holder_address, combiner_public_key, nonce, timestamp, signature: &[u8;64]) -> Result<()>`.
  Pair nodes call this before serving a shard.
- `struct EncryptedShard { link_index: u16, contributor_address: String, encrypted_scalar: Vec<u8>, commitment: [u8;32], contributor_signature: [u8;64] }`.
  The scalar is sealed to the combiner with `asymmetric_encrypt`; the
  contributor signs `kntr_v1:shard:transport || link_index (u16 LE) || contributor_address || encrypted_scalar || commitment`.
- `fn contribute_shard(own: &StellarKeypair, partner: &VerifyingKey, link: &ChainLink, combiner_public: &[u8;32], event_id: &[u8;32], request_timestamp: i64, current_time: i64) -> Result<EncryptedShard>`.
- `struct RedemptionSession`: `new(RedemptionRequest, combiner: StellarKeypair) -> Result<Self>`
  (verifies chain integrity and the holder signature) ·
  `receive_shard(&EncryptedShard, contributor: &VerifyingKey) -> Result<()>` ·
  `is_complete() -> bool` · `received_count() / total_count() -> usize` ·
  `compose_and_sign(self, message: &[u8]) -> Result<(Signature, [u8;32])>`.
  `compose_and_sign` consumes the session, checks the composed key equals the
  note's ephemeral key, signs, and drops the secret.

## ecdh

NaCl-box shared secrets (used for encryption, not for shards).

- `struct SharedSecret` (zeroized on drop):
  `derive(own: &StellarKeypair, peer: &StellarKeypair) -> Self` ·
  `derive_from_x25519(&StaticSecret, &X25519Public) -> Self` ·
  `derive_from_b64url(own: &StellarKeypair, peer_x25519_b64url: &str) -> Result<Self>` ·
  `raw_bytes() -> &[u8;32]` · `derive_key(salt: &[u8]) -> Zeroizing<[u8;32]>` (`SHA-256(salt || raw)`) ·
  `derive_signing_key(domain: &[u8]) -> String` (hex of `SHA-256(domain || raw)`) ·
  `derive_token_signing_key() -> String` (domain `kntr_v1:token:sign`).

## encrypt

NaCl-box (XSalsa20-Poly1305) encryption between two Stellar keys. Output is
ASCII with `|` separators.

- `fn asymmetric_encrypt(sender: &StellarKeypair, receiver: &X25519Public, plaintext: &[u8]) -> Result<Vec<u8>>` ·
  `fn asymmetric_decrypt(receiver: &StellarKeypair, sender: &X25519Public, data: &[u8]) -> Result<Vec<u8>>`.
  Format `base64url(salt) | base64url(nonce) | hex(ciphertext)`; the salt is
  carried but not used in the key.
- `fn hybrid_encrypt(sender, receiver: &X25519Public, plaintext) -> Result<Vec<u8>>` ·
  `fn hybrid_decrypt(receiver, sender: &X25519Public, sender_ed25519_address: &str, data) -> Result<Vec<u8>>`.
  Format `base64url(salt) | base64url(nonce) | base64url(signature) | hex(ciphertext)`.
  The sender signs `salt || nonce`; the box keys are derived from
  `SHA-256(salt || shared)` and the two signature halves. Decryption verifies
  the sender's signature first.
- `fn encrypt_keypair(sender, receiver: &X25519Public, shared: &StellarKeypair) -> Result<Vec<u8>>` ·
  `fn decrypt_keypair(receiver, sender: &X25519Public, data) -> Result<StellarKeypair>`.
  The raw secret, hex-encoded, under `asymmetric_encrypt`.

A malformed nonce is an error, not a panic: these functions are reached with
bytes a remote node chose.

## caveats and kntr_file (data files)

A separate surface for wrapping arbitrary files; not used by notes.

- `caveats`: `enum Caveat { MaxFileSize(u64), FileType(String), FileHash(String), Custom(String, String) }` ·
  `struct CaveatVerifier`: `new(Vec<Caveat>)` ·
  `verify_all(file_bytes: &[u8], filename: Option<&str>) -> Result<()>`
  (the hash comparison is constant-time).
- `kntr_file`: `const MAGIC: &[u8;8]` = `b"KNTRTOKN"` · `VERSION_MAJOR: u16` = `1` ·
  `VERSION_MINOR: u16` = `0` · `MAX_FILE_SIZE: u64` = 100 MiB ·
  `WARN_FILE_SIZE: u64` = 50 MiB · `CHUNK_SIZE: usize` = 2 MiB.
  - `struct KntrHeader { version: String, created_at: String, original_filename: String, file_size: u64, file_hash: String, token_type: String }`.
  - `fn write_header<W: Write>(&mut W, &KntrHeader) -> Result<()>` ·
    `fn read_header<R: Read>(&mut R) -> Result<KntrHeader>` ·
    `fn is_kntr_format(&[u8]) -> bool`.
  - Header layout: magic (8) · version major (u16 LE) · version minor (u16 LE) ·
    flags (u16 LE, 0) · JSON length (u32 LE) · compact JSON of `KntrHeader`.
    `read_header` refuses a JSON header over 1 MiB. The size constants are
    exported for callers; `read_header` does not enforce them.

## domain

`struct DomainSeparation` holds every hash and signature tag as an associated
`&[u8]` constant. All are `kntr_v1:*`.

| Constant | Value | Used by |
|---|---|---|
| `VERSION` | `kntr_v1` | |
| `TOKEN_SIGNING` | `kntr_v1:token:sign` | `SharedSecret::derive_token_signing_key` |
| `TOKEN_SECRET` | `kntr_v1:token:secret` | reserved |
| `HYBRID_ENCRYPT` | `kntr_v1:hybrid:encrypt` | reserved |
| `ASYMMETRIC_ENCRYPT` | `kntr_v1:asymmetric:encrypt` | reserved |
| `DATA_FILE` | `kntr_v1:data:file` | reserved |
| `JWT_SIGNING` | `kntr_v1:jwt:sign` | reserved |
| `BEARER_TOKEN` | `kntr_v1:bearer:token` | reserved |
| `SHARD_DERIVE` | `kntr_v1:shard:derive` | `derive_shard_from_x25519` |
| `TOKEN_COMPOSE` | `kntr_v1:token:compose` | reserved |
| `CHAIN_LINK` | `kntr_v1:chain:link` | `ChainLink` signatures and hash |
| `REDEMPTION_REQUEST` | `kntr_v1:redemption:request` | `holder_signable_bytes` |
| `REDEEM_CLAIM` | `kntr_v1:redeem:claim` | `BearerToken::sign_claim`; the mint's `CLAIM_TAG` |
| `SHARD_TRANSPORT` | `kntr_v1:shard:transport` | `EncryptedShard` signature |
| `SPEND_OWNER_COMMIT` | `kntr_v1:spend:owner` | `owner_commitment` |
| `SPEND_AUTH` | `kntr_v1:spend:auth` | `spend_signable_bytes` |
| `SPEND_REDEEM` | `kntr_v1:spend:redeem` | `redeem_owner_signable_bytes` |

"Reserved" tags are defined and pinned by the test vectors but not applied by
any code path; in particular `encrypt` does not use the `*_ENCRYPT` tags. The
ephemeral-key redemption tag `kntr_v1:redeem:key` lives in the mint contract,
not here: that signature is produced by `RedemptionSession::compose_and_sign`
over a message the caller builds.

## error

- `enum CryptoError` (`thiserror`): `InvalidStellarSecret(String)`,
  `InvalidStellarAddress(String)`, `InvalidKeyLength { expected, got }`,
  `EcdhFailed(String)`, `EncryptionFailed(String)`, `DecryptionFailed(String)`,
  `SignatureVerificationFailed`, `InvalidTokenFormat(String)`, `HashMismatch`,
  `CaveatFailed(String)`, `TokenExpired`, `InvalidKntrFile(String)`,
  `FileTooLarge { size, max }`, `Base64Error(String)`,
  `ShardDerivationFailed(String)`, `CompositionFailed(String)`,
  `InvalidToken(String)`, `ChainVerificationFailed(String)`,
  `ShardCommitmentMismatch`, `OwnerCommitmentMismatch`,
  `ChainLinkSignatureInvalid { index: u16 }`, `ChainLinkHashMismatch { index: u16 }`,
  `RedemptionFailed(String)`, `RedemptionIncomplete { received, total }`,
  `DuplicateShard { index: u16 }`, `IoError(std::io::Error)`.
  `ShardDerivationFailed`, `TokenExpired` and `FileTooLarge` are defined but
  not raised by current code.
- `type Result<T> = std::result::Result<T, CryptoError>`.

## Tests and vectors

- `tests/bearer_token.rs`: multi-pair chain construction and redemption, container round trip and integrity, chain-link tampering.
- `tests/spend_vectors.rs`: spend and redeem byte layouts against
  `tests/vectors/spend_vectors.json`, which external signers (card applet,
  firmware) must reproduce.
- `tests/cross_language.rs`: keypair, X25519, ECDH, domain tags, the
  `KNTRTOKN` header and both encryption formats against the fixed vectors in
  `tests/vectors/test_vectors.json`, produced by an independent
  implementation. A failure there is a format break.

## Limits

- No threshold redemption: every pair must contribute (n-of-n).
- `InitiationProof.vrf_proof` is carried, never produced or verified.
