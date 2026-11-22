# Bearer token format

## Overview

A Kenter bearer token (a note) is a self-contained cryptographic instrument
produced by a chain of node pairs. No single node, and no single pair, ever
holds the complete secret. The depositor holds the first and last pairs and
assembles the finished note on its own machine.

The note proves ownership of an ephemeral Stellar address whose secret is the
sum of ECDH-derived shards, one per pair. It also carries a random claim key,
generated at assembly, that every pure-bearer redemption must sign with.

The code is `kenter-crypto`: `shard.rs`, `token.rs`, `container.rs`,
`chain_data.rs`, `redemption.rs` and `spend.rs`. How the pairs are chosen is
in [Node selection](/architecture/node-selection); how a note is held and
redeemed is in [Tokens and their lifecycle](/architecture/tokens).

---

## Lifecycle

```
          PRINTING                              TRANSFER            REDEMPTION
          ────────                              ────────            ──────────
 request_print         walk the chain            note moves          Path B: present
 (depositor names  ──► link 0: depositor     ──► off-ledger     ──►  chain + claim
  its end pairs;       link 1..k: selected       as a file:          signature;
  drand seeds the      pairs, each adds a        QR, paper,          contract checks
  draw; pairs claim)   dual-signed link          message, card       the commitment
                       link k+1: depositor
                       closes it locally         (spend mode:        Path A: pairs
                                                  one `spend`        re-derive shards
                       assemble note, generate    transaction per    for a combiner
                       claim key, register        transfer)
                       chain_hash + claim key
```

---

## Token types

| Type | Byte | Purpose |
|---|---|---|
| `Bearer` | `0x01` | Complete note, ready for transfer and redemption |
| `Data` | `0x02` | File wrapper (reserved) |
| `Partial` | `0x03` | In-flight token during chain construction |

---

## Cryptographic primitives

### ECDH shard derivation

Each pair of nodes contributes a **shard**: an Ed25519 scalar derived from
their shared ECDH secret.

```
1. Convert both nodes' Ed25519 keys to X25519
2. raw_dh  = X25519_DH(node_a_secret, node_b_public)      raw DH, no HSalsa20
3. hash_64 = SHA-512(SHARD_DERIVE ‖ raw_dh ‖ event_id)     64 bytes, salted
4. scalar  = hash_64 mod L                                 valid Ed25519 scalar
5. P_i     = scalar · G                                    partial public key
6. C_i     = SHA-256(scalar_bytes)                         shard commitment
```

This uses the *raw* X25519 output, not the NaCl Box shared key (which applies
HSalsa20). The raw output is hashed through SHA-512 and reduced mod L to give
an unbiased Ed25519 scalar. `SHARD_DERIVE` is `kntr_v1:shard:derive`.

**Per-note salt.** The `event_id` from the note header is part of the hash
input, so the same pair produces a different shard for every note. Without
it, compromising one note's shard for a pair would reveal that pair's shard
for every note. The event id is public; the security comes from the DH, not
the salt.

Both nodes of a pair derive the same shard independently, since ECDH is
symmetric. **The unit of trust is the pair, not the node**: either member can
compute the pair's shard.

### Additive key composition

```
Secret:  s = shard_1 + shard_2 + … + shard_n   (mod L)
Public:  P = P_1     + P_2     + … + P_n       (Edwards point addition)
```

`(s, P)` is a valid Ed25519 keypair. To Stellar, `P` is an ordinary account
public key. The composition is **n-of-n**: every shard is needed.

### Signing with the composed key

The composed keypair signs with `ed25519_dalek::hazmat::ExpandedSecretKey`:

```
scalar      = composed sum of shard scalars
hash_prefix = SHA-512(scalar_bytes)[32..64]    deterministic nonce key
```

This produces standard Ed25519 signatures that any implementation verifies.

---

## Chain links

Each pair's contribution is wrapped in a **ChainLink**: a dual-signed,
hash-chained record that makes the chain tamper-evident.

### Structure

```
ChainLink
├── node_a_public: [u8; 32]       Raw Ed25519 public key of node A
├── node_b_public: [u8; 32]       Raw Ed25519 public key of node B
├── partial_public_key: [u8; 32]  P_i = shard_i · G
├── shard_commitment: [u8; 32]    SHA-256(shard_i scalar bytes)
├── prev_link_hash: [u8; 32]      Hash of the previous link (zeros for link 0)
├── link_index: u16               Zero-based position in the chain
├── signature_a: [u8; 64]         Ed25519 by node A
└── signature_b: [u8; 64]         Ed25519 by node B
```

### Signed payload

Both nodes sign identical bytes:

```
"kntr_v1:chain:link" ‖ node_a_pub(32) ‖ node_b_pub(32) ‖
partial_public_key(32) ‖ shard_commitment(32) ‖ prev_link_hash(32) ‖
link_index(2 LE) ‖ event_id(32)
```

The `event_id` is signed but not stored in the link. That stops a valid link
from one note being spliced into another.

### Hash chain

```
link_hash = SHA-256(signable_bytes ‖ signature_a ‖ signature_b)
```

This becomes the next link's `prev_link_hash`.

### Properties

- **Tamper detection.** Changing any field invalidates both signatures.
- **Ordering.** The hash chain prevents reordering or removing links.
- **Cross-note protection.** The event id in the signed payload prevents
  splicing.
- **Attribution.** Both nodes of the pair signed the contribution.

The mint records each link's partial key at `confirm_link` but does not check
that it derives from the confirming node's keys. Shard independence is a
property of honest nodes, not something the contract enforces; what protects
a note is the depositor's own closing link (see [Security
model](/architecture/security-model)).

---

## Building the chain

### Step 1: initiation (depositor)

The depositor holds both keys of pair 0 and opens the chain:

```
initiator + partner  →  ECDH  →  shard_0,  P_0,  C_0

ChainLink_0:  prev_link_hash = [0; 32], link_index = 0,
              signed by initiator and partner

PartialToken:
  header (version, event_id, timestamp, denomination)
  running_public_key = P_0
  chain: [ChainLink_0]
  initiation_proof (initiator public key, empty vrf_proof)
  remaining_pairs = total_pairs − 1
```

The depositor confirms link 0 on chain.

### Step 2: extension (each selected interior pair)

The depositor sends the partial token to the pair selected for the next
position, through the relay. The node checks the request against the slot
(event id, exactly the confirmed links, each signed by its assigned pair,
this pair next), then:

```
node_i + partner_i  →  ECDH  →  shard_i,  P_i,  C_i

ChainLink_i:  prev_link_hash = link_hash(ChainLink_{i−1}), link_index = i,
              signed by node_i and partner_i

running_public_key += P_i
chain.push(ChainLink_i)
remaining_pairs −= 1
```

The node confirms its link on chain and returns the extended token. The
depositor checks that the header and every earlier link are unchanged and
that exactly one correctly signed link has been added before sending it on.

### Step 3: assembly (depositor)

When `remaining_pairs == 1`:

```
1. Verify the chain (dual signatures, hash chain)
2. Derive the final shard with its own partner key (ECDH)
3. Create the final ChainLink, chained to the previous one
4. Compute P from public data only: P = P_0 + P_1 + … + P_n
5. Generate the claim secret: 32 bytes of independent randomness
6. Assemble the BearerToken with its slot id and mint binding
7. Sign the container with the requestor's Ed25519 key
8. Confirm the last link, then register_token with:
     ephemeral_key = P
     chain_hash    = SHA-256(chain_data)
     claim_pubkey  = public half of the claim secret
     mode, initial_owner_commitment
```

The depositor never reconstructs the full secret `s`, only the public `P`.
The final link never leaves the depositor's machine, so no set of network
nodes holds every link or every shard.

---

## Redemption

Both paths pay the escrow, less interior node fees, to a recipient the holder
names. Both require a proof of possession bound to that recipient:

- **Pure bearer:** a signature from the claim key over
  `SHA-256("kntr_v1:redeem:claim" ‖ contract_xdr ‖ slot_id (u32 BE) ‖ P ‖ recipient_xdr)`.
- **Spend mode:** a signature from the current owner key, described in
  [Bearer and spend mode](/architecture/spend-mode#what-the-owner-signs).

### Path B: by chain (used by the client)

The holder submits the canonical chain data:

```
chain_data = event_id (32) ‖ link_count (2, LE) ‖ links (link_count × 290)
```

The mint requires `SHA-256(chain_data) == chain_hash` from registration,
verifies the claim signature (or owner proof), then verifies every link's
signatures, the hash chain and the indices on chain. No node is contacted.
The chain becomes public.

The commitment is what makes this safe. The ephemeral key, event id and pair
count are all public, so without it anyone could build a self-consistent
chain from their own keys and drain the escrow. The claim signature is what
keeps a published chain from being reused: a failed redemption publishes the
chain while the note stays live, but the chain alone does not redeem.

### Path A: by key

Path A reconstructs `s` and signs with it. It is built in `kenter-crypto`
and the mint, and no client drives it.

**1. Redemption request.** The holder creates a signed `RedemptionRequest`:

```
token, token_hash, holder_address,
combiner_public_key   (bound into the signature),
nonce (32 random bytes), timestamp

signed: "kntr_v1:redemption:request" ‖ token_hash ‖ holder_address ‖
        combiner_public_key ‖ nonce ‖ timestamp
```

Binding the combiner key into the signature stops a relay substituting its
own combiner to intercept shards. Pair nodes check that the combiner key in
the shard request matches the signed one.

**2. Shard collection.** For each link, one node of the pair:

```
0. Checks freshness (at most 300 s old, at most 60 s in the future)
   and the rate limit (one response per (event_id, link_index) per 15 min)
1. Re-derives its shard by ECDH with the partner key in the link
2. Checks SHA-256(scalar) == C_i and scalar · G == P_i
3. Encrypts the scalar to the combiner's X25519 key (NaCl Box)
4. Signs the encrypted payload
```

The node needs only its persistent keypair. It stores nothing from printing.

**3. Composition.** The combiner decrypts each scalar, checks it against the
link's commitment, sums them, checks the sum's public key equals `P`, signs,
and wipes `s`. `compose_and_sign()` consumes the session, so the composed
secret exists only inside that call.

**4. On chain.** `redeem_by_key` needs two signatures:

```
signature        under P, over
                 SHA-256("kntr_v1:redeem:key" ‖ contract_xdr ‖ slot_id (u32 BE) ‖ P ‖ recipient_xdr)
claim_signature  under the claim key, over the Path B claim digest
```

The ephemeral signature proves the note was **constructed**; the claim
signature proves it is **held**. Both are required because knowing `s` is not
the same as holding the note: either member of each pair can derive its
shard, and the shard endpoint answers anyone with a well-formed request. In
spend mode (`redeem_by_key_owned`) the owner proof takes the claim
signature's place.

---

## Bearer token structure

```
BearerToken
├── Header
│   ├── version: u16              (6)
│   ├── token_type: Bearer
│   ├── event_id: [u8; 32]        names the print
│   ├── print_timestamp: i64      Unix seconds
│   └── denomination: Option<u64> stroops of the pay token
│
├── slot_id: u32                  the mint's record key
│
├── mint_binding: Option<MintBinding>
│   ├── mint: [u8; 32]            contract id of the issuing mint
│   └── pay_token: [u8; 32]       contract id of the escrowed asset
│
├── ephemeral_public_key: [u8; 32]
│   └── P = P_0 + P_1 + … + P_n   compressed Edwards Y
│
├── claim_secret: [u8; 32]        never transmitted
│
├── Chain
│   ├── total_pairs: u16
│   ├── required_pairs: u16       == total_pairs (n-of-n)
│   └── links: Vec<ChainLink>     290 bytes each
│
├── Initiation proof
│   ├── initiator_public_key: [u8; 32]
│   └── vrf_proof: Vec<u8>        reserved; always empty
│
├── Caveats: Vec<TokenCaveat>
│   ├── Expiration(i64)           0x01
│   ├── MaxRedemptions(u32)       0x02
│   └── Custom(String, String)    0x03
│
└── Signature: [u8; 64]           requestor's Ed25519 over all preceding bytes
```

Assembly always writes `MaxRedemptions(1)` and writes `Expiration` only when
asked. Caveats are signed and carried; the mint does not read them, and the
wallet does not enforce them.

The mint binding is absent only for a note assembled without a mint (an
offline test print). A note from a real print always carries it.

---

## Binary format (SYMTOKEN container v6)

All multi-byte integers are **little-endian** unless marked BE.

### Bearer token

```
Offset  Size    Field
──────  ────    ─────
 0       8      magic                  "SYMTOKEN"
 8       2      version                u16 (6)
10       1      token_type             0x01 (Bearer)
11       1      flags                  0x00 (reserved)

── Header ──
12      32      event_id
44       8      print_timestamp        i64
52       1      has_denomination       0x00 or 0x01
53     0|8      denomination           u64, present only if has_denomination = 1

── Slot ──  (V = 53 or 61)
 V       4      slot_id                u32

── Mint binding ──
V+4      1      has_binding            0x00 or 0x01
V+5   0|64      mint (32) ‖ pay_token (32), present only if has_binding = 1

── Ephemeral key ──  (B = V+5 or V+69)
 B      32      ephemeral_public_key   compressed Edwards Y

── Claim key ──
B+32    32      claim_secret

── Chain ──
B+64     2      total_pairs            u16
B+66     2      required_pairs         u16
B+68            links, total_pairs × 290 bytes:
           32    node_a_public
           32    node_b_public
           32    partial_public_key
           32    shard_commitment
           32    prev_link_hash
            2    link_index            u16
           64    signature_a
           64    signature_b

── Initiation proof ──  (N = B+68 + 290·total_pairs)
 N      32      initiator_public_key
N+32     2      vrf_proof_len          u16 (0)
N+34     K      vrf_proof              reserved

── Caveats ──
 C       2      num_caveats            u16
                for each:
            1    caveat_type           0x01 Expiration, 0x02 MaxRedemptions, 0x03 Custom
            2    data_len              u16
            D    data                  Expiration: i64 (8)
                                       MaxRedemptions: u32 (4)
                                       Custom: u16 key_len ‖ key ‖ u16 val_len ‖ val

── Signature ──
LAST−64 64      signature              Ed25519 over bytes [0 .. LAST−64)
```

Only version 6 is read. Any other version is refused.

### Partial token

Same preamble and header as a bearer token, with `token_type = 0x03`, then:

```
 V      32      running_public_key     current sum of P_i
V+32     2      total_pairs            u16 (target)
V+34     2      links_collected        u16
V+36     2      remaining_pairs        u16
V+38            links, links_collected × 290 bytes
 N      32      initiator_public_key
N+32     2      vrf_proof_len
N+34     K      vrf_proof
```

A partial token has no slot, mint binding, claim secret, caveats or
signature. The claim secret belongs only to the finished note, which only the
depositor ever holds.

---

## Verification

### Offline (any client)

1. Parse the container; check the magic and version 6.
2. **Link integrity:** for each link, sequential `link_index`,
   `prev_link_hash` equal to the previous link's hash (zeros for link 0),
   and both signatures valid over the signed payload with the note's
   `event_id`.
3. **Key consistency:** decompress each `P_i` and check
   `P_0 + … + P_n == ephemeral_public_key`.

`BearerToken::verify_chain_integrity` does steps 2 and 3; the wallet runs it
on import, on receive (gate G1) and on restore. The container signature can
be checked with `verify_bearer_signature` against the requestor's key, which
is `node_a_public` of the final link.

### On chain

4. The mint's record under `slot_id` exists and is `Active`.
5. Its `chain_hash` equals `SHA-256` of this note's canonical chain data.
6. In spend mode, its `owner_commitment` is the expected one.

Steps 4 to 6 are reads through one RPC endpoint; see [Security
model](/architecture/security-model) for what that does and does not prove.

### Shard verification (Path A)

Each pair node re-derives its shard and checks:

- `SHA-256(scalar_bytes) == shard_commitment`
- `scalar · G == partial_public_key`

---

## Signing roles

| What is signed | By whom | Purpose |
|---|---|---|
| The container | Requestor's Ed25519 key | Says who assembled the note |
| Each ChainLink | Both nodes of the pair | Authenticates the pair's contribution |
| Pure-bearer redemption | Claim key | Proves possession, names the recipient |
| Spend-mode transfer and redemption | Current owner key | Proves ownership, names the successor or recipient |
| Path A redemption | Composed ephemeral key | Proves the note was constructed |

The composed ephemeral key exists only briefly, inside `compose_and_sign()`,
and only on Path A. It never signs the note itself.

---

## Rust API

```rust
use kenter_crypto::{
    keypair::StellarKeypair,
    token::{PartialToken, assemble_bearer_token},
    container::{serialize_bearer_token, deserialize_bearer_token, verify_bearer_signature},
    chain_data::token_chain_hash,
    redemption::{RedemptionRequest, RedemptionSession, contribute_shard},
};

// 1. Initiate the chain (depositor holds both keys of pair 0)
let (mut partial, _shard_0) = PartialToken::initiate(
    event_id, timestamp, denomination, total_pairs,
    &initiator, &partner, Vec::new(),   // vrf_proof: always empty
)?;

// 2. Extend (each selected pair, both keys present)
let shard = partial.extend(&node_a, &node_b)?;

// 3. Assemble (depositor; generates the claim key)
let mut bearer = assemble_bearer_token(
    &partial, &requestor, &requestor_partner,
    slot_id, None,                       // expiration
)?;
bearer.mint_binding = Some(binding);

// 4. Serialize and sign
let bytes = serialize_bearer_token(&bearer, &requestor)?;

// 5. What register_token needs
let chain_hash = token_chain_hash(&bearer)?;
let claim_pubkey = bearer.claim_public_key();

// 6. Parse and verify
let parsed = deserialize_bearer_token(&bytes)?;
parsed.verify_chain_integrity()?;   // signatures, hash chain, key sum
verify_bearer_signature(&bytes, &requestor.raw_public())?;

// 7. Path B claim signature for a recipient
let claim_sig = parsed.sign_claim(&contract_xdr, &recipient_xdr);

// 8. Path A: request, shards, composition
let request = RedemptionRequest::new(
    parsed, token_hash, &holder, combiner.raw_public(), now,
);
let encrypted = contribute_shard(
    &node_a, &node_b.verifying_key(),
    &chain_link, &combiner.raw_public(), &event_id,
    request_timestamp, now,
)?;
let mut session = RedemptionSession::new(request, combiner)?;
session.receive_shard(&encrypted, &node_a.verifying_key())?;
// … every shard …
let (signature, public_key) = session.compose_and_sign(&digest)?;
```

---

## Module map

```
kenter-crypto/src/
├── shard.rs        Shard, ChainLink, derive_shard()
├── compose.rs      CompositionBuilder, ComposedKeypair, compute_ephemeral_from_links()
├── token.rs        TokenType, BearerToken, PartialToken, MintBinding,
│                   assemble_bearer_token()
├── container.rs    SYMTOKEN v6 serialization, is_symtoken(), verify_bearer_signature()
├── chain_data.rs   Canonical chain data and chain_hash
├── redemption.rs   RedemptionRequest, EncryptedShard, RedemptionSession,
│                   contribute_shard()
├── spend.rs        Owner commitments and spend-mode authorizations
├── keypair.rs      StellarKeypair (Ed25519 / X25519 / Stellar)
├── ecdh.rs         SharedSecret (NaCl Box ECDH, for encryption, not shards)
├── encrypt.rs      Asymmetric and hybrid encryption
├── domain.rs       Domain separation tags
├── error.rs        CryptoError
├── kntr_file.rs    KNTRTOKN data-file wrapper (not used by notes)
└── caveats.rs      Data-file caveat checks (not used by notes)
```
