# kenter-network: API

Public Rust surface. Native crate (`tokio` async); not WASM. All wire
messages are JSON structs carried as tunnel HTTP request/response bodies.
Crypto types (`ChainLink`, `PartialToken`, `EncryptedShard`,
`StellarKeypair`) come from `kenter-crypto`. The crate is chain-free: the
one chain write a node makes (`confirm_link`) goes through the
`LinkConfirmer` port, which `kenter-node` implements.

## `protocol`: wire messages

Serde structs. The Rust field `msg_type` is serialized as `type`.

| Type | Fields | Notes |
|------|--------|-------|
| `ShardRequest` | `msg_type, chain_link, event_id, combiner_public_key, holder_address, token_hash, nonce, signature, timestamp:i64` | `chain_link` = base64 of the 290-byte link; `event_id`, `combiner_public_key`, `token_hash` (SHA-256 of the container), `nonce` are 32-byte hex; `signature` is the holder's 64-byte hex signature from the `RedemptionRequest`; `timestamp` is the one the holder signed. |
| `ShardResponse` | `msg_type, status, encrypted_shard:Option, error:Option` | `status` emitted: `ok`, `unauthorized`, `not_found`, `refused`, `error`. `encrypted_shard` is base64, present on `ok`. |
| `ExtendRequest` | `msg_type, partial_token, slot_id:u32` | `partial_token` = base64 of a serialized `PartialToken`. `slot_id` is the on-chain print slot, which the node needs to call `confirm_link`. |
| `ExtendResponse` | `msg_type, status, partial_token:Option, error:Option` | `status` is `ok` or `error`. |
| `HealthResponse` | `status, version, node_address:Option, partner_address:Option` | `version` = `CARGO_PKG_VERSION`. `partner_address` lets a print driver name both members of a pair; a node is otherwise reachable only by its own address. |

Constructors: `ShardResponse::ok(String)` / `::error(status, msg)`;
`ExtendResponse::ok(String)` / `::error(msg)`.

## `handlers`: pure request handling

Pair-node handlers plus combiner- and driver-side builders. No I/O.

| Fn | Signature | Notes |
|----|-----------|-------|
| `handle_shard_request` | `(&PairNodeContext, &ShardRequest) -> ShardResponse` | In order: decodes; verifies the holder's signature over `token_hash`, `holder_address`, `combiner_public_key`, `nonce`, `timestamp` (`kenter_crypto::redemption::verify_holder_signature`; `unauthorized` if it fails, so a relay cannot substitute its own combiner key); finds the partner in the link (`not_found` if this node is in neither slot); marks the link in the rate limiter (`refused` if already served); `contribute_shard`, which checks freshness; encrypts to the combiner. |
| `build_shard_request` | `(&ChainLink, event_id:&[u8;32], combiner_public_key:&[u8;32], holder_address:&str, token_hash:&[u8;32], nonce:&[u8;32], holder_signature:&[u8;64], timestamp:i64) -> ShardRequest` | Combiner side. Relays the holder's authorization verbatim. |
| `parse_shard_response` | `(&ShardResponse) -> Result<EncryptedShard, String>` | Errors on a non-`ok` status. |
| `handle_extend_request` | `(&ExtendNodeContext, &ExtendRequest) -> ExtendResponse` | Deserializes, `verify_chain_integrity`, refuses if `remaining_pairs == 0`, `extend`s with both pair keys, re-serializes. Checks only the chain's internal consistency; the slot check is `LinkConfirmer::admits`. |
| `build_extend_request` | `(&PartialToken, slot_id:u32) -> Result<ExtendRequest, String>` | |
| `parse_extend_response` | `(&ExtendResponse) -> Result<PartialToken, String>` | |
| `last_link_of` | `(&ExtendResponse) -> Result<(u32, [u8;32]), String>` | Index and partial public key of the link just added: the two values `confirm_link` needs. |
| `serialize_chain_link` | `(&ChainLink) -> Vec<u8>` | Fixed **290-byte** layout, the same as the `kenter-crypto` container: `node_a_public ‖ node_b_public ‖ partial_public_key ‖ shard_commitment ‖ prev_link_hash` (32 each) `‖ link_index` (u16 LE) `‖ signature_a ‖ signature_b` (64 each). |

Contexts:

- `PairNodeContext { own_keypair: StellarKeypair, rate_limiter: ShardRateLimiter }`.
  A shard handler needs only its own secret: it re-derives the pair's
  shard by ECDH against the partner public key carried in the link.
- `ExtendNodeContext { own_keypair: StellarKeypair, partner_keypair: StellarKeypair }`:
  both pair keys are held by the node process.
- `ShardRateLimiter`: `new()`, `Default`,
  `check_and_mark(event_id:&[u8;32], link_index:u16) -> bool` (true means
  already served: refuse), `tracked() -> usize`. A mark lasts `SERVED_TTL`
  (900 s), longer than a shard request's freshness window, so no valid
  authorization can be replayed against a cleared mark, and short enough
  that a redemption that failed for another reason can be retried. The
  handler marks only after the signature and membership checks pass, so a
  stranger cannot burn a link, and before the shard is produced, so two
  concurrent requests cannot both get one.

## `jwt`: Stellar EdDSA JWT

Used for tunnel authentication.

- Header: `{"alg":"EdDSA","typ":"JWT","kid":"<G… address>"}`.
- Payload: `{"iss":"kenter_tunnler","sub":"<G…>","aud":"<audience>","iat":…,"services":[…]}`,
  plus `exp` when an expiry is given, plus any custom claims (which win on
  collision).
- Signature: Ed25519 over `base64url(header) "." base64url(payload)`,
  base64url without padding.

| Fn | Signature |
|----|-----------|
| `create_stellar_jwt` | `(&StellarKeypair, audience:&str, services:&[String], expires_in_secs:Option<u64>, custom_claims:&HashMap<String,Value>) -> String` |
| `create_stellar_jwt_at` | `(&StellarKeypair, stellar_address:&str, audience:&str, services:&[String], issued_at:u64, expires_in_secs:Option<u64>, custom_claims:&HashMap<String,Value>) -> String`, for tests |
| `verify_stellar_jwt` | `(jwt:&str, signer_public:&[u8;32]) -> Result<Value, String>`: verifies the signature and returns the claims. It does not check `exp`, `aud` or `iat`; the caller does. |

## `tunnel`: WebSocket tunnel client

Connects to a kenter-tunnler relay at `wss://<host>/connect`, answers a
challenge with a Stellar JWT, binds its services, then dispatches
stream-multiplexed requests.

| Item | Notes |
|------|-------|
| `TunnelConfig { host, services, local_port, jwt_expires_secs, auth_timeout_secs, request_timeout_secs, secure }` | `Default`: services `["kenter"]`, port 9090, JWT 3600 s, auth 15 s, request 120 s, `secure = true`. Set `host` to your relay (for example `relay.example.org`). `secure = false` uses `ws://`/`http://` for a local relay with no TLS. Helpers `wss_url()`, `endpoint_base()`. |
| `TunnelClient` | `new(StellarKeypair, TunnelConfig)`; `async run(self, Arc<dyn RequestHandler>) -> Result<(TunnelEndpoint, SessionHandle)>`: connect, authenticate, bind, spawn the message loop. |
| `TunnelEndpoint { endpoint_url, server_address, services, encryption_available }` | `endpoint_url` is the public URL the relay assigned, e.g. `https://<G...>.relay.example.org`. |
| `IncomingRequest { stream_id, method, path, headers, body:Option<String> }` | Delivered to the handler. |
| `RequestHandler` (trait) | `handle_request(&self, IncomingRequest) -> Pin<Box<dyn Future<Output=Value> + Send + '_>>`. |
| `LinkConfirmer` (trait) | `admits(slot_id, event_id, prior_links) -> Result<(), String>` and `confirm_link(slot_id, link_index, partial_public_key) -> Result<(), String>`, both async. No default for `admits`: an implementation that forgot it would admit everything. |
| `KenterHandler { pair_ctx, extend_ctx: Arc<Mutex<Option<ExtendNodeContext>>>, confirmer: Option<Arc<dyn LinkConfirmer>>, served }` | `new(pair_ctx, extend_ctx, confirmer)`. Routes `/kenter/health` and `/kenter/extend`; `/kenter/shard` answers HTTP 404 unless built `with_shard_service()` (tests only). Field `serve_shards`, off by default. |
| `SERVED_KEEP` | 64: how many served extensions a node remembers. |
| `SessionHandle` | `shutdown()`, `shutdown_trigger() -> impl Fn()` (detachable, since `join` consumes the handle), `async join()`, `async request(target, method, path, body:Option<&Value>) -> Result<Value>` (raw peer reply), `async request_json(...)` (unwraps the HTTP envelope; errors on a non-2xx `status_code`). |

**Outbound requests** are correlated by `stream_id`: each registers a
one-shot receiver, and the message loop, the socket's single reader,
routes the matching `tunnel_response` to it. Concurrent requests never
receive each other's responses. The body is sent as a JSON string, as the
relay's HTTP proxy sends it.

**`KenterHandler` responses** are wrapped in the envelope the relay's proxy
expects: `{status_code, headers, body}` with `body` a JSON string.
Protocol failures are HTTP 200 with the error in the payload; only an
unknown path is a 404.

**`/kenter/extend`** handling, in order:

1. A byte-identical request already served returns the stored reply,
   without a second confirmation. A reply lost on the way back otherwise
   leaves the depositor with a confirmed link and no chain to continue.
   Only the original sender has the request bytes.
2. With a confirmer, `admits` checks the request against the slot on
   chain: the chain's event id is the slot's, its links are exactly the
   links confirmed so far, each signed by the pair the slot assigns it, and
   this node is the pair for the next link. `/kenter/extend` is reachable
   by anyone through the relay, so without this a stranger could have a
   node confirm a link into a real print and kill it.
   (`kenter_client::SlotInfo::admits_next` implements the check.)
3. Extend with the local `ExtendNodeContext` (error if the node has none).
4. With a confirmer, submit `confirm_link`; if it fails the request
   fails, since an unconfirmed link cannot be registered.

`request_timeout_secs` (120) covers the slowest answer, `/kenter/extend`,
where the node waits up to 60 s for its `confirm_link` to land. The relay's
own request timeout must be at least this.

**Encryption.** Traffic is TLS to the relay (WSS) and plaintext inside the
tunnel. The relay may announce end-to-end encryption
(`encryption_available`, an `encryption_enabled` message); the client logs
it and does nothing else. Shards are separately encrypted to the
combiner's key by `kenter-crypto`.

## `error`

`NetworkError` (`thiserror`): `WebSocket(tungstenite::Error)`,
`Json(serde_json::Error)`, `AuthFailed(String)`, `ConnectionClosed`,
`Timeout(String)`, `Protocol(String)`, `Crypto(CryptoError)`.
`Result<T> = std::result::Result<T, NetworkError>`.

## Tests

`tests/full_lifecycle.rs` drives the protocol end to end through the
handlers directly. The live tunnel path (`TunnelClient`,
`SessionHandle::request`) is exercised by the kenter-tunnler crate's
`local_tunnel_test` and `multi_node_test` modules against a real relay.
