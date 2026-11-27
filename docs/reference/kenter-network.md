# `kenter-network`

The wire protocol and the tunnel client. Both ends — nodes and clients —
speak through this.

## Modules

| Module | Holds |
|---|---|
| `protocol` | The request and response types |
| `handlers` | What a node does when asked |
| `tunnel` | The WebSocket tunnel client |
| `jwt` | Stellar JWT authentication |
| `error` | `NetworkError`, `Result` |

## `protocol` — the messages

| Type | Purpose |
|---|---|
| `ShardRequest` / `ShardResponse` | Redemption: ask a pair for its shard |
| `ExtendRequest` / `ExtendResponse` | Printing: ask a pair to add a link |
| `HealthResponse` | Liveness |

These are the entire protocol surface. Nodes are stateless beyond their own
keypair, so every request carries what is needed to answer it.

## `handlers` — the node side

| Item | Purpose |
|---|---|
| `PairNodeContext` | A node's own keypair and its shard rate limiter |
| `handle_shard_request(…)` | Answer a shard request (not routed by nodes; see below) |
| `ExtendNodeContext` | Both pair keypairs, for extending a token |
| `handle_extend_request(…)` | Serve `/kenter/extend` |
| `ShardRateLimiter` | Serves each `(event_id, link_index)` at most once per 15 minutes |

And the client side of the same exchanges:

| Item | Purpose |
|---|---|
| `build_shard_request(…)` / `parse_shard_response(…)` | Ask, and read the answer |
| `build_extend_request(…)` / `parse_extend_response(…)` | Same for printing |
| `last_link_of(…)` | The most recent link on a token |
| `serialize_chain_link(…)` | Link to bytes |

::: tip Nodes do not serve shards
`KenterHandler` refuses `/kenter/shard` with HTTP 404 unless it is built
`with_shard_service()`, which only the in-process shard test does. Shards
serve redemption by key, which Kenter's clients do not use.
:::

The shard code stays because the mint has the by-key entry points and the
scheme is tested. `handle_shard_request` re-derives the pair's shard by ECDH
against the partner key carried in the `ChainLink`, verifies the holder's
signature over the combiner key (`unauthorized` otherwise), and serves each
link at most once per 15 minutes (`ShardRateLimiter`).

## `tunnel` — the relay client

| Item | Purpose |
|---|---|
| `TunnelConfig` | The relay address and this endpoint's identity |
| `TunnelEndpoint` | A connected endpoint |
| `TunnelClient` | The connection |
| `SessionHandle` | One session's lifetime |
| `IncomingRequest` | A request arriving through the tunnel |
| `RequestHandler` | Trait: handle an incoming request |
| `LinkConfirmer` | Trait: confirm a link on-chain |
| `KenterHandler` | The standard handler — health and extend; shard only `with_shard_service()` |

`LinkConfirmer` is a separate trait because confirming a link is a **chain
write**, and this crate stays chain-free; `kenter-node` supplies the Soroban
implementation. It has two methods. `admits` runs **before** a node extends:
it checks the request against the slot on-chain (event id, links confirmed
so far and who signed them, and that this node is the next pair), because
`/kenter/extend` is reachable by anyone through the relay. `confirm_link`
runs after extending; if it fails, the extend fails.

`KenterHandler` remembers the last 64 extensions it served
(`SERVED_KEEP`). A byte-identical request gets the stored reply again
without a second confirmation, so a reply lost in transit does not strand
the print.

Responses go back in the envelope the relay's proxy expects,
`{status_code, headers, body}` with `body` a JSON string.
`SessionHandle::request_json` unwraps it; `request` returns it raw.

## `jwt` — authentication

| Function | Purpose |
|---|---|
| `create_stellar_jwt(keypair, audience, services, expires_in, claims)` | EdDSA JWT for tunnel auth |
| `create_stellar_jwt_at(…)` | The same with an explicit issue time — for tests |
| `verify_stellar_jwt(…)` | Verify one |

Header `{"alg":"EdDSA","typ":"JWT","kid":"<G...>"}`; the payload carries
`iss`, `sub`, `aud`, `iat`, `services`, an optional `exp`, and any custom
claims. The relay's challenge-response puts the challenge in the custom
claims. `verify_stellar_jwt` checks only the signature and returns the
claims; expiry and audience are the caller's to check.
`create_stellar_jwt_at` exists so expiry behaviour can be tested without
sleeping.

## Related

- [Relay API](/tunnler-api) — the relay's own interface
- [A local network](/runbook/local-network) — bringing it up
- `tests/full_lifecycle.rs`: the protocol end to end, through the handlers
- `crates/kenter-network/API.md` in the repository: full signatures
