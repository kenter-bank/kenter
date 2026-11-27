# kenter-network — Architecture

**Role.** The node-side transport. It is the client half of the
`kenter-tunnler` relay and the home of Kenter's two wire flows:

- **printing**: building a note's chain one pair at a time (`/kenter/extend`);
- **shard redemption**: collecting each pair's shard to rebuild a note's
  ephemeral key (`/kenter/shard`). Not served by nodes: Kenter redeems by
  chain, and the handler refuses this endpoint unless built
  `with_shard_service()`, which only the in-process shard test does.

It owns the wire message types, the Stellar-JWT handshake, the WebSocket
session with its request dispatch, and the request handlers that wrap
`kenter-crypto`. It moves bytes. It holds no value and makes no ledger calls;
where a flow needs the chain, it asks through a port that another crate
implements.

**Native only.** It uses `tokio` and `tokio-tungstenite`, so it does not
compile to WASM (unlike `kenter-crypto` and the contracts).

## Structure

| Module | Holds |
|---|---|
| `protocol` | JSON request and response structs: `ShardRequest`/`ShardResponse`, `ExtendRequest`/`ExtendResponse`, `HealthResponse` |
| `handlers` | Request handlers backed by `kenter-crypto`, their builders and parsers for the calling side, `ShardRateLimiter`, the 290-byte `ChainLink` wire layout |
| `jwt` | Stellar EdDSA JWT create and verify (also used by the relay to check clients) |
| `tunnel` | `TunnelClient` (connect, authenticate, message loop), `SessionHandle`, the `RequestHandler` and `LinkConfirmer` ports, `KenterHandler` |
| `error` | `NetworkError` |

**Used by:** `kenter-node` (runs a `TunnelClient` with a `KenterHandler` and
supplies the Soroban `LinkConfirmer`), `kenter-print` (builds extend requests
and parses replies as the depositor), `kenter-tunnler` (JWT verification and
its tunnel tests), the desktop shells (`kenter-desktop`, `kenter-ui`) and
`kenter-systest`. The wallet core (`kenter-wallet`) deliberately does not
depend on it, so it stays wasm-safe.

**Depends on:** `kenter-crypto` for all cryptographic work:
`contribute_shard`, `PartialToken::{initiate, extend}`,
`verify_chain_integrity`, `assemble_bearer_token`, partial-token
serialization, `verify_holder_signature`, `StellarKeypair`.

## The tunnel session

`TunnelClient::run`:

1. Connects to `wss://<relay host>/connect` (`ws://` when
   `TunnelConfig::secure` is false, for a local relay with no TLS in front).
2. Receives `auth_challenge`, signs a Stellar JWT that carries the relay's
   random `challenge` and names the relay as audience, sends `auth_response`,
   and waits for `auth_ok` or `auth_failed`. The result is a `TunnelEndpoint`
   (the node's public URL).
3. Binds the `kenter` service.
4. Runs the message loop: a `tokio::select!` over inbound frames, a shutdown
   command and a 30 s keepalive ping. Each inbound `tunnel_request` becomes an
   `IncomingRequest`, handled on its own task by the `RequestHandler`; the
   result goes back as `tunnel_response` on the same `stream_id`.

The message loop is the only reader of the socket. Outbound requests
(`SessionHandle::request`) register a oneshot under a fresh `stream_id`, and
the loop routes each `tunnel_response` to its waiter, so concurrent requests
do not interfere.

`request_timeout_secs` defaults to 120 s. It has to cover the slowest reply a
node gives, which is `/kenter/extend`: the node waits for its `confirm_link`
transaction to land (up to 60 s) before answering. The relay's
`TUNNLER_REQUEST_TIMEOUT` must be at least as long.

## Dispatch (`KenterHandler`)

`KenterHandler` routes by path:

- `/kenter/health`: `HealthResponse`.
- `/kenter/shard`: HTTP 404 (`SHARDS_NOT_SERVED`), or `handle_shard_request`
  when built `with_shard_service()`.
- `/kenter/extend`: the extend flow below. A node without an
  `ExtendNodeContext` answers with an error.
- anything else: HTTP 404.

Every reply is wrapped in the relay's HTTP envelope (`status_code`,
`headers`, `body` as a string). Protocol failures (a refused shard, a chain
that does not fit the slot) are HTTP 200 with the error in the payload,
because they are answers, not transport faults. Callers read `status` from
the payload.

### Extend (printing)

The depositor sends an `ExtendRequest` carrying the partial token and the
print's `slot_id`. The node:

1. **Returns a cached reply** if it has already answered a byte-identical
   request. The last `SERVED_KEEP` (64) successful replies are kept by request
   hash, so a depositor whose reply was lost gets it again without a second
   confirmation on-chain.
2. **Checks the request against the slot** (`LinkConfirmer::admits`): the
   chain's event id must be the slot's, its links must be exactly those
   confirmed on-chain so far, each signed by the pair the slot assigned to
   it, and this pair must be next. `/kenter/extend` is reachable by anyone
   through the relay, and `verify_chain_integrity` only proves the chain is
   internally consistent. Without this check a stranger could build a
   look-alike chain from throwaway keys under a real slot's id and get the
   node to confirm a link into that print, breaking it. The signer check
   matters because event ids and partial keys are public once confirmed.
   `admits` has no default implementation, so an implementer cannot forget
   it and admit everything.
3. **Extends** (`handle_extend_request`): verifies chain integrity, refuses if
   `remaining_pairs == 0`, then `PartialToken::extend` with the pair's two
   keys (ECDH and a dual signature) and re-serializes.
4. **Confirms the link** (`LinkConfirmer::confirm_link`). The mint accepts
   `confirm_link` only from a member of the assigned pair, so this is the
   node's call to make, not the depositor's. If confirmation fails, the extend
   fails: an unconfirmed link can never be registered, so returning it would
   only mislead the depositor.

A node built with no confirmer (transport testing) skips steps 2 and 4; it
touches no ledger and is never in a real print.

`ExtendNodeContext` holds both of the pair's keypairs, because the link is
dual-signed. One process therefore stands for one pair, and the pair is the
unit of trust; see `kenter-node`'s architecture.

`LinkConfirmer` is a port so this crate stays chain-free and the protocol can
be reasoned about as transport plus cryptography. `kenter-node` provides the
Soroban implementation.

### Shard (redemption)

A note can be redeemed by rebuilding its ephemeral key from one shard per
pair. A combiner (the redeeming client) asks each pair for its shard. The
pair-node side, `handle_shard_request`:

1. Decodes the base64 `ChainLink` (fixed 290-byte layout) and the hex fields.
2. **Checks the holder's authorization** (`verify_holder_signature`): the
   holder signs the combiner's public key together with the token hash, a
   nonce and a timestamp. Without this, a relay could substitute its own
   combiner key and receive the shard. A bad or swapped key gets
   `unauthorized`.
3. Finds the partner key in the link. If this node is in neither position,
   `not_found`.
4. **Marks the link served** in `ShardRateLimiter`, keyed by
   `(event_id, link_index)`. A second request inside `SERVED_TTL` (900 s) gets
   `refused`. One shard per link per redemption stops anyone harvesting
   shards by asking again with different combiner keys.
5. Calls `contribute_shard`, which re-derives the shard, checks the request
   timestamp window, and encrypts the shard to the combiner key.

The mark is set only after the authorization and membership checks, so a
request that was going to be refused cannot use up a link the real holder
needs. It is set before `contribute_shard`, so two concurrent requests cannot
both pass. `SERVED_TTL` is longer than the request's freshness window, so a
still-valid authorization cannot be replayed against a cleared mark, and
short enough that a redemption that failed for another reason can be retried.

The combiner side is `build_shard_request` (it relays the holder's
authorization unchanged, including the timestamp the holder signed) and
`parse_shard_response`.

Redemption from chain data alone, with no shards, is a contract flow and has
no handler here.

Shard status codes in use: `ok`, `refused`, `not_found`, `unauthorized`,
`error`. `protocol` also reserves `commitment_mismatch` and `stale_request`,
which no handler emits.

## Invariants

- **Handlers are pure.** `handle_*` take a context and a decoded request and
  return a response; I/O lives in `tunnel.rs`. Every flow can be tested by
  calling handlers directly, with no network.
- **A chain only grows while it has room and is sound.** Extension requires
  `remaining_pairs > 0` and a passing `verify_chain_integrity`. The last step,
  assembling the bearer token, is done by the depositor, never by a node.
- **A node extends only the print it is assigned to**, checked against the
  slot on-chain before any work.
- **A shard is encrypted only to a combiner key the holder signed**, and at
  most once per link inside `SERVED_TTL`.
- **The JWT binds the challenge**, so an `auth_response` cannot be replayed in
  another session.

## Not provided

- **No end-to-end encryption.** `TunnelEndpoint::encryption_available` is read
  from `auth_ok` but not acted on, and the relay always reports `false`.
  Traffic is protected by TLS to the relay, and the relay can read it. The
  flows do not depend on relay confidentiality: shards are encrypted to the
  combiner's key, and links are signed by the pair and checked against the
  chain. See the [security model](../../docs/architecture/security-model.md).
- **No node choice here.** Which pairs build a print is chosen by the mint's
  selection (see [node selection](../../docs/architecture/node-selection.md));
  this crate only carries the requests.

## Tests

Handler tests run in-crate with no network. The tunnel path (a real
`TunnelClient` behind a locally run relay, including requests through the
relay's proxy) is exercised by the tests in `crates/kenter-tunnler/src`
(`local_tunnel_test.rs`, `multi_node_test.rs`). Run a local relay for any
tunnel testing; `TunnelConfig { secure: false, .. }` reaches it over plain
`ws://`.
