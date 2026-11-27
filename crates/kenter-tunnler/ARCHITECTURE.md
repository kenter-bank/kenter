# kenter-tunnler — Architecture

**Role.** The relay server. It lets a node behind NAT accept inbound HTTP
without port forwarding. A node opens a WebSocket to the relay, proves who it
is with a challenge-bound Stellar Ed25519 JWT, and from then on the relay
forwards HTTP requests for that node down the socket. It can also relay
messages from one connected node to another. Access can be gated on the
**kenter-roster** contract. It is a native `tokio`/`axum` binary meant for a
VPS; nodes (`kenter-node`) are its clients. The wire protocol is in
[`docs/tunnler-api.md`](../../docs/tunnler-api.md) and the VPS setup in
[`docs/DEPLOY.md`](../../docs/DEPLOY.md).

## Stateless by design

All state is in memory (`DashMap`): connections, pending challenges, rate-limit
counters and the roster cache. There is no database and nothing on disk. A
restart drops every session; nodes reconnect and the roster cache refills from
the chain on demand. The only durable inputs are the environment and the
roster contract.

This keeps the relay a pure relay. It holds no token value and no key material
beyond its own server identity, so losing or replacing the box loses nothing
that matters. A node that loses its relay falls back to the next relay in its
list, so no single relay is a point of failure for the network.

## Structure

| Module | Holds |
|---|---|
| `main` | Startup, the 60 s background sweep (expired sessions, challenges, rate-limit entries, roster cache) |
| `config` | Environment configuration (below) |
| `server` | The axum router; `client_ip` resolution behind a reverse proxy |
| `ws` | Connection lifecycle: authenticate, register, message loop, cleanup |
| `dispatch` | Messages from a connected node; node-to-node relay |
| `proxy` | The inbound HTTP handler (`/proxy/{address}/{path}`) |
| `auth::challenge`, `auth::jwt`, `auth::rate_limit` | The handshake and its abuse limits |
| `roster::client`, `roster::cache` | Roster membership over Soroban RPC, cached per address |
| `state` | `AppState`, the connection map, per-connection `StreamManager` |
| `error` | Error type |

Routes: `/connect` (WebSocket upgrade), `/health`, and
`/proxy/:stellar_address/*path` for POST only, to the two node paths in
`config::PROXY_PATHS`, with a 64 KiB body limit. Everything else is refused
before a tunnel stream is spent on it.

**Dependencies.** `kenter-crypto` (`StellarKeypair`, the server identity),
`kenter-network` (`verify_stellar_jwt`) and the roster contract, read with
`getLedgerEntries`. In production nginx sits in front: it terminates TLS and
maps `{address}.relay.example.org` to `/proxy/{address}/…`, so each node gets
its own HTTPS subdomain without the relay handling certificates.

## Authenticate, register, relay

1. **Challenge.** On upgrade the relay checks the client IP against the rate
   limiter, then sends `auth_challenge`: a random 16-byte `challenge_id`, a
   32-byte `challenge` and its own `server_address`. The challenge is bound to
   the client IP, single-use, and expires after `challenge_ttl`.
2. **Response.** The client has 15 s to reply with `auth_response` carrying a
   Stellar JWT. `verify_client_jwt` takes the signer from the `kid` header,
   checks the Ed25519 signature, and requires `sub == kid`,
   `aud == server_address`, `exp`/`iat` within `jwt_clock_skew`, and the
   `challenge` claim equal to the one issued.
3. **Roster gate.** If `ROSTER_CONTRACT_ID` is set, `RosterCache::is_member`
   checks the address: a fresh cache entry answers, otherwise the relay reads
   the `DataKey::Node(address)` ledger entry directly (no simulation). A
   missing entry rejects (`not on roster`). An RPC failure also rejects
   (`roster check unavailable`). With no contract id, gating is off.
4. **Register.** The rate-limit record for the IP is cleared, the relay sends
   `auth_ok` (endpoint `https://{address}.{TUNNLER_DOMAIN}`, services,
   `encryption_available: false`), and the connection is stored under
   `"{address}:{service}"` with its own `StreamManager`.
5. **Message loop.** One `tokio::select!` loop handles text from the node
   (to `dispatch`), `Ping` (answered with `Pong`), the outbound queue (to the
   socket), a 30 s keepalive ping, and an absolute `session_timeout` deadline
   that sends `session_expired` and closes.

**Two ways a request reaches a node.**

- *Proxy.* nginx forwards an external request to `/proxy/{address}/{path}`.
  `proxy` allocates a `stream_id` and a oneshot, sends `tunnel_request` (with
  the real method, path, headers and body) down the node's socket, and waits
  for the matching `tunnel_response` up to `request_timeout`.
- *Relay.* A connected node sends `tunnel_request` with a `target` address.
  `dispatch` opens a new stream on the target, forwards the request, and
  returns the reply under the source's original `stream_id`.

`dispatch` handles four message types: `pong`, `bind` (acknowledged with
`bind_ok`; the binding itself happens at registration), `tunnel_request` and
`tunnel_response`. Kenter's shard and extend calls are ordinary HTTP requests
to the node's `/kenter/*` endpoints carried by this generic path; the relay
does not know about them.

## Invariants

- **A challenge is single-use and IP-bound.** `verify` removes it from the
  pending set, checks the stored IP and value, and records the id as used for
  twice the TTL. A second attempt fails with `challenge already used`. A
  challenge is consumed even when the JWT check fails.
- **A node authenticates only as the key it holds.** `sub` must equal the
  `kid` that signed the token. The audience must be this relay's address, so a
  JWT made for another relay is rejected.
- **The roster gate fails closed.** When gating is on, an RPC error denies the
  connection.
- **The gate admits staked addresses.** It checks that a roster record
  exists. A record exists exactly while its stake is locked: from `join`,
  through unbonding after `leave`, until `withdraw` returns the stake and
  deletes it. So every admitted node has stake at risk, paused and
  unbonding ones included. Cached answers live for `TUNNLER_ROSTER_CACHE_TTL`.
- **Streams cannot leak.** Every proxy or relay stream resolves on its
  `tunnel_response`, times out at `request_timeout`, or is cancelled
  (`cancel_all`) when the connection ends.
- **Per-tunnel load is bounded.** At most `MAX_IN_FLIGHT` (256) requests may
  be pending on one tunnel; beyond that `/proxy` answers 503. The outbound
  queue holds `OUTBOUND_QUEUE` (256) messages; when a node stops reading, the
  queue fills and further requests are refused rather than buffered.
- **Lookups are by address.** The connection map is searched by the
  `"{address}:"` prefix, so a node is reachable by its Stellar address
  whatever its service name.

## Rate limiting and client IPs

Failed or abandoned handshakes count against the client IP: more than
`TUNNLER_RATE_LIMIT_MAX_ATTEMPTS` in `TUNNLER_RATE_LIMIT_WINDOW` blocks the IP
for `TUNNLER_RATE_LIMIT_BLOCK_DURATION`. A successful authentication clears
the record.

Behind nginx every TCP peer is the proxy, so the client IP has to come from
`X-Real-IP`. The relay trusts that header only from peers listed in
`TUNNLER_TRUSTED_PROXIES`. A client can send any header, so trusting it from
anyone would let a client dodge its own block or get another IP blocked. From
an untrusted peer the relay uses the peer address.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TUNNLER_SERVER_SECRET` | required | The relay's Stellar secret seed (its identity, the JWT audience) |
| `TUNNLER_HOST` / `TUNNLER_PORT` | `0.0.0.0` / see `config.rs` | Listen address |
| `TUNNLER_DOMAIN` | see `config.rs`; set it | Domain node endpoints are built on (`https://{address}.{domain}`) |
| `TUNNLER_JWT_CLOCK_SKEW` | 60 s | Allowed clock skew on `exp`/`iat` |
| `TUNNLER_SESSION_TIMEOUT` | 86,400 s | Absolute session lifetime |
| `TUNNLER_CHALLENGE_TTL` | 30 s | Challenge lifetime |
| `TUNNLER_RATE_LIMIT_WINDOW` / `_MAX_ATTEMPTS` / `_BLOCK_DURATION` | 60 s / see `config.rs` / 300 s | Handshake rate limit |
| `TUNNLER_REQUEST_TIMEOUT` | 120 s | Wait for a node's `tunnel_response` |
| `TUNNLER_ROSTER_CACHE_TTL` | 300 s | Roster cache lifetime |
| `TUNNLER_TRUSTED_PROXIES` | empty | Comma-separated IPs whose `X-Real-IP` is believed |
| `TUNNLER_LOG_LEVEL` | `info` | Log filter |
| `ROSTER_CONTRACT_ID` | unset | Roster contract; unset or empty turns gating off |
| `SOROBAN_RPC_URL` / `SOROBAN_NETWORK_PASSPHRASE` | testnet | RPC used for roster reads |

For local testing, run the relay without a roster:

```sh
TUNNLER_SERVER_SECRET=S... TUNNLER_PORT=8080 cargo run -p kenter-tunnler
```

## Not provided

- **No end-to-end encryption.** `auth_ok` always reports
  `encryption_available: false`, and traffic between a client and a node is
  protected only by TLS to the relay. The relay can read requests it carries.
  Kenter's protocol does not rely on the relay for confidentiality or
  integrity: shard and link replies are signed by the pair, and the depositor
  checks them. See the [security model](../../docs/architecture/security-model.md).
- **No admin or statistics API.** The only non-tunnel route is `/health`.
- **No custom domains in the server.** Subdomain routing lives in nginx.
