# kenter-tunnler API

`kenter-tunnler` is the WebSocket relay of the Kenter network. Nodes open an
outbound WebSocket to it and authenticate with a Stellar Ed25519 JWT. The
relay can require each node to be on the on-chain roster. It forwards HTTP
requests from wallets to connected nodes, and relays messages between
connected nodes.

Deploying a relay is covered in [Deployment](/DEPLOY). In the examples
below the relay's domain is `relay.example.org`.

## HTTP endpoints

### `GET /connect`

WebSocket upgrade. Starts an authenticated tunnel session (see
[Connection lifecycle](#connection-lifecycle)).

### `GET /health`

```json
{
  "status": "ok",
  "version": "0.1.0",
  "connections": 2,
  "roster_gating": true
}
```

`version` is the crate version. `connections` is the number of connected
nodes.

### `POST /proxy/{stellar_address}/{*path}`

Forwards an HTTP request to the connected node with that address, and
returns its response. The route takes no authentication, so it forwards
only what a wallet needs: `POST` to one of two node paths,

- `/kenter/health`, which a depositor calls before a print to learn a node's
  pair partner, and
- `/kenter/extend`, which asks a node for the next link of a print.

Anything else is refused by the relay and never reaches a tunnel. Bodies are
capped at 64 KiB (an extend request is a few KB). The list is
`PROXY_PATHS` in `crates/kenter-tunnler/src/config.rs`; it is not
configurable.

Wallets use this route to reach nodes when printing:
`https://relay.example.org/proxy/<G...>/kenter/extend`. nginx also maps the
per-node subdomain form, `https://<G...>.relay.example.org/<path>`, onto it.

The request's method, path, headers and body (as text) go to the node in a
`tunnel_request`. The node's `tunnel_response` becomes the HTTP response.

| Status | Meaning |
|--------|---------|
| 400 | Not a valid Stellar account address (56 characters, starting with `G`) |
| 404 | Not one of the two node paths |
| 405 | A method other than `POST` |
| 413 | Body over 64 KiB |
| 502 | No tunnel for this address, send failed, node disconnected, or no answer within `TUNNLER_REQUEST_TIMEOUT` |
| 503 | The node's tunnel is at its in-flight request limit, or its outbound queue is full |

**Forwarded response headers** (allow list): `content-type`,
`content-length`, `cache-control`, `etag`, `last-modified`, `expires`,
`access-control-allow-origin`, `access-control-allow-methods`,
`access-control-allow-headers`, `location`, `x-request-id`. Other headers
from the node are dropped.

---

## Connection lifecycle

```
Client                                Server
  |                                      |
  |---- WebSocket connect /connect ----->|
  |                                      |
  |<--- auth_challenge -----------------|  1. challenge_id + challenge + server_address
  |                                      |
  |---- auth_response ----------------->|  2. JWT (contains challenge) + challenge_id
  |                                      |
  |     [ verify JWT sig, claims,        |  3. Ed25519 sig, aud, exp, challenge binding,
  |       challenge single-use,          |     IP-bound challenge, roster membership
  |       roster membership ]            |
  |                                      |
  |<--- auth_ok / auth_failed ----------|  4. endpoint URL, services
  |                                      |
  |<--> ping/pong (30s) --------------->|  5. keepalive loop
  |                                      |
  |<--- tunnel_request -----------------|     proxy or relay
  |---- tunnel_response --------------->|
  |                                      |
  |<--- session_expired ----------------|     after session_timeout
```

The client has 15 seconds after `auth_challenge` to send `auth_response`.
After that the server sends `auth_failed` with `auth timeout` and closes.

---

## WebSocket messages

All messages are JSON text frames with a `type` field.

### Auth phase

**auth_challenge** (S -> C)

```json
{
  "type": "auth_challenge",
  "challenge_id": "a1b2c3...",
  "challenge": "d4e5f6...",
  "server_address": "G..."
}
```

`challenge_id`: 16 bytes, hex. `challenge`: 32 bytes, hex. Each challenge is
single-use, bound to the client's IP, and valid for `TUNNLER_CHALLENGE_TTL`
seconds. `server_address` is the relay's own Stellar address.

**auth_response** (C -> S)

```json
{
  "type": "auth_response",
  "challenge_id": "a1b2c3...",
  "jwt": "<stellar-jwt>"
}
```

The JWT is signed with the client's Ed25519 key and carries:

| Claim | Value |
|-------|-------|
| `kid` (header) | Client's Stellar address (`G...`) |
| `sub` | Client's Stellar address (must match `kid`) |
| `aud` | The relay's Stellar address |
| `exp` | Expiry timestamp |
| `iat` | Issued-at timestamp |
| `challenge` | The exact challenge value from `auth_challenge` |
| `services` | Array of service names (default `["kenter"]`) |

**auth_ok** (S -> C)

```json
{
  "type": "auth_ok",
  "endpoint": "https://G....relay.example.org",
  "server_address": "G...",
  "services": ["kenter"],
  "encryption_available": false
}
```

`endpoint` is `https://<client address>.<TUNNLER_DOMAIN>`. A node records it
on the roster, and wallets map it back to the relay's `/proxy` route.

**auth_failed** (S -> C)

```json
{
  "type": "auth_failed",
  "error": "not on roster"
}
```

The server closes the connection after sending it. Errors include
`invalid JSON`, `expected auth_response`, `missing jwt`,
`missing challenge_id`, `challenge_id mismatch`, the JWT errors
(`sub does not match kid`, `audience mismatch`, `JWT expired`,
`JWT issued in the future`, `challenge mismatch`), the challenge errors
(`challenge already used`, `challenge expired`, `challenge IP mismatch`),
`not on roster`, `roster check unavailable` and `auth timeout`. A client
that is rate limited gets `auth_failed` with the block reason instead of an
`auth_challenge`.

### Authenticated phase

**ping / pong.** The server sends `ping` every 30 seconds. The client
answers `pong`.

```json
{"type": "ping"}
{"type": "pong"}
```

**bind / bind_ok.** Informational. The services are fixed at
authentication; the server acknowledges a `bind` and changes nothing.

```json
{"type": "bind", "service": "kenter", "local_port": 3000}
{"type": "bind_ok", "service": "kenter", "local_port": 3000}
```

**tunnel_request** (S -> C, or C -> S with `target`)

From the proxy route (no `target`):

```json
{
  "type": "tunnel_request",
  "stream_id": 1,
  "request": {
    "method": "GET",
    "path": "/kenter/health",
    "headers": {"content-type": "application/json"},
    "body": null
  }
}
```

From a node, to relay to another node (with `target`):

```json
{
  "type": "tunnel_request",
  "stream_id": 42,
  "target": "G...",
  "request": { ... }
}
```

**tunnel_response** (C -> S)

```json
{
  "type": "tunnel_response",
  "stream_id": 1,
  "response": {
    "status_code": 200,
    "headers": {"content-type": "application/json"},
    "body": "{\"ok\":true}"
  }
}
```

The proxy reads the status from `status_code` (or `status`), defaulting to
200, and the body as a string.

**session_expired** (S -> C)

```json
{
  "type": "session_expired",
  "error": "session timeout"
}
```

Sent when the session reaches `TUNNLER_SESSION_TIMEOUT`. The server closes
the WebSocket after sending it, and the node reconnects.

---

## Authentication details

### JWT verification

1. Parse the JWT header and take `kid` (the signer's Stellar address).
2. Decode `kid` to an Ed25519 public key.
3. Verify the Ed25519 signature over `header.payload`.
4. Check `sub == kid`.
5. Check `aud` is the relay's address.
6. Check `exp` has not passed (tolerance: `TUNNLER_JWT_CLOCK_SKEW`).
7. Check `iat` is not in the future (same tolerance).
8. Check `challenge` matches the value sent.
9. Consume the challenge. It is single-use, which stops replay, and it is
   consumed even when verification fails.
10. If roster gating is on, check `sub` is a registered node.

### Client IP

The relay keys the rate limiter and the challenge binding on the client's
IP. Behind nginx, the TCP peer is nginx, so the relay reads `X-Real-IP`
instead, but **only** when the peer is in `TUNNLER_TRUSTED_PROXIES`. A client
can set any header itself; from any other peer the header is ignored and the
peer's address is used. If the header is missing or unparseable, the peer's
address is used.

### Rate limiting

Per IP, over a sliding window of `TUNNLER_RATE_LIMIT_WINDOW` seconds. Only
**failed** authentications count. After `TUNNLER_RATE_LIMIT_MAX_ATTEMPTS`
failures the IP is blocked for `TUNNLER_RATE_LIMIT_BLOCK_DURATION` seconds.
A successful authentication clears the IP's record.

### Roster gating

When `ROSTER_CONTRACT_ID` is set, the relay checks that the connecting node
is registered on that roster contract. It looks up the persistent entry
`DataKey::Node(address)` with the Soroban RPC method `getLedgerEntries`. If
the entry exists, the node is a member. Results are cached for
`TUNNLER_ROSTER_CACHE_TTL` seconds. If the RPC call fails, the node is
refused with `roster check unavailable`.

If `ROSTER_CONTRACT_ID` is empty or unset, gating is off and any key can
connect.

---

## Proxy flow

```
Wallet                   nginx              tunnler              Node
      |                    |                    |                      |
      |-- HTTPS request -->|                    |                      |
      |                    |-- /proxy/G.../p -->|                      |
      |                    |                    |-- tunnel_request --->|
      |                    |                    |    stream_id: 1      |
      |                    |                    |                      |
      |                    |                    |<-- tunnel_response --|
      |                    |                    |    stream_id: 1      |
      |                    |<-- HTTP response --|                      |
      |<-- HTTP response --|                    |                      |
```

Each proxy request gets its own `stream_id` on the node's connection. The
`tunnel_response` with the matching `stream_id` completes it. Timeout:
`TUNNLER_REQUEST_TIMEOUT`.

---

## Relay flow

Node-to-node messaging through the relay. Node A sends a `tunnel_request`
with a `target` naming node B's Stellar address.

```
Node A                      tunnler                    Node B
   |                           |                           |
   |-- tunnel_request -------->|                           |
   |   stream_id: 42           |                           |
   |   target: "G..."          |                           |
   |                           |-- tunnel_request -------->|
   |                           |   stream_id: 7 (new)      |
   |                           |                           |
   |                           |<-- tunnel_response -------|
   |                           |   stream_id: 7            |
   |<-- tunnel_response -------|                           |
   |   stream_id: 42           |                           |
```

The relay maps stream ids: A's `stream_id: 42` becomes a new id on B's
connection, and the response goes back to A under 42.

**Relay errors** come back to the source as a `tunnel_response`:

```json
{
  "type": "tunnel_response",
  "stream_id": 42,
  "response": {"status": 502, "error": "target not connected"}
}
```

Possible errors: `target not connected`, `target is busy`,
`target is not keeping up`, `target send failed`, `target disconnected`,
`relay timeout`.

---

## Limits

| Limit | Value | Effect |
|---|---|---|
| In-flight requests per connection | 256 | A further proxy request gets 503; a further relay request gets `target is busy` |
| Outbound queue per connection | 256 messages | When full, the request is shed (503, or `target is not keeping up`) rather than queued |
| Auth response deadline | 15 s | `auth_failed: auth timeout` |
| Keepalive | 30 s | Server sends `ping` |
| Stale connection sweep | 60 s | Removes dead connections and cancels their pending streams |

nginx adds its own limits in front: 5 WebSocket connections per IP on
`/connect`, 10 requests per second (burst 20) per IP on the proxy
routes, bodies capped at 64 KiB and 10-second header and body timeouts, in
the shipped configuration.

---

## Configuration

Environment variables. The relay also loads a `.env` file, found from its
working directory upward, if there is one. The hardened systemd unit gives it
an empty working directory so no stray `.env` is picked up.

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNLER_SERVER_SECRET` | **(required)** | The relay's Stellar secret seed (`S...`). Its address is the JWT audience |
| `TUNNLER_HOST` | `0.0.0.0` | Bind address. Set `127.0.0.1` behind nginx (both install paths do). A public listener exposes port 8000 directly, around nginx and its limits |
| `TUNNLER_PORT` | `8000` | Bind port |
| `TUNNLER_DOMAIN` | *(always set this)* | The relay's domain. Endpoint URLs are `https://<address>.<domain>`. It must match the relay host listed in client releases |
| `TUNNLER_LOG_LEVEL` | `info` | Tracing filter (`debug`, `info`, `warn`, `error`) |
| `TUNNLER_JWT_CLOCK_SKEW` | `60` | Clock skew tolerance, seconds |
| `TUNNLER_SESSION_TIMEOUT` | `86400` | Maximum session length, seconds |
| `TUNNLER_CHALLENGE_TTL` | `30` | How long a challenge is valid, seconds |
| `TUNNLER_RATE_LIMIT_WINDOW` | `60` | Rate limit window, seconds |
| `TUNNLER_RATE_LIMIT_MAX_ATTEMPTS` | `10` | Failed authentications before a block |
| `TUNNLER_RATE_LIMIT_BLOCK_DURATION` | `300` | Block length, seconds, after too many failed authentications |
| `TUNNLER_TRUSTED_PROXIES` | `127.0.0.1,::1` | Comma-separated peers whose `X-Real-IP` is believed. This is what makes the rate limiter per client: without it, every client behind nginx shares one bucket, and ten failures from anyone block everyone. An empty string trusts nobody (relay exposed directly). Unparseable entries are dropped |
| `TUNNLER_REQUEST_TIMEOUT` | `120` | How long a proxy or relay request waits for the node, seconds. It must be at least the client's 120 s: a node answers `/kenter/extend` only after its `confirm_link` lands |
| `ROSTER_CONTRACT_ID` | *(empty)* | Roster contract (`C...`). Empty turns gating off |
| `SOROBAN_RPC_URL` | testnet: `https://soroban-testnet.stellar.org`; mainnet build: `https://rpc.ankr.com/stellar_soroban` | Soroban RPC endpoint for roster checks |
| `SOROBAN_NETWORK_PASSPHRASE` | the build's network passphrase | Network passphrase |
| `TUNNLER_ROSTER_CACHE_TTL` | `300` | Roster membership cache, seconds |

A relay built with `--features mainnet` uses mainnet's RPC and passphrase as
its defaults.

---

## Session management

**Per-connection deadline.** Each WebSocket connection has an absolute
deadline of `now + TUNNLER_SESSION_TIMEOUT`. At the deadline the server sends
`session_expired` and closes.

**Background sweep.** Every 60 seconds a task removes stale connections from
the registry and cancels their pending streams.

**Pending stream cleanup.** When a connection closes, for any reason, all its
pending streams are cancelled, so waiting proxy and relay requests fail at
once instead of waiting for the timeout.

**Shutdown.** `ctrl+c` triggers a graceful shutdown: in-flight requests
finish, then the server exits.
