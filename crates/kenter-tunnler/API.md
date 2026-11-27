# kenter-tunnler: API

The relay. A native binary (`kenter-tunnler`), not a library: the surface
is the HTTP/WS endpoints it serves and the env vars it reads. Nodes hold a
WebSocket open to it; wallets and other nodes reach a node through it by
Stellar address. Config loads from `.env` (via `dotenvy`) or the shell
environment. Server identity is the Stellar keypair of
`TUNNLER_SERVER_SECRET`. The `mainnet` cargo feature switches the default
RPC and passphrase to mainnet.

## HTTP endpoints

Routes are declared in `server::build_router`.

| Method | Path | Handler | Notes |
|--------|------|---------|-------|
| `GET` | `/connect` | WS upgrade | Opens an authenticated tunnel session (see lifecycle). |
| `GET` | `/health` | `health_handler` | JSON `{status, version, connections, roster_gating}`. |
| `POST` | `/proxy/{stellar_address}/{*path}` | `proxy_handler` | Forwards to the connected node and returns its response, for a path in `config::PROXY_PATHS` only (`/kenter/health`, `/kenter/extend`). Body limit `MAX_PROXY_BODY` (64 KiB). |

**`/proxy` status codes:** `404` a path not in `PROXY_PATHS`; `405` a method
other than `POST`; `413` a body over `MAX_PROXY_BODY`; `400` invalid Stellar
address (not 56 chars, not `G…`, or non-alphanumeric); `502` no active tunnel, send failed, client disconnected,
or request timeout; `503` the tunnel already has `MAX_IN_FLIGHT` (256) requests
outstanding, or its outbound queue (`OUTBOUND_QUEUE`, 256) is full. The real
HTTP method, path, headers and body are forwarded in the `tunnel_request`; the
node's `status_code` (or `status`) and `body` become the HTTP response. Response headers are whitelist-filtered: `content-type`,
`content-length`, `cache-control`, `etag`, `last-modified`, `expires`,
`access-control-allow-{origin,methods,headers}`, `location`, `x-request-id`.

## Connection lifecycle (WS `/connect`)

```
S→C  auth_challenge   { challenge_id, challenge, server_address }
C→S  auth_response    { challenge_id, jwt }        (≤15s, else closed)
     [ verify JWT sig · sub==kid · aud · exp/iat · challenge · consume · roster ]
S→C  auth_ok          { endpoint, server_address, services, encryption_available }
  ── or ──
S→C  auth_failed      { error }                    (then close)
S↔C  ping/pong        keepalive, 30s
S→C  session_expired  { error }                    (at session_timeout, then close)
```

## WebSocket messages

Handled in `ws` (auth phase) and `dispatch` (authenticated phase).

| Dir | `type` | Fields | Notes |
|-----|--------|--------|-------|
| S→C | `auth_challenge` | `challenge_id` (16B hex), `challenge` (32B hex), `server_address` | Single-use, IP-bound, TTL `challenge_ttl`. |
| C→S | `auth_response` | `challenge_id`, `jwt` | JWT claims below. |
| S→C | `auth_ok` | `endpoint`, `server_address`, `services`, `encryption_available` | `endpoint` = `https://{address}.{domain}`; `encryption_available` always `false`. |
| S→C | `auth_failed` | `error` | Also sent on rate-limit before challenge. |
| S→C | `ping` / C→S `pong` | — | 30s keepalive; `pong` is ignored. |
| C→S | `bind` / S→C `bind_ok` | `service`, `local_port` | Informational; binding already done at registration. |
| S→C | `tunnel_request` | `stream_id`, `request:{method,path,headers,body}` | From proxy (no `target`). |
| C→S | `tunnel_request` | `stream_id`, `target`, `request` | Node-to-node relay (with `target` address). |
| C→S | `tunnel_response` | `stream_id`, `response:{status_code\|status, headers, body}` | Resolves the pending stream. |
| S→C | `session_expired` | `error` | At `session_timeout`; server then closes. |

**Client JWT claims** (verified by `auth::jwt::verify_client_jwt`):

| Claim | Requirement |
|-------|-------------|
| `kid` (header) | Signer's Stellar address (`G…`); its Ed25519 key verifies the sig. |
| `sub` | Must equal `kid`. |
| `aud` | Must equal the server's Stellar address. |
| `exp` / `iat` | Within `jwt_clock_skew` of now. |
| `challenge` | Must equal the issued `challenge` value. |
| `services` | Array of service names; defaults to `["kenter"]`. |

## Configuration (env vars)

Loaded by `AppConfig::from_env`.

| Variable | Default | Meaning |
|----------|---------|---------|
| `TUNNLER_SERVER_SECRET` | **required** | Server Stellar secret (`S…`). |
| `TUNNLER_HOST` | `0.0.0.0` | Bind host. |
| `TUNNLER_PORT` | `8000` | Bind port. |
| `TUNNLER_DOMAIN` | built-in placeholder; always set it | Base domain for endpoint URLs, e.g. `relay.example.org` gives `https://<G...>.relay.example.org`. |
| `TUNNLER_LOG_LEVEL` | `info` | Tracing filter (overridden by `RUST_LOG` if set). |
| `TUNNLER_JWT_CLOCK_SKEW` | `60` | `exp`/`iat` tolerance (s). |
| `TUNNLER_SESSION_TIMEOUT` | `86400` | Max session duration (s). |
| `TUNNLER_CHALLENGE_TTL` | `30` | Challenge validity (s). |
| `TUNNLER_RATE_LIMIT_WINDOW` | `60` | Auth-attempt sliding window (s). |
| `TUNNLER_RATE_LIMIT_MAX_ATTEMPTS` | `10` | Attempts before block. |
| `TUNNLER_RATE_LIMIT_BLOCK_DURATION` | `300` | Block duration (s) after too many **failed** authentications. A success clears the address's record. |
| `TUNNLER_TRUSTED_PROXIES` | `127.0.0.1,::1` | Peers whose `X-Real-IP` is believed, comma-separated. **This is what makes the auth rate limiter per-client.** The TCP peer behind nginx is nginx, so without it every client shares one bucket and ten connections from anyone block the relay for everyone. Read only from these peers: a client can set the header itself, so trusting it unconditionally lets anyone claim any address. Empty string trusts nobody (tunnler exposed directly). |
| `TUNNLER_REQUEST_TIMEOUT` | `120` | Proxy/relay response timeout (s). Must be at least the node client's own request timeout (120 s), which covers a node waiting for its `confirm_link` to land. |
| `ROSTER_CONTRACT_ID` | *(empty → off)* | Roster contract (`C…`, from the network profile or the deploy output); empty/unset = open access. With it set, only addresses on the roster may authenticate. |
| `SOROBAN_RPC_URL` | testnet: `https://soroban-testnet.stellar.org`; `mainnet` feature: `https://rpc.ankr.com/stellar_soroban` | RPC endpoint for roster checks. |
| `SOROBAN_NETWORK_PASSPHRASE` | the build's network passphrase | Network passphrase. |
| `TUNNLER_ROSTER_CACHE_TTL` | `300` | Roster membership cache TTL (s). |

## Types

- `AppConfig`: parsed env config; `bind_addr()`. `AppState::endpoint_url(addr)` builds the public URL.
- `AppState { config, server_keypair, connections, challenges, rate_limiter, roster:
  Option<RosterCache> }` — shared behind `Arc`.
- `ConnectionMap`: `DashMap<"{address}:{service}", TunnelConnection>`.
  `insert(address, service, sender, services) -> (key, generation, Arc<StreamManager>)`,
  `remove_generation(key, generation) -> bool` (removes only if a reconnect
  has not replaced the entry), `get`, `find_by_address` (prefix match),
  `count`, `expire_sessions(timeout)`, `connected_addresses`.
- `TunnelConnection { sender: mpsc::Sender<Message>, stellar_address, services, connected_at, streams, generation }`.
  The sender is bounded (`OUTBOUND_QUEUE`), so a node that stops reading
  sheds requests instead of accumulating them.
- `StreamManager { pending: DashMap<u64, oneshot::Sender<Value>>, .. }`:
  `create_stream() -> Option<(StreamGuard, Receiver)>` (`None` at
  `MAX_IN_FLIGHT`), `in_flight`, `resolve`, `cancel_all`. A `StreamGuard`
  returns its id on drop unless `answered()` was called, so a timed-out or
  failed request leaves nothing behind.
- `ChallengeStore`: `generate(ip)`, `verify` (single-use, IP-bound, TTL), `cleanup`.
- `RateLimiter`: per-IP sliding window over failed authentications;
  `check`, `record_failure`, `reset`.
- `client_ip(peer, headers, trusted) -> IpAddr`: `X-Real-IP` from a peer in
  `TUNNLER_TRUSTED_PROXIES`, else the TCP peer.
- `RosterCache` / `SorobanClient`: `is_member` / `is_node` via
  `getLedgerEntries` on `DataKey::Node(address)`; `cleanup`, `invalidate`.
- `JwtClaims { stellar_address, public_key, services, session_expires_at }`.
- `TunnlerError` (`thiserror`): `Config`, `AuthFailed`, `RateLimited`,
  `ConnectionNotFound`, `Timeout`, `Protocol`, `RosterCheckFailed`, `NotOnRoster`.

## Relay errors

Node-to-node relay failures return a `tunnel_response` to the source with
`response:{status:502, error}`, where `error` is one of `target not connected`,
`target is busy`, `target is not keeping up`, `target send failed`,
`target disconnected`, `relay timeout`.

## Notes for clients

- **`tunnel_response` status key.** The proxy reads `status_code` **or**
  `status`; relay errors emit `status`. Clients should accept both.
- **No end-to-end encryption.** `encryption_available` is always `false`:
  traffic is TLS between each party and the relay, and plaintext inside the
  relay. Shards are encrypted to the combiner's key by the protocol itself.
- **`/proxy` is unauthenticated.** Anyone can send a request to a connected
  node; the node's handlers do their own checks.
- **Endpoint URLs** are `https://{address}.{TUNNLER_DOMAIN}`. The reverse
  proxy in front (nginx) must route that subdomain to `/proxy/{address}/…`
  and set `X-Real-IP`.
- `ConnectionMap::connected_addresses` and `RosterCache::invalidate` are
  public but not called by the binary.
