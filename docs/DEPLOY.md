# Deployment

Kenter has two deployed parts: the **contracts** (the mint and the roster,
on Soroban) and the **relay** (`kenter-tunnler`, on a server). Nodes are
not deployed centrally. Operators install them from the MSI or the `.deb`
([Testnet environment](/TESTNET), "Running a node on testnet").

This page covers both deployed parts, plus the **rent keeper**, a small
timer job that keeps the contracts' storage rent paid.

---

# The contracts

`scripts/deploy_testnet.sh` deploys a roster and a mint. It deploys to
**testnet only**: the network passphrase is pinned, and the script refuses
any other. Mainnet has its own script, `scripts/deploy_mainnet.sh`; see
[Deploying to mainnet](#deploying-to-mainnet).

## Before you start

- The `stellar` CLI, with the deployer as a keystore alias (`DEPLOYER`,
  default `testnet-deployer`). Node identities are aliases too
  (`NODE_ALIASES`, default `kenter-node-1 kenter-node-1p`). No secret is
  ever passed on a command line.
- The two asset contracts: `XLM_SAC` and `USDC_SAC` in the environment, or
  `XLM_SAC_CONTRACT_ID` and `USDC_SAC_CONTRACT_ID` in `.env`. The script
  reads only those two values from `.env`; it does not source the file.
  [Testnet environment](/TESTNET) shows how to look up both.
- Python, for `scripts/budget_gate.py`.
- The pinned toolchain from `rust-toolchain.toml` (rustup picks it up
  automatically), with the `wasm32v1-none` target.

## Running it

```bash
DRY_RUN=1 scripts/deploy_testnet.sh          # print every command, send nothing
scripts/deploy_testnet.sh                    # build, gate, deploy both, warm, register nodes
DEPLOY_WHAT=roster scripts/deploy_testnet.sh # just the roster
DEPLOY_WHAT=mint ROSTER_ID=C... scripts/deploy_testnet.sh   # a new mint on an existing roster
DEPLOY_WHAT=warm ROSTER_ID=C... MINT_ID=C... scripts/deploy_testnet.sh
DEPLOY_WHAT=nodes ROSTER_ID=C... scripts/deploy_testnet.sh  # just register the node aliases
PREBUILT_DIR=dir scripts/deploy_testnet.sh   # deploy wasm built elsewhere instead of building
```

`PREBUILT_DIR` names a folder holding `kenter_mint.wasm` and
`kenter_roster.wasm`, built from the same commit on another machine. Use it
to put the Linux build on testnet from a machine that is not Linux, so
testnet runs the bytes mainnet will. The files are copied where a local
build would go, so the budget checks measure them; their hashes are
printed.

`DRY_RUN` accepts `1`/`true`/`yes`/`y`/`on` and their opposites. It
refuses anything else rather than guess, since a wrong guess spends a
deploy.

The steps, in order:

1. **Build.** `stellar contract build` for both contracts. Not
   `cargo build`: the stellar build adds contract metadata, and its output
   is what the deployed hash is checked against.
2. **Budget gate.** Two wasm benches (`bench_pathb_wasm` and
   `pathb_owned_at_the_ceiling_fits_the_budget_wasm`) must each report
   exactly one passing test. A test filter that matches nothing exits 0,
   so the script checks the result line, not the exit code. Then
   `scripts/budget_gate.py` checks `max_pairs` against the target
   network's live cost table and `tx_max_instructions`, and refuses
   anything above half the limit. A note printed above the budget can
   never be redeemed by chain, and the mint is immutable.
   `SKIP_BUDGET_CHECK=1` skips the gate.
3. **Roster.** `--min_stake`, `--pay_token` (the native XLM SAC),
   `--unbonding_ledgers`. The roster has no admin.
4. **Mint.** `--node_fee`, `--min_pairs`, `--max_pairs`, `--pay_token`
   (the USDC SAC), `--roster`, `--max_print_ledgers` and `--selection`
   (below). The pay token cannot be native XLM: volunteers' fees are
   burned, and the XLM SAC cannot burn.
5. **Warm.** `bump --send=yes` on each contract, from the deployer. A
   fresh contract sits at the minimum TTL, and the first call to cross the
   bump threshold pays to extend everything it touches, code entry
   included. On testnet that first extension costs about 19 XLM, against
   under 0.1 XLM for the same call afterwards. The warm step puts that bill
   on the deployer instead of the first node to join. `--send=yes` is
   required: without it the CLI treats `bump` as read-only and quietly
   sends nothing. Runs with `DEPLOY_WHAT=all` or `warm`. A mint-only deploy
   does not warm, so follow it with `DEPLOY_WHAT=warm`.
6. **Nodes.** `join` on the roster for each alias in `NODE_ALIASES`, with
   the placeholder endpoint `pending`. This step is optional: a running
   node daemon joins the roster and registers its pair by itself, and
   overwrites the endpoint on its first heartbeat.

The script prints the new ids and writes nothing into tracked files. Put
them where the clients read them: the `TESTNET` profile in
`crates/kenter-client/src/network.rs`, or `KENTER_MINT` / `KENTER_ROSTER`
for a local override. Then check the deployed bytecode against the local
build (`stellar contract fetch`, as shown in [Testnet environment](/TESTNET)).

**Redeploying the roster means redeploying the mint**, because the mint is
pinned to a roster address. A new mint on the same roster keeps every
node's stake. Each node registers its pair with the new mint on its next
start.

## Constructor arguments

All of these are immutable after deploy. Each is an environment variable of
the script. The defaults are the mainnet values, except `MIN_NODE_AGE`.

**Mint** (`contracts/kenter-mint/API.md`):

| Variable | Argument | Default | Notes |
|---|---|---|---|
| `NODE_FEE` | `node_fee` | 25 000 | stroops of the pay token per interior participant |
| `MIN_PAIRS` | `min_pairs` | 3 | the constructor refuses less than 3 |
| `MAX_PAIRS` | `max_pairs` | 8 | the constructor refuses more than 12 (`MAX_REDEEMABLE_PAIRS`) |
| `MAX_PRINT_LEDGERS` | `max_print_ledgers` | 17 280 | how long a print may stay open: about one day at 5 s ledgers |
| from `.env` | `pay_token` | the USDC SAC | |
| `ROSTER_ID` | `roster` | the roster just deployed | |
| see below | `selection` | | `SelectionConfig` |

**`selection`** is passed as one JSON object. It configures the
drand-seeded node draw described in
[Node selection](/architecture/node-selection):

| Variable | Field | Default | Notes |
|---|---|---|---|
| `BEACON_PK` | `beacon_pk` | drand quicknet's group key | G2, uncompressed, 192 bytes in hex |
| `BEACON_GENESIS` | `beacon_genesis` | 1692803367 | quicknet genesis, Unix seconds |
| `BEACON_PERIOD` | `beacon_period` | 3 | seconds per round |
| `BEACON_LEAD` | `beacon_lead` | 20 | rounds between the request and the seeding round (60 s) |
| `CLAIM_WINDOW` | `claim_window` | 6 | ledgers pairs may claim after the seed |
| `SERVE_TIMEOUT` | `serve_timeout` | 12 | ledgers before a silent selected pair may be skipped |
| `MIN_NODE_AGE` | `min_node_age` | 0 | ledgers an address must be on the roster before its pair registers or claims. 0 suits testnet; mainnet uses 17 280 (about a day) |
| `FALLBACK_DELAY` | `fallback_delay` | 600 | seconds after a round is due before `seed_fallback` may seed a slot nobody seeded from the beacon. At least 300; the script also refuses a delay that would open after the first half of the print window |

The constructor panics with `InvalidConfig` on a zero period, lead, claim
window or serve timeout, on a claim window not shorter than
`max_print_ledgers`, on a `fallback_delay` under 300 seconds, on the
identity point as beacon key, and on a key
that is not a G2 point in the subgroup. drand quicknet is the same public
chain on testnet and mainnet.

**Roster:**

| Variable | Argument | Default | Notes |
|---|---|---|---|
| `MIN_STAKE` | `min_stake` | 1 500 000 000 | 150 XLM per address |
| `UNBONDING_LEDGERS` | `unbonding_ledgers` | 120 960 | one week at 5 s ledgers; lower it (e.g. 720) only for fast testnet iteration |
| from `.env` | `pay_token` | the native XLM SAC | |

The values of the current testnet deployment are in
[Testnet environment](/TESTNET).

## After deploy: rent

The warm step is not a one-off. Contract TTLs decay, and the bump threshold
is crossed again about every 90 days. Run `bump` on a schedule: see
[The rent keeper](#the-rent-keeper) below and [Ledger costs](/LEDGER_COSTS).

## Deploying to mainnet

`scripts/deploy_mainnet.sh` deploys the roster and the mint to mainnet,
pays their first TTL extension, checks the result, and writes a deploy
record. Its constructor values are fixed in the script, not taken from the
environment: they are the testnet defaults, except `min_node_age`, which is
17 280 (about a day).

The script refuses to run unless:

- the host is **x86_64 Linux**: contract builds differ between platforms,
  and the published hashes are the x86_64 Linux build (see
  [Setting up](/runbook/setup#toolchain));
- `HEAD` is a **signed release tag** that verifies against
  `allowed_signers`, and the working tree is clean;
- `rustc` and the `stellar` CLI are the pinned versions;
- there is **no `.env`** in the repository root, which the CLI would load;
- network traffic leaves **through Tor** (`torsocks`, which refuses any
  connection it can't route through Tor);
- the submitting and verifying RPCs are different, both answer as mainnet,
  and both are healthy;
- the USDC and XLM asset contracts, derived from their assets rather than
  configured, answer on chain as `USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`
  and `native`;
- the deployer holds at least `MIN_DEPLOYER_XLM` (default 100).

Then it builds both contracts, runs the same budget gate as the testnet
script against mainnet's cost table, prints every value it is about to fix,
and waits for `deploy mainnet` to be typed.

```bash
DRY_RUN=1 scripts/deploy_mainnet.sh     # every check, build and gate; deploys nothing
scripts/deploy_mainnet.sh
```

| Variable | Default | Meaning |
|---|---|---|
| `DEPLOYER` | `kntr-deployer` | `stellar` CLI key alias that pays for the deploy |
| `RPC_URL` | `https://rpc.lightsail.network` | RPC the deploy is submitted through |
| `VERIFY_RPC_URL` | `https://mainnet.sorobanrpc.com` | A different operator's RPC, used only to check the result |
| `EXPECT_MINT_SHA`, `EXPECT_ROSTER_SHA` | unset | Wasm hashes from a second Linux build of the same tag; the deploy stops if the local build differs |
| `MIN_DEPLOYER_XLM` | 100 | Balance required before deploying |
| `DEPLOY_WHAT` | `all` | `mint` (with `ROSTER_ID`) resumes after a failed mint; `warm` and `verify` (with both ids) rerun those steps |

After deploying, the script fetches both contracts' code through
`VERIFY_RPC_URL`, compares its hash with the local build, and reads every
constructor value back. It writes `dist/mainnet-deploy-<tag>.txt` with the
ids, hashes, values, the tag, and the ledger it was verified at: publish it
with the release.

**Funds.** A deploy prepays code rent (about 60 XLM, estimated from
testnet), and the warm step pays the first TTL extension (about 15 to 19
XLM). Measure both on mainnet right after deploy. After that the rent is
ongoing: see [The rent keeper](#the-rent-keeper).

**Release build.** Clients are built with `--features kenter-client/mainnet`
and with `KENTER_MAINNET_MINT`, `KENTER_MAINNET_ROSTER` and
`KENTER_MAINNET_RELAYS` set (the MSI's `-Mainnet` switch, the `.deb`'s
`MAINNET=1`). A mainnet build has its contracts baked in and cannot be
pointed at others; built without them, it refuses to start. Built without
relays, it reaches no node. Run the mainnet relay on its own host, separate
from any testnet relay.

---

# The relay: kenter-tunnler

`kenter-tunnler` is a WebSocket relay. Nodes sit behind NAT, so each one
opens an outbound WebSocket to a relay and keeps it open. Wallets reach a
node with plain HTTPS to the relay's `/proxy/<node address>/<path>` route,
and the relay forwards the request down that node's WebSocket. The wire
protocol is in [Relay API](/tunnler-api).

## How the parts fit

```
Internet
   |
   v
[nginx]  ports 80/443, TLS termination, rate limits
   |
   v
[kenter-tunnler]  127.0.0.1:8000, WebSocket relay, roster gating
   |
   v
[Soroban RPC]  on-chain roster membership checks (optional)
```

No database. All state is in memory. Roster membership is read from the
roster contract over Soroban RPC on demand, and cached.

### Which relays a wallet uses

Each release has a built-in list of relays (`Profile::relays` in
`crates/kenter-client/src/network.rs`). When a wallet prints, it looks up
each selected node's endpoint on the roster. The endpoint has the form
`https://<node address>.<relay host>`, and the wallet turns it into
`https://<relay host>/proxy/<node address>/...`. If the relay host is not
on the build's list, the wallet treats the node as one that does not serve
and skips it. Without this check, a node operator could name a relay of
their own and learn the IP address of every depositor their pair serves.

Three consequences for a relay operator:

- `TUNNLER_DOMAIN` must be exactly the host listed in the release. The
  relay builds each node's endpoint from it (`https://<G...>.<TUNNLER_DOMAIN>`),
  and the node records that endpoint on the roster.
- Wallets only use the `/proxy` route on the base domain. Wildcard DNS
  (`*.relay.example.org`) is needed only if you also want the per-node
  subdomain form to resolve.
- A new relay is usable by wallets only after a release lists it.

Nodes name their relays in their own config. `kenter-node` uses one
default relay until the operator names others; see
`DEFAULT_RELAY` in `crates/kenter-node/src/config.rs`.

## Three ways to install

| | `packaging/relay/install-relay.sh` | `packaging/relay/setup-relay.sh` | `scripts/vps_startup.sh` |
|---|---|---|---|
| Host | a fresh Debian/Ubuntu VPS | already runs nginx with TLS for the domain | a fresh Ubuntu/Debian VPS |
| Binary | a signed relay release, verified before anything runs | a prebuilt x86_64 Linux binary you copy over | built on the server from a git checkout |
| Runs as | system user `kenter-relay`, hardened systemd unit | the same | user `kenter`, plain systemd unit |
| Identity key | `/etc/kenter-tunnler/env` (root, 0600), made on the relay | the same | `/home/kenter/kenter/.env` (0600) |
| nginx | written for you: base domain only, TLS, limits, no access log | you configure it | written for you, including the TLS vhosts |
| Also | firewall, key-only SSH, SSH as a Tor onion service | nothing else | nothing else |
| Roster gating | on (from the release) | on (`ROSTER=` is required) | off until you set `ROSTER_CONTRACT_ID` |

Use `install-relay.sh` on a fresh VPS, and `setup-relay.sh` where nginx is
already yours. Both run the relay with no capabilities, a read-only
filesystem, no home directory access and a system-call filter, and the
relay's secret never sits in a user-writable directory.

## Install with install-relay.sh

A relay release (tag `relay-vX.Y.Z`) holds the binary, the unit, the
installer and `relay.env` (network, domain, roster), listed in a signed
`SHA256SUMS`. On the VPS, as root:

```sh
curl -fsSLO https://github.com/kenter-vault/kenter/releases/download/relay-v0.1.0/install-relay.sh
grep '^SIGNERS=' install-relay.sh      # must match allowed_signers in a fresh clone
sh install-relay.sh relay-v0.1.0
```

It checks the signature on `SHA256SUMS` against the key pinned in the
script, every file against `SHA256SUMS`, and that `RELEASE` names the tag
(so an older release can't pose as a newer one), before installing anything.
Then it installs the relay, gets a certificate (point the domain's A and
AAAA records at the VPS first; it checks), writes nginx and the firewall,
makes SSH key-only and publishes it as an onion service. It prints the
onion address and sets a root password for the provider's console, shown
once.

| Setting (environment) | Meaning |
|---|---|
| `DOMAIN` | the relay's name, if not the release's; it must be a relay the wallet builds list |
| `ONION_AUTH` | `descriptor:x25519:<base32>`, one per machine, separated by spaces: only these Tor client keys can reach SSH's onion |
| `SKIP_DNS_CHECK=1` | behind NAT, where the domain can't resolve to an address of the machine |

Once you can log in through the onion, run `sh install-relay.sh --close-ssh`
from that session to close public SSH; it refuses from any other session.
To let another machine reach the onion later, run
`sh install-relay.sh --onion-client NAME descriptor:x25519:<base32>` on the relay.
Run the installer again with a new tag to update. The relay's key, the
certificate and the onion are kept.

## Install with setup-relay.sh

### Build the binary

On a build machine:

```bash
cargo install cargo-zigbuild    # needs zig on PATH
cargo zigbuild --release -p kenter-tunnler --features vendored-openssl \
  --target x86_64-unknown-linux-gnu.2.31
```

`vendored-openssl` builds OpenSSL from source instead of linking the
system's, and the `.2.31` suffix targets glibc 2.31. The result runs on any
x86_64 Linux distribution with glibc 2.31 or newer. For a mainnet relay, add
`--features mainnet` (comma-separated with the other feature): it changes
the default RPC endpoint and network passphrase used for roster checks.

### Run the script

Copy these into one directory on the server:

- `target/x86_64-unknown-linux-gnu/release/kenter-tunnler`
- `packaging/relay/kenter-tunnler.service`
- `packaging/relay/gen-relay-key.py`
- `packaging/relay/setup-relay.sh`

Then, as root, from that directory:

```bash
DOMAIN=relay.example.org ROSTER=C... ./setup-relay.sh
```

`ROSTER` is the roster contract id (from `crates/kenter-client/src/network.rs`
or your deploy output). `PORT` defaults to 8000.

The script:

1. Creates the system user `kenter-relay`.
2. Installs the binary to `/usr/local/bin/kenter-tunnler`.
3. On first run, generates the relay's Stellar identity **on the server**
   (`gen-relay-key.py`) and writes it, with `TUNNLER_HOST=127.0.0.1`, the
   port, the domain and the roster id, to `/etc/kenter-tunnler/env`
   (root, 0600). systemd reads the file as root before dropping privileges.
4. On a rerun, keeps the existing key and refreshes the domain, roster and
   port.
5. Installs and starts `kenter-tunnler.service`.

To change any other setting (see [Configuration](/tunnler-api#configuration)),
edit `/etc/kenter-tunnler/env` and `systemctl restart kenter-tunnler`.

### Configure nginx

nginx must terminate TLS for the domain and forward two things to
`127.0.0.1:8000`:

- `/connect`, as a WebSocket upgrade with long timeouts (a node holds the
  connection for up to 24 hours).
- Everything else, including `/proxy/...` and `/health`, with a read
  timeout above the relay's 120-second request timeout. A node answers an
  `extend` only after its on-chain `confirm_link` lands, which can take
  most of a minute; nginx's default 60-second read timeout cuts that off.

Both locations must set `X-Real-IP` from `$remote_addr`. The relay keys its
auth rate limiter and challenge binding on that header, and believes it only
from a peer in `TUNNLER_TRUSTED_PROXIES` (loopback by default).

A minimal server block:

```nginx
limit_conn_zone $binary_remote_addr zone=ws_conn:10m;
limit_req_zone  $binary_remote_addr zone=proxy_req:10m rate=10r/s;
limit_req_status 429;

upstream tunnler {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name relay.example.org;

    ssl_certificate     /etc/letsencrypt/live/relay.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.org/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 64k;
    client_header_timeout 10s;
    client_body_timeout 10s;

    location /connect {
        limit_conn ws_conn 5;
        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    location / {
        limit_req zone=proxy_req burst=20 nodelay;
        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 150;
    }
}
```

`/proxy` takes no authentication: anyone can aim requests at a connected
node. The relay forwards only `POST` to `/kenter/health` and
`/kenter/extend`, with bodies up to 64 KiB, and caps its own in-flight work
per node (see [Relay API](/tunnler-api#limits)). The `limit_req` zone, body
cap and timeouts stop a flood before it reaches the relay at all.

### Verify

```bash
systemctl status kenter-tunnler
journalctl -u kenter-tunnler -n 20      # look for "roster gating ENABLED"
curl https://relay.example.org/health
```

When a node connects, the relay logs `authenticated` with the node's
address. `curl https://relay.example.org/proxy/<G...>/kenter/health` then
reaches that node through the relay.

### Update

Build a new binary, copy it next to the other files, and rerun
`setup-relay.sh`. It keeps the key and restarts the service.

## Install with vps_startup.sh

`scripts/vps_startup.sh` takes a fresh Ubuntu/Debian VPS (cloud VMs or
container VPSes such as OpenVZ and LXC) to a running relay behind nginx.

### Prerequisites

- Ubuntu 22.04 or newer (Debian works too), with root access.
- A domain you control, with an A record for it and, if you want the
  per-node subdomain form, a wildcard record.
- Ports 22, 80 and 443 reachable.

### Step 1: configure the script

Edit the top of `scripts/vps_startup.sh`:

```bash
DOMAIN="relay.example.org"
REPO_URL="https://github.com/kenter-vault/kenter.git"
REPO_BRANCH="main"
KENTER_USER="kenter"
LOG_LEVEL="info"
GITHUB_TOKEN=""
```

| Variable | Meaning |
|---|---|
| `DOMAIN` | The relay's domain. Nodes connect to `wss://DOMAIN/connect` and get endpoints like `https://<G...>.DOMAIN` |
| `REPO_URL` | Git repository to clone. Change it if you use a fork |
| `REPO_BRANCH` | Branch to build |
| `KENTER_USER` | Linux user that owns the checkout and runs the service |
| `GITHUB_TOKEN` | A read-only token, only if the repository is private. Leave empty otherwise |
| `LOG_LEVEL` | Tracing filter level (`debug`, `info`, `warn`, `error`) |

For a private fork, create a fine-grained GitHub token with read-only
access to the repository's contents, and set `GITHUB_TOKEN` to it.

### Step 2: configure DNS

| Name | Type | Value |
|---|---|---|
| `relay.example.org` | A | your VPS IP |
| `*.relay.example.org` | A | your VPS IP (optional, see above) |

Check it resolves:

```bash
dig +short relay.example.org
```

### Step 3: run the script

```bash
scp scripts/vps_startup.sh root@YOUR_VPS_IP:/root/
ssh root@YOUR_VPS_IP
chmod +x vps_startup.sh
./vps_startup.sh
```

It can also be pasted into a provider's cloud-init "user data" field. Its
output goes to `/var/log/kenter-startup.log`. It is safe to rerun: a marker
in `/var/lib/kenter-tunnler/` records a finished install, and a rerun only
checks that the services are up.

The script:

1. Installs build dependencies, nginx and certbot.
2. Opens ports 22, 80 and 443 in ufw. It skips this on container VPSes and
   when ufw is already active.
3. Creates the Linux account `kenter`.
4. Installs Rust with rustup, as that user.
5. Clones the repository to `/home/kenter/kenter`.
6. Builds `cargo build --release -p kenter-tunnler`.
7. Writes `/home/kenter/kenter/.env` (0600) with the relay's settings,
   unless one exists already.
8. Installs and enables `kenter-tunnler.service`.
9. Writes the nginx config: a port-80 site that serves only ACME challenges
   and redirects, and a separate TLS site, staged but not enabled.
10. Starts the services and prints the remaining steps.

### Step 4: set the relay's identity and options

Check `/home/kenter/kenter/.env`:

```bash
sudo -u kenter nano /home/kenter/kenter/.env
```

`TUNNLER_SERVER_SECRET` must hold a Stellar secret seed (`S...`). If the
script could not generate one, it writes the placeholder
`REPLACE_WITH_YOUR_STELLAR_SECRET_KEY` and the service will not start.
`packaging/relay/gen-relay-key.py` generates a seed on the server and prints
it to stdout; paste it into the file:

```bash
python3 gen-relay-key.py
```

To turn on roster gating, set the roster contract:

```bash
ROSTER_CONTRACT_ID=C...
SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
SOROBAN_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
TUNNLER_ROSTER_CACHE_TTL=300
```

For mainnet, use the mainnet roster, a mainnet RPC endpoint and the mainnet
passphrase (`Public Global Stellar Network ; September 2015`).

Every variable is described under [Configuration](/tunnler-api#configuration).
Keep `TUNNLER_HOST=127.0.0.1`: nginx proxies from loopback, and a public
listener would expose port 8000 directly, around nginx and its limits.

Restart and check:

```bash
sudo systemctl restart kenter-tunnler
journalctl -u kenter-tunnler -n 20
# Look for "roster gating ENABLED" or "roster gating disabled"
```

### Step 5: install the TLS certificate

Until this step, the relay answers nothing useful. Port 80 serves only the
ACME challenge and a redirect, and there is no 443 listener. This is
deliberate: a listener that answers before TLS is set up would carry the
WebSocket handshake, JWT included, in cleartext.

**5a. Obtain a certificate.** A wildcard needs a DNS challenge:

```bash
# On a container VPS, set PATH first:
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

certbot certonly --manual --preferred-challenges dns \
  -d relay.example.org -d "*.relay.example.org"
```

When certbot prompts:

1. Add the TXT record `_acme-challenge.relay.example.org` with the value
   certbot shows.
2. Wait a minute or two, then check:
   `dig +short TXT _acme-challenge.relay.example.org`
3. Press Enter.

Without the wildcard, an HTTP challenge is enough, since the port-80 site
already serves `/.well-known/acme-challenge/` from `/var/www/acme`:

```bash
certbot certonly --webroot -w /var/www/acme -d relay.example.org
```

The certificate lands in `/etc/letsencrypt/live/relay.example.org/`, which
is where the staged TLS site expects it.

**5b. Enable the TLS site:**

```bash
ln -sf /etc/nginx/sites-available/kenter-tunnler-ssl /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

Do not use `certbot install --nginx`. It copies the port-80 server block,
which here is only a challenge and a redirect, so it would build a 443 block
that redirects to itself.

If `nginx -t` reports a missing certificate file, 5a did not finish.

### Step 6: verify

```bash
systemctl status kenter-tunnler
systemctl status nginx
curl https://relay.example.org/health
journalctl -u kenter-tunnler -f
```

### The nginx config it writes

| Site | Serves |
|---|---|
| `kenter-tunnler`, port 80, base domain and subdomains | ACME challenges; everything else redirects to HTTPS |
| `kenter-tunnler-ssl`, base domain | `/connect` (WebSocket, 5 connections per IP, 24 h timeouts) and everything else, `/proxy` and `/health` included (10 requests/s per IP, burst 20) |
| `kenter-tunnler-ssl`, `*.relay.example.org` | every request, rewritten to `/proxy/<G...>/<path>` (10 requests/s per IP, burst 20) |
| default server, port 443 | custom domains, rewritten to `/proxy` |

Every HTTPS site caps bodies at 64 KiB and has 10-second header and body
timeouts. Upstream keepalive is 32 connections. Every site sends `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy` and HSTS headers. The base
domain's `location /` needs `proxy_read_timeout 150` for `/proxy`
requests (see [Configure nginx](#configure-nginx)).

`config/nginx-kenter-tunnler.conf` is the same configuration as a single
file, for a host where you manage nginx yourself. Replace the domain in its
`server_name`, `map` and certificate lines before using it.

### Updating

Pull and rebuild:

```bash
cd /home/kenter/kenter
sudo -u kenter git pull
sudo -u kenter bash -c 'source "$HOME/.cargo/env" && cargo build --release -p kenter-tunnler'
sudo systemctl restart kenter-tunnler
```

Or replace the binary with one built elsewhere (see
[Build the binary](#build-the-binary)):

```bash
sudo systemctl stop kenter-tunnler
sudo -u kenter cp /path/to/kenter-tunnler /home/kenter/kenter/target/release/
sudo systemctl start kenter-tunnler
```

To change the nginx config, edit the files in `/etc/nginx/sites-available/`
and run `nginx -t && systemctl reload nginx`. The TLS site is a separate
file, so editing the port-80 site does not touch it.

### The systemd unit

The script installs this unit. To install it by hand:

```ini
# /etc/systemd/system/kenter-tunnler.service
[Unit]
Description=Kenter Tunnler Service
After=network.target

[Service]
Type=simple
User=kenter
WorkingDirectory=/home/kenter/kenter
EnvironmentFile=/home/kenter/kenter/.env
ExecStart=/home/kenter/kenter/target/release/kenter-tunnler
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kenter-tunnler
```

## Troubleshooting the relay

**The service will not start.** `journalctl -u kenter-tunnler -n 50`.
Common causes: `TUNNLER_SERVER_SECRET` missing, still the placeholder, or not
a valid `S...` seed; port 8000 already in use.

**Nodes are refused with `not on roster`.** Roster gating is on and the
node's address has no `Node` entry on that roster. Check `ROSTER_CONTRACT_ID`
is the roster the node joined. `roster check unavailable` means the RPC call
failed: check `SOROBAN_RPC_URL`.

**Everyone is rate limited at once.** The relay is seeing nginx's address
for every client. Check nginx sets `X-Real-IP` and that nginx's address is
in `TUNNLER_TRUSTED_PROXIES`.

**Prints fail with a 504 from nginx.** The `location` serving `/proxy` has
nginx's default 60-second read timeout. Set `proxy_read_timeout 150`.

**PATH problems on a container VPS.** OpenVZ and LXC images often have a
minimal PATH:

```bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
echo 'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"' >> ~/.bashrc
```

**certbot: "Challenge failed".** Check the TXT record and wait a few minutes
for DNS:

```bash
dig +short TXT _acme-challenge.relay.example.org
```

**Connection refused.** Check `ufw status` (80 and 443 allowed), the
provider's firewall, and `curl http://localhost:8000/health` on the server.

**Subdomains do not route.** The nginx `map` must match your domain:

```nginx
map $host $stellar_address {
    ~*^(?<addr>[A-Za-z0-9]+)\.relay\.example\.org$ $addr;
    default "";
}
```

**Logs:**

```bash
journalctl -u kenter-tunnler -f        # the relay
tail -f /var/log/nginx/error.log       # nginx
cat /var/log/kenter-startup.log        # vps_startup.sh
```

## A local relay for development

The system test starts its own relay. By hand:

```bash
# Roster gating off (ROSTER_CONTRACT_ID unset), so any key can connect.
TUNNLER_SERVER_SECRET=<S...> TUNNLER_HOST=127.0.0.1 TUNNLER_PORT=8000 cargo run -p kenter-tunnler
# listening on 127.0.0.1:8000  (HTTP/WS, no TLS)
```

`kenter-node` uses plain `ws://` for a relay on `127.0.0.1`, `localhost` or
`[::1]` (`--insecure` in the development form). A wallet does not reach
nodes through a local relay, because it is not on the build's relay list.
`kenter print-net --relay <host> --insecure` and the system test can. See
[A local network](/runbook/local-network).

An end-to-end test of the plaintext path is in
`crates/kenter-tunnler/src/local_tunnel_test.rs`
(`cargo test -p kenter-tunnler local_tunnel`).

A local relay does not exercise NAT traversal, the `wss://` path, real
latency against the auth and request timeouts, or clock skew.

---

# The rent keeper

The keeper is not part of the relay, but a relay VPS is a natural host: it
is always on and already runs systemd.

Both contracts charge themselves storage rent, and both top up lazily: only
once an entry is within 30 days of archival, and then out to 120 days. That
keeps rent off an ordinary caller's bill, but one arbitrary transaction
pays the whole top-up. On testnet that lump is about **34 XLM**, against
about **0.0011 XLM** for a warm call, and it lands on whoever calls next: a
depositor, a node joining, a holder redeeming.

`scripts/keeper.sh` pays it on purpose instead. It calls `bump()` on both
contracts, which tops them up whatever their remaining life. Run often,
each run is cheap and the lazy threshold is never reached. The figures are
in [Ledger costs](/LEDGER_COSTS).

## Install

The keeper needs the `stellar` CLI on the host, and a checkout of the
repository for the script. It signs as a stellar-CLI keystore **alias**,
never a key on a command line:

```bash
stellar keys add kenter-keeper --secret-key   # prompts; nothing reaches argv
```

It reads the contract ids from `KENTER_MINT` and `KENTER_ROSTER` in the
checkout's `.env` (or from `MINT` and `ROSTER` in the environment). The
defaults are testnet's RPC and passphrase; set `RPC_URL` and `PASSPHRASE`
for mainnet.

```ini
# /etc/systemd/system/kenter-keeper.service
[Unit]
Description=Kenter contract rent keeper
After=network-online.target

[Service]
Type=oneshot
User=kenter
WorkingDirectory=/home/kenter/kenter
Environment=KEEPER=kenter-keeper
ExecStart=/home/kenter/kenter/scripts/keeper.sh
```

```ini
# /etc/systemd/system/kenter-keeper.timer
[Unit]
Description=Pay Kenter contract rent daily

[Timer]
OnCalendar=daily
# Spread the load, and make a missed window catch up on next boot
# rather than waiting a day.
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now kenter-keeper.timer
systemctl list-timers kenter-keeper.timer
journalctl -u kenter-keeper.service -n 20
```

The script exits non-zero if either bump fails, so the unit reports it.
It is safe at any cadence: a second run in the same ledger costs nothing.
`DRY_RUN=1` prints the commands without sending them.

## Cadence

Daily is the recommendation. Rent is charged for elapsed ledgers, so the
cadence changes the number of transactions, not the rent. What it changes
is exposure.

| Cadence | Per-call overhead | Risk |
|---|---|---|
| Daily | ~2.9 XLM/yr | Each run pays a day; 90 consecutive failures before a user is exposed |
| Weekly | ~0.4 XLM/yr | Each run pays a week |
| Never | — | One arbitrary user pays ~34 XLM, roughly every 90 days |

## Checking it by hand

```bash
stellar contract invoke --id "$KENTER_MINT" --source-account kenter-keeper \
  --rpc-url "$RPC" --network-passphrase "$PASSPHRASE" --send=yes -- bump
```

> **`--send=yes` is required, and leaving it out fails silently.** `bump`
> only extends TTLs, so the simulation's `read_write` footprint is empty and
> the CLI classifies the call as read-only. Without the flag it declines to
> submit: it prints a plausible new TTL ledger, exits zero, and changes
> nothing.

The keeper does **not** bump notes. A note's record is the holder's to keep
current with `bump_token(slot_id, ledgers)`; see [Ledger costs](/LEDGER_COSTS).

---

# Testnet reference

Contract addresses, deploy parameters and the stellar-CLI `.env` pitfall
are in [Testnet environment](/TESTNET).
