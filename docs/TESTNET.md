# Testnet

Kenter's development network is Stellar **testnet**. Testnet XLM and
testnet USDC have no value, so everything in Kenter can be exercised there
for free: printing notes, paying, redeeming, running a node, and deploying
your own mint and roster.

This page covers what a testnet build talks to, how to fund accounts, how to
point a wallet or node at a deployment, and how to deploy one.

## What a testnet build talks to

The network is fixed when a binary is built. A build without the `mainnet`
feature is a testnet build, and nothing set at runtime turns it into a
mainnet one, or the reverse. Each build carries a **network profile**, in
`crates/kenter-client/src/network.rs`:

| Field | Testnet profile |
|---|---|
| passphrase | `Test SDF Network ; September 2015` |
| RPC | `https://soroban-testnet.stellar.org` |
| Horizon | `https://horizon-testnet.stellar.org` |
| mint, roster | the default testnet deployment's contract IDs |
| relays | the relays a wallet reaches selected nodes through |
| contract overrides | allowed |

The contract IDs of the default deployment live in that file, not in the
docs. A client prints the mint and roster it resolved at startup
(`kenter: mint … | roster …`), so you can always see which deployment it
is using.

A mainnet build differs in two ways that matter here: its mint and roster
are baked in at build time from `KENTER_MAINNET_MINT` and
`KENTER_MAINNET_ROSTER` and cannot be overridden, and it refuses to start if
it was built without them.

## Pointing the wallet and node at a deployment

Every component (wallet, desktop CLI, node, system test) resolves its network
the same way: the profile, then overrides.

| Variable | What it changes | Testnet | Mainnet |
|---|---|---|---|
| `KENTER_RPC` | Soroban RPC endpoint | yes | yes |
| `KENTER_HORIZON` | Horizon endpoint (account reads) | yes | yes |
| `KENTER_MINT` | mint contract | yes | refused |
| `KENTER_ROSTER` | roster contract | yes | refused |

Blank values count as unset. A custom RPC endpoint is checked against the
build's passphrase before it is trusted, so a testnet build pointed at a
mainnet server is refused rather than discovered later.

- **Wallet.** Set the variables before starting `kenter-ui`. The RPC
  endpoint can also be set in Settings; an environment variable wins over
  the saved value. The wallet has no node list and no relay setting: it
  reaches selected nodes only through the relays in the profile.
- **Node.** `kenter-node` takes its RPC from `rpc` in its `node.json`, else
  `KENTER_RPC`, else the profile. The mint and roster come from the profile
  or `KENTER_MINT` / `KENTER_ROSTER`.
- **Your own deployment.** Export `KENTER_MINT` and `KENTER_ROSTER` with the
  IDs the deploy script prints (see below) in every shell that runs a
  client or a node. A mint and its roster go together: the mint is pinned to
  one roster address by its constructor.

## Getting testnet XLM and USDC

### XLM

Friendbot creates an account and gives it 10 000 XLM, once per account:

```bash
curl "https://friendbot.stellar.org?addr=<G...>"
```

That covers anything a wallet does, and a node pair's stake as well.

### USDC

Testnet USDC comes from Circle's faucet at `faucet.circle.com`. It is
interactive. Circle's testnet issuer is
`GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5`; this is
Circle's public issuer, not a Kenter account.

An account must hold a **trustline** to the USDC issuer before it can
receive USDC. Depositors need one to pay into the mint, and holders need one
to receive a redemption payout. The wallet adds it: the Activate screen
offers it once the account holds XLM, and Settings has a `trustline` row
afterwards.

### The asset contracts

The mint escrows USDC through its Stellar Asset Contract (SAC); the roster
holds stakes in native XLM through the native SAC. Derive either ID with the
stellar CLI:

```bash
stellar contract id asset --asset native --network testnet
stellar contract id asset --asset USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5 --network testnet
```

## Funding a wallet for a UI run

A wallet created in the GUI shows its address on the Activate screen and
waits. Funding it takes three steps, in a fixed order:

| Step | What | Signed by |
|---|---|---|
| 1 | XLM from friendbot | nobody: friendbot creates the account |
| 2 | a trustline for the mint's asset | the wallet |
| 3 | USDC from a funded account | the funder |

XLM comes first because until friendbot creates it the account does not
exist: it has no sequence number, so it cannot sign, and a trustline raises
the reserve it has to cover. USDC comes last because a SAC `transfer` into an
account with no trustline fails. Step 2 can only be taken in the wallet,
since a trustline is signed by the account it affects.

The system test harness does steps 1 and 3 for you:

```bash
export KENTER_SYSTEST_FUNDER_SECRET=S...   # a testnet account holding USDC
cargo run -p kenter-systest -- --fund G... --amount 5
```

It sends the XLM, then stops and says to add the trustline in the window.
Add it, run the same command again, and it sends the USDC and prints the
funder's remaining balance. It is idempotent. `--fund` reads the mint's
`pay_token` rather than assuming USDC, so it funds for whichever mint
`--mint` names. The funder secret is read from the environment and never
accepted on the command line. The sequence lives in
`crates/kenter-systest/src/fund.rs`.

## Running a node on testnet

A node is one **pair**: two Stellar addresses run by one install. Nobody
chooses nodes. When a depositor requests a print, a future drand round seeds
it, registered pairs claim its interior positions, and the lowest scores win
(see [Node selection](/architecture/node-selection)). A pair that is on the
roster but has not registered with the mint is never drawn.

### Install

- **Windows:** the MSI (`packaging/windows/build-msi.ps1`, output
  `dist/kenter-<version>-testnet-x64.msi`) installs the wallet, the tray
  node (`kenter-node-tray.exe`) and the CLI (`kenter-node.exe`) into
  `C:\Program Files\Kenter`, with Start-menu entries *Kenter Wallet* and
  *Kenter Node*.
- **Raspberry Pi and other Debian-based Linux:** the `.deb`
  (`packaging/linux/build-deb.sh`; arm64 by default,
  `TARGET=x86_64-unknown-linux-gnu` for amd64) installs `kenter-node`,
  `kenter-nodectl` and a systemd unit, `kenter-node.service`. It does not
  start the service.

Both packages are unsigned. Check them against `dist/SHA256SUMS`.

### Set up and join

On Windows, open *Kenter Node* and follow the setup in its window. On
Linux:

```bash
sudo kenter-nodectl init --name <name>      # add --volunteer for a volunteer pair
sudo kenter-nodectl addresses               # the one address to fund, and how much
curl "https://friendbot.stellar.org?addr=<the node's address>"
sudo systemctl enable --now kenter-node
sudo kenter-nodectl status
```

Either way:

1. **Keys.** `init` creates a new recovery phrase, shown once, or reads one
   with `--restore`. Back it up: anyone who has it owns the stake.
2. **Terms.** Paid or volunteer. A volunteer's fees are burned. The choice
   is permanent for both addresses: an address that has volunteered rejoins
   the roster as a volunteer.
3. **Fund one address.** The node creates and funds its partner itself. The
   amount `addresses` prints covers both stakes (`min_stake` each),
   reserves and a fee float. Friendbot's 10 000 XLM covers it.
4. **Join.** Once funded, the running node joins the roster with both
   addresses and binds to the first relay that answers.
5. **Register the pair.** The node then calls `register_pair` on the mint
   by itself, and retries every 30 s until the call succeeds. A pair may register
   only once both addresses have been on the roster for `min_node_age`
   ledgers. Until registration succeeds, the tray reads *Online · not yet registered
   for prints*, Settings offers **Register now**, and `status` shows the
   error.

After that the node watches the mint, seeds slots whose beacon round is out,
claims positions when its score may win, and serves the links it wins.
Claims and seeds cost XLM from the fee float, inside a daily allowance.

### Reinstalling a Linux node

Put the new `.deb` (and `SHA256SUMS`) beside
`packaging/linux/reinstall-kenter-node.sh`, then:

```bash
sudo sh reinstall-kenter-node.sh
```

It checks the package, stops the node (which leaves selection first),
removes the old package without purging, installs the new one, and starts
the node again if it was enabled. Keys, config and stake in
`/var/lib/kenter-node` are kept. On first start against a different mint,
the node registers its pair with it by itself. On Windows, installing a
newer MSI replaces the old one and leaves the node's home and keystore entry
alone.

### Leaving

`kenter-node stop`, then `kenter-node leave` (both stakes start unbonding),
then `kenter-node withdraw` once `unbonding_ledgers` have passed. `claim`
collects a paid pair's credited fees. `claim`, `leave` and `withdraw` refuse
while the node is running. On Linux, stop the service with
`sudo systemctl stop kenter-node` and run the rest through
`sudo kenter-nodectl`.

## Deploying your own mint and roster

`scripts/deploy_testnet.sh` builds both contracts, checks the redemption CPU
budget, deploys the roster and then the mint, warms both, and registers any
node identities you name. How to run it in full is in
[Deployment](/DEPLOY).

```bash
scripts/deploy_testnet.sh                      # deploy both, register nodes
DEPLOY_WHAT=roster scripts/deploy_testnet.sh   # just the roster
ROSTER_ID=C... DEPLOY_WHAT=mint scripts/deploy_testnet.sh   # a mint on an existing roster
DRY_RUN=1 scripts/deploy_testnet.sh            # print the commands only
```

The script signs with the stellar CLI identity named by `DEPLOYER` (default
`testnet-deployer`), and registers the identities in `NODE_ALIASES`. It reads
the two SAC IDs from `XLM_SAC_CONTRACT_ID` and `USDC_SAC_CONTRACT_ID` in
`.env`, or from `XLM_SAC` / `USDC_SAC`. It refuses native XLM as the mint's
pay token, because volunteer fees are burned and the native SAC refuses
`burn`. The network passphrase is fixed to testnet's, so the script cannot
deploy to mainnet.

**Where the contract IDs come from.** The script prints the new IDs at the
end, as `KENTER_ROSTER=…` and `KENTER_MINT=…`. It writes nothing into the
repository. Export them for your clients and nodes, or put them in the
testnet profile in `crates/kenter-client/src/network.rs` to make them a
build's default.

### Constructor parameters

Every value is fixed at deploy: both contracts are adminless, so changing a
parameter means deploying a new contract. The script's defaults are the
mainnet values, except `min_node_age`, so a testnet deployment runs the
mainnet arguments. Each is an environment variable of the same name in upper
case.

| Contract | Parameter | Default | Meaning |
|---|---|---|---|
| mint | `node_fee` | 25 000 | stroops of USDC per interior participant (0.0025 USDC) |
| mint | `min_pairs` / `max_pairs` | 3 / 8 | pairs a print may have; the constructor refuses `min_pairs` below 3 and `max_pairs` above 12 |
| mint | `max_print_ledgers` | 17 280 | how long a print may stay open before it can be cleared (one day) |
| mint | `pay_token` | the USDC SAC | the escrowed asset |
| mint | `roster` | the roster just deployed | |
| mint | `selection` | see below | the node-selection configuration |
| roster | `min_stake` | 1 500 000 000 | 150 XLM per address, 300 per pair |
| roster | `unbonding_ledgers` | 120 960 | one week at 5 s ledgers |
| roster | `pay_token` | the native XLM SAC | |

The `selection` argument:

| Field | Default | Meaning |
|---|---|---|
| `beacon_pk`, `beacon_genesis`, `beacon_period` | drand quicknet: its G2 group key, genesis `1692803367`, period 3 s | the public beacon whose round seeds each print |
| `beacon_lead` | 20 rounds (60 s) | how far ahead the seeding round is fixed, so it does not exist yet when the print is requested |
| `claim_window` | 6 ledgers (~30 s) | how long pairs may claim after the seed |
| `serve_timeout` | 12 ledgers (~60 s) | how long a selected pair has to serve before it can be skipped |
| `min_node_age` | 0 on testnet, 17 280 (one day) on mainnet | ledgers each address must have been on the roster before its pair may register or claim |
| `fallback_delay` | 600 s on both | how long after a round is due a slot nobody seeded from the beacon may be seeded by `seed_fallback` |

Read the deployed values back with the mint's `selection()` view.

Lower values make testnet iteration faster, for example
`UNBONDING_LEDGERS=720`.

### Why `max_pairs` is 8

A realistic print is three or four pairs. Extra pairs add collusion
resistance only to the extent their nodes are run by independent operators,
and they add nothing for privacy: the depositor's two end pairs keep a note
out of reach of any coalition of nodes, and those are present at any pair
count. Each extra pair has a real cost: node fees, a round trip of latency,
one more chance for a print to stall, about 290 bytes of chain, and about
3.8M instructions at redemption.

It is not a CPU limit. An 8-pair redemption uses about 32.1M instructions
against testnet's `tx_max_instructions` of 400M, roughly 8%. The contract
ceiling of 12 pairs sits near 12%.

The deploy script checks the configured `max_pairs` against the target
network's live instruction limit and cost table (`scripts/budget_gate.py`)
and refuses anything that needs more than half the limit. It also runs the
mint's wasm budget tests against the wasm it has just built.

### Warming

A freshly deployed contract sits at the network's minimum TTL. The first
call that crosses the bump threshold pays to extend everything it touches,
including the code entry, which costs tens of XLM. The script calls each
contract's `bump` from the deployer right after deploying, so that bill does
not land on the first node to join. See
[Ledger costs](/LEDGER_COSTS#the-keeper) for why `bump` needs
`--send=yes`.

### Verifying a deployment

The deployed bytecode should match a local build at the same commit, byte
for byte:

```bash
stellar contract fetch --id "$KENTER_MINT" --out-file /tmp/m.wasm
sha256sum /tmp/m.wasm contracts/kenter-mint/target/wasm32v1-none/release/kenter_mint.wasm
```

Build with `stellar contract build`, not `cargo build`. The stellar build
adds contract metadata, so a plain cargo artifact hashes differently and is
not what gets deployed.

### The stellar CLI and this repository's `.env`

The stellar CLI loads `.env` from the working directory. This repository's
`.env` sets `SOROBAN_RPC_URL` but names the passphrase
`SOROBAN_NETWORK_PASSPHRASE`, while the CLI expects
`STELLAR_NETWORK_PASSPHRASE`. Inside the checkout, `--network testnet` then
fails with *"rpc-url is used but network passphrase is missing"*, and the
same command works from any other directory. Pass `--rpc-url` and
`--network-passphrase` explicitly, as the deploy script does.

## Notes belong to the mint that printed them

A note's escrow is held by the mint that printed it, and only that mint's
`redeem_*` can release it. Entry points are fixed at deploy, so a change to a
redemption signature is a new mint, and a client built for one mint's
digests cannot redeem against another's. When you move to a new deployment,
redeem or keep the notes of the old one, and keep its ID: a note is
redeemable only against its own mint. Discarding a wallet discards the
escrow behind its notes.

## Redemption and node fees

A holder may redeem to their own account or to any address they name. The
recipient is not authenticated, since the paying side is the contract, with
one exception: it may not be the mint itself, which would consume the note
and strand the escrow.

Node fees are flat per participant and charged for **interior pairs only**:

```
total fees = node_fee x 2 x (pairs - 2)
```

At `node_fee = 25000`, a three-pair print pays `25000 x 2 x 1 = 50000`
stroops, so a 1.00 USDC note redeems for `0.9950000`, and a five-pair one for
`0.9850000`. The depositor's two end pairs do no node work and are neither
charged nor credited. A volunteer's fees are taken from the note the same way
but burned, not credited (one `FEE burned` event per address).

A position the depositor abandons burns one pair's fee, `2 x node_fee`. A
skip of a silent pair is paid by the depositor at the moment of skipping, on
top of the deposit, so the note still redeems for its face less the usual
fees. A cancel or expiry after selection burns the same per unconfirmed
interior position from the escrow and refunds the rest. See
[Node selection](/architecture/node-selection) for the lifecycle.
