#!/usr/bin/env bash
#
# Deploy a roster and a mint to Stellar testnet, and register the nodes.
#
# The contracts are immutable, so any change to them means a fresh
# deployment of every mint and roster on testnet; this script makes that
# a repeatable step rather than a sequence of remembered commands. See
# docs/DEPLOY.md.
#
# What this does NOT do, on purpose:
#   - choose the constructor values. They are immutable after deploy and
#     belong in a decision, not a default buried in a script. Set them
#     below or pass them in.
#   - write anything into a tracked file. The new ids are printed; what
#     to do with them is the operator's call.
#   - touch mainnet. The network is hardcoded to testnet for that reason.
#
# Usage:
#   scripts/deploy_testnet.sh                    # deploy both, register nodes
#   DEPLOY_WHAT=roster scripts/deploy_testnet.sh # just the roster
#   DRY_RUN=1 scripts/deploy_testnet.sh          # print the commands only
#
set -euo pipefail

NETWORK=testnet
# The network is passed explicitly on every call rather than via
# `--network testnet`.
#
# The stellar CLI auto-loads `.env` from the working directory, and this
# repo's `.env` sets `SOROBAN_RPC_URL` while naming the passphrase
# `SOROBAN_NETWORK_PASSPHRASE`. The CLI honours the first and wants
# `STELLAR_NETWORK_PASSPHRASE` for the second, so inside this repo
# `--network testnet` dies with "rpc-url is used but network passphrase
# is missing" -- while the identical command works from any other
# directory. Two explicit flags cost nothing and remove a footgun that
# would otherwise bite every contract call made from this checkout.
RPC_URL=${RPC_URL:-https://soroban-testnet.stellar.org:443}
# The passphrase is fixed, not a default. The header promises this script
# cannot touch mainnet, and an overridable passphrase made that false: the
# signature commits to the passphrase, so pinning it means a transaction
# built here is invalid on any other network whatever RPC_URL points at.
# A mainnet deploy wants its own script, deliberately.
TESTNET_PASSPHRASE="Test SDF Network ; September 2015"
if [ -n "${PASSPHRASE:-}" ] && [ "$PASSPHRASE" != "$TESTNET_PASSPHRASE" ]; then
    echo "refusing: this script deploys to testnet only (PASSPHRASE is not testnet's)" >&2
    exit 1
fi
PASSPHRASE=$TESTNET_PASSPHRASE
NET_ARGS=(--rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE")
DEPLOYER=${DEPLOYER:-testnet-deployer}
# Node identities, as stellar-CLI keystore aliases. An alias is not a
# secret -- the CLI resolves and signs with it -- which is the whole
# reason to name them this way. Passing the secret itself as
# `--source-account` puts a funded key in the process table and in
# shell history.
NODE_ALIASES=${NODE_ALIASES:-"kenter-node-1 kenter-node-1p"}
DEPLOY_WHAT=${DEPLOY_WHAT:-all}
DRY_RUN=${DRY_RUN:-0}
# Every spelling of "yes" means a dry run: if only `1` did,
# `DRY_RUN=true` -- the natural thing to type -- would deploy for real.
# Anything not plainly "no" is refused rather than guessed at, since the
# wrong guess spends a deploy.
case "$(printf '%s' "$DRY_RUN" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on) DRY_RUN=1 ;;
    0|false|no|n|off|"") DRY_RUN=0 ;;
    *) echo "DRY_RUN=$DRY_RUN is not yes or no; refusing to guess" >&2; exit 1 ;;
esac

# ── Constructor values. Immutable once deployed. ─────────────────────
# Mint. `min_pairs` may not go below 3 and `max_pairs` not above 12;
# the constructor refuses both with InvalidConfig.
# Sized from measurement, not guessed (`docs/LEDGER_COSTS.md`).
#
# A roster node spends one `confirm_link` per print, measured at
# 0.0014 XLM -- about $0.00042. A node_fee of 100 stroops would earn a
# pair 0.00002 USDC for that, so every print would be a loss a node
# absorbs.
#
# 25,000 stroops is 0.0025 USDC per participant. The fee is fixed in
# USDC forever and a node's cost is in XLM, so the margin is a bet on
# the XLM price: an interior pair breaks even with XLM at ~$3.57 (a
# 10,000-stroop fee would break even at ~$1.43).
#
# The depositor pays for interior pairs only: 0.005 USDC on a 3-pair
# note, 0.03 on an 8-pair one -- 0.15% of a $20 note.
#
# Defaults are the intended MAINNET values, so a rehearsal deploy needs
# no overrides. Override for fast testnet
# iteration, e.g. UNBONDING_LEDGERS=720.
NODE_FEE=${NODE_FEE:-25000}
MIN_PAIRS=${MIN_PAIRS:-3}
MAX_PAIRS=${MAX_PAIRS:-8}
# One day. A print takes minutes; the draw's temporary rent scales with
# the window (docs/architecture/node-selection.md).
MAX_PRINT_LEDGERS=${MAX_PRINT_LEDGERS:-17280}

# Roster. `min_stake` is in stroops; 10_000_000 = 1 XLM. The roster has
# no admin, so nothing can take a bond, and the unbonding window is
# purely how long a stake stays locked after a node leaves.
# 150 XLM and one week at 5s ledgers. Each node account needs the stake plus fees:
# friendbot's 10,000 XLM covers it.
MIN_STAKE=${MIN_STAKE:-1500000000}
UNBONDING_LEDGERS=${UNBONDING_LEDGERS:-120960}

# Node selection (docs/architecture/node-selection.md). The beacon is drand
# quicknet, the same public chain on testnet and mainnet: its group key
# (G2, uncompressed, Soroban's encoding), genesis and period. Lead 20
# rounds (60 s, so the round does not exist yet when the request lands
# even if ledger close time trails wall time), a 6-ledger claim window,
# a 12-ledger serve timeout. min_node_age 0 on testnet; about a day (17280) on mainnet.
# The fallback seed opens 600 s after the round is due, on both networks.
BEACON_PK=${BEACON_PK:-03cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a01a714f2edb74119a2f2b0d5a7c75ba902d163700a61bc224ededd8e63aef7be1aaf8e93d7a9718b047ccddb3eb5d68b0e5db2b6bfbb01c867749cadffca88b36c24f3012ba09fc4d3022c5c37dce0f977d3adb5d183c7477c442b1f04515273}
BEACON_GENESIS=${BEACON_GENESIS:-1692803367}
BEACON_PERIOD=${BEACON_PERIOD:-3}
BEACON_LEAD=${BEACON_LEAD:-20}
CLAIM_WINDOW=${CLAIM_WINDOW:-6}
SERVE_TIMEOUT=${SERVE_TIMEOUT:-12}
MIN_NODE_AGE=${MIN_NODE_AGE:-0}
FALLBACK_DELAY=${FALLBACK_DELAY:-600}
SELECTION="{\"beacon_pk\":\"$BEACON_PK\",\"beacon_genesis\":$BEACON_GENESIS,\"beacon_period\":$BEACON_PERIOD,\"beacon_lead\":$BEACON_LEAD,\"claim_window\":$CLAIM_WINDOW,\"serve_timeout\":$SERVE_TIMEOUT,\"min_node_age\":$MIN_NODE_AGE,\"fallback_delay\":$FALLBACK_DELAY}"

# The mint's fallback seed (seed_fallback) must open well inside the
# print window, or a slot the beacon never seeds expires first. The
# window is in ledgers and the delay in seconds: at 5 s a ledger, the
# fallback must open in the window's first half.
if (( BEACON_LEAD * BEACON_PERIOD + FALLBACK_DELAY >= MAX_PRINT_LEDGERS * 5 / 2 )); then
    echo "refusing: fallback_delay $FALLBACK_DELAY s opens too late for a $MAX_PRINT_LEDGERS-ledger print window" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# .env holds secrets as well as addresses, so read the two values we
# need rather than sourcing the file.
env_of() { grep "^$1=" .env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'"' \r'; }
XLM_SAC=${XLM_SAC:-$(env_of XLM_SAC_CONTRACT_ID)}
USDC_SAC=${USDC_SAC:-$(env_of USDC_SAC_CONTRACT_ID)}

say()  { printf '\n\033[1m%s\033[0m\n' "$*" >&2; }
note() { printf '  %s\n' "$*" >&2; }

# Everything human goes to stderr. Only a captured value -- a contract
# id -- is allowed on stdout, or `$(run ...)` swallows the narration and
# uses it as the id. The dry run caught exactly that.
run() {
    if [ "$DRY_RUN" = "1" ]; then printf '  $ %s\n' "$*" >&2; return 0; fi
    "$@"
}

# A command whose stdout is a value we keep.
capture() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '  $ %s\n' "$*" >&2
        printf 'C_DRYRUN_PLACEHOLDER_ID'
        return 0
    fi
    "$@"
}

[ -n "$XLM_SAC" ]  || { echo "XLM_SAC_CONTRACT_ID not found in .env"; exit 1; }
[ -n "$USDC_SAC" ] || { echo "USDC_SAC_CONTRACT_ID not found in .env"; exit 1; }
# The mint burns volunteers' fees with the SAC's `burn`, which Stellar
# refuses for native XLM. A mint paying in XLM would trap every
# settlement that included a volunteer, forever.
[ "$USDC_SAC" != "$XLM_SAC" ] || { echo "the mint's pay token must not be native XLM: volunteer fees are burned"; exit 1; }

DEPLOYER_ADDR=$(stellar keys address "$DEPLOYER")

say "Deploying as $DEPLOYER (${DEPLOYER_ADDR:0:8}...${DEPLOYER_ADDR: -6}) to $NETWORK"
note "mint   : node_fee=$NODE_FEE min_pairs=$MIN_PAIRS max_pairs=$MAX_PAIRS max_print_ledgers=$MAX_PRINT_LEDGERS"
note "roster : min_stake=$MIN_STAKE unbonding_ledgers=$UNBONDING_LEDGERS (no admin, no fee)"
note "select : drand quicknet, lead=$BEACON_LEAD rounds claim_window=$CLAIM_WINDOW serve_timeout=$SERVE_TIMEOUT min_node_age=$MIN_NODE_AGE fallback_delay=$FALLBACK_DELAY"

# ── Build ─────────────────────────────────────────────────────────────
say "Building contracts to wasm"
# `stellar contract build` rather than plain cargo: it sets the target
# and the release profile the toolchain expects, and it is what produced
# the wasm already sitting in those target dirs.
run stellar contract build --manifest-path contracts/kenter-mint/Cargo.toml
run stellar contract build --manifest-path contracts/kenter-roster/Cargo.toml

MINT_WASM=contracts/kenter-mint/target/wasm32v1-none/release/kenter_mint.wasm
ROSTER_WASM=contracts/kenter-roster/target/wasm32v1-none/release/kenter_roster.wasm

# ── Budget gate ───────────────────────────────────────────────────────
# Nothing reaches a ledger without passing the CPU budget.
#
# `MAX_REDEEMABLE_PAIRS = 12` must keep fitting the budget, and the test that
# makes it is `#[ignore]`d, behind a feature, and reads a wasm already
# on disk -- so left alone it runs only when somebody runs it by hand,
# and against a stale artifact it asserts on old code. The build above
# has just produced a fresh one, which makes this the right moment and,
# absent any CI, the only place it reliably happens.
#
# What it protects: the mint is immutable. A `redeem_by_chain_owned`
# that outgrows the per-transaction budget cannot be fixed once notes
# are issued, and such a note is redeemable only through Path A and the
# node network -- the dependency Path B exists to avoid. Catching that
# after deployment is catching it too late.
#
# A mainnet deploy script wants the same step.
# The check demands that a test actually ran.
#
# `cargo test <name>` selects by name, so a rename, a dropped feature
# or a changed cfg makes it match nothing, run nothing, and exit 0.
# That is exactly how the bench went unnoticed for so long (P8-I1),
# and without this it would have been the same failure a second time,
# inside the mitigation written for it. Each assertion is invoked on
# its own and its result line is matched.
budget_check() {
    local name=$1
    if [ "$DRY_RUN" = "1" ]; then
        printf '  $ cargo test ... %s\n' "$name" >&2
        note "$name: skipped (dry run)"
        return 0
    fi
    local out
    if ! out=$(cargo test --manifest-path contracts/kenter-mint/Cargo.toml \
        --features wasm-bench "$name" -- --include-ignored 2>&1); then
        printf '%s\n' "$out" >&2
        echo "deploy aborted: $name failed - redemption does not fit the CPU budget." >&2
        echo "  Lower MAX_REDEEMABLE_PAIRS, or find what grew." >&2
        exit 1
    fi
    if ! printf '%s' "$out" | grep -q "test result: ok. 1 passed"; then
        printf '%s\n' "$out" >&2
        echo "deploy aborted: $name did not run." >&2
        echo "  A budget check that selects nothing exits 0 and proves nothing." >&2
        exit 1
    fi
    note "$name: within budget"
}

if [ "${SKIP_BUDGET_CHECK:-0}" != "1" ]; then
    say "Checking the redemption CPU budget against the wasm just built"
    budget_check bench_pathb_wasm
    budget_check pathb_owned_at_the_ceiling_fits_the_budget_wasm

    # The two above are tripwires on the contract, measured by a host
    # that is not this network. They cannot answer whether a
    # redemption fits, because Soroban prices work with a cost table
    # stored on the ledger and bills it against a ledger-stored
    # `tx_max_instructions` -- both of which differ per network and
    # move by validator vote. Testnet has been measured charging 1.87x
    # mainnet for `VerifyEd25519Sig`, the term that dominates Path B.
    #
    # So this one asks the network the deploy is actually going to.
    # It is the check that matters: `max_pairs` is fixed by the
    # constructor, and a note printed above the budget can never be
    # redeemed by chain.
    say "Checking $MAX_PAIRS pairs against the live network limit"
    if [ "$DRY_RUN" = "1" ]; then
        printf '  $ scripts/budget_gate.py --rpc-url %s --max-pairs %s\n' \
            "$RPC_URL" "$MAX_PAIRS" >&2
        note "skipped (dry run)"
    else
        python scripts/budget_gate.py \
            --rpc-url "$RPC_URL" --max-pairs "$MAX_PAIRS" >&2 || exit 1
    fi
fi

# ── Roster ────────────────────────────────────────────────────────────
ROSTER_ID=${ROSTER_ID:-}
if [ "$DEPLOY_WHAT" = "all" ] || [ "$DEPLOY_WHAT" = "roster" ]; then
    say "Deploying roster"
    ROSTER_ID=$(capture stellar contract deploy \
        --wasm "$ROSTER_WASM" \
        --source-account "$DEPLOYER" \
        "${NET_ARGS[@]}" \
        -- \
        --min_stake "$MIN_STAKE" \
        --pay_token "$XLM_SAC" \
        --unbonding_ledgers "$UNBONDING_LEDGERS")
    note "roster: $ROSTER_ID"
fi

# ── Mint ──────────────────────────────────────────────────────────────
if [ "$DEPLOY_WHAT" = "all" ] || [ "$DEPLOY_WHAT" = "mint" ]; then
    [ -n "$ROSTER_ID" ] || { echo "need ROSTER_ID= to deploy a mint alone"; exit 1; }
    say "Deploying mint (USDC)"
    MINT_ID=$(capture stellar contract deploy \
        --wasm "$MINT_WASM" \
        --source-account "$DEPLOYER" \
        "${NET_ARGS[@]}" \
        -- \
        --node_fee "$NODE_FEE" \
        --min_pairs "$MIN_PAIRS" \
        --max_pairs "$MAX_PAIRS" \
        --pay_token "$USDC_SAC" \
        --roster "$ROSTER_ID" \
        --max_print_ledgers "$MAX_PRINT_LEDGERS"         --selection "$SELECTION")
    note "mint: $MINT_ID"
fi

# ── Warm ──────────────────────────────────────────────────────────────
# A freshly deployed contract sits at the network's minimum TTL, and
# whichever call first crosses the bump threshold pays to extend
# everything it touches -- including the code entry, which is the
# largest thing either contract owns. On the previous roster that bill
# landed on the first node to join: 18.95 XLM, against 0.082 XLM for
# the next identical call, byte-identical footprints.
#
# `bump` exists so the bill lands here instead, on the deployer, who
# chose to pay it. It takes no auth and does nothing else.
#
# This is not a one-off. The TTL decays and the threshold is crossed
# again roughly every 90 days, so a keeper should be calling `bump` on
# a schedule; deploying is just the first time it is due.
if [ "$DEPLOY_WHAT" = "all" ] || [ "$DEPLOY_WHAT" = "warm" ]; then
    say "Warming: paying the first TTL extension from the deployer"
    for pair in "roster:${ROSTER_ID:-}" "mint:${MINT_ID:-}"; do
        name=${pair%%:*}
        id=${pair#*:}
        [ -n "$id" ] || { note "$name: no id, skipped"; continue; }
        note "$name bump"
        # --send=yes is load-bearing. `bump` only extends TTLs, which
        # leaves the read_write footprint empty, so the CLI classifies
        # the simulation as read-only and declines to submit -- quietly,
        # with a zero exit and a plausible-looking return value. The
        # first run of this script hit exactly that: the warm step
        # printed a new TTL ledger, sent nothing, and the next `join`
        # paid 19.23 XLM for the extension nobody had made.
        run stellar contract invoke \
            --id "$id" \
            --source-account "$DEPLOYER" \
            "${NET_ARGS[@]}" \
            --send=yes \
            -- bump
    done
fi

# ── Nodes ─────────────────────────────────────────────────────────────
# A print needs an interior pair of two distinct roster nodes, so two is
# the minimum that can mint anything. Three is what .env carries.
if [ "$DEPLOY_WHAT" = "all" ] || [ "$DEPLOY_WHAT" = "nodes" ]; then
    [ -n "$ROSTER_ID" ] || { echo "need ROSTER_ID= to register nodes"; exit 1; }
    say "Registering nodes on $ROSTER_ID"
    # The daemon self-registers on startup too (`ensure_roster`), so
    # this is only for standing a roster up before any node runs.
    for alias in $NODE_ALIASES; do
        addr=$(stellar keys address "$alias" 2>/dev/null) || {
            note "$alias: not in the keystore, skipped"
            continue
        }
        note "$alias (${addr:0:8}...${addr: -6})"
        # An empty --tunnel_endpoint is rejected by the CLI's parser, and
        # the daemon overwrites this on its first heartbeat anyway.
        run stellar contract invoke \
            --id "$ROSTER_ID" \
            --source-account "$alias" \
            "${NET_ARGS[@]}" \
            -- join \
            --caller "$addr" \
            --name "$alias" \
            --tunnel_endpoint "pending" || note "$alias: join failed (already registered?)"
    done
fi

say "Done"
note "Put these in the build environment, then rebuild the clients:"
note "  KENTER_TESTNET_ROSTER=${ROSTER_ID:-<unchanged>}"
note "  KENTER_TESTNET_MINT=${MINT_ID:-<unchanged>}"
note "(an existing testnet build also accepts KENTER_ROSTER / KENTER_MINT at run time)."
