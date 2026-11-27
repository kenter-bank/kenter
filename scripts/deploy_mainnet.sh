#!/usr/bin/env bash
#
# Deploy the Kenter roster and mint to Stellar mainnet.
#
# Both contracts are immutable and have no admin: once deployed, nothing
# about them can be changed, by anyone. So this script refuses to run
# unless the conditions for a deploy that others can verify are met, shows
# everything it is about to fix forever, and waits for a typed
# confirmation. After deploying it checks the result through a second,
# independent RPC and writes a deploy record.
#
# Conditions:
#   - x86_64 Linux. Contract builds differ between host platforms, and the
#     published hashes are the x86_64 Linux build (docs/runbook/setup.md).
#   - HEAD is a signed release tag that verifies against allowed_signers,
#     and the working tree is clean.
#   - The pinned Rust toolchain and stellar CLI.
#   - No .env in the repository root (the stellar CLI loads it silently).
#   - All network traffic goes through Tor (torsocks).
#
# Usage:
#   DRY_RUN=1 scripts/deploy_mainnet.sh     # every check, build and gate; deploys nothing
#   scripts/deploy_mainnet.sh               # deploy roster + mint, warm, verify, record
#   DEPLOY_WHAT=mint ROSTER_ID=C... scripts/deploy_mainnet.sh   # resume after a failed mint
#   DEPLOY_WHAT=verify ROSTER_ID=C... MINT_ID=C... scripts/deploy_mainnet.sh
#
# Settings (environment):
#   DEPLOYER          stellar CLI key alias that pays (default kntr-deployer)
#   RPC_URL           RPC the deploy is submitted through
#   VERIFY_RPC_URL    a different operator's RPC, used only to check the result
#   EXPECT_MINT_SHA   optional: sha256 the mint wasm must have (from another
#   EXPECT_ROSTER_SHA   Linux build of the same tag); the deploy stops if not
#   MIN_DEPLOYER_XLM  balance required before deploying (default 100)

set -euo pipefail

PASSPHRASE="Public Global Stellar Network ; September 2015"
RPC_URL=${RPC_URL:-https://rpc.lightsail.network}
VERIFY_RPC_URL=${VERIFY_RPC_URL:-https://mainnet.sorobanrpc.com}
DEPLOYER=${DEPLOYER:-kntr-deployer}
DEPLOY_WHAT=${DEPLOY_WHAT:-all}
MIN_DEPLOYER_XLM=${MIN_DEPLOYER_XLM:-100}
RUST_PIN=1.91.1
CLI_PIN=23.4.1

# Circle's USDC issuer on Stellar mainnet. The mint's pay token is the
# Stellar Asset Contract for this asset; its id is derived, not configured.
USDC_ISSUER=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN

DRY_RUN=${DRY_RUN:-0}
case "$(printf '%s' "$DRY_RUN" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on) DRY_RUN=1 ;;
    0|false|no|n|off|"") DRY_RUN=0 ;;
    *) echo "DRY_RUN=$DRY_RUN is not yes or no; refusing to guess" >&2; exit 1 ;;
esac
case "$DEPLOY_WHAT" in
    all|mint|warm|verify) ;;
    *) echo "DEPLOY_WHAT must be all, mint, warm or verify" >&2; exit 1 ;;
esac

# ── Constructor values: immutable once deployed ──────────────────────
# What each value prices: docs/LEDGER_COSTS.md and
# docs/architecture/node-selection.md.
NODE_FEE=25000                 # stroops of USDC per participant (0.0025 USDC)
MIN_PAIRS=3
MAX_PAIRS=8                    # contract ceiling is 12
MAX_PRINT_LEDGERS=17280        # one day
MIN_STAKE=1500000000           # 150 XLM per node address
UNBONDING_LEDGERS=120960       # one week
# Node selection: drand quicknet (group key in Soroban's G2 encoding,
# genesis, period), 20-round lead, 6-ledger claim window, 12-ledger serve
# timeout, nodes must be a day old to be drawn, and the fallback seed
# opens 600 s after a round is due if nobody has posted it.
BEACON_PK=03cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a01a714f2edb74119a2f2b0d5a7c75ba902d163700a61bc224ededd8e63aef7be1aaf8e93d7a9718b047ccddb3eb5d68b0e5db2b6bfbb01c867749cadffca88b36c24f3012ba09fc4d3022c5c37dce0f977d3adb5d183c7477c442b1f04515273
BEACON_GENESIS=1692803367
BEACON_PERIOD=3
BEACON_LEAD=20
CLAIM_WINDOW=6
SERVE_TIMEOUT=12
MIN_NODE_AGE=17280
FALLBACK_DELAY=600
SELECTION="{\"beacon_pk\":\"$BEACON_PK\",\"beacon_genesis\":$BEACON_GENESIS,\"beacon_period\":$BEACON_PERIOD,\"beacon_lead\":$BEACON_LEAD,\"claim_window\":$CLAIM_WINDOW,\"serve_timeout\":$SERVE_TIMEOUT,\"min_node_age\":$MIN_NODE_AGE,\"fallback_delay\":$FALLBACK_DELAY}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MINT_WASM=contracts/kenter-mint/target/wasm32v1-none/release/kenter_mint.wasm
ROSTER_WASM=contracts/kenter-roster/target/wasm32v1-none/release/kenter_roster.wasm

say()  { printf '\n\033[1m%s\033[0m\n' "$*" >&2; }
note() { printf '  %s\n' "$*" >&2; }
die()  { printf '\n\033[31mrefusing:\033[0m %s\n' "$*" >&2; exit 1; }

# Network calls go through Tor. torsocks fails closed: a connection it
# can't route through Tor is refused, not made directly.
tor() { torsocks "$@"; }
NET=(--network-passphrase "$PASSPHRASE")
SUBMIT=(--rpc-url "$RPC_URL" "${NET[@]}")
VERIFY=(--rpc-url "$VERIFY_RPC_URL" "${NET[@]}")

# Only a captured value goes to stdout; everything human goes to stderr.
capture() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '  $ %s\n' "$*" >&2
        printf 'C_DRYRUN_PLACEHOLDER_ID'
        return 0
    fi
    "$@"
}
run() {
    if [ "$DRY_RUN" = "1" ]; then printf '  $ %s\n' "$*" >&2; return 0; fi
    "$@"
}
unquote() { tr -d '"\r\n '; }

# A read-only contract call (simulation only, never submitted).
read_call() {   # read_call RPCARGS-NAME CONTRACT FN [ARGS...]
    local -n rpc=$1; local id=$2; shift 2
    tor stellar contract invoke --id "$id" --source-account "$DEPLOYER" \
        "${rpc[@]}" --send=no -- "$@" 2>/dev/null | unquote
}

rpc_json() {    # rpc_json URL METHOD
    tor curl -fsS --max-time 30 -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\"}" "$1"
}

# ── Preconditions ────────────────────────────────────────────────────
say "Checking preconditions"

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] \
    || die "mainnet contracts are built and deployed on x86_64 Linux only"
note "host: x86_64 Linux"

[ ! -e .env ] || die ".env exists in $ROOT; the stellar CLI would load it. Move it away for the deploy."
# Settings the CLI would pick up from the environment instead of the flags.
for v in $(env | grep -oE '^(STELLAR|SOROBAN)_[A-Z_]+' | grep -v '^STELLAR_CONFIG_DIR$' || true); do
    unset "$v"
done

for t in torsocks curl git python3 sha256sum stellar rustc; do
    command -v "$t" >/dev/null || die "$t not found"
done
cli=$(stellar --version | head -1 | awk '{print $2}')
[ "$cli" = "$CLI_PIN" ] || die "stellar CLI is $cli; the release builds with $CLI_PIN"
rv=$(rustc --version | awk '{print $2}')
[ "$rv" = "$RUST_PIN" ] || die "rustc is $rv in this checkout; rust-toolchain.toml pins $RUST_PIN"
note "toolchain: rustc $rv, stellar $cli"

[ -z "$(git status --porcelain --untracked-files=normal)" ] \
    || die "the working tree is not clean (git status)"
TAG=$(git describe --exact-match --tags HEAD 2>/dev/null) \
    || die "HEAD is not a release tag; check out the signed tag being deployed"
git -c gpg.ssh.allowedSignersFile="$ROOT/allowed_signers" verify-tag "$TAG" >/dev/null 2>&1 \
    || die "tag $TAG does not verify against allowed_signers"
COMMIT=$(git rev-parse HEAD)
note "source: $TAG ($COMMIT), signed"

istor=$(tor curl -fsS --max-time 60 https://check.torproject.org/api/ip || true)
[[ $istor == *'"IsTor":true'* ]] || die "traffic is not leaving through Tor (is tor running? systemctl status tor)"
note "network: through Tor"

[ "$RPC_URL" != "$VERIFY_RPC_URL" ] || die "VERIFY_RPC_URL must be a different RPC from RPC_URL"
for u in "$RPC_URL" "$VERIFY_RPC_URL"; do
    net=$(rpc_json "$u" getNetwork 2>/dev/null || true)
    [[ $net == *"$PASSPHRASE"* ]] || die "$u is unreachable or not a mainnet RPC"
    health=$(rpc_json "$u" getHealth 2>/dev/null || true)
    [[ $health == *'"healthy"'* ]] || die "$u reports it is not healthy"
done
note "rpc: submit via $RPC_URL, verify via $VERIFY_RPC_URL (both mainnet, healthy)"

DEPLOYER_ADDR=$(stellar keys address "$DEPLOYER" 2>/dev/null) \
    || die "no key alias '$DEPLOYER' (stellar keys generate $DEPLOYER --secure-store)"

XLM_SAC=$(tor stellar contract id asset --asset native "${SUBMIT[@]}")
USDC_SAC=$(tor stellar contract id asset --asset "USDC:$USDC_ISSUER" "${SUBMIT[@]}")
[ "$(read_call SUBMIT "$XLM_SAC" name)" = native ] \
    || die "XLM asset contract $XLM_SAC does not answer as native"
[ "$(read_call SUBMIT "$USDC_SAC" name)" = "USDC:$USDC_ISSUER" ] \
    || die "USDC asset contract $USDC_SAC does not answer as USDC:$USDC_ISSUER"
note "pay tokens: XLM $XLM_SAC, USDC $USDC_SAC (checked on chain)"

bal=$(read_call SUBMIT "$XLM_SAC" balance --id "$DEPLOYER_ADDR" || echo 0)
need=$((MIN_DEPLOYER_XLM * 10000000))
[[ $bal =~ ^[0-9]+$ ]] || bal=0
if [ "$DEPLOY_WHAT" != verify ] && [ "$bal" -lt "$need" ]; then
    msg="$DEPLOYER holds $((bal / 10000000)) XLM; at least $MIN_DEPLOYER_XLM XLM needed"
    if [ "$DRY_RUN" = "1" ]; then note "warning: $msg (fund it before the real deploy)"; else die "$msg"; fi
fi
note "deployer: $DEPLOYER $DEPLOYER_ADDR, $((bal / 10000000)) XLM"

# ── Build ────────────────────────────────────────────────────────────
say "Building both contracts from $TAG"
stellar contract build --manifest-path contracts/kenter-roster/Cargo.toml >&2
stellar contract build --manifest-path contracts/kenter-mint/Cargo.toml >&2
MINT_SHA=$(sha256sum "$MINT_WASM" | cut -d' ' -f1)
ROSTER_SHA=$(sha256sum "$ROSTER_WASM" | cut -d' ' -f1)
note "roster wasm sha256 $ROSTER_SHA"
note "mint   wasm sha256 $MINT_SHA"
[ -z "${EXPECT_ROSTER_SHA:-}" ] || [ "$EXPECT_ROSTER_SHA" = "$ROSTER_SHA" ] \
    || die "roster wasm is not EXPECT_ROSTER_SHA ($EXPECT_ROSTER_SHA)"
[ -z "${EXPECT_MINT_SHA:-}" ] || [ "$EXPECT_MINT_SHA" = "$MINT_SHA" ] \
    || die "mint wasm is not EXPECT_MINT_SHA ($EXPECT_MINT_SHA)"

# ── Budget gate ──────────────────────────────────────────────────────
# A redemption that outgrows the transaction budget can't be fixed in an
# immutable mint. The first two checks are tripwires on the contract; the
# third asks mainnet's own cost table whether MAX_PAIRS fits.
budget_check() {
    local name=$1 out
    if ! out=$(cargo test --locked --manifest-path contracts/kenter-mint/Cargo.toml \
        --features wasm-bench "$name" -- --include-ignored 2>&1); then
        printf '%s\n' "$out" >&2
        die "$name failed: redemption does not fit the CPU budget"
    fi
    printf '%s' "$out" | grep -q "test result: ok. 1 passed" \
        || { printf '%s\n' "$out" >&2; die "$name did not run (a check that selects nothing proves nothing)"; }
    note "$name: within budget"
}
if [ "$DEPLOY_WHAT" = all ] || [ "$DEPLOY_WHAT" = mint ]; then
    say "Checking the redemption budget"
    budget_check bench_pathb_wasm
    budget_check pathb_owned_at_the_ceiling_fits_the_budget_wasm
    tor python3 scripts/budget_gate.py --rpc-url "$RPC_URL" --max-pairs "$MAX_PAIRS" >&2 \
        || die "budget gate failed against mainnet"
fi

# ── Confirm ──────────────────────────────────────────────────────────
ROSTER_ID=${ROSTER_ID:-}
MINT_ID=${MINT_ID:-}
say "About to deploy to MAINNET ($DEPLOY_WHAT). None of this can be changed afterwards."
cat >&2 <<EOF
  source        $TAG  $COMMIT
  deployer      $DEPLOYER_ADDR
  roster wasm   $ROSTER_SHA
    min_stake          $MIN_STAKE  ($((MIN_STAKE / 10000000)) XLM)
    pay_token          $XLM_SAC  (XLM)
    unbonding_ledgers  $UNBONDING_LEDGERS
  mint wasm     $MINT_SHA
    node_fee           $NODE_FEE  (stroops of USDC)
    min_pairs/max      $MIN_PAIRS / $MAX_PAIRS
    pay_token          $USDC_SAC  (USDC:$USDC_ISSUER)
    roster             ${ROSTER_ID:-<the roster deployed above>}
    max_print_ledgers  $MAX_PRINT_LEDGERS
    selection          drand quicknet, lead $BEACON_LEAD, claim_window $CLAIM_WINDOW,
                       serve_timeout $SERVE_TIMEOUT, min_node_age $MIN_NODE_AGE,
                       fallback_delay $FALLBACK_DELAY s
EOF
if [ "$DRY_RUN" = "1" ]; then
    note "dry run: not deploying. Commands that would run:"
elif [ "$DEPLOY_WHAT" != verify ]; then
    printf '\n  Type "deploy mainnet" to continue: ' >&2
    read -r answer </dev/tty
    [ "$answer" = "deploy mainnet" ] || die "not confirmed"
fi

# ── Deploy ───────────────────────────────────────────────────────────
if [ "$DEPLOY_WHAT" = all ]; then
    say "Deploying roster"
    ROSTER_ID=$(capture tor stellar contract deploy --wasm "$ROSTER_WASM" \
        --source-account "$DEPLOYER" "${SUBMIT[@]}" -- \
        --min_stake "$MIN_STAKE" \
        --pay_token "$XLM_SAC" \
        --unbonding_ledgers "$UNBONDING_LEDGERS")
    note "roster: $ROSTER_ID"
    note "if anything below fails, resume with: DEPLOY_WHAT=mint ROSTER_ID=$ROSTER_ID $0"
fi
if [ "$DEPLOY_WHAT" = all ] || [ "$DEPLOY_WHAT" = mint ]; then
    [ -n "$ROSTER_ID" ] || die "ROSTER_ID is needed to deploy the mint"
    say "Deploying mint"
    MINT_ID=$(capture tor stellar contract deploy --wasm "$MINT_WASM" \
        --source-account "$DEPLOYER" "${SUBMIT[@]}" -- \
        --node_fee "$NODE_FEE" \
        --min_pairs "$MIN_PAIRS" \
        --max_pairs "$MAX_PAIRS" \
        --pay_token "$USDC_SAC" \
        --roster "$ROSTER_ID" \
        --max_print_ledgers "$MAX_PRINT_LEDGERS" \
        --selection "$SELECTION")
    note "mint: $MINT_ID"
fi

# ── Warm ─────────────────────────────────────────────────────────────
# A new contract sits at the minimum TTL; the first call past the bump
# threshold pays to extend its code entry. `bump` puts that bill on the
# deployer. --send=yes: bump writes nothing, so the CLI would otherwise
# treat it as read-only and not submit it.
if [ "$DEPLOY_WHAT" = all ] || [ "$DEPLOY_WHAT" = mint ] || [ "$DEPLOY_WHAT" = warm ]; then
    say "Paying the first TTL extension"
    for pair in "roster:$ROSTER_ID" "mint:$MINT_ID"; do
        id=${pair#*:}
        [ -n "$id" ] || die "${pair%%:*} id missing"
        run tor stellar contract invoke --id "$id" --source-account "$DEPLOYER" \
            "${SUBMIT[@]}" --send=yes -- bump >&2
        note "${pair%%:*} bumped"
    done
fi
[ "$DRY_RUN" = "1" ] && { say "Dry run complete: every check passed"; exit 0; }

# ── Verify through the second RPC ────────────────────────────────────
say "Verifying through $VERIFY_RPC_URL"
[ -n "$ROSTER_ID" ] && [ -n "$MINT_ID" ] || die "ROSTER_ID and MINT_ID are needed to verify"
tmp=$(mktemp -d)
for pair in "roster:$ROSTER_ID:$ROSTER_SHA" "mint:$MINT_ID:$MINT_SHA"; do
    IFS=: read -r name id want <<<"$pair"
    tor stellar contract fetch --id "$id" "${VERIFY[@]}" -o "$tmp/$name.wasm" 2>/dev/null \
        || die "could not fetch the $name's code from $VERIFY_RPC_URL"
    got=$(sha256sum "$tmp/$name.wasm" | cut -d' ' -f1)
    [ "$got" = "$want" ] || die "$name on chain is $got, local build is $want"
    note "$name code matches the local build"
done
rm -rf "$tmp"

expect() {      # expect LABEL WANT CONTRACT FN [ARGS...]
    local label=$1 want=$2; shift 2
    local got; got=$(read_call VERIFY "$@")
    [ "$got" = "$want" ] || die "$label is $got on chain, expected $want"
    note "$label = $got"
}
# Struct results print as JSON; with quotes and spaces stripped, each field
# reads name:value.
cfg=$(read_call VERIFY "$ROSTER_ID" get_config)
for f in "min_stake:$MIN_STAKE" "unbonding_ledgers:$UNBONDING_LEDGERS" "pay_token:$XLM_SAC"; do
    [[ $cfg == *"$f"[,}]* ]] || die "roster config on chain does not have $f: $cfg"
done
note "roster config matches (min_stake, unbonding_ledgers, pay_token)"
expect "roster min_stake" "$MIN_STAKE" "$ROSTER_ID" min_stake
expect "mint node_fee" "$NODE_FEE" "$MINT_ID" node_fee
expect "mint min_pairs" "$MIN_PAIRS" "$MINT_ID" min_pairs
expect "mint max_pairs" "$MAX_PAIRS" "$MINT_ID" max_pairs
expect "mint max_print_ledgers" "$MAX_PRINT_LEDGERS" "$MINT_ID" max_print_ledgers
expect "mint pay_token" "$USDC_SAC" "$MINT_ID" pay_token
expect "mint roster" "$ROSTER_ID" "$MINT_ID" roster
sel=$(read_call VERIFY "$MINT_ID" selection)
for f in "beacon_genesis:$BEACON_GENESIS" "beacon_period:$BEACON_PERIOD" "beacon_lead:$BEACON_LEAD" \
         "claim_window:$CLAIM_WINDOW" "serve_timeout:$SERVE_TIMEOUT" "min_node_age:$MIN_NODE_AGE" \
         "fallback_delay:$FALLBACK_DELAY"; do
    [[ $sel == *"$f"[,}]* ]] || die "mint selection on chain does not have $f: $sel"
done
[[ ${sel,,} == *"$BEACON_PK"* ]] || die "mint selection on chain has a different beacon key"
note "mint selection matches (beacon key, genesis, period, lead, windows, min_node_age, fallback_delay)"

# ── Record ───────────────────────────────────────────────────────────
ledger=$(rpc_json "$VERIFY_RPC_URL" getLatestLedger | grep -oE '"sequence":[0-9]+' | cut -d: -f2)
mkdir -p dist
record=dist/mainnet-deploy-$TAG.txt
cat >"$record" <<EOF
Kenter mainnet deployment
network            Public Global Stellar Network ; September 2015
source             $TAG $COMMIT
built with         rustc $rv, stellar-cli $cli, x86_64 Linux
verified at ledger $ledger via $VERIFY_RPC_URL
deployer           $DEPLOYER_ADDR

roster             $ROSTER_ID
  wasm sha256      $ROSTER_SHA
  min_stake        $MIN_STAKE
  pay_token        $XLM_SAC (XLM)
  unbonding        $UNBONDING_LEDGERS ledgers

mint               $MINT_ID
  wasm sha256      $MINT_SHA
  node_fee         $NODE_FEE
  pairs            $MIN_PAIRS..$MAX_PAIRS
  pay_token        $USDC_SAC (USDC:$USDC_ISSUER)
  max_print        $MAX_PRINT_LEDGERS ledgers
  selection        $SELECTION

Build environment for mainnet releases:
  KENTER_MAINNET_ROSTER=$ROSTER_ID
  KENTER_MAINNET_MINT=$MINT_ID

To verify: check out $TAG on x86_64 Linux, run stellar contract build in
each contract directory, and compare the sha256 of the wasm with the
contract code fetched from any mainnet RPC (stellar contract fetch --id).
EOF
say "Deployed and verified"
cat "$record" >&2
note "record written to $record: publish it with the release."
