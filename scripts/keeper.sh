#!/usr/bin/env bash
#
# Pay the contracts' storage rent, on a schedule.
#
# Soroban charges rent for every live ledger entry. Both contracts bump
# their own entries lazily -- only once something is within 30 days of
# archival, and then out to 120 days -- which keeps rent off an ordinary
# caller's bill at the cost of making one arbitrary transaction pay the
# whole top-up. Measured on testnet, that lump is 33.98 XLM against
# 0.0011 XLM for a warm call, and it lands on whoever happens to be next
# through the door: a depositor, a node joining, a holder redeeming.
#
# `bump` exists so the bill lands on someone who chose to pay it. It
# tops the entries up whatever their remaining life, so running this
# often makes each run cheap and the lazy threshold is never reached.
#
#   docs/LEDGER_COSTS.md    the figures, who pays what, and why each
#                           entry has the life it has
#
# Usage:
#   scripts/keeper.sh                 # bump both, ids from .env
#   DRY_RUN=1 scripts/keeper.sh       # print the commands only
#   KEEPER=my-alias scripts/keeper.sh # sign as a different identity
#
# Exits non-zero if either bump fails, so a timer or a monitor notices.
#
set -euo pipefail

# The signing identity, as a stellar-CLI keystore alias. An alias is not
# a secret -- the CLI resolves and signs with it -- which is why this
# takes one rather than a key. Passing the secret itself would put a
# funded key in the process table, in shell history and in the journal.
#
# On a fresh host: `stellar keys add kenter-keeper --secret-key` (it
# prompts; the value never reaches argv).
KEEPER=${KEEPER:-testnet-deployer}

RPC_URL=${RPC_URL:-https://soroban-testnet.stellar.org:443}
PASSPHRASE=${PASSPHRASE:-Test SDF Network ; September 2015}
DRY_RUN=${DRY_RUN:-0}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# .env holds secrets as well as addresses, so read the two values we
# need rather than sourcing it. It also cannot be sourced: the network
# passphrase is unquoted and the `;` in it ends the command.
env_of() { grep "^$1=" .env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'"' \r'; }
MINT=${MINT:-$(env_of KENTER_MINT)}
ROSTER=${ROSTER:-$(env_of KENTER_ROSTER)}

[ -n "$MINT" ]   || { echo "keeper: no mint id (set MINT, or KENTER_MINT in .env)" >&2; exit 1; }
[ -n "$ROSTER" ] || { echo "keeper: no roster id (set ROSTER, or KENTER_ROSTER in .env)" >&2; exit 1; }

NET_ARGS=(--rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE")

log() { printf '%s keeper: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

failed=0

bump_one() {
    local name=$1 id=$2

    # --send=yes is load-bearing, and its absence is silent.
    #
    # `bump` only extends TTLs, so the simulation's read_write footprint
    # is empty and the CLI classifies the call as read-only. Without this
    # flag it declines to submit -- printing a plausible new TTL ledger,
    # exiting zero, and changing nothing. The deploy script's warm step
    # did exactly that on its first run, and the next `join` paid 19.23
    # XLM for an extension nobody had made.
    local cmd=(stellar contract invoke
        --id "$id"
        --source-account "$KEEPER"
        "${NET_ARGS[@]}"
        --send=yes
        -- bump)

    if [ "$DRY_RUN" = "1" ]; then
        printf '  $ %s\n' "${cmd[*]}"
        return 0
    fi

    local out
    if out=$("${cmd[@]}" 2>&1); then
        # `bump` returns the ledger the core entries now live until.
        local until
        until=$(printf '%s' "$out" | grep -oE '^[0-9]+$' | tail -1)
        log "$name ok, live until ledger ${until:-?}"
    else
        log "$name FAILED"
        printf '%s\n' "$out" >&2
        failed=1
    fi
}

log "bumping as $KEEPER"
bump_one roster "$ROSTER"
bump_one mint "$MINT"

if [ "$failed" -ne 0 ]; then
    log "one or more bumps failed"
    exit 1
fi

log "done"
