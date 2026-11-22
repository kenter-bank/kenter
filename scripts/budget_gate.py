#!/usr/bin/env python3
"""Refuse a `max_pairs` whose redemption would not comfortably fit.

A note printed above the CPU budget can never be redeemed by chain.
The mint is immutable, so there is no fixing it afterwards -- such a
note is redeemable only through Path A and the live node network,
which is the dependency Path B exists to avoid. The check therefore
belongs at deploy time, before the constructor fixes `max_pairs`.

Why this is not a contract test
-------------------------------
Because a contract test cannot answer the question. Soroban's CPU cost
parameters are a **ledger entry**, not a compiled-in table, so they
differ per network and change by validator vote. When measured,
`VerifyEd25519Sig` cost 706,689 + 4,229/byte on testnet against
377,551 + 4,059 on mainnet and 377,524 + 4,068 in the host's built-in
defaults. Path B verifies two signatures per link, so that one entry
moves the answer by about a third at 3 pairs and more as pairs grow.
The per-transaction ceiling it is all measured against,
`tx_max_instructions`, is a ledger entry too.

So the test suite's 100M `TEST_BUDGET_INSTRUCTIONS` is a self-imposed
tripwire that catches the contract growing, and this is the thing that
answers "will it fit".

The estimate
------------
Anchored on network measurements rather than on a re-priced harness,
because a harness re-priced from defaults can be wrong about this. Two
`simulateTransaction` readings against a live testnet mint,
`redeem_by_chain`, depositor at both ends:

    3 pairs   13,052,010 instructions
    8 pairs   32,115,752 instructions

giving 1.6136M + 3.8127M per pair (see the Path B cost in
`docs/architecture/network.md`).

That fit was taken under testnet's cost table, the dearer of the two,
so applying it unchanged to mainnet is conservative. To stay
conservative when the table *rises*, the estimate is scaled by the
live `VerifyEd25519Sig` constant over the one the fit was measured
under -- the dominant per-pair term -- and the factor is floored at
1.0 so a cheaper table never licenses more pairs than were measured.
That is deliberately cruder than re-pricing every cost type: it is
monotone, it cannot be wrong in the dangerous direction, and the thing
it tracks is the thing that actually moved.

Usage
-----
    scripts/budget_gate.py --rpc-url URL --max-pairs N [--margin 0.5]

Exits 0 if the configured `max_pairs` fits inside `margin` of the live
limit, 1 if it does not, and 2 if the network could not be asked --
failing closed, because an unanswered question is not a pass.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

# ConfigSettingID discriminants, as LedgerKey::ConfigSetting payloads.
# Both keys are 8 bytes: the LedgerEntryType (8 = CONFIG_SETTING)
# followed by the ConfigSettingID.
KEY_COMPUTE = "AAAACAAAAAE="          # 1 = CONTRACT_COMPUTE_V0
KEY_CPU_COST_PARAMS = "AAAACAAAAAY="  # 6 = CONTRACT_COST_PARAMS_CPU_INSTRUCTIONS

# Position of VerifyEd25519Sig in the ContractCostType enum. The RPC
# returns the parameters as a bare array, so the index is the only
# handle on it.
VERIFY_ED25519_SIG = 10

# The fit, and the table it was measured under. Changing either means
# re-measuring: see the module docstring.
FIT_INTERCEPT = 1_613_600
FIT_SLOPE_PER_PAIR = 3_812_700
FIT_MEASURED_UNDER_VERIFY_CONST = 706_689

# The contract's own ceiling on what a deployment may configure.
MAX_REDEEMABLE_PAIRS = 12


def fetch(rpc_url, key):
    """Read one config ledger entry, as JSON."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLedgerEntries",
        "params": {"keys": [key], "xdrFormat": "json"},
    }).encode()
    # A User-Agent is not optional: the public RPC answers 403 to
    # urllib's default one.
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "kenter-budget-gate"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        payload = json.load(r)
    if "error" in payload:
        raise RuntimeError(f"RPC error: {payload['error']}")
    entries = payload.get("result", {}).get("entries") or []
    if not entries:
        raise RuntimeError(f"no config entry returned for key {key}")
    return entries[0]["dataJson"]["config_setting"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc-url", required=True)
    ap.add_argument("--max-pairs", type=int, required=True)
    ap.add_argument(
        "--margin",
        type=float,
        default=0.5,
        help="fraction of the live limit a redemption may use (default 0.5). "
             "Both the limit and the prices move by vote, so the headroom is "
             "the point.",
    )
    args = ap.parse_args()

    try:
        compute = fetch(args.rpc_url, KEY_COMPUTE)["contract_compute_v0"]
        limit = int(compute["tx_max_instructions"])
        params = fetch(args.rpc_url, KEY_CPU_COST_PARAMS)[
            "contract_cost_params_cpu_instructions"
        ]
    except (urllib.error.URLError, OSError, KeyError, ValueError, RuntimeError) as e:
        print(f"budget gate: could not read the network's config: {e}", file=sys.stderr)
        print("  Refusing to deploy on an unanswered question. Set", file=sys.stderr)
        print("  SKIP_BUDGET_CHECK=1 to override deliberately.", file=sys.stderr)
        return 2

    if len(params) <= VERIFY_ED25519_SIG:
        print(
            f"budget gate: cost table has {len(params)} entries, expected more than "
            f"{VERIFY_ED25519_SIG}. The ContractCostType enum has changed; this "
            f"script's index is stale.",
            file=sys.stderr,
        )
        return 2
    verify_const = int(params[VERIFY_ED25519_SIG]["const_term"])

    # Floored at 1.0: a cheaper table than the one the fit was measured
    # under must not buy more pairs than were actually measured.
    factor = max(1.0, verify_const / FIT_MEASURED_UNDER_VERIFY_CONST)

    def estimate(n):
        return (FIT_INTERCEPT + FIT_SLOPE_PER_PAIR * n) * factor

    allowance = args.margin * limit
    largest = 0
    for n in range(1, MAX_REDEEMABLE_PAIRS + 1):
        if estimate(n) <= allowance:
            largest = n

    used = estimate(args.max_pairs)
    print(f"  tx_max_instructions     : {limit:,} (live)")
    print(f"  VerifyEd25519Sig const  : {verify_const:,} "
          f"(fit measured under {FIT_MEASURED_UNDER_VERIFY_CONST:,}, factor {factor:.3f})")
    print(f"  estimate at {args.max_pairs} pairs      : {used:,.0f} "
          f"({used / limit * 100:.1f}% of the limit)")
    print(f"  allowance ({args.margin:.0%} of limit)  : {allowance:,.0f} "
          f"-> largest safe max_pairs {largest}")

    if args.max_pairs > largest:
        sys.stdout.flush()
        print(
            f"\ndeploy aborted: max_pairs={args.max_pairs} needs about "
            f"{used:,.0f} instructions, over the {args.margin:.0%} allowance of "
            f"{allowance:,.0f}.",
            file=sys.stderr,
        )
        print(
            f"  Configure max_pairs <= {largest}, or re-measure if the fit is "
            f"stale. A note printed above the budget can never be redeemed by "
            f"chain, and the mint cannot be changed afterwards.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
