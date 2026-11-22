#!/usr/bin/env bash
# Sign a release's SHA256SUMS with the release key, then verify the signature
# against allowed_signers the way a downloader would.
#
#   scripts/sign-release.sh [dist-dir]      (default: dist)
#
# Writes <dist-dir>/SHA256SUMS.sig. The key is a FIDO2 key on a hardware
# token: expect a PIN prompt and a touch. Override the key reference with
# KENTER_SIGN_KEY (default ~/.ssh/id_kenter_sign).

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST=${1:-dist}
KEY=${KENTER_SIGN_KEY:-$HOME/.ssh/id_kenter_sign}
SIGNERS=$ROOT/allowed_signers
PRINCIPAL=358557624+kenter-bank@users.noreply.github.com

sums=$DIST/SHA256SUMS
[[ -f $sums ]] || { echo "no $sums: build the packages first" >&2; exit 1; }
[[ -f $KEY ]] || { echo "no signing key reference at $KEY" >&2; exit 1; }

# Every file listed must be present and match before anything is signed.
(cd "$DIST" && sha256sum --check --strict SHA256SUMS)

rm -f "$sums.sig"
ssh-keygen -Y sign -f "$KEY" -n file "$sums"
ssh-keygen -Y verify -f "$SIGNERS" -I "$PRINCIPAL" -n file -s "$sums.sig" <"$sums"
echo "signed: $sums.sig"
