#!/usr/bin/env bash
# Build the headless node's .deb (installing it: docs/TESTNET.md).
#
#   packaging/linux/build-deb.sh                 # arm64, for a Raspberry Pi
#   TARGET=x86_64-unknown-linux-gnu packaging/linux/build-deb.sh
#   MAINNET=1 packaging/linux/build-deb.sh       # needs KENTER_MAINNET_MINT/_ROSTER
#
# Runs on Debian or Ubuntu (WSL is fine). Needs zig (pinned below):
#   pip3 install ziglang==0.13.0
# cargo-deb and cargo-zigbuild are installed at their pinned versions.
# plus perl and make (OpenSSL is built from source for the target, feature
# vendored-openssl, so no target OpenSSL packages are needed).
#
# Linked against an old glibc (GLIBC, default 2.31) through zig, not the
# build machine's: a binary built on Debian 13 needs glibc 2.41, and
# Raspberry Pi OS (Bookworm) has 2.36. 2.31 covers Bookworm, Bullseye and
# Ubuntu 20.04 onward.
#
# Output: dist/kenter-node_<version>-1_<arch>-<network>.deb and its line in
# dist/SHA256SUMS. The package is not signed.
set -euo pipefail
cd "$(dirname "$0")/../.."

TARGET=${TARGET:-aarch64-unknown-linux-gnu}
NETWORK=testnet
FEATURES=vendored-openssl
if [ "${MAINNET:-0}" = "1" ]; then
    : "${KENTER_MAINNET_MINT:?a mainnet build needs KENTER_MAINNET_MINT}"
    : "${KENTER_MAINNET_ROSTER:?a mainnet build needs KENTER_MAINNET_ROSTER}"
    : "${KENTER_MAINNET_RELAYS:?a mainnet build needs KENTER_MAINNET_RELAYS}"
    NETWORK=mainnet
    FEATURES="$FEATURES,kenter-client/mainnet"
else
    : "${KENTER_TESTNET_MINT:?a testnet build needs KENTER_TESTNET_MINT}"
    : "${KENTER_TESTNET_ROSTER:?a testnet build needs KENTER_TESTNET_ROSTER}"
    : "${KENTER_TESTNET_RELAYS:?a testnet build needs KENTER_TESTNET_RELAYS}"
fi

GLIBC=${GLIBC:-2.31}

# Pinned build tools: a different tool is a
# different package. Installed if missing, refused if another version.
CARGO_DEB_VERSION=3.8.0
CARGO_ZIGBUILD_VERSION=0.24.1
ZIG_VERSION=0.13.0

rustup target add "$TARGET" >/dev/null
pinned() { cargo install --list | grep -q "^$1 v$2:"; }
pinned cargo-deb "$CARGO_DEB_VERSION"     || cargo install cargo-deb --locked --version "$CARGO_DEB_VERSION"
pinned cargo-zigbuild "$CARGO_ZIGBUILD_VERSION"     || cargo install cargo-zigbuild --locked --version "$CARGO_ZIGBUILD_VERSION"
zig_found=$(python3 -m ziglang version 2>/dev/null || zig version 2>/dev/null || true)
[ "$zig_found" = "$ZIG_VERSION" ] || {
    echo "zig $ZIG_VERSION required (pip3 install ziglang==$ZIG_VERSION), found '${zig_found:-none}'" >&2
    exit 1
}

TARGET_DIR=${CARGO_TARGET_DIR:-target}
cargo zigbuild --release --locked -p kenter-node --bin kenter-node     --target "$TARGET.$GLIBC" --features "$FEATURES"
cargo deb -p kenter-node --target "$TARGET" --no-build

mkdir -p dist
deb=$(ls -t "$TARGET_DIR/$TARGET/debian/"kenter-node_*.deb | head -1)
out="dist/$(basename "${deb%.deb}")-$NETWORK.deb"
cp "$deb" "$out"

# dist/SHA256SUMS: replace this file's line, keep the others.
name=$(basename "$out")
touch dist/SHA256SUMS
{ grep -v "  $name\$" dist/SHA256SUMS || true; (cd dist && sha256sum "$name"); } \
    | sort -k2 > dist/SHA256SUMS.new
mv dist/SHA256SUMS.new dist/SHA256SUMS
echo "Built $out"
