#!/bin/sh
# Replace the installed Kenter node with the .deb beside this script,
# keeping the node's identity: its keys, config and stake.
#
#   sudo sh reinstall-kenter-node.sh
#
# Put this script and the new kenter-node_*.deb (and SHA256SUMS, if you
# have it) in one folder, and run it from anywhere. It:
#
#   1. finds the .deb for this machine's architecture beside the script and
#      checks it against SHA256SUMS when that file is there;
#   2. stops the node, which takes the pair out of selection first;
#   3. removes the old package -- never purges: /var/lib/kenter-node, where
#      the pair's keys and config live, is not touched;
#   4. installs the new one (from /tmp, so apt's sandbox user can read it);
#   5. starts the node again if it was enabled before, and shows its status.
#
# The node's stake is on the roster and its keys are in /var/lib/kenter-node,
# so nothing on chain changes. On first start the new version registers the
# pair with the new mint by itself.
set -eu

die() { echo "reinstall: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run it with sudo: sudo sh $0"
command -v dpkg >/dev/null || die "this is not a Debian-based system"

here=$(cd "$(dirname "$0")" && pwd)
arch=$(dpkg --print-architecture)

# 1. The package for this machine, and only one.
set -- "$here"/kenter-node_*_"$arch"-*.deb
[ -e "$1" ] || die "no kenter-node_*_$arch-*.deb in $here (this machine is $arch)"
[ "$#" -eq 1 ] || die "more than one $arch package in $here; keep only the one to install: $*"
deb=$1
name=$(basename "$deb")
echo "package : $name"

if [ -f "$here/SHA256SUMS" ]; then
    want=$(grep "  $name\$" "$here/SHA256SUMS" | cut -d' ' -f1 || true)
    [ -n "$want" ] || die "SHA256SUMS has no line for $name"
    got=$(sha256sum "$deb" | cut -d' ' -f1)
    [ "$want" = "$got" ] || die "checksum mismatch for $name: expected $want, got $got"
    echo "checksum: ok"
else
    echo "checksum: no SHA256SUMS beside the script, not checked"
fi

new_version=$(dpkg-deb -f "$deb" Version)
old_version=$(dpkg-query -W -f '${Version}' kenter-node 2>/dev/null || true)
echo "version : ${old_version:-not installed} -> $new_version"

# The identity has to be there before anything is removed, or this is a
# fresh install and the operator should know it.
if [ -n "$old_version" ] && [ ! -d /var/lib/kenter-node ]; then
    die "kenter-node is installed but /var/lib/kenter-node is missing; not touching it"
fi

# 2. Stop, remembering whether it should come back.
was_enabled=no
if systemctl is-enabled --quiet kenter-node 2>/dev/null; then
    was_enabled=yes
fi
if systemctl is-active --quiet kenter-node 2>/dev/null; then
    echo "stopping the node (it leaves selection first)..."
    systemctl stop kenter-node
fi

# 3. Remove, never purge.
if [ -n "$old_version" ]; then
    echo "removing $old_version (keys and config in /var/lib/kenter-node are kept)..."
    apt-get remove -y kenter-node
fi

# 4. Install from /tmp: apt reads local packages as its own sandbox user,
# which cannot read most home directories ("Permission denied").
tmp=$(mktemp -d /tmp/kenter-node.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
cp "$deb" "$tmp/"
chmod 0755 "$tmp"
chmod 0644 "$tmp/$name"
echo "installing $new_version..."
apt-get install -y "$tmp/$name"

[ -d /var/lib/kenter-node ] || echo "note: no /var/lib/kenter-node yet; set the node up with: sudo kenter-nodectl init --name <name>"

# 5. Back up if it was running before.
if [ "$was_enabled" = "yes" ]; then
    systemctl daemon-reload
    systemctl enable --now kenter-node
    echo "node started; waiting a few seconds for it to come online..."
    sleep 8
    kenter-nodectl status || true
else
    echo "the node was not enabled before, so it is left stopped."
    echo "start it with: sudo systemctl enable --now kenter-node"
fi
echo "done."
