#!/usr/bin/env bash
# Install or update the Kenter relay on a host that already runs nginx with
# TLS for $DOMAIN (docs/DEPLOY.md). Idempotent: an existing key is
# kept. Run as root, from a directory holding kenter-tunnler (the x86_64
# Linux binary), kenter-tunnler.service and gen-relay-key.py.
#
#   DOMAIN=relay.example.org ROSTER=C... ./setup-relay.sh
set -euo pipefail
: "${DOMAIN:?set DOMAIN}"
: "${ROSTER:?set ROSTER (the roster contract id)}"
PORT=${PORT:-8000}

id kenter-relay >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/kenter-tunnler --shell /usr/sbin/nologin kenter-relay
install -m 0755 kenter-tunnler /usr/local/bin/kenter-tunnler
install -d -m 0700 -o root -g root /etc/kenter-tunnler

ENV=/etc/kenter-tunnler/env
if [ ! -f "$ENV" ]; then
    umask 077
    {
        printf 'TUNNLER_SERVER_SECRET=%s\n' "$(python3 gen-relay-key.py)"
        printf 'TUNNLER_HOST=127.0.0.1\nTUNNLER_PORT=%s\nTUNNLER_DOMAIN=%s\nROSTER_CONTRACT_ID=%s\n' "$PORT" "$DOMAIN" "$ROSTER"
    } > "$ENV"
    echo "generated a new relay key in $ENV"
else
    # Keep the key; refresh the rest.
    sed -i -E "s/^TUNNLER_DOMAIN=.*/TUNNLER_DOMAIN=$DOMAIN/; s/^ROSTER_CONTRACT_ID=.*/ROSTER_CONTRACT_ID=$ROSTER/; s/^TUNNLER_PORT=.*/TUNNLER_PORT=$PORT/" "$ENV"
fi
chown root:root "$ENV"; chmod 0600 "$ENV"   # systemd reads it as root

install -m 0644 kenter-tunnler.service /etc/systemd/system/kenter-tunnler.service
systemctl daemon-reload
systemctl enable kenter-tunnler >/dev/null
systemctl restart kenter-tunnler
sleep 2
systemctl --no-pager --lines=5 status kenter-tunnler | sed -n '1,4p'
