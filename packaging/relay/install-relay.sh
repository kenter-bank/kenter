#!/bin/sh
# Install or update a Kenter relay on a fresh Debian or Ubuntu VPS. As root
# (log in as root; sudo drops what --close-ssh checks):
#
#   sh install-relay.sh TAG          install, or update to the relay release TAG
#   sh install-relay.sh --close-ssh  close public SSH, once you've logged in
#                                    through the onion (run it from that session)
#
# Settings, in the environment:
#   DOMAIN=relay.example.org   the relay's name; default: the release's (relay.env).
#                              It must be a relay the wallet builds list.
#   ONION_AUTH=descriptor:x25519:<base32>
#                              the operator's onion client key: only that key
#                              can reach SSH's onion service. Without it the
#                              onion is open to anyone who learns its address
#                              (SSH still takes keys only).
#   SKIP_DNS_CHECK=1           behind NAT, where DOMAIN can't resolve to an
#                              address of this machine.
#
# A release downloads anonymously from GitHub. Before anything is installed,
# SHA256SUMS must verify against the release key pinned below, every file
# against SHA256SUMS, and RELEASE must name TAG, so an older signed release
# can't pose as a newer one. Compare the pinned key with `allowed_signers`
# in a fresh clone of the kenter repository before you trust this script.
#
# Then it installs the relay under a hardened systemd unit, makes the relay's
# key on this machine, puts nginx in front (TLS from Let's Encrypt, the base
# domain only, per-IP limits, no access log), sets a firewall (80 and 443, and
# 22 until --close-ssh), makes SSH key-only, publishes SSH as a Tor onion
# service, and sets a root password for the provider's console (shown once).
# Run it again to resume after a failure, or with a new TAG to update: the
# relay's key, the certificate and the onion are kept.
set -eu

REPO=kenter-vault/kenter
# The release key, as in the kenter repository's allowed_signers.
PRINCIPAL=358557624+kenter-bank@users.noreply.github.com
SIGNERS='358557624+kenter-bank@users.noreply.github.com namespaces="git,file" sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIKdNBCpNq+7HKdpxBhvzpk8hIDmsgXIdTlgPQVxBvNk/AAAAD3NzaDprZW50ZXItc2lnbg== kenter-sign'
# What a relay release holds. A file not listed in SHA256SUMS stops the install.
FILES="RELEASE relay.env kenter-tunnler kenter-tunnler.service gen-relay-key.py install-relay.sh"

STATE=/var/lib/kenter-relay-install
ENVF=/etc/kenter-tunnler/env
NGINX_SITE=/etc/nginx/sites-available/kenter-relay
ACME=/var/www/acme
ONION_DIR=/var/lib/tor/kenter-ssh
RELAY_PORT=8000

say() { printf '\n== %s\n' "$*"; }
ok() { printf '   ok  %s\n' "$*"; }
die() { printf '\ninstall-relay: %s\n' "$*" >&2; exit 1; }

usage="usage: sh install-relay.sh TAG | --close-ssh"
[ $# -eq 1 ] || die "$usage"
[ "$(id -u)" -eq 0 ] || die "run as root"

# --- Firewall ---------------------------------------------------------------

# SSH's ports, as sshd itself reports them.
ssh_ports() {
    sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u | tr '\n' ' '
}

write_firewall() {
    if [ -e "$STATE/.ssh-closed" ]; then
        ssh_rule="# SSH: only through the onion (install-relay.sh --close-ssh)"
    else
        ports=$(ssh_ports | sed 's/ *$//; s/ /, /g')
        [ -n "$ports" ] || ports=22
        ssh_rule="tcp dport { $ports } accept"
    fi
    cat > /etc/nftables.conf.new <<EOF
#!/usr/sbin/nft -f
# Written by install-relay.sh. In: 80 (ACME, redirect) and 443 (the relay),
# and SSH until --close-ssh. Out: anything.
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        meta l4proto { icmp, ipv6-icmp } accept
        tcp dport { 80, 443 } accept
        $ssh_rule
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    nft -c -f /etc/nftables.conf.new || die "the firewall rules don't parse; nothing changed"
    mv /etc/nftables.conf.new /etc/nftables.conf
    systemctl enable -q nftables
    nft -f /etc/nftables.conf
}

# --- --close-ssh ------------------------------------------------------------

if [ "$1" = "--close-ssh" ]; then
    [ -e "$STATE/.installed" ] || die "install the relay first"
    [ -s "$ONION_DIR/hostname" ] || die "SSH's onion service isn't up; closing 22 would lock you out"
    # An SSH session that came in through the onion arrives from Tor on
    # this machine, so its client address is loopback.
    set -- ${SSH_CONNECTION:-none}
    case $1 in
    127.0.0.1 | ::1) ;;
    *) die "this session didn't come through the onion (from ${1}). Log in through it
  (from the laptop: ssh <the relay's ssh config name>) and run --close-ssh from there." ;;
    esac
    touch "$STATE/.ssh-closed"
    write_firewall
    say "Public SSH is closed"
    echo "   SSH is reachable only at $(cat "$ONION_DIR/hostname")."
    echo "   The provider's console is the way back in."
    exit 0
fi

TAG=$1
case $TAG in
relay-v[0-9]*.[0-9]*.[0-9]*) ;;
*) die "TAG is a relay release, such as relay-v0.1.0 ($usage)" ;;
esac

# --- 1. Checks --------------------------------------------------------------

say "1. Checks"
[ "$(uname -m)" = x86_64 ] || die "x86_64 only (this is $(uname -m))"
. /etc/os-release
case ${ID:-} in debian | ubuntu) ;; *) die "Debian or Ubuntu only (this is ${ID:-unknown})" ;; esac
[ -d /run/systemd/system ] || die "needs systemd"
ok "$PRETTY_NAME, x86_64, systemd"
mkdir -p "$STATE"
chmod 0700 "$STATE"

# --- 2. Packages ------------------------------------------------------------

say "2. Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx certbot nftables tor curl ca-certificates python3 \
    openssh-client openssh-server iproute2 unattended-upgrades >/dev/null
# Security updates install themselves; reboots stay the operator's choice.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
ok "installed; security updates on"

# --- 3. The release ---------------------------------------------------------

say "3. Release $TAG"
REL=$STATE/release/$TAG
if [ -e "$REL/.verified" ]; then
    ok "already verified"
else
    rm -rf "$REL"
    mkdir -p "$REL"
    fetch() {
        curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$REL/$1" \
            "https://github.com/$REPO/releases/download/$TAG/$1" \
            || die "could not download $1 from $TAG's release"
    }
    fetch SHA256SUMS
    fetch SHA256SUMS.sig
    printf '%s\n' "$SIGNERS" > "$REL/allowed_signers"
    ssh-keygen -Y verify -f "$REL/allowed_signers" -I "$PRINCIPAL" -n file \
        -s "$REL/SHA256SUMS.sig" < "$REL/SHA256SUMS" >/dev/null 2>&1 \
        || die "SHA256SUMS is not signed by the release key: refusing $TAG"
    ok "SHA256SUMS signed by the release key"
    for f in $FILES; do
        grep -q "  $f\$" "$REL/SHA256SUMS" || die "SHA256SUMS doesn't list $f"
        fetch "$f"
    done
    (cd "$REL" && grep -E "  ($(echo "$FILES" | tr ' ' '|'))\$" SHA256SUMS | sha256sum -c --quiet --strict) \
        || die "a file doesn't match SHA256SUMS: refusing $TAG"
    [ "$(cat "$REL/RELEASE")" = "$TAG" ] || die "the release says it is $(cat "$REL/RELEASE"), not $TAG"
    ok "every file matches; RELEASE is $TAG"
    touch "$REL/.verified"
fi
get() { sed -n "s/^$1=//p" "$REL/relay.env" | head -n 1; }
DOMAIN=${DOMAIN:-$(get TUNNLER_DOMAIN)}
ROSTER=$(get ROSTER_CONTRACT_ID)
RPC=$(get SOROBAN_RPC_URL)
NETWORK=$(get NETWORK)
[ -n "$DOMAIN" ] && [ -n "$ROSTER" ] && [ -n "$RPC" ] || die "relay.env is missing a setting"
ok "$NETWORK relay $DOMAIN, roster $ROSTER"

# --- 4. The relay -----------------------------------------------------------

say "4. Relay"
id kenter-relay >/dev/null 2>&1 || useradd --system --no-create-home \
    --home-dir /var/lib/kenter-tunnler --shell /usr/sbin/nologin kenter-relay
install -m 0755 "$REL/kenter-tunnler" /usr/local/bin/kenter-tunnler.new
mv /usr/local/bin/kenter-tunnler.new /usr/local/bin/kenter-tunnler
install -m 0644 "$REL/kenter-tunnler.service" /etc/systemd/system/kenter-tunnler.service
install -d -m 0700 /etc/kenter-tunnler
# The relay's key is made here and never leaves. Nothing pins it (nodes
# trust TLS), so a rebuilt relay simply makes a new one.
secret=
[ -f "$ENVF" ] && secret=$(sed -n 's/^TUNNLER_SERVER_SECRET=//p' "$ENVF")
[ -n "$secret" ] || secret=$(python3 "$REL/gen-relay-key.py")
(
    umask 077
    {
        printf 'TUNNLER_SERVER_SECRET=%s\n' "$secret"
        printf 'TUNNLER_HOST=127.0.0.1\nTUNNLER_PORT=%s\n' "$RELAY_PORT"
        printf 'TUNNLER_DOMAIN=%s\nROSTER_CONTRACT_ID=%s\nSOROBAN_RPC_URL=%s\n' "$DOMAIN" "$ROSTER" "$RPC"
        printf 'TUNNLER_TRUSTED_PROXIES=127.0.0.1\nTUNNLER_LOG_LEVEL=info\n'
    } > "$ENVF.new"
)
mv "$ENVF.new" "$ENVF"
secret=
systemctl daemon-reload
systemctl enable -q kenter-tunnler
systemctl restart kenter-tunnler
sleep 3
systemctl is-active -q kenter-tunnler || die "the relay didn't start: journalctl -u kenter-tunnler -n 30"
journalctl -u kenter-tunnler -n 50 --no-pager -o cat | grep -q "roster gating ENABLED" \
    || die "the relay started without roster gating: journalctl -u kenter-tunnler -n 30"
ok "running, roster gating on"

# --- 5. nginx and TLS -------------------------------------------------------

say "5. nginx and TLS for $DOMAIN"
mkdir -p "$ACME"
rm -f /etc/nginx/sites-enabled/default
port80() {
    cat <<EOF
# Written by install-relay.sh. Port 80 serves ACME challenges and a
# redirect, nothing else: proxying here would carry the WebSocket handshake
# in cleartext.
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    access_log off;
    location /.well-known/acme-challenge/ { root $ACME; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
}
port443() {
    cat <<EOF

# /proxy takes no authentication: a wallet reaching a node. The relay
# forwards only POST /kenter/health and /kenter/extend, up to 64 KiB; these
# limits stop a flood before it reaches the relay. A wallet makes a handful
# of calls per print; 10 a second per IP leaves room for depositors who
# share an address (a Tor exit).
limit_conn_zone \$binary_remote_addr zone=ws_conn:10m;
limit_req_zone \$binary_remote_addr zone=proxy_req:10m rate=10r/s;
limit_req_status 429;

upstream tunnler {
    server 127.0.0.1:$RELAY_PORT;
    keepalive 32;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $DOMAIN;
    # No access log: the relay keeps no record of who reached which node.
    access_log off;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 64k;
    client_header_timeout 10s;
    client_body_timeout 10s;

    # Nodes: a WebSocket each, held up to a day.
    location = /connect {
        limit_conn ws_conn 5;
        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        # The relay keys its limits on this and believes it only from
        # loopback (TUNNLER_TRUSTED_PROXIES). Set here, never passed through.
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    location = /health {
        limit_req zone=proxy_req burst=20 nodelay;
        proxy_pass http://tunnler;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    # Wallets. A node answers an extend only after its confirm_link lands,
    # and the relay waits up to 120 s for it.
    location /proxy/ {
        limit_req zone=proxy_req burst=20 nodelay;
        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 150;
        proxy_send_timeout 150;
    }

    location / { return 404; }
}
EOF
}
reload_nginx() {
    nginx -t -q || die "nginx refuses the new config: nginx -t"
    systemctl enable -q nginx
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
}
CERT=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
if [ ! -f "$CERT" ]; then
    if [ "${SKIP_DNS_CHECK:-0}" != 1 ]; then
        mine=$(ip -o addr show scope global | awk '{ sub(/\/.*/, "", $4); print $4 }')
        theirs=$(getent ahosts "$DOMAIN" | awk '{ print $1 }' | sort -u)
        [ -n "$theirs" ] || die "$DOMAIN doesn't resolve yet. Point its A (and AAAA) record here:
$mine"
        match=
        for a in $theirs; do echo "$mine" | grep -qx "$a" && match=$a; done
        [ -n "$match" ] || die "$DOMAIN resolves to $(echo $theirs), not to this machine:
$mine
  Fix the DNS records (or set SKIP_DNS_CHECK=1 behind NAT) and run this again."
        ok "$DOMAIN resolves here ($match)"
    fi
    port80 > "$NGINX_SITE"
    ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/kenter-relay
    reload_nginx
    # No email: Let's Encrypt is told nothing about who runs this.
    certbot certonly --webroot -w "$ACME" -d "$DOMAIN" --non-interactive \
        --agree-tos --register-unsafely-without-email --keep-until-expiring -q \
        || die "certbot couldn't get a certificate (is port 80 reachable from outside?)"
    ok "certificate issued"
fi
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/kenter-reload-nginx
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/kenter-reload-nginx
{ port80; port443; } > "$NGINX_SITE"
ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/kenter-relay
reload_nginx
ok "nginx serves $DOMAIN over TLS; renewal reloads it"

# --- 6. Firewall ------------------------------------------------------------

say "6. Firewall"
write_firewall
if [ -e "$STATE/.ssh-closed" ]; then ok "in: 80, 443 (SSH through the onion only)"
else ok "in: 80, 443, SSH on $(ssh_ports)"; fi

# --- 7. SSH -----------------------------------------------------------------

say "7. SSH"
[ -s /root/.ssh/authorized_keys ] \
    || die "root has no authorized SSH key; turning passwords off would lock you out"
grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config \
    || die "sshd_config doesn't read sshd_config.d; add 'Include /etc/ssh/sshd_config.d/*.conf' first"
cat > /etc/ssh/sshd_config.d/10-kenter-relay.conf <<'EOF'
# Written by install-relay.sh: keys only.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
# sshd -t needs its privilege-separation directory, which a socket-activated
# sshd (Ubuntu 24.04) creates only when it first runs.
mkdir -p /run/sshd
sshd -t || die "sshd refuses its config: sshd -t"
systemctl try-reload-or-restart ssh
ok "keys only"
# SSH as an onion service, so the operator never connects from their own address.
if ! grep -q "^HiddenServiceDir $ONION_DIR" /etc/tor/torrc; then
    printf '\n# install-relay.sh: SSH as an onion service\nHiddenServiceDir %s\nHiddenServicePort 22 127.0.0.1:22\n' \
        "$ONION_DIR" >> /etc/tor/torrc
fi
install -d -m 0700 -o debian-tor -g debian-tor "$ONION_DIR" "$ONION_DIR/authorized_clients"
if [ -n "${ONION_AUTH:-}" ]; then
    case $ONION_AUTH in
    descriptor:x25519:[A-Z2-7]*) ;;
    *) die "ONION_AUTH is descriptor:x25519:<base32 public key> (relay-check.sh onion-key)" ;;
    esac
    printf '%s\n' "$ONION_AUTH" > "$ONION_DIR/authorized_clients/operator.auth"
    chown debian-tor:debian-tor "$ONION_DIR/authorized_clients/operator.auth"
    chmod 0600 "$ONION_DIR/authorized_clients/operator.auth"
fi
runuser -u debian-tor -- tor --verify-config -f /etc/tor/torrc >/dev/null || die "tor refuses its config"
systemctl enable -q tor
systemctl restart tor
i=0
while [ ! -s "$ONION_DIR/hostname" ] && [ $i -lt 60 ]; do sleep 1; i=$((i + 1)); done
[ -s "$ONION_DIR/hostname" ] || die "tor didn't publish SSH's onion: journalctl -u tor@default -n 30"
ONION=$(cat "$ONION_DIR/hostname")
if [ -s "$ONION_DIR/authorized_clients/operator.auth" ]; then ok "onion $ONION (client key required)"
else ok "onion $ONION (no client key: set ONION_AUTH and rerun to require one)"; fi

# --- 8. Console password ----------------------------------------------------

say "8. Console password"
if [ -e "$STATE/.console-password" ]; then
    ok "set on an earlier run"
else
    pw=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)
    printf 'root:%s\n' "$pw" | chpasswd
    touch "$STATE/.console-password"
    echo "   root's password, for the provider's console only (SSH takes keys only)."
    echo "   It is shown once. Store it somewhere safe now:"
    echo
    echo "       $pw"
    pw=
fi

# --- 9. Self-check ----------------------------------------------------------

say "9. Self-check"
local_https() { curl -s -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "$@"; }
health=$(curl -s --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/health")
echo "$health" | grep -q '"roster_gating":true' || die "/health over TLS answered: ${health:-nothing}"
ok "/health over TLS, roster gating on"
G=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[ "$(local_https -X POST "https://$DOMAIN/proxy/$G/kenter/shard")" = 404 ] || die "a path outside the two wasn't refused"
[ "$(local_https "https://$DOMAIN/proxy/$G/kenter/health")" = 405 ] || die "a GET through /proxy wasn't refused"
ok "/proxy refuses other paths and methods"
touch "$STATE/.installed"

say "Done: $TAG on $DOMAIN"
# The log may carry colour codes around field names; strip them first.
esc=$(printf '\033')
addr=$(journalctl -u kenter-tunnler -n 200 --no-pager -o cat | sed "s/$esc\[[0-9;]*m//g" \
    | sed -n 's/.*server_address=\([A-Z0-9]*\).*/\1/p' | tail -n 1)
echo "   relay address  ${addr:-unknown (journalctl -u kenter-tunnler)}"
echo "   SSH onion      $ONION"
echo
if [ ! -e "$STATE/.ssh-closed" ]; then
    echo "   Next: from the laptop, set up the onion login (relay-check.sh onion-auth $ONION),"
    echo "   log in through it, and run: sh install-relay.sh --close-ssh"
else
    echo "   Next: from the laptop, check it from outside: relay-check.sh $DOMAIN"
fi
