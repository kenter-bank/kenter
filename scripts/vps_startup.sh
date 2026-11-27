#!/bin/bash
#
# Kenter Tunnler - VPS Startup Script
#
# Universal startup script that works on any VPS provider:
#   - Oracle Cloud (via cloud-init or manual)
#   - DigitalOcean, Linode, Vultr, Hetzner
#   - Container-based VPS (OpenVZ, LXC)
#   - Any Ubuntu/Debian server
#
# Usage (from local machine with repo cloned):
#   scp scripts/vps_startup.sh root@YOUR_VPS:/root/
#   ssh root@YOUR_VPS
#   chmod +x vps_startup.sh
#   ./vps_startup.sh
#
# For cloud-init: paste into "user data" / "startup script" field
#
# Logs: /var/log/kenter-startup.log
#

set -uo pipefail  # Note: removed -e to handle errors gracefully

#=============================================================================
# CONFIGURATION - Modify these variables for your deployment
#=============================================================================

# Domain for relay endpoints. Required: the script refuses the placeholder.
DOMAIN="relay.example.org"

# Git repository URL (public format -- token is injected automatically if set)
REPO_URL="https://github.com/kenter-bank/kenter.git"

# GitHub Personal Access Token (required for private repos)
# Generate at: https://github.com/settings/tokens (fine-grained, repo read-only)
GITHUB_TOKEN=""

# Git branch to deploy
REPO_BRANCH="main"

# Linux user to run the service
KENTER_USER="kenter"

# Log level (debug, info, warn, error)
LOG_LEVEL="info"

#=============================================================================
# END CONFIGURATION - Do not modify below unless you know what you're doing
#=============================================================================

# Derived paths
KENTER_HOME="/home/${KENTER_USER}"
KENTER_DIR="${KENTER_HOME}/kenter"
MARKER_DIR="/var/lib/kenter-tunnler"
MARKER_FILE="${MARKER_DIR}/.initialized"
LOG_FILE="/var/log/kenter-startup.log"

if [[ "$DOMAIN" == "relay.example.org" ]]; then
    echo "ERROR: set DOMAIN at the top of this script to your relay's domain." >&2
    exit 1
fi

# Ensure PATH is set (fixes issues on container-based VPS like OpenVZ/LXC)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Redirect all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "============================================================"
echo "Kenter Tunnler Startup Script"
echo "Started: $(date)"
echo "============================================================"
echo ""

#-----------------------------------------------------------------------------
# Check if this is a restart (marker file exists)
#-----------------------------------------------------------------------------

if [[ -f "$MARKER_FILE" ]]; then
    echo "=== RESTART DETECTED ==="
    echo "Marker file exists: $MARKER_FILE"
    echo "Skipping initialization (already completed)"
    echo ""
    echo "Ensuring services are running..."

    systemctl is-active --quiet kenter-tunnler || systemctl start kenter-tunnler
    systemctl is-active --quiet nginx || systemctl start nginx

    echo "Services verified."
    echo ""
    echo "Restart complete: $(date)"
    exit 0
fi

echo "=== FIRST BOOT - FULL INITIALIZATION ==="
echo ""

#-----------------------------------------------------------------------------
# Phase 1: System Setup
#-----------------------------------------------------------------------------

echo "--- Phase 1: System Setup ---"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Detect package manager
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
else
    echo "ERROR: No supported package manager found (apt/dnf/yum)"
    exit 1
fi

echo "Detected package manager: $PKG_MANAGER"

if [[ "$PKG_MANAGER" == "apt" ]]; then
    echo "Updating package lists..."
    apt update

    echo "Upgrading existing packages..."
    apt upgrade -y

    echo "Installing required packages..."
    apt install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        nginx \
        certbot \
        python3-certbot-nginx \
        git \
        curl \
        ufw \
        jq || {
            echo "WARNING: Some packages failed to install, continuing..."
        }

elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
    echo "Updating packages..."
    $PKG_MANAGER update -y

    echo "Installing required packages..."
    $PKG_MANAGER install -y \
        gcc \
        openssl-devel \
        nginx \
        certbot \
        python3-certbot-nginx \
        git \
        curl \
        firewalld \
        jq || {
            echo "WARNING: Some packages failed to install, continuing..."
        }
fi

echo "Package installation complete."
echo ""

#-----------------------------------------------------------------------------
# Phase 2: Firewall Configuration
#-----------------------------------------------------------------------------

echo "--- Phase 2: Firewall Configuration ---"
echo ""

# Detect if running in a container (OpenVZ, LXC, Docker)
detect_container() {
    if [[ -f /proc/1/environ ]] && grep -qa 'container=' /proc/1/environ 2>/dev/null; then
        return 0
    fi
    if [[ -f /run/systemd/container ]]; then
        return 0
    fi
    if grep -qa 'docker\|lxc\|openvz' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    if [[ ! -w /proc/sys/net/ipv4/ip_forward ]] 2>/dev/null; then
        return 0
    fi
    return 1
}

if detect_container; then
    echo "Container-based VPS detected (OpenVZ/LXC/Docker)"
    echo "Skipping UFW configuration - use provider's firewall instead"
    echo ""
    echo "IMPORTANT: Configure firewall in your VPS provider's dashboard:"
    echo "  - Allow TCP port 22 (SSH)"
    echo "  - Allow TCP port 80 (HTTP)"
    echo "  - Allow TCP port 443 (HTTPS)"
    echo ""
elif ! command -v ufw &> /dev/null; then
    echo "UFW not available, skipping firewall configuration"
    echo "Ensure ports 22, 80, 443 are open via your provider's firewall"
    echo ""
else
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "Firewall already active, checking rules..."
    else
        echo "Configuring firewall..."
        ufw allow 22/tcp comment "SSH" || true
        ufw allow 80/tcp comment "HTTP" || true
        ufw allow 443/tcp comment "HTTPS" || true
        if ufw --force enable; then
            echo "UFW enabled successfully"
        else
            echo "WARNING: UFW failed to enable - configure firewall manually"
        fi
    fi
    ufw status verbose 2>/dev/null || echo "Could not get UFW status"
fi
echo ""

#-----------------------------------------------------------------------------
# Phase 3: User Setup
#-----------------------------------------------------------------------------

echo "--- Phase 3: User Setup ---"
echo ""

if id "$KENTER_USER" &>/dev/null; then
    echo "User '$KENTER_USER' already exists"
else
    echo "Creating user '$KENTER_USER'..."
    useradd -m -s /bin/bash "$KENTER_USER"
    echo "User created."
fi

echo ""

#-----------------------------------------------------------------------------
# Phase 4: Rust Toolchain
#-----------------------------------------------------------------------------

echo "--- Phase 4: Rust Toolchain ---"
echo ""

if sudo -u "$KENTER_USER" bash -c 'source "$HOME/.cargo/env" 2>/dev/null && rustc --version' &>/dev/null; then
    echo "Rust toolchain already installed"
    sudo -u "$KENTER_USER" bash -c 'source "$HOME/.cargo/env" && rustc --version'
else
    echo "Installing Rust toolchain..."
    sudo -u "$KENTER_USER" bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
fi

echo ""

#-----------------------------------------------------------------------------
# Phase 5: Repository Setup
#-----------------------------------------------------------------------------

echo "--- Phase 5: Repository Setup ---"
echo ""

# Build authenticated URL if token is provided
if [[ -n "$GITHUB_TOKEN" ]]; then
    AUTH_REPO_URL="${REPO_URL/https:\/\//https:\/\/${GITHUB_TOKEN}@}"
    echo "Using authenticated GitHub access (private repo)"
else
    AUTH_REPO_URL="$REPO_URL"
fi

if [[ -d "$KENTER_DIR" ]]; then
    echo "Repository already exists at $KENTER_DIR"
    echo "Pulling latest changes..."
    cd "$KENTER_DIR"
    sudo -u "$KENTER_USER" git remote set-url origin "$AUTH_REPO_URL"
    sudo -u "$KENTER_USER" git fetch origin
    sudo -u "$KENTER_USER" git checkout "$REPO_BRANCH"
    sudo -u "$KENTER_USER" git pull origin "$REPO_BRANCH"
else
    echo "Cloning repository..."
    sudo -u "$KENTER_USER" git clone -b "$REPO_BRANCH" "$AUTH_REPO_URL" "$KENTER_DIR"
fi

echo "Repository ready."
echo ""

#-----------------------------------------------------------------------------
# Phase 6: Build
#-----------------------------------------------------------------------------

echo "--- Phase 6: Build ---"
echo ""

echo "Building kenter-tunnler (release mode)..."
sudo -u "$KENTER_USER" bash -c "source \"\$HOME/.cargo/env\" && cd \"$KENTER_DIR\" && cargo build --release -p kenter-tunnler"

if [[ ! -f "$KENTER_DIR/target/release/kenter-tunnler" ]]; then
    echo "ERROR: Build failed - binary not found"
    exit 1
fi

echo "Build complete."
echo ""

#-----------------------------------------------------------------------------
# Phase 7: Identity Generation
#-----------------------------------------------------------------------------

echo "--- Phase 7: Identity Generation ---"
echo ""

if [[ -f "${KENTER_DIR}/.env" ]]; then
    echo "Server identity already exists (.env file found)"
    echo "Skipping identity generation to preserve existing keys."
else
    echo "Generating server Stellar keypair..."

    # The relay's identity: a fresh Stellar seed made on this machine, so the
    # key never leaves it.
    SERVER_SECRET=$(python3 "${KENTER_DIR}/packaging/relay/gen-relay-key.py")
    if [[ ! "$SERVER_SECRET" =~ ^S[A-Z2-7]{55}$ ]]; then
        echo "ERROR: could not generate the relay key (needs python3)." >&2
        exit 1
    fi

    cat > "${KENTER_DIR}/.env" << EOF
# Kenter Tunnler Configuration
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

# Server identity (Stellar keypair)
TUNNLER_SERVER_SECRET=${SERVER_SECRET}

# Network
TUNNLER_DOMAIN=${DOMAIN}
# Loopback, not 0.0.0.0. nginx proxies from 127.0.0.1 (see the upstream
# block below), so the tunnler never needs a public listener -- and a
# public one is reachable directly on :8000, around nginx and every
# limit it enforces. The firewall was the only thing standing in the
# way, and the firewall step above is skipped on container VPSes and
# when ufw is already active.
TUNNLER_HOST=127.0.0.1
TUNNLER_PORT=8000
TUNNLER_LOG_LEVEL=${LOG_LEVEL}

# Auth
TUNNLER_JWT_CLOCK_SKEW=60
TUNNLER_SESSION_TIMEOUT=86400
TUNNLER_CHALLENGE_TTL=30
TUNNLER_RATE_LIMIT_WINDOW=60
TUNNLER_RATE_LIMIT_MAX_ATTEMPTS=10
TUNNLER_RATE_LIMIT_BLOCK_DURATION=300
TUNNLER_REQUEST_TIMEOUT=120

# Roster gating (leave ROSTER_CONTRACT_ID empty to disable)
ROSTER_CONTRACT_ID=
SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
SOROBAN_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
TUNNLER_ROSTER_CACHE_TTL=300
# nginx proxies from loopback (see the upstream block below), and its
# X-Real-IP is what makes the auth rate limiter per-client rather than
# one bucket shared by everyone behind the proxy.
TUNNLER_TRUSTED_PROXIES=127.0.0.1,::1
EOF

    chown "$KENTER_USER:$KENTER_USER" "${KENTER_DIR}/.env"
    chmod 600 "${KENTER_DIR}/.env"
    echo "Environment file created at ${KENTER_DIR}/.env"
fi

# Display server address
if [[ -f "${KENTER_DIR}/.env" ]]; then
    SERVER_ADDR=$(grep "TUNNLER_SERVER_SECRET=" "${KENTER_DIR}/.env" | head -1 | cut -d= -f2)
    echo ""
    echo "Server secret configured (redacted)"
fi

echo ""

#-----------------------------------------------------------------------------
# Phase 8: Systemd Service
#-----------------------------------------------------------------------------

echo "--- Phase 8: Systemd Service ---"
echo ""

echo "Installing kenter-tunnler.service..."
cat > /etc/systemd/system/kenter-tunnler.service << EOF
[Unit]
Description=Kenter Tunnler Service
After=network.target

[Service]
Type=simple
User=${KENTER_USER}
WorkingDirectory=${KENTER_DIR}
EnvironmentFile=${KENTER_DIR}/.env
ExecStart=${KENTER_DIR}/target/release/kenter-tunnler
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kenter-tunnler

echo "Systemd service installed and enabled."
echo ""

#-----------------------------------------------------------------------------
# Phase 9: Nginx Configuration
#-----------------------------------------------------------------------------

echo "--- Phase 9: Nginx Configuration ---"
echo ""

# Create ACME webroot for certbot challenges
mkdir -p /var/www/acme

echo "Installing nginx configuration..."
cat > /etc/nginx/sites-available/kenter-tunnler << 'NGINXEOF'
# Rate limiting zones (per-IP WebSocket connections)
limit_conn_zone $binary_remote_addr zone=ws_conn:10m;

# /proxy is unauthenticated: any address on the internet can aim requests
# at a connected node, and each one costs the relay a task, a pending
# stream and a message on that node's queue. The tunnler caps its own
# in-flight work; this keeps the flood from arriving in the
# first place. A wallet makes a handful of calls per print; 10 a second
# per IP leaves room for depositors who share an address (a Tor exit).
limit_req_zone $binary_remote_addr zone=proxy_req:10m rate=10r/s;
limit_req_status 429;

upstream tunnler {
    server 127.0.0.1:8000;
    keepalive 32;
}
NGINXEOF

# Append domain-specific configuration (needs variable expansion)
cat >> /etc/nginx/sites-available/kenter-tunnler << EOF

# Map to extract Stellar address from subdomain
map \$host \$stellar_address {
    ~*^(?<addr>[A-Za-z0-9]+)\.${DOMAIN//./\\.}\$ \$addr;
    default "";
}

# HTTP server for base domain (API, WebSocket, certbot)
server {
    listen 80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Everything else is a redirect. Until certbot has run there is no
    # HTTPS listener, so proxying here would carry the WebSocket
    # handshake -- JWT and all -- in cleartext.
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTP server for tunnel subdomains
server {
    listen 80;
    server_name *.${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Everything else is a redirect. Until certbot has run there is no
    # HTTPS listener, so proxying here would carry the WebSocket
    # handshake -- JWT and all -- in cleartext.
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# Catch-all for ACME challenges on custom domains (port 80)
server {
    listen 80 default_server;
    server_name _;

    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# Catch-all for custom domains (port 443)
server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate     /etc/letsencrypt/live/\$ssl_server_name/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/\$ssl_server_name/privkey.pem;
    # A wallet sends at most a few KB; the relay itself refuses a body over
    # 64 KiB. Short header and body timeouts keep slow clients from holding
    # connections open.
    client_max_body_size 64k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        limit_req zone=proxy_req burst=20 nodelay;

        proxy_pass http://tunnler/proxy\$request_uri;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Custom-Domain \$host;
        # The relay waits up to 120 s for a node (TUNNLER_REQUEST_TIMEOUT);
        # nginx must wait longer, or slow requests end in a 504.
        proxy_read_timeout 150;
        proxy_send_timeout 150;
    }
}

# Note: HTTPS server blocks for ${DOMAIN} will be added by certbot after SSL setup
EOF

# Enable site

#-----------------------------------------------------------------------------
# TLS vhosts -- staged, NOT enabled
#-----------------------------------------------------------------------------
# These are the blocks that actually proxy. Port 80 serves the ACME
# challenge and a redirect, and nothing else: proxying there would carry
# the WebSocket handshake, JWT included, in cleartext on every deployment
# until someone ran certbot by hand.
#
# They are staged rather than enabled because nginx will not start when
# a static ssl_certificate path does not exist yet. Enable after the
# certificate is issued -- the final instructions say how.

cat > /etc/nginx/sites-available/kenter-tunnler-ssl << EOF
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    # A wallet sends at most a few KB; the relay itself refuses a body over
    # 64 KiB. Short header and body timeouts keep slow clients from holding
    # connections open.
    client_max_body_size 64k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location /connect {
        limit_conn ws_conn 5;

        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        # The tunnler keys its auth rate limiter and challenge binding on
        # this, and believes it only from TUNNLER_TRUSTED_PROXIES. It
        # must be set here, never passed through from the client.
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    location / {
        limit_req zone=proxy_req burst=20 nodelay;

        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # The relay waits up to 120 s for a node (TUNNLER_REQUEST_TIMEOUT);
        # nginx must wait longer, or slow requests end in a 504.
        proxy_read_timeout 150;
        proxy_send_timeout 150;
    }
}

server {
    listen 443 ssl http2;
    server_name *.${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    # A wallet sends at most a few KB; the relay itself refuses a body over
    # 64 KiB. Short header and body timeouts keep slow clients from holding
    # connections open.
    client_max_body_size 64k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        limit_req zone=proxy_req burst=20 nodelay;

        proxy_pass http://tunnler/proxy/\$stellar_address\$uri\$is_args\$args;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Stellar-Address \$stellar_address;
        # The relay waits up to 120 s for a node (TUNNLER_REQUEST_TIMEOUT);
        # nginx must wait longer, or slow requests end in a 504.
        proxy_read_timeout 150;
        proxy_send_timeout 150;
    }
}
EOF

ln -sf /etc/nginx/sites-available/kenter-tunnler /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and reload nginx
nginx -t
systemctl reload nginx

echo "Nginx configured."
echo ""

#-----------------------------------------------------------------------------
# Phase 10: Start Services & Finalize
#-----------------------------------------------------------------------------

echo "--- Phase 10: Start Services ---"
echo ""

echo "Starting Kenter Tunnler..."
systemctl start kenter-tunnler

# Wait for service to start
sleep 3

# Check service status
echo ""
echo "Service status:"
systemctl is-active kenter-tunnler && echo "  kenter-tunnler: RUNNING" || echo "  kenter-tunnler: FAILED"
systemctl is-active nginx && echo "  nginx: RUNNING" || echo "  nginx: FAILED"

echo ""

# Create marker directory and file
mkdir -p "$MARKER_DIR"

cat > "$MARKER_FILE" << EOF
{
    "initialized_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "domain": "${DOMAIN}",
    "version": "0.1.0",
    "repo_url": "${REPO_URL}",
    "repo_branch": "${REPO_BRANCH}"
}
EOF

echo "Initialization marker created: $MARKER_FILE"
echo ""

#-----------------------------------------------------------------------------
# Summary
#-----------------------------------------------------------------------------

VPS_IP=$(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_IP')

echo "============================================================"
echo "Kenter Tunnler Initialization Complete!"
echo "============================================================"
echo ""
echo "Endpoints (HTTP - configure SSL for production):"
echo "  Health:   http://${DOMAIN}/health"
echo "  Connect:  ws://${DOMAIN}/connect"
echo ""
echo "Next Steps:"
echo "  1. Configure DNS (add these A records in your DNS provider):"
echo ""
echo "     Name              Type    Value"
echo "     ─────────────────────────────────────────────────────"
echo "     ${DOMAIN}      A       ${VPS_IP}"
echo "     *.${DOMAIN}    A       ${VPS_IP}"
echo ""
echo "     Wait for DNS propagation (1-5 min), then verify:"
echo "     dig +short ${DOMAIN}"
echo ""
echo "  2. Install SSL certificate (wildcard requires DNS challenge):"
echo ""
echo "     NOTE: On some container VPS (OpenVZ/LXC), you may need to set PATH first:"
echo "     export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH\""
echo ""
echo "     Step A - Request the certificate:"
echo "     ─────────────────────────────────────────────────────"
echo "     certbot certonly --manual --preferred-challenges dns \\"
echo "       -d ${DOMAIN} -d \"*.${DOMAIN}\""
echo ""
echo "     Step B - When certbot prompts, add a DNS TXT record:"
echo "     ─────────────────────────────────────────────────────"
echo "     Name:   _acme-challenge.${DOMAIN}"
echo "     Type:   TXT"
echo "     Value:  (certbot will display this value)"
echo ""
echo "     Wait 1-2 minutes for DNS propagation, then press Enter in certbot."
echo "     Verify: dig +short TXT _acme-challenge.${DOMAIN}"
echo ""
echo "     Step C - Turn on the TLS vhosts:"
echo "     ─────────────────────────────────────────────────────"
echo "     # Do NOT use 'certbot install --nginx'. It clones the port-80"
echo "     # server block, which is now only an ACME challenge and a"
echo "     # redirect, so it would build a 443 block that redirects to"
echo "     # itself. The real vhosts are already written and staged."
echo "     ln -sf /etc/nginx/sites-available/kenter-tunnler-ssl /etc/nginx/sites-enabled/"
echo "     nginx -t && systemctl reload nginx"
echo ""
echo "     Until this step runs, port 80 answers only the ACME challenge"
echo "     and a redirect, and there is nothing on 443. That is"
echo "     deliberate: the alternative was serving the WebSocket"
echo "     handshake, JWT included, in cleartext."
echo ""
echo "  3. Configure roster gating (optional):"
echo "     sudo -u ${KENTER_USER} nano ${KENTER_DIR}/.env"
echo "     # Set ROSTER_CONTRACT_ID to enable on-chain membership checks"
echo "     sudo systemctl restart kenter-tunnler"
echo ""
echo "  4. Test the server:"
echo "     curl https://${DOMAIN}/health"
echo ""
echo "Logs:"
echo "  Startup:  /var/log/kenter-startup.log"
echo "  Service:  journalctl -u kenter-tunnler -f"
echo ""
echo "Completed: $(date)"
echo "============================================================"
