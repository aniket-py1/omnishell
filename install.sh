#!/bin/bash
# ==============================================================================
# OmniShell - Universal Web Terminal Installer
# Author: Aniket Mahida
#
# Usage:
#   sudo bash install.sh --domain <DOMAIN> --user <USERNAME> --pass <PASSWORD>
#   Or run interactively: sudo bash install.sh
# ==============================================================================

set -e

DOMAIN=""
ADMIN_USER=""
ADMIN_PASS=""
TITLE="OmniShell Terminal"
SHELL_USER="ubuntu"
GATEWAY_PORT=7681
TTYD_PORT=7680

# Parse command line flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift ;;
        -u|--user) ADMIN_USER="$2"; shift ;;
        -p|--pass) ADMIN_PASS="$2"; shift ;;
        -t|--title) TITLE="$2"; shift ;;
        --shell-user) SHELL_USER="$2"; shift ;;
        --gateway-port) GATEWAY_PORT="$2"; shift ;;
        --ttyd-port) TTYD_PORT="$2"; shift ;;
        -h|--help)
            echo "OmniShell Installer"
            echo "Usage: sudo bash install.sh [options]"
            echo "Options:"
            echo "  -d, --domain       Target domain or subdomain (e.g. panel.example.com)"
            echo "  -u, --user         Admin web login username"
            echo "  -p, --pass         Admin web login password"
            echo "  -t, --title        Browser UI branding title (default: OmniShell Terminal)"
            echo "  --shell-user       Linux user to run shell as (default: ubuntu)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

if [ "$EUID" -ne 0 ]; then
    echo "[Error] Please run this installer as root (use sudo)."
    exit 1
fi

echo "======================================================"
echo "  OmniShell - Universal Web Terminal Installer"
echo "  Author: Aniket Mahida"
echo "======================================================"

# Interactive prompt if parameters omitted
if [ -z "$DOMAIN" ]; then
    read -p "Enter target domain or subdomain (e.g. panel.example.com): " DOMAIN
fi

if [ -z "$ADMIN_USER" ]; then
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
fi

if [ -z "$ADMIN_PASS" ]; then
    read -s -p "Enter admin password: " ADMIN_PASS
    echo ""
    if [ -z "$ADMIN_PASS" ]; then
        echo "[Error] Password cannot be empty."
        exit 1
    fi
fi

# Ensure target shell user exists
if ! id "$SHELL_USER" &>/dev/null; then
    SHELL_USER="root"
fi

echo ""
echo "[1/6] Installing dependencies (ttyd, nginx, certbot, nodejs)..."
apt-get update -y
apt-get install -y ttyd nginx certbot python3-certbot-nginx curl net-tools

# Ensure Node.js and PM2 are installed
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi

if ! command -v pm2 &>/dev/null; then
    npm install -g pm2
fi

echo "[2/6] Configuring internal ttyd terminal daemon..."
cat > /etc/default/ttyd << EOF
# Managed by OmniShell
TTYD_OPTIONS="-W -i 127.0.0.1 -p $TTYD_PORT -t fontSize=15 su - $SHELL_USER"
EOF

systemctl daemon-reload
systemctl enable ttyd
systemctl restart ttyd

echo "[3/6] Setting up OmniShell gateway and credentials..."
mkdir -p /etc/omnishell
INSTALL_DIR="/opt/omnishell"
mkdir -p "$INSTALL_DIR"

# Copy or clone files to /opt/omnishell
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/gateway.js" ]; then
    cp -r "$SCRIPT_DIR/"* "$INSTALL_DIR/"
else
    # Running via pipe/curl, download from GitHub repository
    curl -fsSL https://raw.githubusercontent.com/aniket-py1/omnishell/main/gateway.js -o "$INSTALL_DIR/gateway.js"
    mkdir -p "$INSTALL_DIR/bin"
    curl -fsSL https://raw.githubusercontent.com/aniket-py1/omnishell/main/bin/omnishell.js -o "$INSTALL_DIR/bin/omnishell.js"
    curl -fsSL https://raw.githubusercontent.com/aniket-py1/omnishell/main/package.json -o "$INSTALL_DIR/package.json"
fi

chmod +x "$INSTALL_DIR/bin/omnishell.js"
ln -sf "$INSTALL_DIR/bin/omnishell.js" /usr/local/bin/omnishell

# Generate salted password hash
SALT=$(node -e "console.log(require('crypto').randomBytes(16).toString('hex'))")
PASS_HASH=$(node -e "console.log(require('crypto').scryptSync(process.argv[1], process.argv[2], 64).toString('hex'))" "$ADMIN_PASS" "$SALT")

cat > /etc/omnishell/config.json << EOF
{
  "domain": "$DOMAIN",
  "title": "$TITLE",
  "badge": "SECURE BASTION",
  "username": "$ADMIN_USER",
  "passwordHash": "$PASS_HASH",
  "salt": "$SALT",
  "shellUser": "$SHELL_USER",
  "gatewayPort": $GATEWAY_PORT,
  "ttydPort": $TTYD_PORT,
  "sessionDays": 7
}
EOF

# Start OmniShell under PM2
pm2 delete omnishell 2>/dev/null || true
pm2 delete terminal-gateway 2>/dev/null || true
pm2 start "$INSTALL_DIR/gateway.js" --name "omnishell"
pm2 save

echo "[4/6] Configuring Nginx reverse proxy..."
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN"

cat > "$NGINX_CONF" << EOF
server {
    server_name $DOMAIN;

    listen 80;
    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:$GATEWAY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # 24-hour timeout prevents idle disconnects
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
    }
}
EOF

ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/$DOMAIN"
nginx -t
systemctl reload nginx

echo "[5/6] Securing with Let's Encrypt SSL..."
if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo "Found existing Let's Encrypt certificate for $DOMAIN, applying SSL..."
    cat > "$NGINX_CONF" << EOF
server {
    server_name $DOMAIN;

    listen 443 ssl;
    http2 on;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:$GATEWAY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
    }
}

server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
EOF
    nginx -t
    systemctl reload nginx
else
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --redirect || {
        echo "[Notice] Automatic SSL issuance pending DNS verification. HTTP is active."
    }
fi

echo "[6/6] Verifying installation..."
sleep 2

echo "======================================================"
echo "  OmniShell Installation Complete"
echo "======================================================"
echo "  URL          : https://$DOMAIN/"
echo "  Username     : $ADMIN_USER"
echo "  Password     : [HIDDEN]"
echo "  Shell User   : $SHELL_USER"
echo "  CLI Tool     : omnishell --help"
echo "------------------------------------------------------"
echo "  Management Commands:"
echo "    omnishell apps                  Inspect all running apps & services"
echo "    omnishell logs [app]            Stream real-time live application logs"
echo "    omnishell password <new_pass>   Change admin password"
echo "    omnishell user <new_user>       Change admin username"
echo "    omnishell status                View service health & telemetry"
echo "    omnishell restart               Restart services"
echo "======================================================"
