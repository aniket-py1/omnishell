#!/bin/bash
# ==============================================================================
# OmniShell - Uninstaller Script
# Author: Aniket Mahida
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[Error] Please run as root (use sudo)."
    exit 1
fi

DOMAIN="$1"

echo "Stopping OmniShell processes..."
pm2 delete omnishell 2>/dev/null || true
pm2 save 2>/dev/null || true
systemctl stop ttyd 2>/dev/null || true
systemctl disable ttyd 2>/dev/null || true

echo "Removing configuration and binaries..."
rm -rf /etc/omnishell /opt/omnishell /usr/local/bin/omnishell /etc/default/ttyd

if [ -n "$DOMAIN" ]; then
    echo "Removing Nginx configuration for $DOMAIN..."
    rm -f "/etc/nginx/sites-enabled/$DOMAIN" "/etc/nginx/sites-available/$DOMAIN"
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
fi

echo "OmniShell has been completely uninstalled."
