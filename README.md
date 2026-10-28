# OmniShell

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Ubuntu/Debian](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-E95420.svg?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Runtime: Node.js 18+](https://img.shields.io/badge/Node.js-18%2B-339933.svg?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Proxy: Nginx](https://img.shields.io/badge/Proxy-Nginx%201.20%2B-009639.svg?logo=nginx&logoColor=white)](https://nginx.org/)
[![SSL: Let's Encrypt](https://img.shields.io/badge/SSL-Let's%20Encrypt-003A70.svg?logo=letsencrypt&logoColor=white)](https://letsencrypt.org/)
[![Memory: < 20MB](https://img.shields.io/badge/RAM-~18%20MB-success.svg)](https://github.com/aniket-py1/omnishell)

A lightweight, zero-dependency web terminal gateway for Linux servers.
Provides secure, encrypted browser-based terminal access via HTTPS and WebSockets with dynamic authentication, salted password hashing, brute-force protection, and universal CLI management.

Designed and developed by **Aniket Mahida**.

---

## Technical Overview

OmniShell couples the high-performance C binary `ttyd` (libwebsockets + xterm.js) with a lightweight Node.js authentication gateway and Nginx reverse proxy. It provides direct shell access from any browser (desktop, tablet, or smartphone) while consuming less than 20 MB RAM and zero idle CPU.

### Core Features

- High Performance: Native C pseudo-terminal emulation with xterm.js frontend.
- Zero Control Panel Bloat: Operates cleanly on native systemd, PM2, and Nginx without heavy web panels.
- Universal Application Auto-Discovery: Dynamically discovers, monitors, and streams live logs for any running PM2 app or systemd service without hardcoding.
- Enterprise Security:
  - TLS 1.3 encryption on standard HTTPS port 443 via Let's Encrypt.
  - Salted password hashing utilizing Node.js native `scrypt` algorithm.
  - Brute-force rate limiting: 5 consecutive failed attempts trigger an automatic 15-minute IP lockout.
  - Signed HMAC session tokens with configurable TTL.
  - Internal terminal socket bound strictly to `127.0.0.1` (no exposed high ports).
- Session Persistence: Nginx proxy timeouts configured to 86,400 seconds (24 hours) to prevent disconnection during long-running tasks.
- Mobile Touch Support: Fully functional on-screen keyboard support for Safari and Chrome on iOS and Android.
- CLI Management: Integrated `omnishell` CLI for runtime credential changes and log streaming without process restarts.

---

## Installation Guide

### Method 1: Single-Command Automated Installer (Recommended)

Run the following command on any Ubuntu (20.04/22.04/24.04) or Debian (11/12) server:

```bash
curl -fsSL https://raw.githubusercontent.com/aniket-py1/omnishell/main/install.sh | sudo bash -s -- --domain panel.example.com --user admin --pass YourSecurePassword123
```

### Method 2: Interactive Wizard

If you run the script without arguments, the interactive setup wizard will guide you through domain, username, and password selection:

```bash
curl -fsSL https://raw.githubusercontent.com/aniket-py1/omnishell/main/install.sh | sudo bash
```

### Method 3: Manual Clone Installation

```bash
git clone https://github.com/aniket-py1/omnishell.git
cd omnishell
sudo bash install.sh --domain panel.example.com --user admin --pass YourSecurePassword123
```

---

## CLI Management Reference

OmniShell includes a global CLI utility linked to `/usr/local/bin/omnishell`.

| Command | Description | Example |
| :--- | :--- | :--- |
| `omnishell apps` | Displays real-time status, cluster counts, and memory for all apps & services | `omnishell apps` |
| `omnishell logs [app] [n]` | Streams live logs for any PM2 app, systemd service, or log file | `omnishell logs api` |
| `omnishell logs` | Streams multi-colored real-time logs for all PM2 applications combined | `omnishell logs` |
| `omnishell password <pass>` | Updates admin password with fresh salt and scrypt hash | `omnishell password SecretPass@2026` |
| `omnishell user <username>` | Updates administrator login username | `omnishell user devops-lead` |
| `omnishell title "<title>"` | Updates browser tab label and login page heading | `omnishell title "Core Production Node"` |
| `omnishell status` | Displays service health, ports, memory usage, and URL | `omnishell status` |
| `omnishell restart [app]` | Restarts OmniShell or any target PM2 application | `omnishell restart api` |
| `omnishell help` | Displays available commands | `omnishell help` |

### Log Streaming Examples

```bash
# Stream logs for an app matching "api"
omnishell logs api

# Stream logs for Redis service
omnishell logs redis

# Stream logs for Nginx
omnishell logs nginx

# Stream last 100 lines and follow live
omnishell logs api 100
```

---

## Architecture

```
[ Client Browser / Mobile ]
            |
            |  HTTPS / WSS (Port 443)
            v
[ Nginx Reverse Proxy (Let's Encrypt SSL) ]
   - TLS 1.3 Termination
   - WebSocket Handshake (HTTP 101)
   - 24-Hour Read/Send Timeouts
            |
            |  HTTP / WS (127.0.0.1:7681)
            v
[ OmniShell Gateway (Node.js Daemon) ]
   - Salted Scrypt Authentication
   - Brute-Force IP Guard (5 attempts / 15 min lock)
   - Dynamic Branding (/etc/omnishell/config.json)
            |
            |  HTTP / WS (127.0.0.1:7680)
            v
[ ttyd Native C Daemon (libwebsockets + xterm.js) ]
   - PTY Allocation (xterm-256color)
            |
            v
[ Linux Shell Session (/bin/bash, User: ubuntu) ]
```

---

## Configuration File

The gateway reads its configuration from `/etc/omnishell/config.json`:

```json
{
  "domain": "panel.example.com",
  "title": "OmniShell Terminal",
  "badge": "SECURE BASTION",
  "username": "admin",
  "passwordHash": "c20df44b419b4b0451cf4550cf6bbdb7...",
  "salt": "a4d3e2f1...",
  "shellUser": "ubuntu",
  "gatewayPort": 7681,
  "ttydPort": 7680,
  "sessionDays": 7
}
```

The gateway dynamically watches this file and reloads updates automatically without interrupting active WebSocket sessions.

---

## Cloudflare DNS Configuration

When proxying OmniShell through Cloudflare:
1. Ensure your DNS record (e.g. `panel`) is set to Proxied (Orange Cloud) or DNS-Only (Grey Cloud).
2. Set Cloudflare SSL/TLS encryption mode to **Full** or **Full (strict)**.
3. In Cloudflare Dashboard, ensure **WebSockets** is toggled **ON** under Network settings.

---

## Uninstallation

To cleanly remove OmniShell, its configurations, and the Nginx site:

```bash
sudo bash uninstall.sh panel.example.com
```

---

## License

Released under the [MIT License](LICENSE).  
Copyright (c) 2026 Aniket Mahida.
