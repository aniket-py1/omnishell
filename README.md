# OmniShell

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Ubuntu/Debian](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-E95420.svg?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Runtime: Node.js 18+](https://img.shields.io/badge/Node.js-18%2B-339933.svg?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Proxy: Nginx](https://img.shields.io/badge/Proxy-Nginx%201.20%2B-009639.svg?logo=nginx&logoColor=white)](https://nginx.org/)
[![SSL: Let's Encrypt](https://img.shields.io/badge/SSL-Let's%20Encrypt-003A70.svg?logo=letsencrypt&logoColor=white)](https://letsencrypt.org/)
[![Memory: < 20MB](https://img.shields.io/badge/RAM-~18%20MB-success.svg)](https://github.com/aniket-py1/omnishell)

A lightweight, zero-dependency web terminal gateway for Linux servers.
Provides secure, encrypted browser-based terminal access via HTTPS and WebSockets with real-time server telemetry HUD, salted scrypt authentication, brute-force protection, dynamic application fleet monitoring, and universal log streaming.

Designed and developed by **Aniket Mahida**.

---

## 1-Click Automated Installation

Deploy a complete, production-grade secure web terminal with SSL and real-time telemetry in under 60 seconds.

### Prerequisites
- Operating System: Ubuntu 20.04 / 22.04 / 24.04 LTS or Debian 11 / 12 (x86_64 or ARM64)
- Access: Root or sudo privileges
- DNS: A-record pointing your domain/subdomain to your server's public IP
- Inbound Ports: 80 (HTTP) and 443 (HTTPS) open in your firewall or AWS Security Group

### Method 1: Unattended 1-Line Setup (Recommended)
Replace `panel.example.com`, `admin`, and `YourSecurePassword123` with your own credentials:

```bash
curl -fsSL https://raw.githubusercontent.com/aniket-py1/omnishell/main/install.sh | sudo bash -s -- --domain panel.example.com --user admin --pass YourSecurePassword123
```

### Method 2: Interactive Wizard Mode
Run without arguments and follow the interactive step-by-step terminal prompts:

```bash
curl -fsSL https://raw.githubusercontent.com/aniket-py1/omnishell/main/install.sh | sudo bash
```

### What the 1-Click Installer Executes Automatically:
1. Detects OS and installs prerequisites (`ttyd`, `nginx`, `certbot`, `python3-certbot-nginx`, `nodejs 22 LTS`, `pm2`).
2. Generates salted `scrypt` credentials in `/etc/omnishell/config.json`.
3. Configures the internal `ttyd` pseudo-terminal daemon (loopback on port 7680).
4. Launches the OmniShell security gateway and telemetry daemon under PM2.
5. Configures Nginx reverse proxy with WebSocket support and 24-hour keep-alive.
6. Automatically requests and binds a Let's Encrypt SSL certificate for your domain.
7. Installs the global management command `omnishell` to `/usr/local/bin/omnishell`.

---

## Real-Time Server Telemetry HUD (All-Time Header)

OmniShell embeds a permanent, non-intrusive live telemetry bar at the top of the terminal session inside your browser. It updates every 1,500 milliseconds via an asynchronous `/api/stats` endpoint without interrupting active terminal keystrokes:

- **Host Telemetry**: System hostname, Linux distribution, and kernel version.
- **Instantaneous CPU Sampling**: Real-time CPU percentage calculated via 1-second tick deltas (user, system, idle) accompanied by Unix load averages and core counts.
- **Live Memory (RAM)**: Real-time RAM consumption with a visual dynamic threshold progress bar (Green < 70%, Yellow > 70%, Red > 85%).
- **Live Storage (Disk)**: Root filesystem capacity, used space, and utilization percentage.
- **Server Uptime**: Days, hours, and minutes since last reboot.
- **Active Fleet**: Live count of online PM2 cluster instances and background services across all system users (`root`, `ubuntu`).
- **Interactive Apps Drawer**: Dropdown modal displaying complete PM2 cluster instance counts, memory usage, CPU %, and systemd service health.
- **Interactive Logs Drawer**: Dropdown modal providing 1-click selectors to copy or stream live logs for any application (`omnishell logs [app]`).
- **Inactivity Session Guard**: 15-minute sliding idle timeout that displays a 60-second visual countdown warning and automatically invalidates the session and severs the WebSocket if inactive.

---

## Application Fleet Monitoring & Universal Log Streaming

OmniShell includes built-in dynamic service discovery. You can inspect all running applications and stream their live logs directly from the terminal without remembering process IDs or log file paths.

### 1. View Running Application Fleet (`omnishell apps`)
Run `omnishell apps` to get an instant real-time status of all Node.js/Python/Go PM2 clusters and system services:

```bash
omnishell apps
```

Example Output:
```
======================================================
  OmniShell Application Fleet Status
======================================================
  PM2 Applications:
    [ONLINE]  lgbs-api             : 14 cluster instances   (RAM: 1840 MB, CPU: 0.3%)
    [ONLINE]  tronpay-api          : 8 cluster instances    (RAM: 980 MB, CPU: 0.1%)
    [ONLINE]  lgbs-webhook         : fork                   (RAM: 55 MB, CPU: 0%)
    [ONLINE]  omnishell            : fork                   (RAM: 32 MB, CPU: 0%)
------------------------------------------------------
  System Services:
    [ACTIVE]  nginx                : systemd service
    [ACTIVE]  redis-server         : systemd service
    [ACTIVE]  ttyd                 : systemd service
======================================================
```

### 2. Stream Live Application Logs (`omnishell logs [app]`)
OmniShell dynamically discovers and streams logs using smart matching:

```bash
# Stream live logs for any PM2 app matching "api"
omnishell logs api

# Stream live logs for a specific application
omnishell logs lgbs
omnishell logs tronpay
omnishell logs webhook

# Stream systemd journal for infrastructure services
omnishell logs redis
omnishell logs nginx

# Stream all applications simultaneously in real-time
omnishell logs all

# Specify custom history line count (default: 50 lines)
omnishell logs api 100
```

---

## CLI Management Reference

The `omnishell` CLI is linked globally to `/usr/local/bin/omnishell`:

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
   - Real-Time Telemetry Engine (/api/stats)
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

## Security Specifications

- Zero Control Panel Footprint: Eliminates bloated web management panels (such as aaPanel or Webmin).
- Password Security: Evaluates passwords using `crypto.scryptSync` with 16-byte cryptographically secure salts.
- Rate Limiting: Blocks IP addresses for 15 minutes after 5 consecutive failed login attempts.
- Session Security: HMAC SHA-256 signed session cookies with configurable expiration.
- Network Isolation: Terminal daemon binds strictly to loopback interface `127.0.0.1`.

---

## Cloudflare DNS Configuration

When proxying OmniShell through Cloudflare:
1. Ensure your DNS record (e.g. `panel`) is set to Proxied (Orange Cloud) or DNS-Only (Grey Cloud).
2. Set Cloudflare SSL/TLS encryption mode to **Full** or **Full (strict)**.
3. In Cloudflare Dashboard, verify **WebSockets** is toggled **ON** under Network settings.

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
