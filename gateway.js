const http = require('http');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const CONFIG_PATHS = [
  '/etc/omnishell/config.json',
  path.join(__dirname, 'config.json'),
  path.join(__dirname, 'config.local.json')
];

function loadConfig() {
  for (const p of CONFIG_PATHS) {
    if (fs.existsSync(p)) {
      try {
        return JSON.parse(fs.readFileSync(p, 'utf8'));
      } catch (e) {
        console.error(`[OmniShell] Failed to parse config at ${p}:`, e.message);
      }
    }
  }
  return {
    domain: 'localhost',
    title: 'OmniShell Terminal',
    badge: 'SECURE BASTION',
    username: 'admin',
    passwordHash: '',
    salt: '',
    gatewayPort: 7681,
    ttydPort: 7680,
    sessionDays: 7,
    inactivityMinutes: 15
  };
}

let config = loadConfig();

for (const p of CONFIG_PATHS) {
  if (fs.existsSync(p)) {
    fs.watchFile(p, { interval: 2000 }, () => {
      console.log(`[OmniShell] Reloading config from ${p}`);
      config = loadConfig();
    });
    break;
  }
}

const SECRET_KEY = crypto.randomBytes(32).toString('hex');

// Brute-force protection
const failedAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function isIpLocked(ip) {
  const record = failedAttempts.get(ip);
  if (!record) return false;
  if (record.count >= MAX_ATTEMPTS) {
    if (Date.now() - record.lastTime < LOCKOUT_MS) return true;
    failedAttempts.delete(ip);
  }
  return false;
}

function recordFailedAttempt(ip) {
  const record = failedAttempts.get(ip) || { count: 0, lastTime: 0 };
  record.count += 1;
  record.lastTime = Date.now();
  failedAttempts.set(ip, record);
}

function resetFailedAttempts(ip) {
  failedAttempts.delete(ip);
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, storedHash, salt) {
  if (!storedHash || !salt) return false;
  try {
    const computed = hashPassword(password, salt);
    return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(storedHash, 'hex'));
  } catch (e) {
    return false;
  }
}

// Inactivity Session Tracker
// token -> { lastActive: number, username: string }
const sessionActivityMap = new Map();

function getInactivityTimeoutMs() {
  const mins = parseInt(config.inactivityMinutes, 10) || 15;
  return mins * 60 * 1000;
}

function signSession(username) {
  const timestamp = Date.now();
  const payload = `${username}:${timestamp}`;
  const hmac = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex');
  const token = Buffer.from(`${payload}:${hmac}`).toString('base64');
  sessionActivityMap.set(token, { lastActive: Date.now(), username });
  return token;
}

function touchSession(token) {
  if (!token) return;
  const item = sessionActivityMap.get(token);
  if (item) {
    item.lastActive = Date.now();
  }
}

function verifySession(token) {
  if (!token) return false;
  try {
    const raw = Buffer.from(token, 'base64').toString('utf8');
    const parts = raw.split(':');
    if (parts.length !== 3) return false;
    const [user, timestamp, hmac] = parts;
    const expected = crypto.createHmac('sha256', SECRET_KEY).update(`${user}:${timestamp}`).digest('hex');
    if (hmac !== expected) return false;

    // Fixed absolute max age check
    const maxAge = (config.sessionDays || 7) * 24 * 3600 * 1000;
    if (Date.now() - parseInt(timestamp, 10) > maxAge) return false;
    if (user !== config.username) return false;

    // Sliding inactivity timeout check
    const activity = sessionActivityMap.get(token);
    const timeout = getInactivityTimeoutMs();
    if (activity) {
      if (Date.now() - activity.lastActive > timeout) {
        sessionActivityMap.delete(token);
        return false;
      }
    } else {
      // In case server restarted, seed with current time
      sessionActivityMap.set(token, { lastActive: Date.now(), username: user });
    }
    return true;
  } catch (e) {
    return false;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  const match = header.match(new RegExp(`(^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[2]) : null;
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

// -----------------------------------------------------------------------------
// Real-Time System Telemetry Engine (Non-Blocking & 1s Delta CPU Sampling)
// -----------------------------------------------------------------------------

let prevCpuTimes = null;
let currentCpuPercent = 0;

function sampleCpuUsage() {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    for (const type in cpu.times) {
      total += cpu.times[type];
    }
    idle += cpu.times.idle;
  }

  if (prevCpuTimes) {
    const totalDiff = total - prevCpuTimes.total;
    const idleDiff = idle - prevCpuTimes.idle;
    if (totalDiff > 0) {
      currentCpuPercent = Math.max(0, Math.min(100, Math.round(((totalDiff - idleDiff) / totalDiff) * 100)));
    }
  }
  prevCpuTimes = { total, idle };
  return currentCpuPercent;
}

// Background 1-second CPU tick delta sampler
sampleCpuUsage();
setInterval(sampleCpuUsage, 1000);

let cachedFleet = {
  diskUsage: 'N/A',
  pm2Online: 0,
  pm2Total: 0,
  breakdown: '',
  groupedApps: [],
  services: []
};

function refreshFleetStats() {
  let diskUsage = 'N/A';
  try {
    const df = execSync("df -h / 2>/dev/null | tail -n 1 | awk '{print $3 \"/\" $2 \" (\" $5 \")\"}'", { encoding: 'utf8' }).trim();
    if (df) diskUsage = df;
  } catch (e) {}

  let pm2Online = 0;
  let pm2Total = 0;
  const groups = {};
  const seenKeys = new Set();
  const pm2Homes = ['/root/.pm2'];
  try {
    if (fs.existsSync('/home')) {
      const users = fs.readdirSync('/home');
      for (const u of users) {
        const p = `/home/${u}/.pm2`;
        if (fs.existsSync(p)) pm2Homes.push(p);
      }
    }
  } catch (e) {}

  for (const home of pm2Homes) {
    try {
      const raw = execSync(`PM2_HOME="${home}" pm2 jlist 2>/dev/null`, { encoding: 'utf8' }).trim();
      if (raw.startsWith('[') && raw.endsWith(']')) {
        const list = JSON.parse(raw);
        for (const app of list) {
          const key = `${app.name}:${app.pm_id}`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            pm2Total++;
            const isOnline = app.pm2_env && app.pm2_env.status === 'online';
            if (isOnline) pm2Online++;

            if (!groups[app.name]) {
              groups[app.name] = {
                name: app.name,
                count: 0,
                onlineCount: 0,
                mode: app.pm2_env ? app.pm2_env.exec_mode : 'fork',
                memoryMb: 0,
                cpuTotal: 0,
                user: app.pm2_env ? (app.pm2_env.username || 'unknown') : 'unknown'
              };
            }
            groups[app.name].count++;
            if (isOnline) groups[app.name].onlineCount++;
            if (app.monit && app.monit.memory) groups[app.name].memoryMb += Math.round(app.monit.memory / 1024 / 1024);
            if (app.monit && app.monit.cpu) groups[app.name].cpuTotal += app.monit.cpu;
          }
        }
      }
    } catch (e) {}
  }

  const groupedApps = Object.values(groups).map(g => ({
    name: g.name,
    instances: g.count,
    onlineInstances: g.onlineCount,
    mode: g.mode,
    memoryFormatted: g.memoryMb > 1024 ? `${(g.memoryMb / 1024).toFixed(2)} GB` : `${g.memoryMb} MB`,
    cpuFormatted: `${g.cpuTotal.toFixed(1)}%`,
    status: g.onlineCount === g.count ? 'ONLINE' : (g.onlineCount > 0 ? 'PARTIAL' : 'OFFLINE'),
    user: g.user
  }));

  // Systemd services inspection
  const checkServices = ['nginx', 'redis-server', 'ttyd'];
  const services = [];
  for (const svc of checkServices) {
    try {
      const status = execSync(`systemctl is-active ${svc} 2>/dev/null`, { encoding: 'utf8' }).trim();
      services.push({ name: svc, status: status === 'active' ? 'ACTIVE' : (status || 'INACTIVE') });
    } catch (e) {
      services.push({ name: svc, status: 'INACTIVE' });
    }
  }

  const breakdown = groupedApps.map(a => `${a.name} (${a.onlineInstances}/${a.instances})`).join(', ');

  cachedFleet = {
    diskUsage,
    pm2Online,
    pm2Total,
    breakdown: breakdown || 'No active apps',
    groupedApps,
    services
  };
}

// Initial fleet population and 3-second non-blocking background refresh
refreshFleetStats();
setInterval(refreshFleetStats, 3000);

function getSystemStats() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const uptimeSec = os.uptime();

  const d = Math.floor(uptimeSec / 86400);
  const h = Math.floor((uptimeSec % 86400) / 3600);
  const m = Math.floor((uptimeSec % 3600) / 60);
  const uptimeStr = (d > 0 ? `${d}d ` : '') + `${h}h ${m}m`;

  const ramUsedGb = (usedMem / 1024 / 1024 / 1024).toFixed(1);
  const ramTotalGb = (totalMem / 1024 / 1024 / 1024).toFixed(1);
  const ramPercent = Math.round((usedMem / totalMem) * 100);

  return {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()}`,
    cpuPercent: currentCpuPercent,
    cpuLoad: os.loadavg()[0].toFixed(2),
    vCPUs: cpus.length,
    ramUsed: `${ramUsedGb} / ${ramTotalGb} GB`,
    ramPercent,
    diskUsage: cachedFleet.diskUsage,
    uptime: uptimeStr,
    pm2Online: cachedFleet.pm2Online,
    pm2Total: cachedFleet.pm2Total,
    breakdown: cachedFleet.breakdown,
    apps: cachedFleet.groupedApps,
    services: cachedFleet.services,
    inactivityMinutes: parseInt(config.inactivityMinutes, 10) || 15
  };
}

// -----------------------------------------------------------------------------
// HTML Templates
// -----------------------------------------------------------------------------

function renderLoginHtml(error = '', notice = '') {
  const title = config.title || 'OmniShell Terminal';
  const badge = config.badge || 'SECURE BASTION';
  const domain = config.domain || 'localhost';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #090d16;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #e6edf3;
      padding: 20px;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 40px 32px;
      width: 100%;
      max-width: 410px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    }
    .header {
      text-align: center;
      margin-bottom: 28px;
    }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      background: rgba(56, 189, 248, 0.1);
      color: #38bdf8;
      border: 1px solid rgba(56, 189, 248, 0.3);
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 12px;
    }
    h1 {
      font-size: 20px;
      font-weight: 600;
      color: #f0f6fc;
      margin-bottom: 6px;
    }
    p {
      font-size: 13px;
      color: #8b949e;
    }
    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      margin-bottom: 6px;
      color: #c9d1d9;
    }
    input {
      width: 100%;
      padding: 11px 14px;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #f0f6fc;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus {
      border-color: #38bdf8;
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }
    button {
      width: 100%;
      padding: 12px;
      background: #1f6feb;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 6px;
      transition: background 0.2s;
    }
    button:hover {
      background: #388bfd;
    }
    .error-box {
      background: rgba(248, 81, 73, 0.15);
      border: 1px solid rgba(248, 81, 73, 0.4);
      color: #f85149;
      padding: 10px 14px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 20px;
      text-align: center;
    }
    .notice-box {
      background: rgba(210, 153, 34, 0.15);
      border: 1px solid rgba(210, 153, 34, 0.4);
      color: #d29922;
      padding: 10px 14px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 20px;
      text-align: center;
    }
    .footer {
      text-align: center;
      margin-top: 24px;
      font-size: 11px;
      color: #484f58;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="badge">${badge}</div>
      <h1>${title}</h1>
      <p>Authorized personnel authentication required</p>
    </div>
    ${notice ? `<div class="notice-box">${notice}</div>` : ''}
    ${error ? `<div class="error-box">${error}</div>` : ''}
    <form method="POST" action="/login">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autocomplete="username" autofocus>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autocomplete="current-password">
      </div>
      <button type="submit">Sign In</button>
    </form>
    <div class="footer">
      <span>OmniShell Gateway &bull; ${domain}</span>
    </div>
  </div>
</body>
</html>`;
}

// Master Dashboard with Real-Time HUD Bar, Dropdown Drawers & Inactivity Guard
function renderDashboardHtml() {
  const title = config.title || 'OmniShell Terminal';
  const inactivityMinutes = parseInt(config.inactivityMinutes, 10) || 15;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body {
      width: 100%;
      height: 100%;
      overflow: hidden;
      background: #0d1117;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #c9d1d9;
    }
    #hud-bar {
      height: 42px;
      background: #161b22;
      border-bottom: 1px solid #30363d;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 16px;
      font-size: 12px;
      user-select: none;
      z-index: 100;
      position: relative;
    }
    .hud-left {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .hud-brand {
      font-weight: 700;
      color: #f0f6fc;
      letter-spacing: 0.5px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .hud-pulse {
      width: 8px;
      height: 8px;
      background: #238636;
      border-radius: 50%;
      box-shadow: 0 0 8px #238636;
    }
    .hud-host {
      color: #8b949e;
      font-family: monospace;
      background: #21262d;
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid #30363d;
    }
    .hud-center {
      display: flex;
      align-items: center;
      gap: 18px;
    }
    .stat-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: default;
    }
    .stat-label {
      color: #8b949e;
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
    }
    .stat-val {
      color: #f0f6fc;
      font-family: monospace;
      font-weight: 600;
    }
    .bar-wrap {
      width: 44px;
      height: 6px;
      background: #21262d;
      border-radius: 3px;
      overflow: hidden;
      border: 1px solid #30363d;
    }
    .bar-fill {
      height: 100%;
      background: #238636;
      transition: width 0.3s ease, background 0.3s ease;
    }
    .hud-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .btn {
      padding: 5px 12px;
      background: #21262d;
      color: #c9d1d9;
      border: 1px solid #30363d;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.2s, color 0.2s, border-color 0.2s;
    }
    .btn:hover {
      background: #30363d;
      color: #f0f6fc;
      border-color: #8b949e;
    }
    .btn-active {
      background: #1f6feb !important;
      border-color: #388bfd !important;
      color: #fff !important;
    }
    .btn-danger:hover {
      background: #b62324;
      border-color: #b62324;
      color: #fff;
    }
    #term-frame {
      width: 100%;
      height: calc(100% - 42px);
      border: none;
      display: block;
      background: #0d1117;
    }
    
    /* Popover Modal Drawers */
    .modal-overlay {
      display: none;
      position: fixed;
      top: 42px;
      left: 0;
      width: 100%;
      height: calc(100% - 42px);
      background: rgba(0, 0, 0, 0.55);
      backdrop-filter: blur(2px);
      z-index: 200;
      justify-content: center;
      align-items: flex-start;
      padding-top: 24px;
    }
    .modal-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      width: 90%;
      max-width: 680px;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 16px 36px rgba(0,0,0,0.6);
      animation: modalSlide 0.15s ease-out;
    }
    @keyframes modalSlide {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .modal-header {
      padding: 14px 18px;
      border-bottom: 1px solid #30363d;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-title {
      font-size: 14px;
      font-weight: 700;
      color: #f0f6fc;
    }
    .modal-close {
      background: none;
      border: none;
      color: #8b949e;
      font-size: 18px;
      cursor: pointer;
      line-height: 1;
    }
    .modal-close:hover { color: #f0f6fc; }
    .modal-body {
      padding: 16px 18px;
    }
    .fleet-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-bottom: 16px;
    }
    .fleet-table th, .fleet-table td {
      padding: 8px 12px;
      text-align: left;
      border-bottom: 1px solid #21262d;
    }
    .fleet-table th {
      color: #8b949e;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
    }
    .status-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 10px;
      font-weight: 700;
    }
    .status-online {
      background: rgba(35, 134, 54, 0.2);
      color: #3fb950;
      border: 1px solid rgba(63, 185, 80, 0.3);
    }
    .status-inactive {
      background: rgba(139, 148, 158, 0.2);
      color: #8b949e;
      border: 1px solid rgba(139, 148, 158, 0.3);
    }
    .action-row {
      display: flex;
      gap: 6px;
    }
    .mini-btn {
      padding: 3px 8px;
      background: #21262d;
      color: #c9d1d9;
      border: 1px solid #30363d;
      border-radius: 4px;
      font-size: 11px;
      cursor: pointer;
    }
    .mini-btn:hover {
      background: #30363d;
      color: #fff;
    }
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #1f6feb;
      color: #fff;
      padding: 10px 18px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
      z-index: 300;
      display: none;
      animation: fadeIn 0.2s ease-in;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    /* Inactivity Warning Modal */
    #inactivity-modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.8);
      z-index: 500;
      justify-content: center;
      align-items: center;
    }
    .inactivity-box {
      background: #161b22;
      border: 1px solid #f85149;
      border-radius: 10px;
      padding: 28px;
      max-width: 440px;
      text-align: center;
      box-shadow: 0 20px 50px rgba(0,0,0,0.8);
    }
    .inactivity-box h2 {
      color: #f85149;
      font-size: 18px;
      margin-bottom: 12px;
    }
    .inactivity-box p {
      color: #c9d1d9;
      font-size: 13px;
      line-height: 1.5;
      margin-bottom: 20px;
    }
    .countdown-timer {
      font-size: 32px;
      font-family: monospace;
      font-weight: 700;
      color: #f0f6fc;
      margin-bottom: 20px;
    }
    @media (max-width: 900px) {
      .hud-center { gap: 10px; }
      .stat-badge:nth-child(n+4) { display: none; }
    }
    @media (max-width: 640px) {
      .hud-center { display: none; }
    }
  </style>
</head>
<body>
  <div id="hud-bar">
    <div class="hud-left">
      <div class="hud-brand">
        <div class="hud-pulse"></div>
        <span>OmniShell</span>
      </div>
      <span class="hud-host" id="hud-hostname">Loading...</span>
    </div>

    <div class="hud-center">
      <div class="stat-badge" title="Instantaneous CPU Utilization (1-second tick delta) & Load Average">
        <span class="stat-label">CPU:</span>
        <div class="bar-wrap">
          <div class="bar-fill" id="hud-cpu-bar" style="width: 0%;"></div>
        </div>
        <span class="stat-val" id="hud-cpu">0%</span>
      </div>

      <div class="stat-badge" id="hud-ram-badge" title="Memory Allocation">
        <span class="stat-label">RAM:</span>
        <div class="bar-wrap">
          <div class="bar-fill" id="hud-ram-bar" style="width: 0%;"></div>
        </div>
        <span class="stat-val" id="hud-ram">--%</span>
      </div>

      <div class="stat-badge" title="Root Filesystem Disk Capacity">
        <span class="stat-label">Disk:</span>
        <span class="stat-val" id="hud-disk">--</span>
      </div>

      <div class="stat-badge" title="System Uptime">
        <span class="stat-label">Uptime:</span>
        <span class="stat-val" id="hud-uptime">--</span>
      </div>

      <div class="stat-badge" id="hud-apps-badge" style="cursor: pointer;" onclick="toggleAppsModal()" title="Click to view running application fleet">
        <span class="stat-label">Apps:</span>
        <span class="stat-val" id="hud-apps" style="color: #38bdf8; text-decoration: underline;">-- Online</span>
      </div>
    </div>

    <div class="hud-right">
      <button class="btn" id="btn-apps" onclick="toggleAppsModal()">Apps</button>
      <button class="btn" id="btn-logs" onclick="toggleLogsModal()">Logs</button>
      <a href="/logout" class="btn btn-danger">Logout</a>
    </div>
  </div>

  <!-- Apps Modal -->
  <div id="apps-modal" class="modal-overlay" onclick="closeOnBackdrop(event, 'apps-modal')">
    <div class="modal-card">
      <div class="modal-header">
        <div class="modal-title">Application Fleet & Process Overview</div>
        <button class="modal-close" onclick="toggleAppsModal()">&times;</button>
      </div>
      <div class="modal-body">
        <div style="font-size: 11px; color: #8b949e; margin-bottom: 12px;">Active PM2 Clusters & Daemon Services (Updated Live):</div>
        <table class="fleet-table">
          <thead>
            <tr>
              <th>Application</th>
              <th>Instances</th>
              <th>Memory</th>
              <th>CPU</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="fleet-table-body">
            <tr><td colspan="6" style="text-align: center; color: #8b949e;">Loading application telemetry...</td></tr>
          </tbody>
        </table>

        <div style="font-size: 11px; color: #8b949e; margin-bottom: 8px;">Systemd Services:</div>
        <table class="fleet-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="services-table-body">
            <tr><td colspan="3" style="text-align: center; color: #8b949e;">Loading services...</td></tr>
          </tbody>
        </table>

        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px;">
          <button class="btn" onclick="copyAndToast('omnishell apps')">Copy Status Command</button>
          <button class="btn" onclick="toggleAppsModal()">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Logs Modal -->
  <div id="logs-modal" class="modal-overlay" onclick="closeOnBackdrop(event, 'logs-modal')">
    <div class="modal-card">
      <div class="modal-header">
        <div class="modal-title">Application Log Streamer</div>
        <button class="modal-close" onclick="toggleLogsModal()">&times;</button>
      </div>
      <div class="modal-body">
        <p style="font-size: 12px; color: #8b949e; margin-bottom: 14px;">
          Select any application to copy its live streaming command to your clipboard. Paste into terminal with <strong>Ctrl+V</strong> or right-click to stream.
        </p>

        <div style="margin-bottom: 14px;">
          <label style="font-size: 11px; color: #8b949e; display: block; margin-bottom: 6px;">History Lines:</label>
          <select id="log-lines-select" class="btn" style="padding: 6px 10px;">
            <option value="20">Last 20 lines</option>
            <option value="50" selected>Last 50 lines</option>
            <option value="100">Last 100 lines</option>
            <option value="200">Last 200 lines</option>
          </select>
        </div>

        <div id="logs-targets-container" style="display: flex; flex-direction: column; gap: 8px;">
          <!-- Dynamically populated targets -->
        </div>

        <div style="display: flex; justify-content: flex-end; margin-top: 18px;">
          <button class="btn" onclick="toggleLogsModal()">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Inactivity Warning Modal -->
  <div id="inactivity-modal">
    <div class="inactivity-box">
      <h2>Session Inactivity Warning</h2>
      <p>
        Your session has been idle to protect server access. You will be automatically logged out in:
      </p>
      <div class="countdown-timer" id="inactivity-countdown">60s</div>
      <button class="btn btn-active" style="padding: 10px 24px; font-size: 13px;" onclick="resetInactivityTimer()">Stay Logged In</button>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast-notify" class="toast">Command copied to clipboard</div>

  <iframe id="term-frame" src="/?bare=1"></iframe>

  <script>
    let latestStats = null;
    let lastActivityTime = Date.now();
    let heartbeatThrottled = false;
    const INACTIVITY_MINUTES = ${inactivityMinutes};
    const INACTIVITY_MS = INACTIVITY_MINUTES * 60 * 1000;
    const WARNING_MS = Math.max(60000, INACTIVITY_MS - 60000); // Trigger 60s before logout

    // Inactivity Tracking
    function recordUserActivity() {
      lastActivityTime = Date.now();
      const warnModal = document.getElementById('inactivity-modal');
      if (warnModal.style.display === 'flex') {
        warnModal.style.display = 'none';
      }

      if (!heartbeatThrottled) {
        heartbeatThrottled = true;
        fetch('/api/heartbeat', { method: 'POST' }).catch(() => {});
        setTimeout(() => { heartbeatThrottled = false; }, 30000);
      }
    }

    ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'].forEach(evt => {
      window.addEventListener(evt, recordUserActivity, { passive: true });
    });

    // Attach activity listeners to iframe once loaded
    const termFrame = document.getElementById('term-frame');
    termFrame.addEventListener('load', () => {
      try {
        const frameDoc = termFrame.contentDocument || termFrame.contentWindow.document;
        ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'].forEach(evt => {
          frameDoc.addEventListener(evt, recordUserActivity, { passive: true });
        });
      } catch (e) {}
    });

    // Inactivity countdown timer
    setInterval(() => {
      const idleMs = Date.now() - lastActivityTime;
      const warnModal = document.getElementById('inactivity-modal');
      
      if (idleMs >= INACTIVITY_MS) {
        window.location.href = '/login?reason=idle_timeout';
        return;
      }

      if (idleMs >= WARNING_MS) {
        const remainingSec = Math.max(0, Math.ceil((INACTIVITY_MS - idleMs) / 1000));
        document.getElementById('inactivity-countdown').textContent = remainingSec + 's';
        warnModal.style.display = 'flex';
      } else {
        warnModal.style.display = 'none';
      }
    }, 1000);

    function resetInactivityTimer() {
      recordUserActivity();
      fetch('/api/heartbeat', { method: 'POST' }).catch(() => {});
      document.getElementById('inactivity-modal').style.display = 'none';
    }

    // Real-Time Telemetry Polling (Every 1.5 seconds)
    async function updateStats() {
      try {
        const res = await fetch('/api/stats');
        if (res.status === 401) {
          window.location.href = '/login?reason=idle_timeout';
          return;
        }
        if (!res.ok) return;
        const d = await res.json();
        latestStats = d;

        document.getElementById('hud-hostname').textContent = d.hostname;
        
        // Instantaneous CPU Utilization + Load Average
        document.getElementById('hud-cpu').textContent = d.cpuPercent + '% (' + d.cpuLoad + ')';
        const cpuBar = document.getElementById('hud-cpu-bar');
        cpuBar.style.width = Math.min(100, Math.max(2, d.cpuPercent)) + '%';
        if (d.cpuPercent > 80) cpuBar.style.background = '#f85149';
        else if (d.cpuPercent > 40) cpuBar.style.background = '#d29922';
        else cpuBar.style.background = '#238636';

        // RAM
        document.getElementById('hud-ram').textContent = d.ramPercent + '%';
        document.getElementById('hud-ram-badge').title = 'Memory Allocation: ' + d.ramUsed;
        const ramBar = document.getElementById('hud-ram-bar');
        ramBar.style.width = d.ramPercent + '%';
        if (d.ramPercent > 85) ramBar.style.background = '#f85149';
        else if (d.ramPercent > 70) ramBar.style.background = '#d29922';
        else ramBar.style.background = '#238636';

        document.getElementById('hud-disk').textContent = d.diskUsage;
        document.getElementById('hud-uptime').textContent = d.uptime;
        document.getElementById('hud-apps').textContent = d.pm2Online + ' Online';
        document.getElementById('hud-apps-badge').title = d.breakdown;

        renderAppsTable(d);
        renderLogsTargets(d);
      } catch (e) {}
    }

    function renderAppsTable(d) {
      if (!d.apps) return;
      var tbody = document.getElementById('fleet-table-body');
      if (d.apps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #8b949e;">No PM2 applications running</td></tr>';
      } else {
        var rows = '';
        for (var i = 0; i < d.apps.length; i++) {
          var a = d.apps[i];
          var pillClass = a.status === 'ONLINE' ? 'status-online' : 'status-inactive';
          rows += '<tr>' +
            '<td style="font-weight: 600; color: #f0f6fc;">' + a.name + '</td>' +
            '<td>' + a.onlineInstances + ' / ' + a.instances + ' (' + a.mode + ')</td>' +
            '<td>' + a.memoryFormatted + '</td>' +
            '<td>' + a.cpuFormatted + '</td>' +
            '<td><span class="status-pill ' + pillClass + '">' + a.status + '</span></td>' +
            '<td><div class="action-row">' +
              '<button class="mini-btn" onclick="copyAndToast(\\'omnishell logs ' + a.name + '\\')">Logs</button>' +
              '<button class="mini-btn" onclick="copyAndToast(\\'omnishell restart ' + a.name + '\\')">Restart</button>' +
            '</div></td>' +
          '</tr>';
        }
        tbody.innerHTML = rows;
      }

      var svcBody = document.getElementById('services-table-body');
      if (d.services && d.services.length > 0) {
        var sRows = '';
        for (var j = 0; j < d.services.length; j++) {
          var s = d.services[j];
          var sPill = s.status === 'ACTIVE' ? 'status-online' : 'status-inactive';
          sRows += '<tr>' +
            '<td style="font-weight: 600; color: #f0f6fc;">' + s.name + '</td>' +
            '<td><span class="status-pill ' + sPill + '">' + s.status + '</span></td>' +
            '<td><button class="mini-btn" onclick="copyAndToast(\\'omnishell logs ' + s.name + '\\')">View Journal</button></td>' +
          '</tr>';
        }
        svcBody.innerHTML = sRows;
      }
    }

    function renderLogsTargets(d) {
      var container = document.getElementById('logs-targets-container');
      var lines = document.getElementById('log-lines-select').value;
      var html = '<div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #21262d; border-radius: 6px;">' +
        '<div>' +
          '<div style="font-weight: 600; color: #f0f6fc;">All PM2 Applications (Unified)</div>' +
          '<div style="font-size: 11px; color: #8b949e;">Stream live multi-colored logs for all active clusters</div>' +
        '</div>' +
        '<button class="btn" onclick="copyAndToast(\\'omnishell logs all ' + lines + '\\')">Copy Command</button>' +
      '</div>';

      if (d.apps) {
        for (var i = 0; i < d.apps.length; i++) {
          var a = d.apps[i];
          html += '<div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #21262d; border-radius: 6px;">' +
            '<div>' +
              '<div style="font-weight: 600; color: #f0f6fc;">' + a.name + '</div>' +
              '<div style="font-size: 11px; color: #8b949e;">' + a.instances + ' instance(s) &bull; ' + a.memoryFormatted + ' &bull; ' + a.status + '</div>' +
            '</div>' +
            '<button class="btn" onclick="copyAndToast(\\'omnishell logs ' + a.name + ' ' + lines + '\\')">Copy Command</button>' +
          '</div>';
        }
      }

      if (d.services) {
        for (var j = 0; j < d.services.length; j++) {
          var s = d.services[j];
          html += '<div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #21262d; border-radius: 6px;">' +
            '<div>' +
              '<div style="font-weight: 600; color: #f0f6fc;">' + s.name + ' (systemd)</div>' +
              '<div style="font-size: 11px; color: #8b949e;">System service journal &bull; ' + s.status + '</div>' +
            '</div>' +
            '<button class="btn" onclick="copyAndToast(\\'omnishell logs ' + s.name + ' ' + lines + '\\')">Copy Command</button>' +
          '</div>';
        }
      }

      container.innerHTML = html;
    }

    document.getElementById('log-lines-select').addEventListener('change', () => {
      if (latestStats) renderLogsTargets(latestStats);
    });

    function toggleAppsModal() {
      const modal = document.getElementById('apps-modal');
      const isVisible = modal.style.display === 'flex';
      closeAllModals();
      if (!isVisible) {
        modal.style.display = 'flex';
        document.getElementById('btn-apps').classList.add('btn-active');
      }
    }

    function toggleLogsModal() {
      const modal = document.getElementById('logs-modal');
      const isVisible = modal.style.display === 'flex';
      closeAllModals();
      if (!isVisible) {
        modal.style.display = 'flex';
        document.getElementById('btn-logs').classList.add('btn-active');
      }
    }

    function closeAllModals() {
      document.getElementById('apps-modal').style.display = 'none';
      document.getElementById('logs-modal').style.display = 'none';
      document.getElementById('btn-apps').classList.remove('btn-active');
      document.getElementById('btn-logs').classList.remove('btn-active');
    }

    function closeOnBackdrop(e, modalId) {
      if (e.target.id === modalId) {
        closeAllModals();
      }
    }

    function copyAndToast(cmd) {
      navigator.clipboard.writeText(cmd).then(() => {
        showToast('Copied: "' + cmd + '" (Paste into terminal)');
        closeAllModals();
        termFrame.focus();
      }).catch(() => {
        showToast('Command: ' + cmd);
      });
    }

    function showToast(msg) {
      const t = document.getElementById('toast-notify');
      t.textContent = msg;
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 3500);
    }

    updateStats();
    setInterval(updateStats, 1500);
  </script>
</body>
</html>`;
}

// -----------------------------------------------------------------------------
// HTTP Server & Reverse Proxy
// -----------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  const ip = getClientIp(req);
  const token = getCookie(req, 'omnishell_auth');
  const isAuth = verifySession(token);

  // Endpoint: Heartbeat to refresh sliding activity timer
  if (req.url === '/api/heartbeat' && req.method === 'POST') {
    if (!isAuth) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    touchSession(token);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', lastActive: Date.now() }));
  }

  // Endpoint: Real-time Telemetry API
  if (req.url === '/api/stats') {
    if (!isAuth) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    touchSession(token);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    return res.end(JSON.stringify(getSystemStats()));
  }

  // Endpoint: Login GET
  if (req.url.startsWith('/login') && req.method === 'GET') {
    if (isAuth) {
      res.writeHead(302, { Location: '/' });
      return res.end();
    }
    const isTimeout = req.url.includes('reason=idle_timeout');
    const notice = isTimeout ? `Session expired due to ${config.inactivityMinutes || 15} minutes of inactivity. Please sign in again.` : '';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(renderLoginHtml('', notice));
  }

  // Endpoint: Login POST
  if (req.url === '/login' && req.method === 'POST') {
    if (isIpLocked(ip)) {
      res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(renderLoginHtml('Too many failed attempts. Access temporarily locked for 15 minutes.'));
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const user = (params.get('username') || '').trim();
      const pass = params.get('password') || '';

      const validUser = user === config.username;
      const validPass = verifyPassword(pass, config.passwordHash, config.salt);

      if (validUser && validPass) {
        resetFailedAttempts(ip);
        const sessionToken = signSession(user);
        const maxAge = (config.sessionDays || 7) * 24 * 3600;
        res.writeHead(302, {
          'Set-Cookie': `omnishell_auth=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`,
          Location: '/'
        });
        return res.end();
      } else {
        recordFailedAttempt(ip);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(renderLoginHtml('Invalid username or password.'));
      }
    });
    return;
  }

  // Endpoint: Logout
  if (req.url === '/logout') {
    if (token) sessionActivityMap.delete(token);
    res.writeHead(302, {
      'Set-Cookie': 'omnishell_auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
      Location: '/login'
    });
    return res.end();
  }

  // Authentication Guard
  if (!isAuth) {
    res.writeHead(302, { Location: '/login' });
    return res.end();
  }

  // Main Dashboard View (Serves Real-Time HUD Bar + Embedded Terminal)
  if ((req.url === '/' || req.url === '/index.html') && !req.url.includes('bare=1')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(renderDashboardHtml());
  }

  // Proxy directly to ttyd socket for bare terminal assets and raw requests
  const ttydPort = config.ttydPort || 7680;
  const targetPath = req.url.replace(/\?bare=1/, '').replace(/&bare=1/, '');
  const options = {
    hostname: '127.0.0.1',
    port: ttydPort,
    path: targetPath || '/',
    method: req.method,
    headers: { ...req.headers, host: `127.0.0.1:${ttydPort}` }
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxyReq.on('error', (err) => {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Gateway Error: Failed to connect to ttyd backend socket.');
  });

  req.pipe(proxyReq, { end: true });
});

// Proxy WebSocket connections to ttyd socket with activity tracking & idle termination
server.on('upgrade', (req, clientSocket, head) => {
  const token = getCookie(req, 'omnishell_auth');
  if (!verifySession(token)) {
    clientSocket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    clientSocket.destroy();
    return;
  }

  const ttydPort = config.ttydPort || 7680;
  const targetSocket = net.connect(ttydPort, '127.0.0.1', () => {
    let rawHeaders = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
    for (const [key, value] of Object.entries(req.headers)) {
      rawHeaders += `${key}: ${value}\r\n`;
    }
    rawHeaders += '\r\n';

    targetSocket.write(rawHeaders);
    if (head && head.length) {
      targetSocket.write(head);
    }

    clientSocket.pipe(targetSocket);
    targetSocket.pipe(clientSocket);
  });

  // When keystrokes flow through clientSocket, touch session to keep sliding active
  clientSocket.on('data', () => {
    touchSession(token);
  });

  // Server-side WebSocket idle killer: terminates connection if session expires
  const idleCheckInterval = setInterval(() => {
    if (!verifySession(token)) {
      clearInterval(idleCheckInterval);
      try {
        clientSocket.write('HTTP/1.1 401 Session Inactivity Timeout\r\n\r\n');
        clientSocket.destroy();
        targetSocket.destroy();
      } catch (e) {}
    }
  }, 10000);

  clientSocket.on('close', () => clearInterval(idleCheckInterval));
  targetSocket.on('close', () => clearInterval(idleCheckInterval));
  targetSocket.on('error', () => { clientSocket.destroy(); });
  clientSocket.on('error', () => { targetSocket.destroy(); });
});

const gatewayPort = config.gatewayPort || 7681;
server.listen(gatewayPort, '127.0.0.1', () => {
  console.log(`[OmniShell Gateway] Listening on 127.0.0.1:${gatewayPort}, forwarding to ttyd on :${config.ttydPort || 7680}`);
  console.log(`[OmniShell Gateway] Inactivity Auto-Expiry: ${config.inactivityMinutes || 15} minutes`);
});
