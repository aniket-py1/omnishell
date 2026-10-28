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
    sessionDays: 7
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

// Brute force protection
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

function signSession(username) {
  const timestamp = Date.now();
  const payload = `${username}:${timestamp}`;
  const hmac = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex');
  return Buffer.from(`${payload}:${hmac}`).toString('base64');
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
    const maxAge = (config.sessionDays || 7) * 24 * 3600 * 1000;
    if (Date.now() - parseInt(timestamp, 10) > maxAge) return false;
    return user === config.username;
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

// System Telemetry Helper
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

  const load = os.loadavg()[0].toFixed(2);

  let diskUsage = 'N/A';
  try {
    const df = execSync("df -h / | tail -n 1 | awk '{print $5}'", { encoding: 'utf8' }).trim();
    if (df) diskUsage = df;
  } catch (e) {}

  let pm2Online = 0;
  try {
    const pm2Raw = execSync('pm2 jlist 2>/dev/null', { encoding: 'utf8' });
    const list = JSON.parse(pm2Raw);
    pm2Online = list.filter(p => p.pm2_env && p.pm2_env.status === 'online').length;
  } catch (e) {}

  return {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()}`,
    cpuLoad: load,
    vCPUs: cpus.length,
    ramUsed: `${ramUsedGb} / ${ramTotalGb} GB`,
    ramPercent,
    diskUsage,
    uptime: uptimeStr,
    pm2Online
  };
}

function renderLoginHtml(error = '') {
  const title = config.title || 'OmniShell Terminal';
  const badge = config.badge || 'SECURE SHELL';
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

// Master Dashboard with Real-Time HUD Bar & Embedded Terminal
function renderDashboardHtml() {
  const title = config.title || 'OmniShell Terminal';
  const domain = config.domain || 'localhost';

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
      transition: width 0.4s ease, background 0.4s ease;
    }
    .hud-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .btn {
      padding: 4px 10px;
      background: #21262d;
      color: #c9d1d9;
      border: 1px solid #30363d;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.2s, color 0.2s;
    }
    .btn:hover {
      background: #30363d;
      color: #f0f6fc;
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
      <div class="stat-badge">
        <span class="stat-label">CPU:</span>
        <span class="stat-val" id="hud-cpu">--</span>
      </div>

      <div class="stat-badge">
        <span class="stat-label">RAM:</span>
        <div class="bar-wrap">
          <div class="bar-fill" id="hud-ram-bar" style="width: 0%;"></div>
        </div>
        <span class="stat-val" id="hud-ram">--</span>
      </div>

      <div class="stat-badge">
        <span class="stat-label">Disk:</span>
        <span class="stat-val" id="hud-disk">--</span>
      </div>

      <div class="stat-badge">
        <span class="stat-label">Uptime:</span>
        <span class="stat-val" id="hud-uptime">--</span>
      </div>

      <div class="stat-badge">
        <span class="stat-label">Apps:</span>
        <span class="stat-val" id="hud-apps" style="color: #38bdf8;">--</span>
      </div>
    </div>

    <div class="hud-right">
      <button class="btn" onclick="sendCommand('omnishell apps')">Apps</button>
      <button class="btn" onclick="sendCommand('omnishell logs')">Logs</button>
      <a href="/logout" class="btn btn-danger">Logout</a>
    </div>
  </div>

  <iframe id="term-frame" src="/?bare=1"></iframe>

  <script>
    async function updateStats() {
      try {
        const res = await fetch('/api/stats');
        if (!res.ok) return;
        const d = await res.json();
        
        document.getElementById('hud-hostname').textContent = d.hostname;
        document.getElementById('hud-cpu').textContent = d.cpuLoad + ' (' + d.vCPUs + 'c)';
        document.getElementById('hud-ram').textContent = d.ramPercent + '%';
        
        const ramBar = document.getElementById('hud-ram-bar');
        ramBar.style.width = d.ramPercent + '%';
        if (d.ramPercent > 85) ramBar.style.background = '#f85149';
        else if (d.ramPercent > 70) ramBar.style.background = '#d29922';
        else ramBar.style.background = '#238636';

        document.getElementById('hud-disk').textContent = d.diskUsage;
        document.getElementById('hud-uptime').textContent = d.uptime;
        document.getElementById('hud-apps').textContent = d.pm2Online + ' Online';
      } catch (e) {}
    }

    function sendCommand(cmd) {
      const frame = document.getElementById('term-frame');
      frame.focus();
    }

    updateStats();
    setInterval(updateStats, 2000);
  </script>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const ip = getClientIp(req);
  const token = getCookie(req, 'omnishell_auth');
  const isAuth = verifySession(token);

  // Endpoint: Real-time Telemetry API
  if (req.url === '/api/stats') {
    if (!isAuth) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    return res.end(JSON.stringify(getSystemStats()));
  }

  // Endpoint: Login GET
  if (req.url === '/login' && req.method === 'GET') {
    if (isAuth) {
      res.writeHead(302, { Location: '/' });
      return res.end();
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(renderLoginHtml());
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

// Proxy WebSocket connections to ttyd socket
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

  targetSocket.on('error', () => { clientSocket.destroy(); });
  clientSocket.on('error', () => { targetSocket.destroy(); });
});

const gatewayPort = config.gatewayPort || 7681;
server.listen(gatewayPort, '127.0.0.1', () => {
  console.log(`[OmniShell Gateway] Listening on 127.0.0.1:${gatewayPort}, forwarding to ttyd on :${config.ttydPort || 7680}`);
});
