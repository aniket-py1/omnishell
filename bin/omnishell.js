#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { execSync, spawn } = require('child_process');

const CONFIG_PATH = fs.existsSync('/etc/omnishell/config.json') 
  ? '/etc/omnishell/config.json'
  : path.join(__dirname, '..', 'config.json');

function readConfig() {
  if (!fs.existsSync(CONFIG_PATH)) {
    console.error(`[Error] Configuration file not found at ${CONFIG_PATH}`);
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
}

function writeConfig(cfg) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function getAllPm2Apps() {
  const allApps = [];
  const seenKeys = new Set();
  const isRoot = !process.getuid || process.getuid() === 0;

  // 1. Current user's PM2 apps
  try {
    const raw = execSync('pm2 jlist 2>/dev/null', { encoding: 'utf8' }).trim();
    if (raw.startsWith('[') && raw.endsWith(']')) {
      const list = JSON.parse(raw);
      for (const app of list) {
        const key = `${app.name}:${app.pm_id}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          app.__asSudo = false;
          allApps.push(app);
        }
      }
    }
  } catch (e) {}

  // 2. If running as non-root user, query root's PM2 apps via sudo -n
  if (!isRoot) {
    try {
      const raw = execSync('sudo -n pm2 jlist 2>/dev/null', { encoding: 'utf8' }).trim();
      if (raw.startsWith('[') && raw.endsWith(']')) {
        const list = JSON.parse(raw);
        for (const app of list) {
          const key = `${app.name}:${app.pm_id}`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            app.__asSudo = true;
            allApps.push(app);
          }
        }
      }
    } catch (e) {}
  } else {
    // 3. If running as root, scan /home/*/.pm2
    try {
      if (fs.existsSync('/home')) {
        const users = fs.readdirSync('/home');
        for (const u of users) {
          const home = `/home/${u}/.pm2`;
          if (fs.existsSync(home)) {
            try {
              const raw = execSync(`PM2_HOME="${home}" pm2 jlist 2>/dev/null`, { encoding: 'utf8' }).trim();
              if (raw.startsWith('[') && raw.endsWith(']')) {
                const list = JSON.parse(raw);
                for (const app of list) {
                  const key = `${app.name}:${app.pm_id}`;
                  if (!seenKeys.has(key)) {
                    seenKeys.add(key);
                    app.__pm2Home = home;
                    app.__asSudo = false;
                    allApps.push(app);
                  }
                }
              }
            } catch (e) {}
          }
        }
      }
    } catch (e) {}
  }

  return allApps;
}

const args = process.argv.slice(2);
const command = args[0];

function printHelp() {
  console.log(`
OmniShell CLI - Server & Terminal Management Tool
Author: Aniket Mahida

Usage:
  omnishell <command> [arguments]

Available Commands:
  apps                    Display dynamic status of all running apps & services
  logs [app] [lines]      Stream real-time logs for any app (auto-detected)
  password <new_pass>     Change admin password with fresh salted hash
  user <new_username>     Change admin username
  title <new_title>       Update terminal title and browser branding
  status                  Show OmniShell gateway health, ports, and URL
  restart [app]           Restart OmniShell or any target application
  help                    Show this help guide

Log Streaming Examples:
  omnishell logs              Stream logs from all PM2 applications
  omnishell logs lgbs         Stream logs from lgbs-api cluster
  omnishell logs tronpay      Stream logs from tronpay-api cluster
  omnishell logs redis        Stream systemd journal for redis-server
  omnishell logs nginx        Stream systemd journal for nginx
  omnishell logs api 100      Stream last 100 lines and follow live
`);
}

if (!command || command === 'help' || command === '--help' || command === '-h') {
  printHelp();
  process.exit(0);
}

switch (command) {
  case 'apps':
  case 'ps':
  case 'list': {
    console.log('======================================================');
    console.log('  OmniShell Application Fleet Status');
    console.log('======================================================');

    // 1. Dynamic PM2 Applications across users
    const pm2List = getAllPm2Apps();
    if (pm2List.length === 0) {
      console.log('  PM2 Applications : None running');
    } else {
      const groups = {};
      for (const app of pm2List) {
        const name = app.name;
        if (!groups[name]) {
          groups[name] = { count: 0, status: app.pm2_env ? app.pm2_env.status : 'online', mem: 0, cpu: 0, mode: app.pm2_env ? app.pm2_env.exec_mode : 'fork' };
        }
        groups[name].count += 1;
        groups[name].mem += (app.monit ? app.monit.memory : 0);
        groups[name].cpu += (app.monit ? app.monit.cpu : 0);
        if (app.pm2_env && app.pm2_env.status !== 'online') groups[name].status = app.pm2_env.status;
      }

      console.log('  PM2 Applications:');
      for (const [name, info] of Object.entries(groups)) {
        const memMb = Math.round(info.mem / 1024 / 1024);
        const typeStr = info.count > 1 ? `${info.count} cluster instances` : `${info.mode || 'fork'}`;
        const badge = info.status === 'online' ? '[ONLINE]' : `[${info.status.toUpperCase()}]`;
        console.log(`    ${badge.padEnd(9)} ${name.padEnd(20)} : ${typeStr.padEnd(22)} (RAM: ${memMb} MB, CPU: ${info.cpu}%)`);
      }
    }

    // 2. Dynamic Infrastructure & System Services
    console.log('------------------------------------------------------');
    console.log('  System Services:');
    const systemServices = ['nginx', 'redis-server', 'redis', 'mongod', 'mongodb', 'docker', 'postgresql', 'mysql', 'ttyd'];
    const seenSvc = new Set();
    for (const s of systemServices) {
      if (seenSvc.has(s)) continue;
      try {
        const state = execSync(`systemctl is-active ${s} 2>/dev/null`, { encoding: 'utf8' }).trim();
        if (state === 'active') {
          seenSvc.add(s);
          console.log(`    [ACTIVE]  ${s.padEnd(20)} : systemd service`);
        }
      } catch (e) {}
    }
    console.log('======================================================');
    break;
  }

  case 'logs': {
    const target = args[1];
    const lines = parseInt(args[2], 10) || 50;

    // Case A: No target or target is 'all' -> stream all PM2 logs
    if (!target || target === 'all') {
      console.log(`[+] Streaming logs for all PM2 applications (lines: ${lines})...`);
      const allApps = getAllPm2Apps();
      const spawnEnv = { ...process.env };
      const appWithHome = allApps.find(a => a.__pm2Home);
      if (appWithHome) {
        spawnEnv.PM2_HOME = appWithHome.__pm2Home;
      }
      const child = spawn('pm2', ['logs', '--lines', lines.toString()], {
        stdio: 'inherit',
        env: spawnEnv
      });
      child.on('exit', code => process.exit(code || 0));
      break;
    }

    // Case B: Check if target matches custom path in config.json
    const cfg = readConfig();
    if (cfg.logs && cfg.logs[target] && fs.existsSync(cfg.logs[target])) {
      console.log(`[+] Tailing custom log file: ${cfg.logs[target]}`);
      const child = spawn('tail', ['-f', '-n', lines.toString(), cfg.logs[target]], { stdio: 'inherit' });
      child.on('exit', code => process.exit(code || 0));
      break;
    }

    // Case C: Check PM2 apps for exact or fuzzy match
    const pm2List = getAllPm2Apps();
    const appNames = [...new Set(pm2List.map(a => a.name))];

    let matchedPm2Name = appNames.find(n => n.toLowerCase() === target.toLowerCase());
    if (!matchedPm2Name) {
      matchedPm2Name = appNames.find(n => n.toLowerCase().includes(target.toLowerCase()));
    }

    if (matchedPm2Name) {
      console.log(`[+] Found PM2 application: "${matchedPm2Name}". Streaming live logs...`);
      const matchedApp = pm2List.find(a => a.name === matchedPm2Name);
      if (matchedApp && matchedApp.__asSudo) {
        const child = spawn('sudo', ['pm2', 'logs', matchedPm2Name, '--lines', lines.toString()], { stdio: 'inherit' });
        child.on('exit', code => process.exit(code || 0));
        break;
      }
      const spawnEnv = { ...process.env };
      if (matchedApp && matchedApp.__pm2Home) {
        spawnEnv.PM2_HOME = matchedApp.__pm2Home;
      }
      const child = spawn('pm2', ['logs', matchedPm2Name, '--lines', lines.toString()], {
        stdio: 'inherit',
        env: spawnEnv
      });
      child.on('exit', code => process.exit(code || 0));
      break;
    }

    // Case D: Check if target is a running or installed systemd service
    try {
      const isSystemd = execSync(`systemctl list-unit-files "${target}*" 2>/dev/null`, { encoding: 'utf8' });
      if (isSystemd.includes(target)) {
        console.log(`[+] Found systemd service: "${target}". Streaming journal logs...`);
        const child = spawn('journalctl', ['-u', target, '-f', '-n', lines.toString()], { stdio: 'inherit' });
        child.on('exit', code => process.exit(code || 0));
        break;
      }
    } catch (e) {}

    // Case E: Check common log files in /var/log
    const commonPath = `/var/log/${target}.log`;
    if (fs.existsSync(commonPath)) {
      console.log(`[+] Found system log file: "${commonPath}". Streaming logs...`);
      const child = spawn('tail', ['-f', '-n', lines.toString(), commonPath], { stdio: 'inherit' });
      child.on('exit', code => process.exit(code || 0));
      break;
    }

    console.log(`[Error] Could not find any running PM2 app, systemd service, or log file matching "${target}".`);
    console.log('Run "omnishell apps" to see all discoverable services on this server.');
    process.exit(1);
  }

  case 'password': {
    const newPass = args[1];
    if (!newPass) {
      console.log('Error: Password cannot be empty.');
      console.log('Usage: omnishell password <new_password>');
      process.exit(1);
    }
    const cfg = readConfig();
    const newSalt = crypto.randomBytes(16).toString('hex');
    cfg.salt = newSalt;
    cfg.passwordHash = hashPassword(newPass, newSalt);
    writeConfig(cfg);
    console.log('[Success] Password updated successfully with new salted hash.');
    console.log('[Notice] Active sessions will be required to authenticate with the new credentials.');
    break;
  }

  case 'user': {
    const newUser = args[1];
    if (!newUser) {
      console.log('Usage: omnishell user <new_username>');
      process.exit(1);
    }
    const cfg = readConfig();
    cfg.username = newUser.trim();
    writeConfig(cfg);
    console.log(`[Success] Admin username updated to: ${newUser}`);
    break;
  }

  case 'title': {
    const newTitle = args.slice(1).join(' ');
    if (!newTitle) {
      console.log('Usage: omnishell title "<New Title>"');
      process.exit(1);
    }
    const cfg = readConfig();
    cfg.title = newTitle.trim();
    writeConfig(cfg);
    console.log(`[Success] Terminal title updated to: "${newTitle}"`);
    break;
  }

  case 'status': {
    const cfg = readConfig();
    console.log('======================================================');
    console.log('  OmniShell Service Status');
    console.log('======================================================');
    console.log(`  Access URL   : https://${cfg.domain || 'localhost'}/`);
    console.log(`  Admin User   : ${cfg.username}`);
    console.log(`  Gateway Port : ${cfg.gatewayPort || 7681} (HTTP Gateway)`);
    console.log(`  ttyd Port    : ${cfg.ttydPort || 7680} (Internal PTY)`);
    console.log(`  Shell User   : ${cfg.shellUser || 'ubuntu'}`);
    console.log('------------------------------------------------------');
    try {
      const pm2List = getAllPm2Apps();
      const app = pm2List.find(p => p.name === 'omnishell' || p.name === 'terminal-gateway');
      if (app) {
        console.log(`  PM2 Process  : ${app.name} [Status: ${app.pm2_env.status}] (PID: ${app.pid}, Memory: ${Math.round(app.monit.memory / 1024 / 1024)} MB)`);
      } else {
        console.log('  PM2 Process  : omnishell [Not detected]');
      }
    } catch (e) {
      console.log('  PM2 Status   : Not available');
    }
    try {
      const ttydStatus = execSync('systemctl is-active ttyd 2>/dev/null', { encoding: 'utf8' }).trim();
      console.log(`  ttyd Daemon  : ${ttydStatus}`);
    } catch (e) {}
    console.log('======================================================');
    break;
  }

  case 'restart': {
    const target = args[1];
    if (target && target !== 'omnishell') {
      console.log(`[+] Restarting application: "${target}"...`);
      const pm2List = getAllPm2Apps();
      const matchedApp = pm2List.find(a => a.name.toLowerCase().includes(target.toLowerCase()));
      if (matchedApp && matchedApp.__asSudo) {
        execSync(`sudo -n pm2 restart "${matchedApp.name}"`, { stdio: 'inherit' });
      } else {
        const envPrefix = (matchedApp && matchedApp.__pm2Home) ? `PM2_HOME="${matchedApp.__pm2Home}" ` : '';
        execSync(`${envPrefix}pm2 restart "${target}"`, { stdio: 'inherit' });
      }
      console.log(`[Success] Application "${target}" restarted.`);
      break;
    }
    console.log('[+] Restarting ttyd daemon...');
    try { execSync('sudo -n systemctl restart ttyd 2>/dev/null || systemctl restart ttyd'); } catch (e) {}
    console.log('[+] Restarting OmniShell gateway...');
    try { execSync('sudo -n pm2 restart omnishell 2>/dev/null || pm2 restart omnishell || pm2 restart terminal-gateway'); } catch (e) {}
    console.log('[Success] OmniShell restarted successfully.');
    break;
  }

  default:
    console.log(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
}
