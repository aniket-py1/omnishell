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
  restart [app]           Restart OmniShell or any running application
  help                    Show this help guide

Log Streaming Examples:
  omnishell logs              Stream logs from all PM2 applications
  omnishell logs api          Stream logs from any app matching "api"
  omnishell logs redis        Stream systemd journal for redis-server
  omnishell logs nginx        Stream systemd journal for nginx
  omnishell logs api 100      Stream last 100 lines and follow
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

    // 1. Dynamic PM2 Applications
    try {
      const pm2Raw = execSync('pm2 jlist 2>/dev/null', { encoding: 'utf8' });
      const pm2List = JSON.parse(pm2Raw);

      if (pm2List.length === 0) {
        console.log('  PM2 Applications : None running');
      } else {
        // Group by app name to calculate clusters
        const groups = {};
        for (const app of pm2List) {
          const name = app.name;
          if (!groups[name]) {
            groups[name] = { count: 0, status: app.pm2_env.status, mem: 0, cpu: 0, mode: app.pm2_env.exec_mode };
          }
          groups[name].count += 1;
          groups[name].mem += (app.monit ? app.monit.memory : 0);
          groups[name].cpu += (app.monit ? app.monit.cpu : 0);
          if (app.pm2_env.status !== 'online') groups[name].status = app.pm2_env.status;
        }

        console.log('  PM2 Applications:');
        for (const [name, info] of Object.entries(groups)) {
          const memMb = Math.round(info.mem / 1024 / 1024);
          const typeStr = info.count > 1 ? `${info.count} cluster instances` : `${info.mode || 'fork'}`;
          const badge = info.status === 'online' ? '[ONLINE]' : `[${info.status.toUpperCase()}]`;
          console.log(`    ${badge.padEnd(9)} ${name.padEnd(20)} : ${typeStr.padEnd(22)} (RAM: ${memMb} MB, CPU: ${info.cpu}%)`);
        }
      }
    } catch (e) {
      console.log('  PM2 Applications : PM2 daemon not running');
    }

    // 2. Dynamic Infrastructure & System Services
    console.log('------------------------------------------------------');
    console.log('  System Services:');
    const systemServices = ['nginx', 'redis-server', 'redis', 'mongod', 'mongodb', 'docker', 'postgresql', 'mysql', 'ttyd'];
    for (const s of systemServices) {
      try {
        const state = execSync(`systemctl is-active ${s} 2>/dev/null`, { encoding: 'utf8' }).trim();
        if (state === 'active') {
          console.log(`    [ACTIVE]  ${s.padEnd(20)} : systemd service`);
        }
      } catch (e) {
        // Service not installed or inactive
      }
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
      const child = spawn('pm2', ['logs', '--lines', lines.toString()], { stdio: 'inherit' });
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
    let matchedPm2Name = null;
    try {
      const pm2Raw = execSync('pm2 jlist 2>/dev/null', { encoding: 'utf8' });
      const pm2List = JSON.parse(pm2Raw);
      const appNames = [...new Set(pm2List.map(a => a.name))];

      // Exact match first
      matchedPm2Name = appNames.find(n => n.toLowerCase() === target.toLowerCase());

      // Fuzzy / substring match
      if (!matchedPm2Name) {
        matchedPm2Name = appNames.find(n => n.toLowerCase().includes(target.toLowerCase()));
      }
    } catch (e) {}

    if (matchedPm2Name) {
      console.log(`[+] Found PM2 application: "${matchedPm2Name}". Streaming live logs...`);
      const child = spawn('pm2', ['logs', matchedPm2Name, '--lines', lines.toString()], { stdio: 'inherit' });
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
      const pm2Status = execSync('pm2 jlist 2>/dev/null', { encoding: 'utf8' });
      const list = JSON.parse(pm2Status);
      const app = list.find(p => p.name === 'omnishell' || p.name === 'terminal-gateway');
      if (app) {
        console.log(`  PM2 Process  : ${app.name} [Status: ${app.pm2_env.status}] (PID: ${app.pid}, Memory: ${Math.round(app.monit.memory / 1024 / 1024)} MB)`);
      }
    } catch (e) {
      console.log('  PM2 Status   : Not available');
    }
    try {
      const ttydStatus = execSync('systemctl is-active ttyd 2>/dev/null', { encoding: 'utf8' }).trim();
      console.log(`  ttyd Daemon  : ${ttydStatus}`);
    } catch (e) {
      console.log('  ttyd Daemon  : inactive');
    }
    console.log('======================================================');
    break;
  }

  case 'restart': {
    const target = args[1];
    if (target && target !== 'omnishell') {
      console.log(`[+] Restarting application: "${target}"...`);
      try {
        execSync(`pm2 restart "${target}"`, { stdio: 'inherit' });
      } catch (e) {
        console.error(`Failed to restart PM2 app "${target}".`);
      }
      break;
    }
    console.log('[+] Restarting ttyd daemon...');
    try { execSync('systemctl restart ttyd'); } catch (e) {}
    console.log('[+] Restarting OmniShell gateway...');
    try { execSync('pm2 restart omnishell || pm2 restart terminal-gateway'); } catch (e) {}
    console.log('[Success] OmniShell restarted successfully.');
    break;
  }

  default:
    console.log(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
}
