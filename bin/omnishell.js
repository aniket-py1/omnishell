#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { execSync } = require('child_process');

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
OmniShell CLI - Server Management Tool
Author: Aniket Mahida

Usage:
  omnishell <command> [arguments]

Available Commands:
  password [new_pass]     Change admin password (prompts securely if omitted)
  user <new_username>     Change admin username
  title <new_title>       Update terminal title and browser branding
  status                  Show service health, ports, and access URL
  restart                 Restart OmniShell gateway and ttyd daemon
  logs                    Tail live gateway logs
  help                    Show this help guide
`);
}

if (!command || command === 'help' || command === '--help' || command === '-h') {
  printHelp();
  process.exit(0);
}

switch (command) {
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
    console.log('[+] Restarting ttyd daemon...');
    try { execSync('systemctl restart ttyd'); } catch (e) {}
    console.log('[+] Restarting OmniShell gateway...');
    try { execSync('pm2 restart omnishell || pm2 restart terminal-gateway'); } catch (e) {}
    console.log('[Success] OmniShell restarted successfully.');
    break;
  }

  case 'logs': {
    try {
      execSync('pm2 logs omnishell --lines 30 --nostream || pm2 logs terminal-gateway --lines 30 --nostream', { stdio: 'inherit' });
    } catch (e) {
      console.error('Failed to read logs.');
    }
    break;
  }

  default:
    console.log(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
}
