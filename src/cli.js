#!/usr/bin/env node
'use strict';

const { program } = require('commander');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');
const os = require('os');

const PROJECT_ROOT = path.join(__dirname, '..');
const PID_FILE = path.join(PROJECT_ROOT, 'captures', 'intercept.pid');

// ── Shared startup ────────────────────────────────────────────────────────────
async function startIntercept({ proxyPort, uiPort, open: autoOpen }) {
  // Check if already running
  if (fs.existsSync(PID_FILE)) {
    try {
      const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
      process.kill(pid, 0);
      console.log(chalk.yellow(`[intercept] Already running (PID ${pid})`));
      console.log(chalk.cyan(`  Proxy: http://127.0.0.1:${proxyPort}`));
      console.log(chalk.cyan(`  Dashboard: http://127.0.0.1:${uiPort}`));
      return;
    } catch {
      fs.unlinkSync(PID_FILE); // stale pid file
    }
  }

  console.log(chalk.bold.blue('\n  Claude Intercept\n'));

  // Init cert manager (generates CA if needed)
  const certManager = require('./proxy/cert_manager');
  certManager.init();

  // Init database
  const db = require('./storage/db');
  db.init();

  // Init proxy first so we can pass the instance to the UI server
  const ProxyServer = require('./proxy/index');
  const proxy = new ProxyServer({ port: proxyPort, db, broadcast: () => {} }); // broadcast patched below

  // Init UI + WebSocket
  const { createUIServer } = require('./ui/server');
  const { broadcast, listen: listenUI } = createUIServer({ uiPort, proxyPort, proxyInstance: proxy });

  // Patch broadcast into proxy now that we have it
  proxy.broadcast = broadcast;

  await listenUI();
  await proxy.listen();

  // Write PID
  fs.mkdirSync(path.dirname(PID_FILE), { recursive: true });
  fs.writeFileSync(PID_FILE, String(process.pid));

  const localIp = getLocalIP();

  console.log(chalk.green('  ✓ Proxy running'));
  console.log(`    ${chalk.bold('HTTP/HTTPS proxy:')} ${chalk.cyan(`127.0.0.1:${proxyPort}`)}`);
  console.log(`    ${chalk.bold('LAN access:')}       ${chalk.cyan(`${localIp}:${proxyPort}`)}`);
  console.log('');
  console.log(chalk.green('  ✓ Dashboard running'));
  console.log(`    ${chalk.cyan(`http://127.0.0.1:${uiPort}`)}`);
  console.log('');
  console.log(chalk.dim('  CA Certificate: ' + certManager.getCACertPath()));
  console.log(chalk.dim('  Ctrl+C to stop\n'));

  if (autoOpen) {
    const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    require('child_process').spawn(opener, [`http://127.0.0.1:${uiPort}`], { detached: true, stdio: 'ignore' });
  }

  // Graceful shutdown
  process.on('SIGINT', () => shutdown(proxy));
  process.on('SIGTERM', () => shutdown(proxy));
}

function shutdown(proxy) {
  console.log(chalk.dim('\n  Shutting down…'));
  proxy.close();
  // Restore system proxy so the network isn't broken after exit
  try {
    const sysProxy = require('./system_proxy');
    const result = sysProxy.disable();
    if (result.deactivated?.length) {
      console.log(chalk.dim('  System proxy restored.'));
    }
  } catch {}
  if (fs.existsSync(PID_FILE)) fs.unlinkSync(PID_FILE);
  process.exit(0);
}

// Safety net: restore proxy on uncaught errors so network isn't left broken
process.on('uncaughtException', (err) => {
  console.error(chalk.red('\n  Fatal error: ' + err.message));
  try {
    const sysProxy = require('./system_proxy');
    sysProxy.disable();
  } catch {}
  if (fs.existsSync(PID_FILE)) fs.unlinkSync(PID_FILE);
  process.exit(1);
});

// ── CLI commands ──────────────────────────────────────────────────────────────
program
  .name('claude-intercept')
  .description('MITM proxy for capturing and analyzing HTTP/S traffic')
  .version(require('../package.json').version);

program
  .command('start')
  .description('Start the proxy and dashboard')
  .option('-p, --proxy-port <port>', 'Proxy port', '7777')
  .option('-u, --ui-port <port>', 'Dashboard port', '7778')
  .option('--no-open', 'Do not open the dashboard automatically')
  .action(async (opts) => {
    try {
      await startIntercept({
        proxyPort: parseInt(opts.proxyPort, 10),
        uiPort: parseInt(opts.uiPort, 10),
        open: opts.open !== false,
      });
    } catch (err) {
      console.error(chalk.red('  Error: ' + err.message));
      process.exit(1);
    }
  });

program
  .command('stop')
  .description('Stop a running proxy')
  .action(() => {
    if (!fs.existsSync(PID_FILE)) {
      console.log(chalk.yellow('  No running instance found.'));
      return;
    }
    const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
    try {
      process.kill(pid, 'SIGTERM');
      fs.unlinkSync(PID_FILE);
      console.log(chalk.green(`  Stopped (PID ${pid})`));
    } catch {
      console.log(chalk.yellow('  Process not found, clearing PID file.'));
      fs.unlinkSync(PID_FILE);
    }
  });

program
  .command('status')
  .description('Show proxy status and stats')
  .action(() => {
    if (!fs.existsSync(PID_FILE)) {
      console.log(chalk.red('  ✗ Not running'));
      return;
    }
    const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
    try {
      process.kill(pid, 0);
      console.log(chalk.green(`  ✓ Running (PID ${pid})`));
      try {
        const db = require('./storage/db');
        db.init();
        const stats = db.getStats();
        console.log(`    Captures: ${stats.total}  |  Hosts: ${stats.hosts}`);
      } catch {}
    } catch {
      console.log(chalk.red('  ✗ Stale PID file — process not found'));
      fs.unlinkSync(PID_FILE);
    }
  });

program
  .command('clear')
  .description('Clear all captured traffic')
  .action(() => {
    const db = require('./storage/db');
    db.init();
    db.clearCaptures();
    console.log(chalk.green('  Captures cleared.'));
  });

program
  .command('export')
  .description('Export captures to stdout for Claude analysis')
  .option('--mode <mode>', 'Export mode: api-docs | auth | summary | full', 'api-docs')
  .option('--host <host>', 'Filter by host')
  .option('--limit <n>', 'Max captures', '100')
  .action((opts) => {
    const db = require('./storage/db');
    const { buildClaudeExport } = require('./analyze');
    db.init();
    const { rows } = db.queryCaptures({ host: opts.host, limit: parseInt(opts.limit, 10) });
    if (!rows.length) {
      console.error(chalk.yellow('  No captures found.'));
      process.exit(1);
    }
    const output = buildClaudeExport(rows, opts.mode);
    process.stdout.write(output + '\n');
  });

program
  .command('cert')
  .description('Show CA certificate path')
  .action(() => {
    const certManager = require('./proxy/cert_manager');
    certManager.init();
    const p = certManager.getCACertPath();
    console.log(p);
    console.log(chalk.dim('\nInstall this as a trusted root CA on the devices you want to intercept.'));
  });

const proxyCmd = program
  .command('proxy')
  .description('Control this machine\'s system proxy settings');

proxyCmd
  .command('on [port]')
  .description('Route this machine\'s traffic through claude-intercept (default port 7777)')
  .action((port) => {
    const sysProxy = require('./system_proxy');
    const p = parseInt(port, 10) || 7777;
    console.log(chalk.bold.blue(`\n  Enabling system proxy → 127.0.0.1:${p}\n`));
    const result = sysProxy.enable(p);

    if (result.error) {
      console.error(chalk.red(`  ✗ ${result.error}`));
      process.exit(1);
    }

    if (result.activated) {
      for (const svc of result.activated) {
        console.log(chalk.green(`  ✓ ${svc}`));
      }
    }
    if (result.errors?.length) {
      for (const e of result.errors) console.log(chalk.yellow(`  ! ${e}`));
    }
    if (result.envLines) {
      console.log(chalk.dim('\n  Add these to your shell for CLI tools:'));
      for (const l of result.envLines) console.log(chalk.cyan(`    ${l}`));
    }

    console.log(chalk.dim(`\n  All HTTP/HTTPS traffic from this machine will now be intercepted.`));
    console.log(chalk.dim(`  Run "proxy off" to restore normal network settings.\n`));
  });

proxyCmd
  .command('off')
  .description('Disable the system proxy (restore normal settings)')
  .action(() => {
    const sysProxy = require('./system_proxy');
    console.log(chalk.bold.blue('\n  Disabling system proxy…\n'));
    const result = sysProxy.disable();

    if (result.deactivated) {
      for (const svc of result.deactivated) {
        console.log(chalk.green(`  ✓ ${svc} — restored`));
      }
    }
    if (result.error) {
      console.error(chalk.red(`  ✗ ${result.error}`));
    } else {
      console.log(chalk.dim('\n  Normal network settings restored.\n'));
    }
  });

proxyCmd
  .command('status')
  .description('Show current system proxy state')
  .action(() => {
    const sysProxy = require('./system_proxy');
    const result = sysProxy.status();
    console.log(chalk.bold(`\n  System proxy (${result.platform}):\n`));

    if (!result.services?.length) {
      console.log(chalk.dim('  No network services found or unsupported platform.'));
      return;
    }

    for (const s of result.services) {
      const httpIcon  = s.httpEnabled  ? chalk.green('●') : chalk.dim('○');
      const httpsIcon = s.httpsEnabled ? chalk.green('●') : chalk.dim('○');
      const dest = s.httpEnabled ? chalk.cyan(`${s.server}:${s.port}`) : chalk.dim('off');
      const tag = s.pointsHere ? chalk.green(' ← claude-intercept') : '';
      console.log(`  ${s.service}`);
      console.log(`    HTTP  ${httpIcon}  HTTPS ${httpsIcon}  →  ${dest}${tag}`);
    }
    console.log('');
  });

program.parse(process.argv);

// If no command, show help
if (!process.argv.slice(2).length) {
  program.outputHelp();
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function getLocalIP() {
  try {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      for (const iface of ifaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) return iface.address;
      }
    }
  } catch {}
  return '0.0.0.0';
}
