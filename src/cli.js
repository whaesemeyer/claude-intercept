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

function readStatus() {
  if (!fs.existsSync(PID_FILE)) {
    return { running: false, pid: null, stats: null };
  }
  const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
  try {
    process.kill(pid, 0);
    let stats = null;
    try {
      const db = require('./storage/db');
      db.init();
      stats = db.getStats();
    } catch {}
    return { running: true, pid, stats };
  } catch {
    fs.unlinkSync(PID_FILE);
    return { running: false, pid: null, stats: null, stalePid: true };
  }
}

program
  .command('status')
  .description('Show proxy status and stats')
  .option('--json', 'Output status as JSON (for agents/scripts)')
  .action((opts) => {
    const s = readStatus();
    if (opts.json) {
      process.stdout.write(JSON.stringify(s, null, 2) + '\n');
      return;
    }
    if (s.running) {
      console.log(chalk.green(`  ✓ Running (PID ${s.pid})`));
      if (s.stats) {
        console.log(`    Captures: ${s.stats.total}  |  Hosts: ${s.stats.hosts}`);
      }
    } else if (s.stalePid) {
      console.log(chalk.red('  ✗ Stale PID file — process not found'));
    } else {
      console.log(chalk.red('  ✗ Not running'));
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
  .command('devices')
  .description('List device labels seen in captured traffic')
  .option('--json', 'Output as JSON (for agents/scripts)')
  .action((opts) => {
    const db = require('./storage/db');
    db.init();
    const devices = db.getDevices();
    if (opts.json) {
      process.stdout.write(JSON.stringify({ devices }, null, 2) + '\n');
      return;
    }
    if (!devices.length) {
      console.log(chalk.dim('  No devices recorded yet.'));
      return;
    }
    console.log(chalk.bold('\n  Devices:\n'));
    for (const d of devices) console.log(`  • ${d}`);
    console.log('');
  });

program
  .command('export')
  .description('Export captures to stdout for Claude analysis')
  .option('--mode <mode>', 'Export mode: api-docs | auth | summary | full', 'api-docs')
  .option('--host <host>', 'Filter by host')
  .option('--device <label>', 'Filter by device label (see "devices")')
  .option('--limit <n>', 'Max captures', '100')
  .option('--json', 'Emit structured JSON instead of Markdown (for agents/scripts)')
  .action((opts) => {
    const db = require('./storage/db');
    const { buildClaudeExport, buildJsonExport } = require('./analyze');
    db.init();
    const { rows } = db.queryCaptures({
      host: opts.host,
      device: opts.device,
      limit: parseInt(opts.limit, 10),
    });
    if (opts.json) {
      // Always emit valid JSON (even when empty) so callers can parse unconditionally.
      const doc = buildJsonExport(rows, { mode: opts.mode });
      process.stdout.write(JSON.stringify(doc, null, 2) + '\n');
      return;
    }
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

function printTrustSteps(result) {
  for (const s of result.steps || []) {
    const icon = s.ok ? chalk.green('✓') : chalk.yellow('✗');
    const detail = s.detail ? chalk.dim(` — ${s.detail}`) : '';
    console.log(`  ${icon} ${s.name}${detail}`);
  }
  if (result.ok) {
    console.log(chalk.green('\n  All steps completed.\n'));
  } else {
    console.log(chalk.yellow('\n  Some steps need attention — see the Linux setup tab for the manual equivalents.\n'));
  }
}

program
  .command('trust')
  .description('Install & trust the CA on Linux (system store + Chrome/Chromium + Firefox)')
  .action(() => {
    if (os.platform() !== 'linux') {
      console.log(chalk.yellow('  Automated trust is Linux-only. On macOS use the Setup tab; on Windows import the cert manually.'));
      return;
    }
    const certManager = require('./proxy/cert_manager');
    certManager.init();
    const { trustCertLinux } = require('./setup_wizard');
    console.log(chalk.bold.blue('\n  Trusting Claude Intercept CA…\n'));
    console.log(chalk.dim('  You may be prompted for your sudo password.\n'));
    const result = trustCertLinux({ prefer: 'sudo' });
    printTrustSteps(result);
  });

program
  .command('untrust')
  .description('Remove the Claude Intercept CA from Linux trust stores')
  .action(() => {
    if (os.platform() !== 'linux') {
      console.log(chalk.yellow('  Automated untrust is Linux-only.'));
      return;
    }
    const { untrustCertLinux } = require('./setup_wizard');
    console.log(chalk.bold.blue('\n  Removing Claude Intercept CA…\n'));
    console.log(chalk.dim('  You may be prompted for your sudo password.\n'));
    const result = untrustCertLinux({ prefer: 'sudo' });
    printTrustSteps(result);
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
    if (result.message) {
      console.log(chalk.yellow(`  ! ${result.message}`));
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
    if (result.errors?.length) {
      for (const e of result.errors) console.log(chalk.yellow(`  ! ${e}`));
    }
    if (result.message) {
      console.log(chalk.yellow(`  ! ${result.message}`));
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
  .option('--json', 'Output as JSON (for agents/scripts)')
  .action((opts) => {
    const sysProxy = require('./system_proxy');
    const result = sysProxy.status();
    if (opts.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      return;
    }
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
