#!/usr/bin/env node
'use strict';

const { program } = require('commander');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('node:net');
const { randomBytes, timingSafeEqual } = require('node:crypto');

const PROJECT_ROOT = path.join(__dirname, '..');
const PID_FILE = path.join(PROJECT_ROOT, 'captures', 'intercept.pid');
const LOG_FILE = path.join(PROJECT_ROOT, 'captures', 'intercept.log');
const MAX_EXPORT_LIMIT = 5000;
const EXPORT_MODES = new Set(['api-docs', 'auth', 'summary', 'full']);
let activeInstance = null;

function livePid(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

function readPidRecord() {
  const directory = fs.lstatSync(path.dirname(PID_FILE), { throwIfNoEntry: false });
  if (directory && !directory.isDirectory()) return { invalid: true };
  const stat = fs.lstatSync(PID_FILE, { throwIfNoEntry: false });
  if (!stat) return null;
  if (!stat.isFile()) return { invalid: true };
  let raw;
  try { raw = fs.readFileSync(PID_FILE, 'utf8').trim(); } catch { return { invalid: true }; }
  if (/^[1-9]\d*$/.test(raw)) {
    const pid = Number(raw);
    return Number.isSafeInteger(pid) ? { pid, legacy: true } : { invalid: true };
  }
  try {
    const record = JSON.parse(raw);
    if (record.version === 1 && Number.isSafeInteger(record.pid) && record.pid > 0 &&
        /^[0-9a-f]{64}$/.test(record.token) && typeof record.controlPath === 'string' &&
        record.controlPath.length < 200 && Number.isSafeInteger(record.proxyPort) &&
        record.proxyPort >= 1 && record.proxyPort <= 65535) return record;
  } catch {}
  return { invalid: true };
}

function removePidRecordIfSame(record) {
  try {
    const current = readPidRecord();
    if (current && !current.invalid && current.pid === record.pid &&
        current.token === record.token && current.controlPath === record.controlPath) {
      fs.unlinkSync(PID_FILE);
    }
  } catch {}
}

function controlRequest(record, command, timeoutMs = 700) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(record.controlPath);
    let response = '';
    let settled = false;
    const done = (err, value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (err) reject(err); else resolve(value);
    };
    socket.setTimeout(timeoutMs, () => done(new Error('Control channel timed out')));
    socket.on('connect', () => socket.write(JSON.stringify({ token: record.token, command }) + '\n'));
    socket.on('data', chunk => {
      response += chunk.toString('utf8');
      if (response.length > 4096) return done(new Error('Control response too large'));
      const end = response.indexOf('\n');
      if (end === -1) return;
      try { done(null, JSON.parse(response.slice(0, end))); }
      catch { done(new Error('Invalid control response')); }
    });
    socket.on('error', err => done(err));
    socket.on('end', () => done(new Error('Control channel closed without a response')));
  });
}

async function inspectInstance() {
  const record = readPidRecord();
  if (!record) return { running: false };
  if (record.invalid) return { running: false, unverified: true };
  if (record.legacy) {
    if (livePid(record.pid)) return { running: false, unverified: true, pid: record.pid };
    removePidRecordIfSame(record);
    return { running: false, stalePid: true };
  }
  try {
    const response = await controlRequest(record, 'status');
    if (response.ok === true && response.pid === record.pid &&
        response.proxyPort === record.proxyPort) {
      return { running: true, pid: record.pid, record };
    }
  } catch {}
  if (livePid(record.pid)) return { running: false, unverified: true, pid: record.pid };
  removePidRecordIfSame(record);
  return { running: false, stalePid: true };
}

function validToken(given, expected) {
  if (typeof given !== 'string' || !/^[0-9a-f]{64}$/.test(given)) return false;
  return timingSafeEqual(Buffer.from(given, 'hex'), Buffer.from(expected, 'hex'));
}

async function startControlChannel(proxy, ui, token, proxyPort) {
  const nonce = randomBytes(12).toString('hex');
  const controlPath = process.platform === 'win32'
    ? `\\\\.\\pipe\\claude-intercept-${nonce}`
    : `/tmp/claude-intercept-${nonce}.sock`;
  const record = { version: 1, pid: process.pid, token, controlPath, proxyPort };
  const server = net.createServer(socket => {
    let request = '';
    socket.setTimeout(1000, () => socket.destroy());
    socket.on('data', chunk => {
      request += chunk.toString('utf8');
      if (request.length > 4096) return socket.destroy();
      const end = request.indexOf('\n');
      if (end === -1) return;
      socket.removeAllListeners('data');
      let message;
      try { message = JSON.parse(request.slice(0, end)); } catch { return socket.destroy(); }
      if (!validToken(message.token, token)) return socket.end('{"ok":false}\n');
      if (message.command === 'status') {
        return socket.end(JSON.stringify({ ok: true, pid: process.pid, proxyPort }) + '\n');
      }
      if (message.command === 'stop') {
        return socket.end(JSON.stringify({ ok: true, pid: process.pid }) + '\n', () => {
          setImmediate(() => shutdown());
        });
      }
      socket.end('{"ok":false}\n');
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(controlPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
  try {
    if (process.platform !== 'win32') fs.chmodSync(controlPath, 0o600);
    fs.writeFileSync(PID_FILE, JSON.stringify(record), { mode: 0o600, flag: 'wx' });
    activeInstance = { record, server, proxy, ui };
  } catch (err) {
    server.close();
    if (process.platform !== 'win32') try { fs.unlinkSync(controlPath); } catch {}
    throw err;
  }
}

function parsePort(value, label = 'Port') {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new RangeError(`${label} must be an integer from 1 to 65535`);
  }
  return port;
}

function parseExportOptions({ mode, limit }) {
  const count = Number(limit);
  if (!EXPORT_MODES.has(mode)) {
    throw new RangeError(`Unknown export mode: ${mode}`);
  }
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_EXPORT_LIMIT) {
    throw new RangeError(`Export limit must be an integer from 1 to ${MAX_EXPORT_LIMIT}`);
  }
  return { mode, limit: count };
}

// ── Shared startup ────────────────────────────────────────────────────────────
async function startIntercept({ proxyPort, uiPort, open: autoOpen, lan = false }) {
  const existing = await inspectInstance();
  if (existing.running) {
    console.log(chalk.yellow(`[intercept] Already running (PID ${existing.pid})`));
    console.log(chalk.dim('  Existing instance settings are unchanged. Stop it before changing LAN access.'));
    return;
  }
  if (existing.unverified) throw new Error('An unverified PID file exists; inspect it before starting another instance');

  console.log(chalk.bold.blue('\n  Claude Intercept\n'));

  // Init cert manager (generates CA if needed)
  const certManager = require('./proxy/cert_manager');
  certManager.init();

  // Init database
  const db = require('./storage/db');
  db.init();

  // Init proxy first so we can pass the instance to the UI server
  const ProxyServer = require('./proxy/index');
  const listenHost = lan ? '0.0.0.0' : '127.0.0.1';
  const proxy = new ProxyServer({ port: proxyPort, uiPort, listenHost, db, broadcast: () => {} }); // broadcast patched below
  const instanceToken = randomBytes(32).toString('hex');

  // Init UI + WebSocket
  const { createUIServer } = require('./ui/server');
  const ui = createUIServer({ uiPort, proxyPort, proxyInstance: proxy,
    uiHost: listenHost, proxyOwnerId: instanceToken });
  const { broadcast, listen: listenUI } = ui;

  // Patch broadcast into proxy now that we have it
  proxy.broadcast = broadcast;

  try {
    await listenUI();
    await proxy.listen();
    await startControlChannel(proxy, ui, instanceToken, proxyPort);
  } catch (err) {
    try { proxy.close(); } catch {}
    try { await ui.close(); } catch {}
    throw err;
  }

  console.log(chalk.green('  ✓ Proxy running'));
  console.log(`    ${chalk.bold('HTTP/HTTPS proxy:')} ${chalk.cyan(`127.0.0.1:${proxyPort}`)}`);
  if (lan) console.log(`    ${chalk.bold('LAN proxy:')}        ${chalk.cyan(`${getLocalIP()}:${proxyPort}`)}`);
  console.log('');
  console.log(chalk.green('  ✓ Dashboard running'));
  console.log(`    ${chalk.cyan(`http://127.0.0.1:${uiPort}`)}`);
  if (lan) console.log(`    ${chalk.bold('LAN certificate:')} ${chalk.cyan(`http://${getLocalIP()}:${uiPort}/api/cert`)}`);
  console.log('');
  console.log(chalk.dim('  CA Certificate: ' + certManager.getCACertPath()));
  console.log(chalk.dim('  Ctrl+C to stop\n'));

  if (autoOpen) {
    const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    require('child_process').spawn(opener, [`http://127.0.0.1:${uiPort}`], { detached: true, stdio: 'ignore' });
  }

  // Graceful shutdown
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function shutdown() {
  const instance = activeInstance;
  if (!instance) return;
  activeInstance = null;
  console.log(chalk.dim('\n  Shutting down…'));
  try { instance.proxy.close(); } catch {}
  try { instance.ui.httpServer.close(); } catch {}
  try { instance.server.close(); } catch {}
  // Only remove proxy settings this exact instance enabled and still owns.
  try {
    const sysProxy = require('./system_proxy');
    const result = sysProxy.disable({ ownerId: instance.record.token });
    if (result.deactivated?.length) {
      console.log(chalk.dim('  Intercept-owned system proxy disabled.'));
    }
  } catch {}
  removePidRecordIfSame(instance.record);
  if (process.platform !== 'win32') {
    try { fs.unlinkSync(instance.record.controlPath); } catch {}
  }
  process.exit(0);
}

// ── Daemon mode ───────────────────────────────────────────────────────────────

// Pure: argv for the detached child. Deliberately omits --daemon so the child
// runs the normal foreground path (and writes its own PID) — no fork loop.
function daemonChildArgs(cliPath, { proxyPort, uiPort, open, lan = false }) {
  const args = [cliPath, 'start', '--proxy-port', String(proxyPort), '--ui-port', String(uiPort)];
  if (lan) args.push('--lan');
  if (!open) args.push('--no-open');
  return args;
}

// Spawn a detached background instance, then wait for it to write the PID file
// so we can confirm a clean start before the parent exits.
async function startDaemon({ proxyPort, uiPort, open, lan = false }) {
  const existing = await inspectInstance();
  if (existing.running) {
    console.log(chalk.yellow(`[intercept] Already running (PID ${existing.pid})`));
    console.log(chalk.dim('  Existing instance settings are unchanged. Stop it before changing LAN access.'));
    return;
  }
  if (existing.unverified) throw new Error('An unverified PID file exists; inspect it before starting another instance');

  const captureDir = path.dirname(LOG_FILE);
  fs.mkdirSync(captureDir, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(captureDir).isDirectory()) {
    throw new Error(`Capture path is not a directory: ${captureDir}`);
  }
  fs.chmodSync(captureDir, 0o700);
  if (fs.existsSync(LOG_FILE) && !fs.lstatSync(LOG_FILE).isFile()) {
    throw new Error(`Log path is not a regular file: ${LOG_FILE}`);
  }
  const logFd = fs.openSync(LOG_FILE, 'a', 0o600);
  fs.chmodSync(LOG_FILE, 0o600);
  const { spawn } = require('child_process');
  const child = spawn(
    process.execPath,
    daemonChildArgs(__filename, { proxyPort, uiPort, open, lan }),
    { detached: true, stdio: ['ignore', logFd, logFd] }
  );
  let spawnError = null;
  child.once('error', err => { spawnError = err; });
  child.unref();
  fs.closeSync(logFd);

  const deadline = Date.now() + 8000;
  while (Date.now() <= deadline) {
    if (spawnError) throw spawnError;
    const state = await inspectInstance();
    if (state.running && state.pid === child.pid) {
      console.log(chalk.green(`  ✓ Claude Intercept started (PID ${state.pid})`));
      console.log(`    ${chalk.bold('Proxy:')}     ${chalk.cyan(`http://127.0.0.1:${proxyPort}`)}`);
      console.log(`    ${chalk.bold('Dashboard:')} ${chalk.cyan(`http://127.0.0.1:${uiPort}`)}`);
      if (lan) console.log(`    ${chalk.bold('LAN proxy:')} ${chalk.cyan(`${getLocalIP()}:${proxyPort}`)}`);
      if (lan) console.log(`    ${chalk.bold('LAN certificate:')} ${chalk.cyan(`http://${getLocalIP()}:${uiPort}/api/cert`)}`);
      console.log(chalk.dim(`    Logs:  ${LOG_FILE}`));
      console.log(chalk.dim(`    Stop:  claude-intercept stop\n`));
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new Error(`Daemon did not come up within 8s. Check the log: ${LOG_FILE}`);
}

// Safety net: restore proxy on uncaught errors so network isn't left broken
process.on('uncaughtException', (err) => {
  console.error(chalk.red('\n  Fatal error: ' + err.message));
  if (activeInstance) {
    try {
      const sysProxy = require('./system_proxy');
      sysProxy.disable({ ownerId: activeInstance.record.token });
    } catch {}
    removePidRecordIfSame(activeInstance.record);
    if (process.platform !== 'win32') {
      try { fs.unlinkSync(activeInstance.record.controlPath); } catch {}
    }
  }
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
  .option('--lan', 'Allow LAN devices to use the proxy and download its CA certificate')
  .option('--no-open', 'Do not open the dashboard automatically')
  .option('-d, --daemon', 'Run detached in the background; logs to captures/intercept.log')
  .action(async (opts) => {
    try {
      const cfg = {
        proxyPort: parsePort(opts.proxyPort, 'Proxy port'),
        uiPort: parsePort(opts.uiPort, 'Dashboard port'),
        open: opts.open !== false,
        lan: !!opts.lan,
      };
      if (cfg.proxyPort === cfg.uiPort) {
        throw new RangeError('Proxy and dashboard ports must differ');
      }
      if (opts.daemon) {
        await startDaemon(cfg);
      } else {
        await startIntercept(cfg);
      }
    } catch (err) {
      console.error(chalk.red('  Error: ' + err.message));
      process.exit(1);
    }
  });

program
  .command('stop')
  .description('Stop a running proxy')
  .action(async () => {
    const state = await inspectInstance();
    if (!state.running) {
      if (state.unverified) {
        console.error(chalk.red('  PID file does not identify a running Intercept instance; refusing to signal that PID.'));
        process.exitCode = 1;
        return;
      }
      console.log(chalk.yellow('  No running instance found.'));
      return;
    }
    try {
      const response = await controlRequest(state.record, 'stop');
      if (response.ok !== true || response.pid !== state.pid) throw new Error('Instance did not confirm shutdown');
      console.log(chalk.green(`  Stopping Intercept (PID ${state.pid})`));
    } catch (err) {
      console.error(chalk.red(`  Could not stop Intercept: ${err.message}`));
      process.exitCode = 1;
    }
  });

async function readStatus() {
  const state = await inspectInstance();
  if (!state.running) {
    return { running: false, pid: state.pid || null, stats: null,
      ...(state.stalePid ? { stalePid: true } : {}),
      ...(state.unverified ? { unverifiedPid: true } : {}) };
  }
  let stats = null;
  try {
    const db = require('./storage/db');
    db.init();
    stats = db.getStats();
  } catch {}
  return { running: true, pid: state.pid, stats };
}

program
  .command('status')
  .description('Show proxy status and stats')
  .option('--json', 'Output status as JSON (for agents/scripts)')
  .action(async (opts) => {
    const s = await readStatus();
    if (opts.json) {
      process.stdout.write(JSON.stringify(s, null, 2) + '\n');
      return;
    }
    if (s.running) {
      console.log(chalk.green(`  ✓ Running (PID ${s.pid})`));
      if (s.stats) {
        console.log(`    Captures: ${s.stats.total}  |  Hosts: ${s.stats.hosts}`);
      }
    } else if (s.unverifiedPid) {
      console.log(chalk.red('  ✗ PID file does not identify a running Intercept instance'));
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
  .option('--mode <mode>', 'Export mode: api-docs | auth | summary | full', 'summary')
  .option('--host <host>', 'Filter by host')
  .option('--device <label>', 'Filter by device label (see "devices")')
  .option('--limit <n>', 'Max captures', '100')
  .option('--json', 'Emit structured JSON instead of Markdown (for agents/scripts)')
  .action((opts) => {
    let exportOptions;
    try {
      exportOptions = parseExportOptions(opts);
    } catch (err) {
      console.error(chalk.red(`  ${err.message}`));
      process.exitCode = 1;
      return;
    }
    const db = require('./storage/db');
    const { buildClaudeExport, buildJsonExport } = require('./analyze');
    db.init();
    const { rows } = db.queryCaptures({
      host: opts.host,
      device: opts.device,
      limit: exportOptions.limit,
    });
    if (opts.json) {
      // Always emit valid JSON (even when empty) so callers can parse unconditionally.
      const doc = buildJsonExport(rows, { mode: exportOptions.mode });
      process.stdout.write(JSON.stringify(doc, null, 2) + '\n');
      return;
    }
    if (!rows.length) {
      console.error(chalk.yellow('  No captures found.'));
      process.exit(1);
    }
    const output = buildClaudeExport(rows, exportOptions.mode);
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
  .action(async (port) => {
    let p;
    try {
      p = parsePort(port === undefined ? 7777 : port, 'Proxy port');
    } catch (err) {
      console.error(chalk.red(`  ${err.message}`));
      process.exitCode = 1;
      return;
    }
    const instance = await inspectInstance();
    if (!instance.running) {
      console.error(chalk.red('  Start a verified Intercept instance before enabling the system proxy.'));
      process.exitCode = 1;
      return;
    }
    if (instance.record.proxyPort !== p) {
      console.error(chalk.red(`  Running Intercept instance uses port ${instance.record.proxyPort}; refusing port ${p}.`));
      process.exitCode = 1;
      return;
    }
    const sysProxy = require('./system_proxy');
    console.log(chalk.bold.blue(`\n  Enabling system proxy → 127.0.0.1:${p}\n`));
    const result = sysProxy.enable(p, { ownerId: instance.record.token });

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

    if (!result.degraded) {
      console.log(chalk.dim(`\n  All HTTP/HTTPS traffic from this machine will now be intercepted.`));
      console.log(chalk.dim(`  Run "proxy off" to disable Intercept-owned settings.\n`));
    }
  });

proxyCmd
  .command('off')
  .description('Disable only system proxy settings owned by this Intercept installation')
  .action(() => {
    const sysProxy = require('./system_proxy');
    console.log(chalk.bold.blue('\n  Disabling system proxy…\n'));
    const result = sysProxy.disable();

    if (result.deactivated) {
      for (const svc of result.deactivated) {
        console.log(chalk.green(`  ✓ ${svc} — disabled`));
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
      console.log(chalk.dim(`\n  ${result.message || 'Intercept-owned system proxy settings disabled.'}\n`));
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

// Only drive the CLI when executed directly; `require()` (tests) just gets the
// exported helpers without parsing argv or printing help.
if (require.main === module) {
  program.parseAsync(process.argv).catch(err => {
    console.error(chalk.red('  Error: ' + err.message));
    process.exitCode = 1;
  });

  // If no command, show help
  if (!process.argv.slice(2).length) {
    program.outputHelp();
  }
}

module.exports = { daemonChildArgs, parseExportOptions, parsePort };

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
