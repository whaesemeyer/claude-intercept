'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '../..');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intercept-instance-'));
  const src = path.join(root, 'src');
  fs.mkdirSync(path.join(src, 'proxy'), { recursive: true });
  fs.mkdirSync(path.join(src, 'storage'));
  fs.mkdirSync(path.join(src, 'ui'));
  fs.mkdirSync(path.join(root, 'captures'), { mode: 0o700 });
  fs.copyFileSync(path.join(ROOT, 'src/cli.js'), path.join(src, 'cli.js'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '1.0.0' }));
  fs.writeFileSync(path.join(src, 'proxy/cert_manager.js'),
    "module.exports = { init() {}, getCACertPath() { return 'fixture-ca.crt'; } };\n");
  fs.writeFileSync(path.join(src, 'proxy/index.js'), `
    module.exports = class ProxyServer {
      async listen() {}
      close() {
        const ms = Number(process.env.TEST_SHUTDOWN_DELAY_MS || 0);
        if (ms) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
      }
    };
  `);
  fs.writeFileSync(path.join(src, 'storage/db.js'),
    'module.exports = { init() {}, getStats() { return { total: 0, hosts: 0 }; } };\n');
  fs.writeFileSync(path.join(src, 'ui/server.js'),
    'module.exports = { createUIServer() { return { broadcast() {}, async listen() {}, async close() {}, httpServer: { close() {} } }; } };\n');
  fs.writeFileSync(path.join(src, 'system_proxy.js'),
    'module.exports = { disable() { return {}; } };\n');
  const env = { ...process.env, NODE_PATH: path.join(ROOT, 'node_modules') };
  const cli = path.join(src, 'cli.js');
  const pidFile = path.join(root, 'captures/intercept.pid');
  let ownedPid = null;
  t.after(() => {
    if (ownedPid) try { process.kill(ownedPid, 'SIGTERM'); } catch {}
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, cli, env, pidFile, own: pid => { ownedPid = pid; } };
}

function run(cli, env, command) {
  return spawnSync(process.execPath, [cli, ...command], {
    env, encoding: 'utf8', timeout: 15000,
  });
}

async function waitFor(check, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for instance state');
}

function requestControl(record, command) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(record.controlPath);
    let response = '';
    socket.on('connect', () => socket.write(JSON.stringify({ token: record.token, command }) + '\n'));
    socket.on('data', chunk => {
      response += chunk.toString();
      if (response.includes('\n')) resolve(JSON.parse(response.trim()));
    });
    socket.on('error', reject);
    socket.on('end', () => {
      if (!response) reject(new Error('No control response'));
    });
  });
}

test('daemon status and stop require the private control channel', async t => {
  const { cli, env, pidFile, own } = fixture(t);
  const started = run(cli, env, ['start', '--daemon', '--no-open']);
  assert.equal(started.status, 0, started.stderr);
  const record = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
  own(record.pid);
  assert.equal(record.version, 1);
  assert.equal(record.token.length, 64);
  assert.equal(fs.statSync(pidFile).mode & 0o777, 0o600);

  const status = run(cli, env, ['status', '--json']);
  assert.equal(status.status, 0, status.stderr);
  assert.deepEqual(JSON.parse(status.stdout), { running: true, pid: record.pid,
    stats: { total: 0, hosts: 0 } });

  const stopped = run(cli, env, ['stop']);
  assert.equal(stopped.status, 0, stopped.stderr);
  await waitFor(() => !fs.existsSync(pidFile));
});

test('stop waits for shutdown before an immediate restart with LAN access', t => {
  const { cli, env, pidFile, own } = fixture(t);
  const started = run(cli, { ...env, TEST_SHUTDOWN_DELAY_MS: '1200' },
    ['start', '--daemon', '--no-open']);
  assert.equal(started.status, 0, started.stderr);
  const first = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
  own(first.pid);

  const stopped = run(cli, env, ['stop']);
  assert.equal(stopped.status, 0, stopped.stderr);
  assert.equal(fs.existsSync(pidFile), false);

  const restarted = run(cli, env, ['start', '--daemon', '--no-open', '--lan']);
  assert.equal(restarted.status, 0, restarted.stderr);
  assert.match(restarted.stdout, /Claude Intercept started/);
  const second = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
  assert.notEqual(second.pid, first.pid);
  own(second.pid);
  assert.equal(run(cli, env, ['stop']).status, 0);
});

test('legacy numeric PID cannot make stop signal an unrelated process', t => {
  const { cli, env, pidFile } = fixture(t);
  const unrelated = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'],
    { stdio: 'ignore' });
  t.after(() => { try { process.kill(unrelated.pid, 'SIGTERM'); } catch {} });
  fs.writeFileSync(pidFile, String(unrelated.pid));

  const stopped = run(cli, env, ['stop']);
  assert.notEqual(stopped.status, 0);
  assert.match(stopped.stderr, /refusing to signal/);
  assert.equal(fs.readFileSync(pidFile, 'utf8'), String(unrelated.pid));
  assert.doesNotThrow(() => process.kill(unrelated.pid, 0));
});

test('shutdown leaves a PID file replaced by another instance untouched', async t => {
  const { cli, env, pidFile, own } = fixture(t);
  const started = run(cli, env, ['start', '--daemon', '--no-open']);
  assert.equal(started.status, 0, started.stderr);
  const record = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
  own(record.pid);
  const replacement = { ...record, pid: record.pid + 1, token: 'a'.repeat(64) };
  fs.writeFileSync(pidFile, JSON.stringify(replacement));

  const response = await requestControl(record, 'stop');
  assert.deepEqual(response, { ok: true, pid: record.pid });
  await waitFor(() => !fs.existsSync(record.controlPath));
  assert.deepEqual(JSON.parse(fs.readFileSync(pidFile, 'utf8')), replacement);
});

test('CA trust commands fail when unsupported or incomplete', t => {
  const { root, cli, env } = fixture(t);
  fs.writeFileSync(path.join(root, 'src/setup_wizard.js'), `
    const result = () => {
      const ok = process.env.TEST_TRUST_OK === '1';
      return { ok, steps: [{ name: 'System trust store', ok }] };
    };
    module.exports = { trustCertLinux: result, untrustCertLinux: result };
  `);
  const runPlatform = (platform, command, ok = false) => {
    const preload = path.join(root, `platform-${platform}.js`);
    fs.writeFileSync(preload, `require('node:os').platform = () => '${platform}';\n`);
    return spawnSync(process.execPath, ['--require', preload, cli, command], {
      env: { ...env, TEST_TRUST_OK: ok ? '1' : '0' },
      encoding: 'utf8', timeout: 15000,
    });
  };

  for (const platform of ['darwin', 'win32']) {
    for (const command of ['trust', 'untrust']) {
      const result = runPlatform(platform, command);
      assert.equal(result.status, 1, `${platform} ${command}: ${result.stderr}`);
      assert.match(result.stderr, /Linux-only/);
    }
  }
  for (const command of ['trust', 'untrust']) {
    const failed = runPlatform('linux', command);
    assert.equal(failed.status, 1, failed.stderr);
    assert.match(failed.stdout, /Some steps need attention/);
    const succeeded = runPlatform('linux', command, true);
    assert.equal(succeeded.status, 0, succeeded.stderr);
    assert.match(succeeded.stdout, /All steps completed/);
  }
});

test('export forwards the baseline capture ID to storage', t => {
  const { root, cli, env } = fixture(t);
  const recordPath = path.join(root, 'query-options.json');
  fs.writeFileSync(path.join(root, 'src/storage/db.js'), `
    const fs = require('node:fs');
    module.exports = {
      init() {},
      queryCaptures(options) {
        fs.writeFileSync(${JSON.stringify(recordPath)}, JSON.stringify(options));
        return { rows: [{ id: 43, host: 'api.example.com', method: 'GET' }] };
      }
    };
  `);
  fs.writeFileSync(path.join(root, 'src/analyze.js'),
    "module.exports = { buildClaudeExport() { return 'fresh capture'; } };\n");
  const result = run(cli, env, [
    'export', '--mode', 'summary', '--host', 'api.example.com', '--after-id', '42',
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /fresh capture/);
  assert.deepEqual(JSON.parse(fs.readFileSync(recordPath, 'utf8')), {
    host: 'api.example.com', limit: 100, offset: 0, afterId: 42,
    summaryOnly: true,
  });
});

test('proxy off reports ownership refusal as a command failure', t => {
  const { root, cli, env } = fixture(t);
  fs.writeFileSync(path.join(root, 'src/system_proxy.js'),
    "module.exports = { disable() { return { error: 'unverified owner' }; } };\n");
  const result = run(cli, env, ['proxy', 'off']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unverified owner/);
});
