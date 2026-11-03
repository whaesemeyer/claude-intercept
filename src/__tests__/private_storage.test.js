'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '../..');

function fixture(t, source) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intercept-private-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const modulePath = path.join(root, 'src', source);
  fs.mkdirSync(path.dirname(modulePath), { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'src', source), modulePath);
  return { root, modulePath };
}

function runFixture(modulePath, script) {
  const result = spawnSync(process.execPath, ['-e', script, modulePath], {
    encoding: 'utf8',
    env: { ...process.env, NODE_PATH: path.join(ROOT, 'node_modules') },
    timeout: 30000,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim().split('\n').at(-1));
}

test('certificate keys are owner-only on creation and existing keys are repaired', { skip: process.platform === 'win32' }, t => {
  const { modulePath } = fixture(t, 'proxy/cert_manager.js');
  const result = runFixture(modulePath, `
    const fs = require('node:fs');
    const path = require('node:path');
    const forge = require('node-forge');
    const manager = require(process.argv[1]);
    const dir = path.join(path.dirname(process.argv[1]), '../../certs');
    const keyPaths = ['ca.key', 'leaf.key'].map(name => path.join(dir, name));
    const modes = () => [dir, ...keyPaths].map(file => fs.statSync(file).mode & 0o777);
    manager.init();
    const created = modes();
    fs.chmodSync(dir, 0o755);
    for (const file of keyPaths) fs.chmodSync(file, 0o644);
    manager.init();
    const sans = host => forge.pki.certificateFromPem(manager.getCertForHost(host).certPem)
      .getExtension('subjectAltName').altNames.map(({ type }) => type);
    const originalNow = Date.now;
    Date.now = () => 1234567890000;
    const certA = forge.pki.certificateFromPem(manager.getCertForHost('a.example').certPem);
    const certB = forge.pki.certificateFromPem(manager.getCertForHost('b.example').certPem);
    Date.now = originalNow;
    console.log(JSON.stringify({ created, repaired: modes(), ipv4Sans: sans('127.0.0.1'),
      ipv6Sans: sans('::1'), dnsSans: sans('example.com'),
      serials: [certA.serialNumber, certB.serialNumber],
      leafDays: (certA.validity.notAfter - certA.validity.notBefore) / 86400000 }));
  `);
  assert.deepEqual(result.created, [0o700, 0o600, 0o600]);
  assert.deepEqual(result.repaired, [0o700, 0o600, 0o600]);
  assert.deepEqual(result.ipv4Sans, [7]);
  assert.deepEqual(result.ipv6Sans, [7]);
  assert.deepEqual(result.dnsSans, [2]);
  assert.notEqual(result.serials[0], result.serials[1]);
  assert.ok(result.serials.every(serial => serial.length === 32 && parseInt(serial[0], 16) < 8));
  assert.ok(result.leafDays >= 90 && result.leafDays < 91);
});

test('incomplete or mismatched CA files fail instead of replacing trusted identity', t => {
  const { modulePath } = fixture(t, 'proxy/cert_manager.js');
  const result = runFixture(modulePath, `
    const fs = require('node:fs');
    const path = require('node:path');
    const manager = require(process.argv[1]);
    const dir = path.join(path.dirname(process.argv[1]), '../../certs');
    const caKey = path.join(dir, 'ca.key');
    manager.init();
    fs.copyFileSync(path.join(dir, 'leaf.key'), caKey);
    let mismatch = false;
    try { manager.init(); } catch (err) { mismatch = /Invalid CA certificate\\/key/.test(err.message); }
    fs.unlinkSync(caKey);
    let incomplete = false;
    try { manager.init(); } catch (err) { incomplete = /incomplete/.test(err.message); }
    console.log(JSON.stringify({ mismatch, incomplete }));
  `);
  assert.deepEqual(result, { mismatch: true, incomplete: true });
});

test('capture database and SQLite sidecars are owner-only, including existing files', { skip: process.platform === 'win32' }, t => {
  const { root, modulePath } = fixture(t, 'storage/db.js');
  const dir = path.join(root, 'captures');
  fs.mkdirSync(dir, { mode: 0o755 });
  fs.chmodSync(dir, 0o755);
  fs.writeFileSync(path.join(dir, 'captures.db'), '', { mode: 0o644 });
  fs.chmodSync(path.join(dir, 'captures.db'), 0o644);
  const result = runFixture(modulePath, `
    const fs = require('node:fs');
    const path = require('node:path');
    const db = require(process.argv[1]);
    const dir = path.join(path.dirname(process.argv[1]), '../../captures');
    const files = ['captures.db', 'captures.db-wal', 'captures.db-shm'].map(name => path.join(dir, name));
    const modes = () => [dir, ...files.filter(fs.existsSync)].map(file => fs.statSync(file).mode & 0o777);
    db.init();
    const created = modes();
    fs.chmodSync(dir, 0o755);
    for (const file of files.filter(fs.existsSync)) fs.chmodSync(file, 0o644);
    db.init();
    console.log(JSON.stringify({ created, repaired: modes() }));
  `);
  assert.equal(result.created.length, 4, 'SQLite created the database, WAL, and SHM files');
  assert.equal(result.created[0], 0o700);
  assert.ok(result.created.slice(1).every(value => value === 0o600));
  assert.equal(result.repaired.length, 4);
  assert.equal(result.repaired[0], 0o700);
  assert.ok(result.repaired.slice(1).every(value => value === 0o600));
});

test('capture queries bound invalid limits and empty deletes are harmless', t => {
  const { modulePath } = fixture(t, 'storage/db.js');
  const result = runFixture(modulePath, `
    const storage = require(process.argv[1]);
    const conn = storage.init();
    conn.exec('BEGIN');
    const insert = conn.prepare("INSERT INTO captures (timestamp, method, url, host, path) VALUES (?, 'GET', 'https://example.com/', 'example.com', '/')");
    for (let i = 0; i < 120; i++) insert.run(i);
    conn.exec('COMMIT');
    const rows = storage.queryCaptures({ limit: -1, offset: -1 }).rows;
    console.log(JSON.stringify({ length: rows.length, firstId: rows[0].id,
      emptyDelete: storage.deleteCaptures([]), count: storage.getStats().total }));
  `);
  assert.deepEqual(result, { length: 100, firstId: 120, emptyDelete: 0, count: 120 });
});
