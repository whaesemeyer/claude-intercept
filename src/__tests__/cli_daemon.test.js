'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { daemonChildArgs, parseExportOptions, parsePort,
  dashboardOpenCommand, openDashboard } = require('../cli');

const CLI = '/abs/path/to/cli.js';

test('builds start argv with stringified ports, no --no-open when open', () => {
  assert.deepStrictEqual(
    daemonChildArgs(CLI, { proxyPort: 7777, uiPort: 7778, open: true }),
    [CLI, 'start', '--proxy-port', '7777', '--ui-port', '7778']
  );
});

test('appends --no-open when open is false', () => {
  assert.deepStrictEqual(
    daemonChildArgs(CLI, { proxyPort: 9090, uiPort: 9091, open: false }),
    [CLI, 'start', '--proxy-port', '9090', '--ui-port', '9091', '--no-open']
  );
});

test('passes explicit LAN access to the detached child', () => {
  const local = daemonChildArgs(CLI, { proxyPort: 7777, uiPort: 7778, open: false });
  const lan = daemonChildArgs(CLI, { proxyPort: 7777, uiPort: 7778, open: false, lan: true });
  assert.ok(!local.includes('--lan'));
  assert.ok(lan.includes('--lan'));
});

test('never passes --daemon to the child (no fork loop)', () => {
  for (const open of [true, false]) {
    const args = daemonChildArgs(CLI, { proxyPort: 1, uiPort: 2, open });
    assert.ok(!args.includes('--daemon'), `--daemon leaked with open=${open}`);
    assert.ok(!args.includes('-d'), `-d leaked with open=${open}`);
  }
});

test('requiring the CLI module does not parse argv or exit', () => {
  // If `require.main === module` were not guarded, requiring ../cli above
  // would have run program.parse() and likely thrown/exited before here.
  assert.strictEqual(typeof daemonChildArgs, 'function');
});

test('export rejects invalid modes and unbounded limits before opening captures', () => {
  assert.deepStrictEqual(parseExportOptions({ mode: 'summary', limit: '50' }),
    { mode: 'summary', limit: 50, offset: 0 });
  for (const limit of ['-1', '0', 'NaN', '5001', '10junk']) {
    assert.throws(() => parseExportOptions({ mode: 'summary', limit }), /Export limit/);
  }
  assert.throws(() => parseExportOptions({ mode: 'summry', limit: '50' }), /Unknown export mode/);
  assert.deepStrictEqual(parseExportOptions({ mode: 'full', json: true, offset: '250' }),
    { mode: 'full', limit: 25, offset: 250 });
  assert.deepStrictEqual(parseExportOptions({ mode: 'api-docs' }),
    { mode: 'api-docs', limit: 100, offset: 0 });
  assert.throws(() => parseExportOptions({ mode: 'full', json: true, limit: '26' }), /Export limit/);
  assert.throws(() => parseExportOptions({ mode: 'api-docs', limit: '101' }), /Export limit/);
  assert.throws(() => parseExportOptions({ mode: 'auth', limit: '51' }), /Export limit/);
  for (const offset of ['-1', '1.5', 'NaN', '3junk']) {
    assert.throws(() => parseExportOptions({ mode: 'summary', offset }), /Export offset/);
  }
  assert.deepStrictEqual(parseExportOptions({ mode: 'summary', afterId: '42' }),
    { mode: 'summary', limit: 100, offset: 0, afterId: 42 });
  for (const afterId of ['-1', '1.5', 'NaN', '3junk', '01', '9007199254740992']) {
    assert.throws(() => parseExportOptions({ mode: 'summary', afterId }), /Export after-id/);
  }
});

test('ports require exact integers in the valid TCP range', () => {
  assert.equal(parsePort('7777', 'Proxy port'), 7777);
  for (const value of ['0', '-1', '65536', '7777junk', '1.5', 'NaN']) {
    assert.throws(() => parsePort(value, 'Proxy port'), /Proxy port must be/);
  }
});

test('dashboard opener uses an executable on Windows and handles missing desktop opener', t => {
  const url = 'http://127.0.0.1:7778';
  assert.deepStrictEqual(dashboardOpenCommand('win32', url), {
    command: 'cmd.exe', args: ['/d', '/s', '/c', `start "" "${url}"`],
  });
  const warnings = [];
  t.mock.method(console, 'warn', message => warnings.push(message));
  const child = new EventEmitter();
  child.unref = () => {};
  openDashboard(url, () => child);
  assert.doesNotThrow(() => child.emit('error', new Error('opener missing')));
  assert.match(warnings[0], /Could not open dashboard: opener missing/);
});
