'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { daemonChildArgs, parseExportOptions, parsePort } = require('../cli');

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
    { mode: 'summary', limit: 50 });
  for (const limit of ['-1', '0', 'NaN', '5001', '10junk']) {
    assert.throws(() => parseExportOptions({ mode: 'summary', limit }), /Export limit/);
  }
  assert.throws(() => parseExportOptions({ mode: 'summry', limit: '50' }), /Unknown export mode/);
});

test('ports require exact integers in the valid TCP range', () => {
  assert.equal(parsePort('7777', 'Proxy port'), 7777);
  for (const value of ['0', '-1', '65536', '7777junk', '1.5', 'NaN']) {
    assert.throws(() => parsePort(value, 'Proxy port'), /Proxy port must be/);
  }
});
