'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { daemonChildArgs } = require('../cli');

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
