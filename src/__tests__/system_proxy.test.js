'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const {
  linuxEnvLines,
  parseGsettingsValue,
  linuxStatusFromValues,
  kdeProxyConfigOps,
  binExists,
} = require('../system_proxy');

test('linuxEnvLines returns the exact 5 export lines', () => {
  assert.deepStrictEqual(linuxEnvLines(7777), [
    'export http_proxy=http://127.0.0.1:7777',
    'export https_proxy=http://127.0.0.1:7777',
    'export HTTP_PROXY=http://127.0.0.1:7777',
    'export HTTPS_PROXY=http://127.0.0.1:7777',
    'export no_proxy=localhost,127.0.0.1',
  ]);
});

test('parseGsettingsValue strips quotes from scalars', () => {
  assert.strictEqual(parseGsettingsValue("'manual'"), 'manual');
  assert.strictEqual(parseGsettingsValue("'none'"), 'none');
  assert.strictEqual(parseGsettingsValue('"127.0.0.1"'), '127.0.0.1');
});

test('parseGsettingsValue parses integers', () => {
  assert.strictEqual(parseGsettingsValue('7777'), 7777);
  assert.strictEqual(parseGsettingsValue(' 0 '), 0);
});

test('parseGsettingsValue parses booleans', () => {
  assert.strictEqual(parseGsettingsValue('true'), true);
  assert.strictEqual(parseGsettingsValue('false'), false);
});

test('parseGsettingsValue parses array literals', () => {
  assert.deepStrictEqual(parseGsettingsValue("['localhost']"), ['localhost']);
  assert.deepStrictEqual(
    parseGsettingsValue("['localhost', '127.0.0.0/8', '::1']"),
    ['localhost', '127.0.0.0/8', '::1']
  );
});

test('parseGsettingsValue treats empty arrays as []', () => {
  assert.deepStrictEqual(parseGsettingsValue('@as []'), []);
  assert.deepStrictEqual(parseGsettingsValue('[]'), []);
});

test('linuxStatusFromValues — manual pointing here', () => {
  const s = linuxStatusFromValues({
    mode: 'manual',
    httpHost: '127.0.0.1',
    httpPort: 7777,
    httpsHost: '127.0.0.1',
  });
  assert.strictEqual(s.service, 'GNOME');
  assert.strictEqual(s.httpEnabled, true);
  assert.strictEqual(s.httpsEnabled, true);
  assert.strictEqual(s.server, '127.0.0.1');
  assert.strictEqual(s.port, 7777);
  assert.strictEqual(s.pointsHere, true);
});

test('linuxStatusFromValues — service defaults to GNOME, KDE propagates', () => {
  const def = linuxStatusFromValues({
    mode: 'manual',
    httpHost: '127.0.0.1',
    httpPort: 7777,
    httpsHost: '127.0.0.1',
  });
  assert.strictEqual(def.service, 'GNOME');

  const kde = linuxStatusFromValues({
    mode: 'manual',
    httpHost: '127.0.0.1',
    httpPort: 7777,
    httpsHost: '127.0.0.1',
    service: 'KDE',
  });
  assert.strictEqual(kde.service, 'KDE');
});

test('linuxStatusFromValues — manual but elsewhere', () => {
  const s = linuxStatusFromValues({
    mode: 'manual',
    httpHost: '10.0.0.2',
    httpPort: 8080,
    httpsHost: '10.0.0.2',
  });
  assert.strictEqual(s.httpEnabled, true);
  assert.strictEqual(s.pointsHere, false);
});

test('linuxStatusFromValues — mode none means off', () => {
  const s = linuxStatusFromValues({
    mode: 'none',
    httpHost: '127.0.0.1',
    httpPort: 7777,
  });
  assert.strictEqual(s.httpEnabled, false);
  assert.strictEqual(s.httpsEnabled, false);
  assert.strictEqual(s.pointsHere, false);
});

test('linuxStatusFromValues — string port is coerced', () => {
  const s = linuxStatusFromValues({
    mode: 'manual',
    httpHost: '127.0.0.1',
    httpPort: '7777',
    httpsHost: '127.0.0.1',
  });
  assert.strictEqual(s.port, 7777);
  assert.strictEqual(s.pointsHere, true);
});

test('kdeProxyConfigOps returns the expected arg vectors', () => {
  const ops = kdeProxyConfigOps(7777);
  assert.deepStrictEqual(ops.on, [
    ['--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'ProxyType', '1'],
    ['--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'httpProxy', 'http://127.0.0.1 7777'],
    ['--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'httpsProxy', 'http://127.0.0.1 7777'],
    ['--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'NoProxyFor', 'localhost,127.0.0.1'],
  ]);
  assert.deepStrictEqual(ops.off, [
    ['--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'ProxyType', '0'],
  ]);
  assert.deepStrictEqual(ops.readType,
    ['--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'ProxyType']);
  assert.deepStrictEqual(ops.readHttp,
    ['--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'httpProxy']);
});

test('binExists finds an on-PATH binary and rejects a junk name', () => {
  assert.strictEqual(binExists('sh'), true);
  assert.strictEqual(binExists('definitely-not-a-real-bin-xyz'), false);
});
