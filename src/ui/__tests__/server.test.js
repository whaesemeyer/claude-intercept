'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const WebSocket = require('ws');
const db = require('../../storage/db');
const certManager = require('../../proxy/cert_manager');
const { createUIServer, canAccessDashboard } = require('../server');

function request(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path, headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    }).on('error', reject);
  });
}

function sendRequest(port, method, path, headers = {}, body = '') {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path, method, headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('dashboard listens on loopback and rejects cross-origin and rebinding requests', async t => {
  t.mock.method(db, 'getStats', () => ({ total: 0, hosts: 0 }));
  const ui = createUIServer({ uiPort: 0 });
  t.after(() => ui.close());
  const port = await ui.listen();

  assert.equal(ui.httpServer.address().address, '127.0.0.1');
  const status = await request(port, '/api/status');
  assert.equal(status.status, 200);
  assert.equal(status.headers['cache-control'], 'no-store');
  assert.equal(status.headers['x-content-type-options'], 'nosniff');
  assert.match(status.headers['content-security-policy'], /frame-ancestors 'none'/);
  const page = await request(port, '/');
  const script = page.body.match(/<script>([\s\S]*?)<\/script>/i);
  assert.ok(script);
  const hash = crypto.createHash('sha256').update(script[1]).digest('base64');
  assert.ok(page.headers['content-security-policy'].includes(`script-src 'sha256-${hash}'`));
  assert.doesNotMatch(page.headers['content-security-policy'], /script-src[^;]*unsafe-inline/);
  assert.doesNotMatch(page.body, /\son(?:click|input|change|error|load)\s*=/i);
  const data = JSON.parse(status.body);
  assert.deepEqual(data.ui, { port, host: '127.0.0.1', lanEnabled: false });
  assert.equal(data.certUrl, `http://127.0.0.1:${port}/api/cert`);
  assert.equal(data.tailscaleCertUrl, null);

  assert.equal((await request(port, '/api/capture/state', {
    Origin: 'http://evil.example',
  })).status, 403);
  assert.equal((await request(port, '/api/capture/state', {
    'Sec-Fetch-Site': 'cross-site',
  })).status, 403);
  assert.equal((await request(port, '/api/capture/state', {
    Host: `evil.example:${port}`,
  })).status, 403);
  assert.equal((await request(port, '/api/capture/state', {
    Origin: `http://127.0.0.1:${port}`,
  })).status, 200);
});

test('capture listing clamps negative and oversized limits', async t => {
  let query;
  t.mock.method(db, 'queryCaptures', options => {
    query = options;
    return { total: 0, rows: [] };
  });
  const ui = createUIServer({ uiPort: 0 });
  t.after(() => ui.close());
  const port = await ui.listen();
  assert.equal((await request(port, '/api/captures?limit=-1&offset=-20')).status, 200);
  assert.equal(query.limit, 1);
  assert.equal(query.offset, 0);
  assert.equal((await request(port, '/api/captures?limit=999999')).status, 200);
  assert.equal(query.limit, 500);
  assert.equal(query.listOnly, true);
});

test('state-changing routes require the dashboard action header even without Origin', async t => {
  const paused = [];
  const ui = createUIServer({ uiPort: 0, proxyInstance: {
    setPaused(value) { paused.push(value); },
    paused: false,
  } });
  t.after(() => ui.close());
  const port = await ui.listen();
  assert.equal((await sendRequest(port, 'POST', '/api/capture/pause')).status, 403);
  assert.deepEqual(paused, []);
  assert.equal((await sendRequest(port, 'POST', '/api/capture/pause', {
    'X-Claude-Intercept-Action': '1', Origin: 'http://evil.example',
  })).status, 403);
  assert.deepEqual(paused, []);
  assert.equal((await sendRequest(port, 'POST', '/api/capture/pause', {
    'X-Claude-Intercept-Action': '1',
  })).status, 200);
  assert.deepEqual(paused, [true]);
  assert.equal((await sendRequest(port, 'DELETE', '/api/captures')).status, 403);
});

test('API query arrays and excessive export IDs are rejected', async t => {
  t.mock.method(db, 'queryCaptures', () => ({ total: 0, rows: [] }));
  const ui = createUIServer({ uiPort: 0 });
  t.after(() => ui.close());
  const port = await ui.listen();
  assert.equal((await request(port, '/api/captures?method[]=GET')).status, 400);
  assert.equal((await request(port, '/api/captures/not-an-id')).status, 400);
  assert.equal((await request(port, '/api/qr?url[]=http://example.com')).status, 400);
  assert.equal((await request(port, '/api/analyze?ids[]=1')).status, 400);
  assert.equal((await request(port, `/api/analyze?ids=${Array.from({ length: 501 }, (_, i) => i + 1).join(',')}`)).status, 400);
  assert.equal((await request(port, '/api/analyze?mode=unknown')).status, 400);
  assert.equal((await request(port, '/api/analyze?mode=full&limit=51')).status, 400);
});

test('summary analysis reads only projected capture metadata', async t => {
  const queries = [];
  const lookups = [];
  t.mock.method(db, 'queryCaptures', options => {
    queries.push(options);
    return { total: 1, rows: [{ id: 1, host: 'api.example.com', method: 'GET', responseStatus: 200, duration: 2 }] };
  });
  t.mock.method(db, 'getCaptureById', (id, options) => {
    lookups.push({ id, options });
    return { id, host: 'api.example.com', method: 'GET', responseStatus: 200, duration: 2 };
  });
  const ui = createUIServer({ uiPort: 0 });
  t.after(() => ui.close());
  const port = await ui.listen();
  const all = await request(port, '/api/analyze?mode=summary&limit=125');
  assert.equal(all.status, 200);
  assert.equal(queries[0].summaryOnly, true);
  assert.equal(queries[0].limit, 125);
  const selected = await request(port, '/api/analyze?mode=summary&ids=1,2');
  assert.equal(selected.status, 200);
  assert.deepEqual(lookups, [
    { id: 1, options: { summaryOnly: true } },
    { id: 2, options: { summaryOnly: true } },
  ]);
});

test('LAN clients can download only the public CA certificate', () => {
  const remote = '192.0.2.20';
  assert.equal(canAccessDashboard(remote, 'GET', '/api/cert', true), true);
  assert.equal(canAccessDashboard(remote, 'HEAD', '/api/cert', true), true);
  for (const [method, requestPath] of [
    ['GET', '/'], ['GET', '/api/captures'], ['GET', '/api/status'],
    ['GET', '/api/analyze'], ['POST', '/api/proxy/on'],
    ['DELETE', '/api/captures'], ['POST', '/api/cert'],
  ]) {
    assert.equal(canAccessDashboard(remote, method, requestPath, true), false,
      `${method} ${requestPath} should be local-only`);
  }
  assert.equal(canAccessDashboard(remote, 'GET', '/api/cert', false), false);
  assert.equal(canAccessDashboard('127.0.0.1', 'GET', '/api/captures', false), true);
  assert.equal(canAccessDashboard('::ffff:127.0.0.1', 'POST', '/api/proxy/on', true), true);
});

test('public CA download works from a cross-site phone navigation', async t => {
  t.mock.method(certManager, 'getCACertPem', () => 'TEST PUBLIC CERT');
  const ui = createUIServer({ uiPort: 0, uiHost: '0.0.0.0' });
  t.after(() => ui.close());
  const port = await ui.listen();
  const cert = await request(port, '/api/cert', {
    Origin: 'https://camera.example',
    'Sec-Fetch-Site': 'cross-site',
  });
  assert.equal(cert.status, 200);
  assert.equal(cert.body, 'TEST PUBLIC CERT');
});

test('dashboard rejects cross-origin WebSocket capture access', async t => {
  t.mock.method(db, 'getStats', () => ({ total: 0, hosts: 0 }));
  const ui = createUIServer({ uiPort: 0 });
  t.after(() => ui.close());
  const port = await ui.listen();
  const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
    origin: 'http://evil.example',
  });
  const status = await new Promise((resolve, reject) => {
    ws.once('unexpected-response', (_req, res) => {
      res.resume();
      resolve(res.statusCode);
    });
    ws.once('open', () => {
      ws.close();
      reject(new Error('Cross-origin WebSocket was accepted'));
    });
    ws.once('error', reject);
  });
  assert.equal(status, 401);

  const sameOrigin = new WebSocket(`ws://127.0.0.1:${port}`, {
    origin: `http://127.0.0.1:${port}`,
  });
  const message = await new Promise((resolve, reject) => {
    sameOrigin.once('message', data => resolve(JSON.parse(data.toString())));
    sameOrigin.once('error', reject);
  });
  assert.deepEqual(message, { type: 'stats', data: { total: 0, hosts: 0 } });
  sameOrigin.close();
  await new Promise(resolve => sameOrigin.once('close', resolve));
});

test('dashboard closes WebSocket clients that send oversized messages', async t => {
  t.mock.method(db, 'getStats', () => ({ total: 0, hosts: 0 }));
  const ui = createUIServer({ uiPort: 0 });
  t.after(() => ui.close());
  const port = await ui.listen();
  const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
    origin: `http://127.0.0.1:${port}`,
  });
  const code = await new Promise((resolve, reject) => {
    ws.once('open', () => ws.send('x'.repeat(2048)));
    ws.once('close', resolve);
    ws.once('error', reject);
  });
  assert.equal(code, 1009);
});

test('LAN dashboard binding requires an explicit host', async t => {
  assert.throws(() => createUIServer({ uiHost: 'example.com' }), /Dashboard host/);
  const ui = createUIServer({ uiPort: 0, uiHost: '0.0.0.0' });
  t.after(() => ui.close());
  await ui.listen();
  assert.equal(ui.httpServer.address().address, '0.0.0.0');
});
