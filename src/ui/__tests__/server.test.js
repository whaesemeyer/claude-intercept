'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const WebSocket = require('ws');
const db = require('../../storage/db');
const { createUIServer } = require('../server');

function request(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path, headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    }).on('error', reject);
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
  const data = JSON.parse(status.body);
  assert.deepEqual(data.ui, { port, host: '127.0.0.1', lanEnabled: false });
  assert.equal(data.certUrl, `http://127.0.0.1:${port}/api/cert`);
  assert.equal(data.tailscaleCertUrl, null);

  assert.equal((await request(port, '/api/capture/state', {
    Origin: 'http://evil.example',
  })).status, 403);
  assert.equal((await request(port, '/api/capture/state', {
    Host: `evil.example:${port}`,
  })).status, 403);
  assert.equal((await request(port, '/api/capture/state', {
    Origin: `http://127.0.0.1:${port}`,
  })).status, 200);
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

test('LAN dashboard binding requires an explicit host', async t => {
  assert.throws(() => createUIServer({ uiHost: 'example.com' }), /Dashboard host/);
  const ui = createUIServer({ uiPort: 0, uiHost: '0.0.0.0' });
  t.after(() => ui.close());
  await ui.listen();
  assert.equal(ui.httpServer.address().address, '0.0.0.0');
});
