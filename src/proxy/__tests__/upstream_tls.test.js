'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const https = require('node:https');
const { Readable } = require('node:stream');
const forge = require('node-forge');
const ProxyServer = require('../index');

function selfSignedCertificate() {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 60_000);
  const name = [{ name: 'commonName', value: '127.0.0.1' }];
  cert.setSubject(name);
  cert.setIssuer(name);
  cert.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 7, ip: '127.0.0.1' }] }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
}

test('HTTPS and WebSocket forwarding reject an untrusted upstream certificate', async () => {
  let requests = 0;
  const origin = https.createServer(selfSignedCertificate(), (_req, res) => {
    requests++;
    res.end('unexpected');
  });
  await new Promise((resolve, reject) => {
    origin.once('error', reject);
    origin.listen(0, '127.0.0.1', resolve);
  });

  try {
    const port = origin.address().port;
    const db = { insertCapture: () => 1 };
    const proxy = new ProxyServer({ db, broadcast: () => {} });
    const req = Readable.from([]);
    req.method = 'GET';
    req.headers = {};
    let status;
    const res = {
      headersSent: false,
      writeHead(code) { status = code; this.headersSent = true; },
      end() {},
    };

    await proxy._forward({ req, res, host: '127.0.0.1', port, path: '/', isHttps: true });
    assert.equal(status, 502);
    assert.equal(requests, 0, 'the HTTPS request must not reach the untrusted origin');

    const clientSocket = new EventEmitter();
    clientSocket.remoteAddress = '127.0.0.1';
    clientSocket.setNoDelay = () => {};
    let resolveDisconnect;
    const disconnected = new Promise(resolve => { resolveDisconnect = resolve; });
    clientSocket.destroy = () => resolveDisconnect();
    let timeout;
    try {
      proxy._handleWebSocketUpgrade({
        method: 'GET',
        url: '/',
        headers: { host: '127.0.0.1', connection: 'Upgrade', upgrade: 'websocket' },
        socket: { _interceptHost: '127.0.0.1', _interceptPort: port },
      }, clientSocket, Buffer.alloc(0));
      await Promise.race([
        disconnected,
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error('WebSocket tunnel did not close')), 3000);
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
    assert.equal(requests, 0, 'the WebSocket upgrade must not reach the untrusted origin');
  } finally {
    await new Promise(resolve => origin.close(resolve));
  }
});

test('proxy binds to loopback unless a LAN host is explicitly requested', async () => {
  for (const listenHost of [undefined, '0.0.0.0']) {
    const proxy = new ProxyServer({ port: 0, listenHost, db: {}, broadcast: () => {} });
    await proxy.listen();
    try {
      assert.equal(proxy.server.address().address, listenHost || '127.0.0.1');
    } finally {
      await new Promise((resolve, reject) => proxy.server.close(err => err ? reject(err) : resolve()));
    }
  }
});
