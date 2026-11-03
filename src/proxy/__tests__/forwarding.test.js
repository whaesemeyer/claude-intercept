'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const dns = require('node:dns');
const http = require('node:http');
const os = require('node:os');
const tls = require('node:tls');
const ProxyServer = require('../index');
const { MAX_BODY } = require('../body');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
}

test('large uploads and downloads pass through intact while captures stay bounded', async t => {
  const upload = Buffer.alloc(MAX_BODY + 16_384, 0x75);
  const download = Buffer.alloc(MAX_BODY + 32_768, 0x64);
  let received = 0;
  let upstreamHeaders;
  let upstreamPath;
  const upstream = http.createServer((req, res) => {
    upstreamHeaders = req.headers;
    upstreamPath = req.url;
    req.on('data', chunk => { received += chunk.length; });
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': download.length });
      res.end(download);
    });
  });
  const upstreamPort = await listen(upstream);
  t.after(() => close(upstream));

  let captureResult;
  const captured = new Promise(resolve => { captureResult = resolve; });
  const proxy = new ProxyServer({
    port: 0,
    db: { insertCapture(capture) { captureResult(capture); return 1; } },
    broadcast: () => {},
  });
  await proxy.listen();
  t.after(() => close(proxy.server));

  const body = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: proxy.server.address().port, method: 'POST',
      path: `http://127.0.0.1:${upstreamPort}/upload?x=1`,
      headers: {
        'content-length': upload.length,
        'proxy-authorization': 'Basic local-only',
        connection: 'keep-alive, x-hop',
        'x-hop': 'must-not-reach-origin',
      },
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject);
    req.end(upload);
  });

  const capture = await captured;
  assert.equal(received, upload.length);
  assert.deepEqual(body, download);
  assert.equal(upstreamPath, '/upload?x=1');
  assert.equal(upstreamHeaders['proxy-authorization'], undefined);
  assert.equal(upstreamHeaders['x-hop'], undefined);
  assert.equal(capture.requestBodySize, upload.length);
  assert.equal(capture.responseBodySize, download.length);
  assert.match(capture.requestBody, /capture limited/);
  assert.match(capture.responseBody, /capture limited/);
});

test('malformed CONNECT authorities are rejected before TLS interception', () => {
  const proxy = new ProxyServer({ db: {}, broadcast: () => {} });
  for (const authority of [
    'example.com:0', 'example.com:65536', 'example.com:bad',
    'example.com:443/other', 'user@example.com:443', '[::1]:bad',
  ]) {
    let reply;
    proxy._handleCONNECT({ url: authority }, { end(value) { reply = value; } }, Buffer.alloc(0));
    assert.match(reply, /^HTTP\/1\.1 400 Bad Request/, authority);
  }
});

test('plain HTTP rejects malformed absolute targets', async () => {
  const proxy = new ProxyServer({ db: {}, broadcast: () => {} });
  for (const url of ['http:example.com', 'http:////example.com', 'https://example.com/', '/relative']) {
    const res = responseStub();
    await proxy._handleHTTP({ url, socket: { remoteAddress: '127.0.0.1' }, headers: {} }, res);
    assert.equal(res.status, 400, url);
  }
});

function responseStub() {
  return {
    status: null,
    body: null,
    writeHead(status) { this.status = status; },
    end(body) { this.body = body; },
  };
}

test('LAN HTTP and CONNECT cannot reach the loopback dashboard', async () => {
  const proxy = new ProxyServer({ db: {}, broadcast: () => {} });
  let forwarded = false;
  proxy._forward = async () => { forwarded = true; };
  const req = {
    url: 'http://127.0.0.1:7778/api/captures',
    socket: { remoteAddress: '192.168.1.25' },
    headers: {},
  };
  const res = responseStub();
  await proxy._handleHTTP(req, res);
  assert.equal(res.status, 403);
  assert.equal(forwarded, false);

  const mapped = responseStub();
  await proxy._handleHTTP({ ...req, url: 'http://[::ffff:127.0.0.1]:7778/api/captures' }, mapped);
  assert.equal(mapped.status, 403);

  const replies = [];
  const socket = {
    remoteAddress: '192.168.1.25',
    pause() {},
    end(value) { replies.push(value); },
  };
  await proxy._handleCONNECT({ url: '127.0.0.1:7778' }, socket, Buffer.alloc(0));
  await proxy._handleCONNECT({ url: '[::ffff:127.0.0.1]:7778' }, socket, Buffer.alloc(0));
  assert.equal(replies.length, 2);
  for (const reply of replies) assert.match(reply, /^HTTP\/1\.1 403 Forbidden/);
});

test('LAN DNS destinations are checked and pinned before forwarding', async t => {
  let answer = '127.0.0.1';
  let lookups = 0;
  t.mock.method(dns.promises, 'lookup', async () => {
    lookups++;
    return [{ address: answer, family: 4 }];
  });
  const proxy = new ProxyServer({ db: {}, broadcast: () => {} });
  let forwarded;
  proxy._forward = async options => { forwarded = options; };
  const req = {
    url: 'http://rebind.example/api/captures',
    socket: { remoteAddress: '192.168.1.25' },
    headers: {},
  };
  const denied = responseStub();
  await proxy._handleHTTP(req, denied);
  assert.equal(denied.status, 403);
  assert.equal(forwarded, undefined);

  answer = '8.8.8.8';
  const allowed = responseStub();
  await proxy._handleHTTP(req, allowed);
  assert.equal(allowed.status, null);
  assert.equal(forwarded.connectAddress, '8.8.8.8');
  assert.equal(lookups, 2, 'the vetted request must not require a second DNS lookup');
});

test('LAN cannot reach a public IP assigned to the proxy host', async t => {
  t.mock.method(os, 'networkInterfaces', () => ({ en0: [{ address: '8.8.8.8', family: 'IPv4' }] }));
  t.mock.method(dns.promises, 'lookup', async () => [{ address: '8.8.8.8', family: 4 }]);
  const proxy = new ProxyServer({ db: {}, broadcast: () => {} });
  let forwarded = false;
  proxy._forward = async () => { forwarded = true; };
  for (const url of ['http://8.8.8.8:7778/api/captures', 'http://local-ui.example:7778/api/captures']) {
    const res = responseStub();
    await proxy._handleHTTP({ url, socket: { remoteAddress: '192.168.1.25' }, headers: {} }, res);
    assert.equal(res.status, 403, url);
  }
  assert.equal(forwarded, false);
});

test('LAN cannot reach the configured dashboard port through a public gateway', async () => {
  const proxy = new ProxyServer({ uiPort: 9555, db: {}, broadcast: () => {} });
  let forwarded = false;
  proxy._forward = async () => { forwarded = true; };
  const res = responseStub();
  await proxy._handleHTTP({
    url: 'http://8.8.8.8:9555/api/captures',
    socket: { remoteAddress: '192.168.1.25' }, headers: {},
  }, res);
  assert.equal(res.status, 403);
  assert.equal(forwarded, false);

  let reply;
  await proxy._handleCONNECT({ url: '8.8.8.8:9555' }, {
    remoteAddress: '192.168.1.25',
    end(value) { reply = value; },
  }, Buffer.alloc(0));
  assert.match(reply, /^HTTP\/1\.1 403 Forbidden/);
});

test('loopback clients retain local proxy access, including mapped IPv4', async () => {
  const proxy = new ProxyServer({ db: {}, broadcast: () => {} });
  let options;
  proxy._forward = async value => { options = value; };
  const res = responseStub();
  await proxy._handleHTTP({
    url: 'http://127.0.0.1:7778/api/captures',
    socket: { remoteAddress: '::ffff:127.0.0.1' },
    headers: {},
  }, res);
  assert.equal(res.status, null);
  assert.equal(options.host, '127.0.0.1');
  assert.equal(options.connectAddress, undefined);
});

test('WebSocket upgrade strips proxy credentials and pins CONNECT authority', async t => {
  const upstream = new EventEmitter();
  let written = '';
  let connectionOptions;
  upstream.setTimeout = () => {};
  upstream.setNoDelay = () => {};
  upstream.write = value => { written += value; };
  upstream.pipe = target => target;
  upstream.destroy = () => {};
  t.mock.method(tls, 'connect', options => {
    connectionOptions = options;
    return upstream;
  });

  const client = new EventEmitter();
  client.remoteAddress = '192.168.1.25';
  client.pause = () => {};
  client.setNoDelay = () => {};
  client.pipe = target => target;
  client.destroy = () => {};
  const proxy = new ProxyServer({ db: {}, broadcast: () => {} });
  proxy._handleWebSocketUpgrade({
    method: 'GET', url: '/socket',
    headers: {
      host: '127.0.0.1:7778',
      connection: 'Upgrade, x-hop', upgrade: 'websocket',
      'x-hop': 'private', 'proxy-authorization': 'Basic secret',
      'proxy-connection': 'keep-alive',
    },
    socket: {
      _interceptHost: 'public.example', _interceptPort: 443,
      _interceptUpstreamIp: '8.8.8.8', _interceptRestricted: true,
    },
  }, client, Buffer.alloc(0));
  assert.equal(connectionOptions.host, '8.8.8.8');
  assert.equal(connectionOptions.servername, 'public.example');
  upstream.emit('secureConnect');
  assert.match(written, /\r\nhost: public\.example\r\n/i);
  assert.match(written, /\r\nconnection: Upgrade\r\n/i);
  assert.doesNotMatch(written, /proxy-authorization|proxy-connection|x-hop|Basic secret/i);
});
