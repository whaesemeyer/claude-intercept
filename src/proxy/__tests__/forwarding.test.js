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
  const notifications = [];
  const proxy = new ProxyServer({
    port: 0,
    db: { insertCapture(capture) { captureResult(capture); return 1; } },
    broadcast: event => notifications.push(event),
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
        'proxy-connection': 'keep-alive',
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
  assert.equal(upstreamHeaders['proxy-connection'], undefined);
  assert.equal(upstreamHeaders['x-hop'], undefined);
  assert.equal(capture.requestBodySize, upload.length);
  assert.equal(capture.requestHeaders['proxy-authorization'], undefined);
  assert.equal(capture.requestHeaders['proxy-connection'], undefined);
  assert.equal(capture.responseBodySize, download.length);
  assert.match(capture.requestBody, /capture limited/);
  assert.match(capture.responseBody, /capture limited/);
  assert.equal(notifications[0].data.requestHeaders, undefined);
  assert.equal(notifications[0].data.requestBodyPreview, undefined);
  assert.equal(notifications[0].data.responseBodyPreview, undefined);
});

test('capture quota reports once per full episode while forwarding continues', async t => {
  const origin = http.createServer((_req, res) => res.end('origin response'));
  const originPort = await listen(origin);
  t.after(() => close(origin));
  const events = [];
  const quotaError = Object.assign(new Error('capture storage full'), {
    code: 'CAPTURE_QUOTA_EXCEEDED',
  });
  let inserts = 0;
  const proxy = new ProxyServer({
    port: 0,
    db: {
      insertCapture() {
        inserts++;
        if (inserts === 3) return 1; // Simulate captures resuming after clear.
        throw quotaError;
      },
      getStats() { return { storageBytes: 100, storageLimitBytes: 100 }; },
    },
    broadcast: event => events.push(event),
  });
  await proxy.listen();
  t.after(() => close(proxy.server));
  t.mock.method(console, 'error', () => {});

  for (let i = 0; i < 4; i++) {
    const body = await new Promise((resolve, reject) => {
      http.get({
        host: '127.0.0.1', port: proxy.server.address().port,
        path: `http://127.0.0.1:${originPort}/`,
      }, res => {
        assert.equal(res.statusCode, 200);
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => resolve(Buffer.concat(chunks).toString()));
      }).on('error', reject);
    });
    assert.equal(body, 'origin response');
  }
  const quotaNotice = {
    type: 'captureStorageFull',
    data: { storageBytes: 100, storageLimitBytes: 100, storageLimitReached: true },
  };
  assert.deepEqual(events.map(event => event.type), [
    'captureStorageFull', 'capture', 'captureStorageFull',
  ]);
  assert.deepEqual(events[0], quotaNotice);
  assert.deepEqual(events[2], quotaNotice);
});

test('concurrent response captures share a bounded memory budget', async t => {
  const firstBody = Buffer.alloc(MAX_BODY, 0x61);
  let releaseFirst;
  const firstCanEnd = new Promise(resolve => { releaseFirst = resolve; });
  t.after(() => releaseFirst());
  const origin = http.createServer((req, res) => {
    if (req.url === '/held') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.write(firstBody);
      firstCanEnd.then(() => res.end());
    } else {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('second response');
    }
  });
  const originPort = await listen(origin);
  t.after(() => close(origin));
  const captures = [];
  const proxy = new ProxyServer({
    port: 0,
    db: { insertCapture(capture) { captures.push(capture); return captures.length; } },
    broadcast: () => {},
  });
  proxy._captureBudget.max = MAX_BODY;
  await proxy.listen();
  t.after(() => close(proxy.server));

  let firstBytesReceived;
  const firstBytes = new Promise(resolve => { firstBytesReceived = resolve; });
  const firstDone = new Promise((resolve, reject) => {
    http.get({
      host: '127.0.0.1', port: proxy.server.address().port,
      path: `http://127.0.0.1:${originPort}/held`,
    }, res => {
      let received = 0;
      res.on('data', chunk => {
        received += chunk.length;
        if (received >= MAX_BODY) firstBytesReceived();
      });
      res.on('end', resolve);
    }).on('error', reject);
  });
  await firstBytes;
  assert.equal(proxy._captureBudget.used, MAX_BODY);

  const secondBody = await new Promise((resolve, reject) => {
    http.get({
      host: '127.0.0.1', port: proxy.server.address().port,
      path: `http://127.0.0.1:${originPort}/second`,
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString()));
    }).on('error', reject);
  });
  assert.equal(secondBody, 'second response');
  assert.match(captures.find(c => c.path === '/second').responseBody, /capture limited by active memory budget/);
  releaseFirst();
  await firstDone;
  assert.equal(proxy._captureBudget.used, 0);
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
  let wsCapture;
  const proxy = new ProxyServer({
    db: {
      insertCapture(capture) { wsCapture = capture; return 1; },
      finalizeWsCapture() {},
    },
    broadcast: () => {},
  });
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
  client.emit('close');
  assert.equal(wsCapture.requestHeaders['proxy-authorization'], undefined);
  assert.equal(wsCapture.requestHeaders['proxy-connection'], undefined);
});

test('WebSocket upgrade keeps an absolute 15-second deadline until complete 101 headers', t => {
  let upstream;
  t.mock.method(tls, 'connect', () => upstream);

  const deadlines = [];
  const realSetTimeout = global.setTimeout;
  const realClearTimeout = global.clearTimeout;
  t.mock.method(global, 'setTimeout', (callback, ms, ...args) => {
    if (ms !== 15_000) return realSetTimeout(callback, ms, ...args);
    const timer = { callback, ms, cleared: false };
    deadlines.push(timer);
    return timer;
  });
  t.mock.method(global, 'clearTimeout', timer => {
    if (deadlines.includes(timer)) timer.cleared = true;
    else realClearTimeout(timer);
  });

  const openUpgrade = () => {
    upstream = new EventEmitter();
    const client = new EventEmitter();
    let upstreamDestroyed = false;
    let clientDestroyed = false;
    upstream.setTimeout = upstream.setNoDelay = upstream.write = () => {};
    upstream.pipe = target => target;
    upstream.destroy = () => { upstreamDestroyed = true; };
    client.remoteAddress = '127.0.0.1';
    client.pause = client.setNoDelay = () => {};
    client.pipe = target => target;
    client.destroy = () => { clientDestroyed = true; };
    const proxy = new ProxyServer({
      db: { insertCapture() { return 1; }, finalizeWsCapture() {} },
      broadcast: () => {},
    });
    proxy._handleWebSocketUpgrade({
      method: 'GET', url: '/socket',
      headers: { host: 'example.com', connection: 'Upgrade', upgrade: 'websocket' },
      socket: { _interceptHost: 'example.com', _interceptPort: 443 },
    }, client, Buffer.alloc(0));
    const deadline = deadlines.at(-1);
    assert.equal(deadline.ms, 15_000);
    upstream.emit('secureConnect');
    return {
      upstream, client, deadline,
      destroyed: () => upstreamDestroyed && clientDestroyed,
    };
  };

  const trickled = openUpgrade();
  for (const part of ['HTTP/1.1 101 Switching Protocols\r\n', 'Upgrade: websocket\r\n']) {
    trickled.upstream.emit('data', Buffer.from(part));
    assert.equal(trickled.deadline.cleared, false);
  }
  trickled.deadline.callback();
  assert.equal(trickled.destroyed(), true);

  const accepted = openUpgrade();
  accepted.upstream.emit('data', Buffer.from('HTTP/1.1 101 Switching Protocols\r\n'));
  assert.equal(accepted.deadline.cleared, false);
  accepted.upstream.emit('data', Buffer.from('Upgrade: websocket\r\n\r\n'));
  assert.equal(accepted.deadline.cleared, true);
  assert.equal(accepted.destroyed(), false);
  accepted.client.emit('close');

  const rejected = openUpgrade();
  rejected.upstream.emit('data', Buffer.from('HTTP/1.1 403 Forbidden\r\n\r\n'));
  assert.equal(rejected.deadline.cleared, false);
  rejected.deadline.callback();
  assert.equal(rejected.destroyed(), true);

  const oversized = openUpgrade();
  oversized.upstream.emit('data', Buffer.alloc(16 * 1024, 0x61));
  assert.equal(oversized.deadline.cleared, false);
  oversized.deadline.callback();
  assert.equal(oversized.destroyed(), true);
});

test('WebSocket observation records a bounded prefix without replacing the tunnel', t => {
  const upstream = new EventEmitter();
  const client = new EventEmitter();
  const pipes = [];
  upstream.setTimeout = upstream.setNoDelay = upstream.write = upstream.destroy = () => {};
  upstream.pipe = target => { pipes.push('upstream'); return target; };
  client.remoteAddress = '127.0.0.1';
  client.pause = client.setNoDelay = client.destroy = () => {};
  client.pipe = target => { pipes.push('client'); return target; };
  t.mock.method(tls, 'connect', () => upstream);
  const frames = [];
  const events = [];
  let final;
  const proxy = new ProxyServer({
    db: {
      insertCapture() { return 11; },
      insertWsFrame(frame) { frames.push(frame); return frames.length; },
      finalizeWsCapture(_id, update) { final = update; },
    },
    broadcast: event => events.push(event),
  });
  const makeFrame = payload => {
    const data = Buffer.from(payload);
    const header = data.length < 126
      ? Buffer.from([0x81, data.length])
      : Buffer.from([0x81, 126, data.length >> 8, data.length & 0xff]);
    return Buffer.concat([header, data]);
  };
  proxy._handleWebSocketUpgrade({
    method: 'GET', url: '/socket',
    headers: { host: 'example.com', connection: 'Upgrade', upgrade: 'websocket' },
    socket: { _interceptHost: 'example.com', _interceptPort: 443 },
  }, client, Buffer.alloc(0));
  upstream.emit('secureConnect');
  assert.deepEqual(pipes, ['upstream', 'client']);
  upstream.emit('data', Buffer.concat([
    Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n'),
    makeFrame('server message'),
  ]));
  client.emit('data', makeFrame('client message'));
  upstream.emit('data', makeFrame(Buffer.alloc(40 * 1024, 0x61)));
  upstream.emit('data', makeFrame('not recorded'));
  client.emit('close');
  assert.deepEqual(frames.map(frame => frame.payload), ['server message', 'client message']);
  assert.match(final.responseBody, /capture limited/);
  assert.equal(final.responseStatus, 101);
  assert.equal(events.filter(event => event.type === 'wsFrame').length, 2);
  assert.equal(events.find(event => event.type === 'wsFrame').data.payload, undefined);
});

test('rejected WebSocket upgrades forward without interpreting HTTP bodies as frames', t => {
  const upstream = new EventEmitter();
  const client = new EventEmitter();
  const pipes = [];
  upstream.setTimeout = upstream.setNoDelay = upstream.write = upstream.destroy = () => {};
  upstream.pipe = target => { pipes.push('upstream'); return target; };
  client.remoteAddress = '127.0.0.1';
  client.pause = client.setNoDelay = client.destroy = () => {};
  client.pipe = target => { pipes.push('client'); return target; };
  t.mock.method(tls, 'connect', () => upstream);
  let inserted = 0;
  let final;
  const proxy = new ProxyServer({
    db: {
      insertCapture() { return 1; },
      insertWsFrame() { inserted++; return inserted; },
      finalizeWsCapture(_id, update) { final = update; },
    },
    broadcast: () => {},
  });
  proxy._handleWebSocketUpgrade({
    method: 'GET', url: '/socket',
    headers: { host: 'example.com', connection: 'Upgrade', upgrade: 'websocket' },
    socket: { _interceptHost: 'example.com', _interceptPort: 443 },
  }, client, Buffer.alloc(0));
  upstream.emit('secureConnect');
  upstream.emit('data', Buffer.concat([
    Buffer.from('HTTP/1.1 403 Forbidden\r\nContent-Length: 5\r\n\r\n'),
    Buffer.from([0x81, 0x03, 0x62, 0x61, 0x64]),
  ]));
  client.emit('close');
  assert.deepEqual(pipes, ['upstream', 'client']);
  assert.equal(inserted, 0);
  assert.equal(final.responseStatus, 403);
});

test('WebSocket capture stops storage attempts after quota failure while the tunnel stays open', t => {
  const upstream = new EventEmitter();
  const client = new EventEmitter();
  const pipes = [];
  upstream.setTimeout = upstream.setNoDelay = upstream.write = upstream.destroy = () => {};
  upstream.pipe = target => { pipes.push('upstream'); return target; };
  client.remoteAddress = '127.0.0.1';
  client.pause = client.setNoDelay = client.destroy = () => {};
  client.pipe = target => { pipes.push('client'); return target; };
  t.mock.method(tls, 'connect', () => upstream);
  let attempts = 0;
  let final;
  const events = [];
  const proxy = new ProxyServer({
    db: {
      insertCapture() { return 1; },
      insertWsFrame() {
        attempts++;
        const err = new Error('Capture database limit reached');
        err.code = 'CAPTURE_QUOTA_EXCEEDED';
        throw err;
      },
      finalizeWsCapture(_id, update) { final = update; },
      getStats() { return { storageLimitBytes: 1024, storageBytes: 1024 }; },
    },
    broadcast: event => events.push(event),
  });
  proxy._handleWebSocketUpgrade({
    method: 'GET', url: '/socket',
    headers: { host: 'example.com', connection: 'Upgrade', upgrade: 'websocket' },
    socket: { _interceptHost: 'example.com', _interceptPort: 443 },
  }, client, Buffer.alloc(0));
  upstream.emit('secureConnect');
  upstream.emit('data', Buffer.from('HTTP/1.1 101 Switching Protocols\r\n\r\n'));
  upstream.emit('data', Buffer.from([0x81, 0x01, 0x61, 0x81, 0x01, 0x62]));
  client.emit('data', Buffer.from([0x81, 0x01, 0x63]));
  assert.equal(attempts, 1);
  assert.deepEqual(pipes, ['upstream', 'client']);
  assert.equal(events.filter(event => event.type === 'captureStorageFull').length, 1);
  client.emit('close');
  assert.match(final.responseBody, /capture limited/);
});
