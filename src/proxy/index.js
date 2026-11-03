'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const dns = require('node:dns').promises;
const os = require('node:os');
const { URL } = require('url');
const certManager = require('./cert_manager');
const { tryDecodeBody, MAX_BODY } = require('./body');

// LAN clients may use the proxy for public destinations, but must not be able
// to reach this machine's dashboard, cloud metadata endpoints, or other local
// services through it. Loopback clients retain full access for local testing.
// Keep address families separate: Node checks IPv4 rules through IPv4-mapped
// IPv6 addresses, so an IPv6 ::/3 rule in the same list would block every IPv4.
const blockedIpv4 = new net.BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
  ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blockedIpv4.addSubnet(address, prefix);
// Only ordinary global-unicast IPv6 destinations are eligible. Exclude the
// transition and documentation ranges within 2000::/3 as well.
const blockedIpv6 = new net.BlockList();
for (const [address, prefix] of [
  ['::', 3], ['4000::', 2], ['8000::', 1],
  ['2001::', 32], ['2001:db8::', 32], ['2002::', 16],
]) blockedIpv6.addSubnet(address, prefix, 'ipv6');

const loopbackSources = new net.BlockList();
loopbackSources.addSubnet('127.0.0.0', 8);
loopbackSources.addAddress('::1', 'ipv6');

class BlockedDestinationError extends Error {
  constructor() {
    super('Destination blocked for LAN client');
    this.code = 'DESTINATION_BLOCKED';
  }
}

function isLoopbackSource(address) {
  const family = net.isIP(address);
  return family !== 0 && loopbackSources.check(address, family === 6 ? 'ipv6' : 'ipv4');
}

function localInterfaceAddresses() {
  const addresses = new net.BlockList();
  for (const interfaces of Object.values(os.networkInterfaces())) {
    for (const iface of interfaces || []) {
      const family = net.isIP(iface.address);
      if (family) addresses.addAddress(iface.address, family === 6 ? 'ipv6' : 'ipv4');
    }
  }
  return addresses;
}

function isPublicAddress(address, localAddresses) {
  const family = net.isIP(address);
  if (family === 4) {
    return !blockedIpv4.check(address) && !localAddresses.check(address);
  }
  if (family === 6) {
    return !blockedIpv4.check(address, 'ipv6') && !blockedIpv6.check(address, 'ipv6') &&
      !localAddresses.check(address, 'ipv6');
  }
  return false;
}

async function publicDestination(host) {
  if (net.isIP(host)) {
    if (isPublicAddress(host, localInterfaceAddresses())) return host;
    throw new BlockedDestinationError();
  }
  const name = host.toLowerCase().replace(/\.$/, '');
  if (!name.includes('.') || /\.(?:local|localhost|internal|lan|home\.arpa)$/.test(name)) {
    throw new BlockedDestinationError();
  }
  let timer;
  const lookup = dns.lookup(name, { all: true });
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Destination lookup timed out')), 10_000);
  });
  let addresses;
  try {
    addresses = await Promise.race([lookup, timeout]);
  } finally {
    clearTimeout(timer);
  }
  const localAddresses = localInterfaceAddresses();
  const publicAddress = addresses.find(({ address }) => isPublicAddress(address, localAddresses));
  if (!publicAddress) throw new BlockedDestinationError();
  // Pin the vetted IP for the outbound connection so a second DNS answer
  // cannot rebind the request to a private address after this check.
  return publicAddress.address;
}

function outboundError(res, err) {
  if (res.destroyed) return;
  if (res.headersSent) {
    res.destroy?.(err);
    return;
  }
  res.writeHead(err.code === 'DESTINATION_BLOCKED' ? 403 : 502);
  res.end(err.code === 'DESTINATION_BLOCKED' ? 'Destination blocked' : 'Bad Gateway');
}

function connectError(socket, err) {
  if (socket.destroyed) return;
  const status = err.code === 'DESTINATION_BLOCKED'
    ? '403 Forbidden' : '502 Bad Gateway';
  socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
}

function deriveDeviceLabel(ip, ua) {
  if (!ip || ip === '127.0.0.1' || ip === '::1') return 'This Mac';
  const u = (ua || '').toLowerCase();
  if (u.includes('iphone'))  return 'iPhone';
  if (u.includes('ipad'))    return 'iPad';
  if (u.includes('android')) return 'Android';
  if (u.includes('mac os x') || u.includes('macintosh')) return `Mac (${ip})`;
  if (u.includes('windows')) return `Windows (${ip})`;
  if (u.includes('linux') && !u.includes('android')) return `Linux (${ip})`;
  return ip;
}

function captureBody() {
  const chunks = [];
  let stored = 0;
  let total = 0;
  return {
    add(chunk) {
      total += chunk.length;
      if (stored >= MAX_BODY) return;
      const kept = chunk.subarray(0, MAX_BODY - stored);
      chunks.push(Buffer.from(kept));
      stored += kept.length;
    },
    decode(contentType, contentEncoding) {
      if (total > MAX_BODY) {
        return {
          text: `<body ${total} bytes — capture limited to ${MAX_BODY} bytes>`,
          encoding: contentEncoding || 'identity',
          originalSize: total,
        };
      }
      return tryDecodeBody(Buffer.concat(chunks, stored), contentType, contentEncoding);
    },
    get size() { return total; },
  };
}

function parseConnectAuthority(authority) {
  if (typeof authority !== 'string' || authority.length > 300) return null;
  const ipv6 = /^\[([^\]]+)\]:(\d{1,5})$/.exec(authority);
  const domain = /^([A-Za-z0-9._-]+):(\d{1,5})$/.exec(authority);
  if (!ipv6 && !domain) return null;
  const host = ipv6 ? ipv6[1] : domain[1];
  if (ipv6 && net.isIP(host) !== 6) return null;
  const port = Number((ipv6 || domain)[2]);
  if (port < 1 || port > 65535) return null;
  return { host, port };
}

function authorityHeader(host, port, defaultPort) {
  const name = net.isIP(host) === 6 ? `[${host}]` : host;
  return port === defaultPort ? name : `${name}:${port}`;
}

function stripHopByHopHeaders(headers) {
  const result = Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  for (const name of String(result.connection || '').split(',')) {
    delete result[name.trim().toLowerCase()];
  }
  for (const name of [
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  ]) delete result[name];
  return result;
}

function webSocketHeaders(headers, host, port) {
  const result = Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  for (const name of String(result.connection || '').split(',')) {
    if (name.trim().toLowerCase() !== 'upgrade') delete result[name.trim().toLowerCase()];
  }
  for (const name of [
    'host', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection',
    'keep-alive', 'te', 'trailer', 'transfer-encoding',
  ]) delete result[name];
  result.host = authorityHeader(host, port, 443);
  result.connection = 'Upgrade';
  result.upgrade = 'websocket';
  return result;
}

class ProxyServer {
  constructor({ port = 8080, uiPort = 7778, listenHost = '127.0.0.1', db, broadcast }) {
    this.port = port;
    this.uiPort = uiPort;
    this.listenHost = listenHost;
    this.db = db;
    this.broadcast = broadcast; // fn(eventObj) → WebSocket broadcast
    this.paused = false;

    // Handles plain HTTP proxy requests
    this.server = http.createServer((req, res) => {
      this._handleHTTP(req, res).catch(err => outboundError(res, err));
    });
    this.server.maxConnections = 128;
    this.server.headersTimeout = 30_000;
    this.server.requestTimeout = 300_000;
    this.server.on('connect', (req, socket, head) => {
      this._handleCONNECT(req, socket, head).catch(err => connectError(socket, err));
    });
    this.server.on('error', (err) => console.error('[proxy] server error:', err.message));

    // Handles HTTPS after TLS unwrapping — all CONNECT tunnels land here
    this._httpsHandler = new http.Server((req, res) => {
      this._handleHTTPS(req, res).catch(err => outboundError(res, err));
    });
    this._httpsHandler.headersTimeout = 30_000;
    this._httpsHandler.requestTimeout = 300_000;
    this._httpsHandler.on('upgrade', (req, socket, head) => {
      try {
        this._handleWebSocketUpgrade(req, socket, head);
      } catch {
        socket.destroy();
      }
    });
    this._httpsHandler.on('error', () => {}); // suppress
  }

  // ── Plain HTTP forwarding ─────────────────────────────────────────────────

  async _handleHTTP(req, res) {
    let targetUrl;
    try {
      if (!/^http:\/\/[^/]/i.test(req.url)) throw new Error('Invalid proxy target');
      targetUrl = new URL(req.url);
    } catch {
      res.writeHead(400);
      return res.end('Bad Request');
    }
    if (targetUrl.protocol !== 'http:' || !targetUrl.hostname ||
        targetUrl.username || targetUrl.password) {
      res.writeHead(400);
      return res.end('Bad Request');
    }

    const host = targetUrl.hostname.replace(/^\[|\]$/g, '');
    const port = Number(targetUrl.port) || 80;
    let connectAddress;
    if (!isLoopbackSource(req.socket?.remoteAddress)) {
      if (port === this.uiPort) return outboundError(res, new BlockedDestinationError());
      try {
        connectAddress = await publicDestination(host);
      } catch (err) {
        return outboundError(res, err);
      }
    }

    await this._forward({
      req,
      res,
      host,
      port,
      path: targetUrl.pathname + targetUrl.search,
      isHttps: false,
      connectAddress,
    });
  }

  // ── CONNECT tunnel (HTTPS) ────────────────────────────────────────────────

  async _handleCONNECT(req, clientSocket, head) {
    const target = parseConnectAuthority(req.url);
    if (!target) {
      clientSocket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      return;
    }
    const { host, port } = target;

    const restricted = !isLoopbackSource(clientSocket.remoteAddress);
    if (restricted && port === this.uiPort) {
      connectError(clientSocket, new BlockedDestinationError());
      return;
    }

    // CONNECT can arrive with TLS bytes immediately after its headers. Pause
    // the raw socket while DNS is checked, then pin the vetted destination for
    // every request carried by this tunnel.
    clientSocket.pause?.();
    let connectAddress;
    if (restricted) {
      try {
        connectAddress = await publicDestination(host);
      } catch (err) {
        connectError(clientSocket, err);
        return;
      }
    }

    let certInfo;
    try {
      certInfo = certManager.getCertForHost(host);
    } catch (err) {
      connectError(clientSocket, err);
      return;
    }

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    // Wrap the plain socket in a TLS server socket
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      cert: certInfo.certPem,
      key: certInfo.keyPem,
    });

    tlsSocket._interceptHost = host;
    tlsSocket._interceptPort = port;
    tlsSocket._interceptUpstreamIp = connectAddress;
    tlsSocket._interceptRestricted = Boolean(connectAddress);

    tlsSocket.on('error', () => {}); // cert pinning, client errors — ignore
    tlsSocket.setTimeout(300_000, () => tlsSocket.destroy());
    clientSocket.on('error', () => {});

    this._httpsHandler.emit('connection', tlsSocket);

    if (head && head.length > 0) tlsSocket.push(head);
    clientSocket.resume?.();
  }

  // ── HTTPS (post-TLS) forwarding ───────────────────────────────────────────

  async _handleHTTPS(req, res) {
    const socket = req.socket;
    const host = socket._interceptHost || req.headers.host?.split(':')[0] || 'unknown';
    const port = socket._interceptPort || 443;

    if (!req.url.startsWith('/')) {
      res.writeHead(400);
      return res.end('Bad Request');
    }

    if (socket._interceptRestricted && !socket._interceptUpstreamIp) {
      return outboundError(res, new BlockedDestinationError());
    }

    await this._forward({
      req, res, host, port, path: req.url, isHttps: true,
      connectAddress: socket._interceptUpstreamIp,
    });
  }

  // ── WebSocket upgrade (wss://) — transparent tunnel + connection log ──────
  //
  // Cert-pinned single-page apps (Spotify web, Discord) require a working
  // WebSocket upgrade or they hang at the loading state. Node's http.Server
  // emits 'upgrade' instead of 'request' when a client sends Upgrade: websocket.
  // We can't decrypt frames here without a full RFC 6455 parser; for now we
  // forward bytes verbatim and log a single capture row per connection so the
  // dashboard shows the WS happened.

  _handleWebSocketUpgrade(req, clientSocket, head) {
    const tlsSocket = req.socket;
    const host = tlsSocket._interceptHost || req.headers.host?.split(':')[0] || 'unknown';
    const port = tlsSocket._interceptPort || 443;
    if (req.method !== 'GET' || !req.url.startsWith('/') ||
        String(req.headers.upgrade || '').toLowerCase() !== 'websocket' ||
        (tlsSocket._interceptRestricted && !tlsSocket._interceptUpstreamIp)) {
      clientSocket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      return;
    }
    const startMs = Date.now();
    const rawIp = clientSocket.remoteAddress || '';
    const clientIp = rawIp.replace(/^::ffff:/, '');
    const clientLabel = deriveDeviceLabel(clientIp, req.headers['user-agent']);

    let logged = false;
    const finalize = (status) => {
      if (logged || this.paused) return;
      logged = true;
      const duration = Date.now() - startMs;
      const capture = {
        timestamp: startMs,
        method: 'WS',
        url: `wss://${host}${req.url}`,
        host,
        path: req.url,
        requestHeaders: req.headers,
        requestBody: '',
        requestEncoding: 'identity',
        requestBodySize: 0,
        responseStatus: status,
        responseHeaders: {},
        responseBody: `[WebSocket — duration ${duration}ms]`,
        responseEncoding: 'identity',
        responseBodySize: 0,
        contentType: 'websocket',
        duration,
        clientIp,
        clientLabel,
      };
      try {
        const id = this.db.insertCapture(capture);
        capture.id = id;
        this.broadcast({ type: 'capture', data: this._serializeCapture(capture) });
      } catch (err) {
        console.error('[proxy] WS capture error:', err.message);
      }
    };

    // Force HTTP/1.1 — WebSocket-over-HTTP/2 (RFC 8441) is a separate path
    // most servers don't enable, and the Upgrade header semantics only work
    // over h1. Keep Node's default certificate and hostname verification.
    clientSocket.pause?.();
    const upstream = tls.connect({
      host: tlsSocket._interceptUpstreamIp || host,
      port,
      servername: net.isIP(host) ? undefined : host,
      ALPNProtocols: ['http/1.1'],
    });
    upstream.setTimeout(15_000, () => cleanup(0));

    const cleanup = (status) => {
      finalize(status);
      try { upstream.destroy(); } catch {}
      try { clientSocket.destroy(); } catch {}
    };

    // Disable Nagle so small WS control frames flush immediately.
    try { clientSocket.setNoDelay?.(true); } catch {}

    upstream.on('error', () => cleanup(0));
    clientSocket.on('error', () => cleanup(0));
    clientSocket.on('close', () => cleanup(101));
    upstream.on('close', () => cleanup(101));

    upstream.once('secureConnect', () => {
      upstream.setTimeout(0);
      try { upstream.setNoDelay?.(true); } catch {}

      const reqLine = `${req.method} ${req.url} HTTP/1.1\r\n`;
      const headerBlock = Object.entries(webSocketHeaders(req.headers, host, port))
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
        .join('\r\n');
      try {
        upstream.write(reqLine + headerBlock + '\r\n\r\n');
        if (head && head.length > 0) upstream.write(head);
      } catch {
        return cleanup(0);
      }

      // Keep both write sides open until cleanup, while pipe() provides
      // backpressure when either peer reads slowly. Its default end-on-end
      // behavior can truncate the final WebSocket frame on TLSSocket pairs.
      upstream.pipe(clientSocket, { end: false });
      clientSocket.pipe(upstream, { end: false });
    });
  }

  // ── Shared forward + capture logic ───────────────────────────────────────

  async _forward({ req, res, host, port, path, isHttps, connectAddress }) {
    const requestCapture = captureBody();
    const startMs = Date.now();
    const rawIp = req.socket?.remoteAddress || '';
    const clientIp = rawIp.replace(/^::ffff:/, '');
    const clientLabel = deriveDeviceLabel(clientIp, req.headers['user-agent']);

    // HTTPS must validate the real upstream, even though this proxy presents
    // its own certificate to the client on the inbound connection.
    const options = {
      hostname: connectAddress || host,
      port,
      path,
      method: req.method,
      headers: {
        ...stripHopByHopHeaders(req.headers),
        host: authorityHeader(host, port, isHttps ? 443 : 80),
      },
    };
    if (isHttps && !net.isIP(host)) options.servername = host;

    const lib = isHttps ? https : http;

    return new Promise((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        resolve();
      };
      const proxyReq = lib.request(options, (proxyRes) => {
        const responseCapture = captureBody();
        const passHeaders = stripHopByHopHeaders(proxyRes.headers);

        try {
          res.writeHead(proxyRes.statusCode, passHeaders);
        } catch {
          proxyRes.destroy();
          return finish();
        }

        proxyRes.on('data', (chunk) => responseCapture.add(chunk));
        proxyRes.on('end', () => {
          const duration = Date.now() - startMs;
          const contentType = proxyRes.headers['content-type'] || '';
          const contentEncoding = proxyRes.headers['content-encoding'] || '';

          const reqDecoded = requestCapture.decode(
            req.headers['content-type'],
            req.headers['content-encoding'] || '',
          );
          const resDecoded = responseCapture.decode(contentType, contentEncoding);

          const capture = {
            timestamp: Date.now(),
            method: req.method,
            url: `${isHttps ? 'https' : 'http'}://${host}${path}`,
            host,
            path,
            requestHeaders: req.headers,
            requestBody: reqDecoded.text,
            requestEncoding: reqDecoded.encoding,
            requestBodySize: requestCapture.size,
            responseStatus: proxyRes.statusCode,
            responseHeaders: proxyRes.headers,
            responseBody: resDecoded.text,
            responseEncoding: resDecoded.encoding,
            responseBodySize: responseCapture.size,
            contentType,
            duration,
            clientIp,
            clientLabel,
          };

          if (!this.paused) {
            try {
              const id = this.db.insertCapture(capture);
              capture.id = id;
              this.broadcast({ type: 'capture', data: this._serializeCapture(capture) });
            } catch (err) {
              console.error('[proxy] capture error:', err.message);
            }
          }

          finish();
        });

        proxyRes.on('error', (err) => { res.destroy?.(err); finish(); });
        proxyRes.on('aborted', () => { res.destroy?.(); finish(); });
        proxyRes.on('close', () => {
          if (!proxyRes.complete) res.destroy?.();
          finish();
        });
        proxyRes.pipe(res);
      });

      proxyReq.on('error', (err) => {
        if (!res.headersSent && !res.destroyed) {
          res.writeHead(502);
          res.end('Bad Gateway');
        } else {
          res.destroy?.(err);
        }
        finish();
      });

      proxyReq.setTimeout(120_000, () => proxyReq.destroy(new Error('Upstream timeout')));
      req.on('error', err => proxyReq.destroy(err));
      req.on('close', () => { if (req.aborted) proxyReq.destroy(); });
      res.on?.('close', () => { if (!res.writableEnded) proxyReq.destroy(); });
      res.on?.('error', err => { proxyReq.destroy(err); finish(); });

      // Forward the complete request with backpressure. Keep only a bounded
      // copy for the capture database; large uploads must never be truncated.
      req.on('data', chunk => requestCapture.add(chunk));
      req.pipe(proxyReq);
    });
  }

  _serializeCapture(c) {
    return {
      id: c.id,
      timestamp: c.timestamp,
      method: c.method,
      url: c.url,
      host: c.host,
      path: c.path,
      requestHeaders: c.requestHeaders,
      requestBodyPreview: typeof c.requestBody === 'string' ? c.requestBody.slice(0, 512) : '',
      requestEncoding: c.requestEncoding || 'identity',
      requestBodySize: c.requestBodySize || 0,
      responseStatus: c.responseStatus,
      responseHeaders: c.responseHeaders,
      responseBodyPreview: typeof c.responseBody === 'string' ? c.responseBody.slice(0, 512) : '',
      responseEncoding: c.responseEncoding || 'identity',
      responseBodySize: c.responseBodySize || 0,
      contentType: c.contentType,
      duration: c.duration,
      clientIp: c.clientIp,
      clientLabel: c.clientLabel,
    };
  }

  setPaused(val) { this.paused = val; }

  listen() {
    return new Promise((resolve, reject) => {
      this.server.listen(this.port, this.listenHost, (err) => {
        if (err) return reject(err);
        resolve(this.port);
      });
    });
  }

  close() {
    this.server.close();
    this._httpsHandler.close();
  }
}

module.exports = ProxyServer;
