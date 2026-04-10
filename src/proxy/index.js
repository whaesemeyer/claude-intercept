'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const certManager = require('./cert_manager');

// Max body size to capture (1MB)
const MAX_BODY = 1024 * 1024;

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

function tryDecodeBody(buffer, contentType = '') {
  if (!buffer || buffer.length === 0) return '';
  if (buffer.length > MAX_BODY) return `<binary ${buffer.length} bytes — truncated>`;

  const ct = contentType.toLowerCase();
  const isText =
    ct.includes('json') ||
    ct.includes('text') ||
    ct.includes('xml') ||
    ct.includes('javascript') ||
    ct.includes('form') ||
    ct.includes('graphql') ||
    buffer.length < 4096; // short payloads: try text anyway

  if (!isText) return `<binary ${buffer.length} bytes>`;

  try {
    return buffer.toString('utf8');
  } catch {
    return `<binary ${buffer.length} bytes>`;
  }
}

function collectBody(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    stream.on('data', (chunk) => {
      total += chunk.length;
      if (total <= MAX_BODY + chunk.length) chunks.push(chunk);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

class ProxyServer {
  constructor({ port = 8080, db, broadcast }) {
    this.port = port;
    this.db = db;
    this.broadcast = broadcast; // fn(eventObj) → WebSocket broadcast
    this.paused = false;

    // Handles plain HTTP proxy requests
    this.server = http.createServer((req, res) => this._handleHTTP(req, res));
    this.server.on('connect', (req, socket, head) => this._handleCONNECT(req, socket, head));
    this.server.on('error', (err) => console.error('[proxy] server error:', err.message));

    // Handles HTTPS after TLS unwrapping — all CONNECT tunnels land here
    this._httpsHandler = new http.Server((req, res) => this._handleHTTPS(req, res));
    this._httpsHandler.on('error', () => {}); // suppress
  }

  // ── Plain HTTP forwarding ─────────────────────────────────────────────────

  async _handleHTTP(req, res) {
    let targetUrl;
    try {
      targetUrl = new URL(req.url);
    } catch {
      res.writeHead(400);
      return res.end('Bad Request');
    }

    await this._forward({
      req,
      res,
      host: targetUrl.hostname,
      port: Number(targetUrl.port) || 80,
      path: targetUrl.pathname + targetUrl.search,
      isHttps: false,
    });
  }

  // ── CONNECT tunnel (HTTPS) ────────────────────────────────────────────────

  _handleCONNECT(req, clientSocket, head) {
    const [host, portStr] = req.url.split(':');
    const port = parseInt(portStr, 10) || 443;

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    let certInfo;
    try {
      certInfo = certManager.getCertForHost(host);
    } catch (err) {
      clientSocket.destroy();
      return;
    }

    // Wrap the plain socket in a TLS server socket
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      cert: certInfo.certPem,
      key: certInfo.keyPem,
      rejectUnauthorized: false,
    });

    tlsSocket._interceptHost = host;
    tlsSocket._interceptPort = port;

    tlsSocket.on('error', () => {}); // cert pinning, client errors — ignore
    clientSocket.on('error', () => {});

    this._httpsHandler.emit('connection', tlsSocket);

    if (head && head.length > 0) tlsSocket.push(head);
  }

  // ── HTTPS (post-TLS) forwarding ───────────────────────────────────────────

  async _handleHTTPS(req, res) {
    const socket = req.socket;
    const host = socket._interceptHost || req.headers.host?.split(':')[0] || 'unknown';
    const port = socket._interceptPort || 443;

    await this._forward({ req, res, host, port, path: req.url, isHttps: true });
  }

  // ── Shared forward + capture logic ───────────────────────────────────────

  async _forward({ req, res, host, port, path, isHttps }) {
    const reqBody = await collectBody(req);
    const startMs = Date.now();
    const rawIp = req.socket?.remoteAddress || '';
    const clientIp = rawIp.replace(/^::ffff:/, '');
    const clientLabel = deriveDeviceLabel(clientIp, req.headers['user-agent']);

    const options = {
      hostname: host,
      port,
      path,
      method: req.method,
      headers: { ...req.headers, host },
      rejectUnauthorized: false,
    };

    const lib = isHttps ? https : http;

    return new Promise((resolve) => {
      const proxyReq = lib.request(options, async (proxyRes) => {
        const resChunks = [];
        const passHeaders = { ...proxyRes.headers };

        res.writeHead(proxyRes.statusCode, passHeaders);

        proxyRes.on('data', (chunk) => {
          resChunks.push(chunk);
          res.write(chunk);
        });

        proxyRes.on('end', () => {
          res.end();
          const duration = Date.now() - startMs;
          const resBody = Buffer.concat(resChunks);
          const contentType = proxyRes.headers['content-type'] || '';

          const capture = {
            timestamp: Date.now(),
            method: req.method,
            url: `${isHttps ? 'https' : 'http'}://${host}${path}`,
            host,
            path,
            requestHeaders: req.headers,
            requestBody: tryDecodeBody(reqBody, req.headers['content-type']),
            responseStatus: proxyRes.statusCode,
            responseHeaders: proxyRes.headers,
            responseBody: tryDecodeBody(resBody, contentType),
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

          resolve();
        });

        proxyRes.on('error', () => { res.end(); resolve(); });
      });

      proxyReq.on('error', (err) => {
        if (!res.headersSent) {
          res.writeHead(502);
          res.end(`Proxy error: ${err.message}`);
        }
        resolve();
      });

      if (reqBody.length > 0) proxyReq.write(reqBody);
      proxyReq.end();
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
      responseStatus: c.responseStatus,
      responseHeaders: c.responseHeaders,
      responseBodyPreview: typeof c.responseBody === 'string' ? c.responseBody.slice(0, 512) : '',
      contentType: c.contentType,
      duration: c.duration,
      clientIp: c.clientIp,
      clientLabel: c.clientLabel,
    };
  }

  setPaused(val) { this.paused = val; }

  listen() {
    return new Promise((resolve, reject) => {
      this.server.listen(this.port, '0.0.0.0', (err) => {
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
