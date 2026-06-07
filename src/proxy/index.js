'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const certManager = require('./cert_manager');
const { tryDecodeBody, MAX_BODY } = require('./body');
const { WsFrameParser, OPCODES, parseHandshakeResponse } = require('./ws_frame');

// Per-connection WebSocket capture caps. High-throughput sockets (Slack
// presence, Discord gateway) can produce thousands of frames/min, so we cap
// both the number of stored frames and each frame's stored payload to keep the
// DB from ballooning. PING/PONG control frames are counted but not stored.
const WS_MAX_FRAMES = 5000;          // stored frames per connection
const WS_MAX_PAYLOAD_CHARS = 64 * 1024; // stored chars per frame (text or base64)

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
    this._httpsHandler.on('upgrade', (req, socket, head) => this._handleWebSocketUpgrade(req, socket, head));
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

  // ── WebSocket upgrade (wss://) — transparent tunnel + frame capture ───────
  //
  // Cert-pinned single-page apps (Spotify web, Discord) require a working
  // WebSocket upgrade or they hang at the loading state. Node's http.Server
  // emits 'upgrade' instead of 'request' when a client sends Upgrade: websocket.
  // We forward bytes verbatim AND, beside the shuttle, run an RFC 6455 framer
  // (./ws_frame.js) over both directions so the dashboard can replay what
  // actually flowed through the socket — not just that a WS connection happened.
  //
  // The connection-level row (method 'WS') is inserted up front so individual
  // frames have a connection_id to link to; it's updated with the final
  // duration + summary when the socket closes.

  _handleWebSocketUpgrade(req, clientSocket, head) {
    const tlsSocket = req.socket;
    const host = tlsSocket._interceptHost || req.headers.host?.split(':')[0] || 'unknown';
    const port = tlsSocket._interceptPort || 443;
    const startMs = Date.now();
    const rawIp = clientSocket.remoteAddress || '';
    const clientIp = rawIp.replace(/^::ffff:/, '');
    const clientLabel = deriveDeviceLabel(clientIp, req.headers['user-agent']);

    // Insert the connection row immediately so frames can reference it. If
    // capture is paused we leave connectionId null and skip persistence.
    let connectionId = null;
    if (!this.paused) {
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
        responseStatus: 101,
        responseHeaders: {},
        responseBody: '[WebSocket — capturing frames…]',
        responseEncoding: 'identity',
        responseBodySize: 0,
        contentType: 'websocket',
        duration: 0,
        clientIp,
        clientLabel,
      };
      try {
        connectionId = this.db.insertCapture(capture);
        capture.id = connectionId;
        this.broadcast({ type: 'capture', data: this._serializeCapture(capture) });
      } catch (err) {
        console.error('[proxy] WS capture error:', err.message);
      }
    }

    let frameCount = 0;
    let droppedFrames = 0;
    let pingPong = 0;

    const recordFrame = (direction, msg) => {
      if (this.paused || connectionId === null) return;

      // Control frames: count ping/pong but keep them out of the timeline;
      // close frames are worth keeping (status code + reason).
      if (msg.isControl) {
        if (msg.opcode === OPCODES.PING || msg.opcode === OPCODES.PONG) {
          pingPong++;
          return;
        }
      }

      if (frameCount >= WS_MAX_FRAMES) {
        droppedFrames++;
        return;
      }

      let payload;
      let isText;
      if (msg.isText) {
        payload = msg.payload.toString('utf8');
        isText = true;
      } else if (msg.opcode === OPCODES.BINARY || msg.compressed) {
        // Binary frames, and deflated frames the framer couldn't inflate
        // (context-takeover streams), are stored as base64.
        payload = msg.payload.toString('base64');
        isText = false;
      } else {
        // close (and any other non-text control we chose to keep) → hex
        payload = msg.payload.toString('hex');
        isText = false;
      }

      let truncated = msg.truncated;
      if (payload.length > WS_MAX_PAYLOAD_CHARS) {
        payload = payload.slice(0, WS_MAX_PAYLOAD_CHARS);
        truncated = true;
      }

      const frame = {
        connectionId,
        timestamp: Date.now(),
        direction,
        opcode: msg.opcode,
        isText,
        payload,
        payloadSize: msg.payload.length,
        truncated,
        compressed: !!msg.compressed,
      };
      try {
        frame.id = this.db.insertWsFrame(frame);
        frameCount++;
        this.broadcast({ type: 'wsFrame', data: frame });
      } catch (err) {
        console.error('[proxy] WS frame error:', err.message);
      }
    };

    // The real handshake status (e.g. 101, or 403 when Cloudflare rejects the
    // upgrade) is read from the upstream's response head once it arrives.
    let negotiatedStatus = null;

    let finalized = false;
    const finalize = (status) => {
      if (finalized) return;
      finalized = true;
      if (connectionId === null) return;
      const duration = Date.now() - startMs;
      // Prefer the real handshake status; fall back to the close/error status.
      const finalStatus = negotiatedStatus !== null ? negotiatedStatus : status;
      const parts = [`${frameCount} frame${frameCount === 1 ? '' : 's'}`];
      if (droppedFrames) parts.push(`${droppedFrames} dropped (cap)`);
      if (pingPong) parts.push(`${pingPong} ping/pong`);
      parts.push(`${duration}ms`);
      const summary = `[WebSocket — ${parts.join(', ')}]`;
      try {
        this.db.finalizeWsCapture(connectionId, {
          duration,
          responseBody: summary,
          responseStatus: finalStatus,
        });
        this.broadcast({
          type: 'wsClosed',
          data: { id: connectionId, duration, frameCount, responseStatus: finalStatus, responseBody: summary },
        });
      } catch (err) {
        console.error('[proxy] WS finalize error:', err.message);
      }
    };

    // Force HTTP/1.1 — WebSocket-over-HTTP/2 (RFC 8441) is a separate path
    // most servers don't enable, and the Upgrade header semantics only work
    // over h1.
    const upstream = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      ALPNProtocols: ['http/1.1'],
    });

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
      try { upstream.setNoDelay?.(true); } catch {}

      const reqLine = `${req.method} ${req.url} HTTP/1.1\r\n`;
      const headerBlock = Object.entries(req.headers)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
        .join('\r\n');
      try {
        upstream.write(reqLine + headerBlock + '\r\n\r\n');
        if (head && head.length > 0) upstream.write(head);
      } catch {
        return cleanup(0);
      }

      // One framer per direction. Client→server frames are masked, server→
      // client are not — the parser auto-detects from the MASK bit. We never
      // touch the bytes being shuttled; the parser only observes copies.
      //
      // The framers are created lazily once we've parsed the upstream's
      // handshake response, because whether permessage-deflate (RFC 7692) is
      // active — and therefore whether frame payloads are deflated — is only
      // known from the negotiated `Sec-WebSocket-Extensions` header.
      let clientToServer = null;
      let serverToClient = null;

      // The first bytes the upstream sends are the `HTTP/1.1 101 Switching
      // Protocols` response, not a WS frame. Strip everything up to and
      // including the header terminator before feeding the framer; the raw
      // bytes are still forwarded to the client untouched.
      let handshakeStripped = false;
      let handshakeBuf = Buffer.alloc(0);
      // Client frames that arrive before the handshake is parsed (rare) are
      // held here and replayed once the client→server framer exists.
      let pendingClient = [];

      const initFramers = (permessageDeflate) => {
        clientToServer = new WsFrameParser({ permessageDeflate });
        serverToClient = new WsFrameParser({ permessageDeflate });
        for (const buf of pendingClient) {
          for (const msg of clientToServer.push(buf)) recordFrame('client→server', msg);
        }
        pendingClient = null;
      };

      // Manual data shuttle (instead of stream.pipe). pipe()'s default
      // end-on-end behavior turns one side's FIN into a write-side close
      // on the other, which on TLSSocket pairs has been observed to
      // truncate WS frames mid-flight.
      upstream.on('data', (chunk) => {
        try { clientSocket.write(chunk); } catch {}
        try {
          let frameData = chunk;
          if (!handshakeStripped) {
            handshakeBuf = Buffer.concat([handshakeBuf, chunk]);
            const idx = handshakeBuf.indexOf('\r\n\r\n');
            if (idx === -1) return; // still reading the handshake response
            handshakeStripped = true;
            const head101 = parseHandshakeResponse(handshakeBuf.subarray(0, idx));
            negotiatedStatus = head101.status || 101;
            frameData = handshakeBuf.subarray(idx + 4);
            handshakeBuf = null;
            initFramers(head101.permessageDeflate);
          }
          for (const msg of serverToClient.push(frameData)) {
            recordFrame('server→client', msg);
          }
        } catch (err) {
          console.error('[proxy] WS parse error (s→c):', err.message);
        }
      });
      clientSocket.on('data', (chunk) => {
        try { upstream.write(chunk); } catch {}
        try {
          if (!clientToServer) { pendingClient.push(Buffer.from(chunk)); return; }
          for (const msg of clientToServer.push(chunk)) {
            recordFrame('client→server', msg);
          }
        } catch (err) {
          console.error('[proxy] WS parse error (c→s):', err.message);
        }
      });

      // Any client bytes that arrived alongside the upgrade headers (rare —
      // clients usually wait for the 101) are buffered until the framer exists.
      if (head && head.length > 0) pendingClient.push(Buffer.from(head));
    });
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
          const contentEncoding = proxyRes.headers['content-encoding'] || '';

          const reqDecoded = tryDecodeBody(
            reqBody,
            req.headers['content-type'],
            req.headers['content-encoding'] || '',
          );
          const resDecoded = tryDecodeBody(resBody, contentType, contentEncoding);

          const capture = {
            timestamp: Date.now(),
            method: req.method,
            url: `${isHttps ? 'https' : 'http'}://${host}${path}`,
            host,
            path,
            requestHeaders: req.headers,
            requestBody: reqDecoded.text,
            requestEncoding: reqDecoded.encoding,
            requestBodySize: reqDecoded.originalSize,
            responseStatus: proxyRes.statusCode,
            responseHeaders: proxyRes.headers,
            responseBody: resDecoded.text,
            responseEncoding: resDecoded.encoding,
            responseBodySize: resDecoded.originalSize,
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
