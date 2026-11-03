'use strict';

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('path');
const os = require('os');
const net = require('net');
const QRCode = require('qrcode');
const db = require('../storage/db');
const certManager = require('../proxy/cert_manager');
const { buildClaudeExport } = require('../analyze');

const ACTION_HEADER = 'x-claude-intercept-action';
const EXPORT_MODES = new Set(['summary', 'api-docs', 'auth', 'full']);
const MAX_WS_BUFFERED_BYTES = 1024 * 1024;

function maxAnalysisCaptures(mode) {
  if (mode === 'full' || mode === 'auth') return 50;
  if (mode === 'api-docs') return 100;
  return 500;
}

const dashboardHtml = fs.readFileSync(path.join(__dirname, 'public/index.html'), 'utf8');
const inlineScript = dashboardHtml.match(/<script>([\s\S]*?)<\/script>/i);
if (!inlineScript) throw new Error('Dashboard script is missing');
const scriptHash = crypto.createHash('sha256').update(inlineScript[1]).digest('base64');

function getNetworkInfo() {
  const ifaces = os.networkInterfaces();
  let lanIp = null;
  let tailscaleIp = null;

  try {
    for (const [name, addrs] of Object.entries(ifaces)) {
      for (const iface of addrs) {
        if (iface.family !== 'IPv4' || iface.internal) continue;
        // Tailscale uses 100.x.x.x (CGNAT range) and the interface is named "tailscale0" or "utun" on macOS
        const isTailscale =
          name.toLowerCase().includes('tailscale') ||
          name.toLowerCase().startsWith('utun') ||
          iface.address.startsWith('100.');
        if (isTailscale && !tailscaleIp) {
          tailscaleIp = iface.address;
        } else if (!isTailscale && !lanIp) {
          lanIp = iface.address;
        }
      }
    }
  } catch {}

  return { lanIp: lanIp || '127.0.0.1', tailscaleIp };
}

function isLoopbackAddress(address) {
  return address === '::1' || /^127\./.test(address || '') ||
    /^::ffff:127\./i.test(address || '');
}

function canAccessDashboard(address, method, requestPath, lanEnabled) {
  if (isLoopbackAddress(address)) return true;
  // Phones only need to download the public CA certificate. Keep captures,
  // control routes, and the live WebSocket stream on the local machine even
  // when the proxy accepts traffic from the LAN.
  return lanEnabled && (method === 'GET' || method === 'HEAD') &&
    requestPath === '/api/cert';
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) return fallback;
  return Math.min(Math.max(number, minimum), maximum);
}

function validQueryStrings(query, limits) {
  return Object.entries(limits).every(([name, maxLength]) =>
    query[name] === undefined ||
    (typeof query[name] === 'string' && query[name].length <= maxLength));
}

function parseIds(value, maximum) {
  if (typeof value !== 'string') return null;
  const parts = value.split(',');
  if (!parts.length || parts.length > maximum) return null;
  const ids = parts.map(part => Number(part));
  if (parts.some((part, index) => !/^[1-9]\d*$/.test(part) ||
      !Number.isSafeInteger(ids[index]))) return null;
  return [...new Set(ids)];
}

function createUIServer({ uiPort = 7778, proxyPort = 7777, proxyInstance = null,
  uiHost = '127.0.0.1', proxyOwnerId = null }) {
  if (uiHost !== '127.0.0.1' && uiHost !== '0.0.0.0') {
    throw new Error('Dashboard host must be 127.0.0.1 or 0.0.0.0');
  }
  const lanEnabled = uiHost === '0.0.0.0';

  // A browser page can reach localhost even when the dashboard only listens
  // there. Restrict Host to IP literals/localhost to prevent DNS rebinding,
  // and require browser requests to come from this dashboard's own origin.
  function allowedHost(authority) {
    if (typeof authority !== 'string' || /[\/?#@]/.test(authority)) return false;
    try {
      const parsed = new URL(`http://${authority}`);
      if (parsed.host.toLowerCase() !== authority.toLowerCase()) return false;
      const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
      return hostname === 'localhost' || hostname === '127.0.0.1' ||
        (lanEnabled && net.isIP(hostname) !== 0);
    } catch {
      return false;
    }
  }

  function allowedOrigin(req) {
    if (req.path === '/api/cert' && (req.method === 'GET' || req.method === 'HEAD')) {
      return true; // Public CA certificate download from a phone or QR scanner.
    }
    const fetchSite = req.headers['sec-fetch-site'];
    if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') return false;
    const origin = req.headers.origin;
    if (!origin) return true; // CLI clients do not send Origin.
    try {
      const parsed = new URL(origin);
      return parsed.protocol === 'http:' &&
        parsed.host.toLowerCase() === req.headers.host.toLowerCase();
    } catch {
      return false;
    }
  }

  const app = express();
  // Preserve the query shape used by our validators: bracketed and repeated
  // parameters must parse as arrays so they are rejected as non-scalar input.
  app.set('query parser', 'extended');
  app.use((req, res, next) => {
    res.set({
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
    });
    if (!allowedHost(req.headers.host) || !allowedOrigin(req) ||
        (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers[ACTION_HEADER] !== '1') ||
        !canAccessDashboard(req.socket.remoteAddress, req.method, req.path, lanEnabled)) {
      return res.status(403).end();
    }
    res.set('Content-Security-Policy',
      `default-src 'self'; script-src 'sha256-${scriptHash}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://${req.headers.host}; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'`);
    next();
  });
  app.use(express.json());

  const httpServer = http.createServer(app);
  const dashboardPort = () => httpServer.address()?.port || uiPort;
  const wss = new WebSocket.Server({
    server: httpServer,
    maxPayload: 1024,
    verifyClient: ({ req }) => isLoopbackAddress(req.socket.remoteAddress) &&
      allowedHost(req.headers.host) && allowedOrigin(req),
  });

  const clients = new Set();
  wss.on('connection', (ws) => {
    clients.add(ws);
    ws.on('close', () => clients.delete(ws));
    ws.on('error', () => clients.delete(ws));
    // Send current stats on connect
    ws.send(JSON.stringify({ type: 'stats', data: db.getStats() }));
  });

  function broadcast(obj) {
    const msg = JSON.stringify(obj);
    const messageBytes = Buffer.byteLength(msg);
    for (const ws of clients) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      if (ws.bufferedAmount + messageBytes > MAX_WS_BUFFERED_BYTES) {
        ws.terminate();
        clients.delete(ws);
        continue;
      }
      ws.send(msg, err => {
        if (err) {
          ws.terminate();
          clients.delete(ws);
        }
      });
    }
  }

  // ── REST API ──────────────────────────────────────────────────────────────

  app.get('/api/status', (req, res) => {
    const { lanIp, tailscaleIp } = getNetworkInfo();
    const port = dashboardPort();
    const platform = os.platform();
    let de = null;
    if (platform === 'linux') {
      try { de = require('../system_proxy').detectLinuxDe(); } catch {}
    }
    res.json({
      proxy: { port: proxyPort, running: true },
      ui: { port, host: uiHost, lanEnabled },
      platform,
      de,
      lanIp,
      tailscaleIp,
      certUrl: `http://${lanEnabled ? lanIp : '127.0.0.1'}:${port}/api/cert`,
      tailscaleCertUrl: lanEnabled && tailscaleIp ? `http://${tailscaleIp}:${port}/api/cert` : null,
      stats: db.getStats(),
    });
  });

  // QR code for any URL (used for iOS cert install)
  app.get('/api/qr', async (req, res) => {
    const { url } = req.query;
    if (typeof url !== 'string' || !url || url.length > 2048) {
      return res.status(400).json({ error: 'url must be a string of at most 2048 characters' });
    }
    try {
      const dataUrl = await QRCode.toDataURL(url, {
        width: 220,
        margin: 2,
        color: { dark: '#e6edf3', light: '#161b22' },
      });
      res.json({ dataUrl });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/captures', (req, res) => {
    if (!validQueryStrings(req.query, {
      host: 256, method: 32, status: 16, contentType: 256, search: 2048,
      hasAuth: 5, device: 256, afterId: 20, limit: 20, offset: 20,
    })) return res.status(400).json({ error: 'Invalid capture query' });
    const { host, method, status, contentType, search, hasAuth, device, afterId, limit, offset } = req.query;
    const parsedAfterId = afterId === undefined ? undefined : Number(afterId);
    if (afterId !== undefined && (!Number.isSafeInteger(parsedAfterId) || parsedAfterId < 1)) {
      return res.status(400).json({ error: 'afterId must be a positive integer' });
    }
    const result = db.queryCaptures({
      host,
      method,
      status,
      contentType,
      search,
      hasAuth: hasAuth === 'true',
      device,
      afterId: parsedAfterId,
      limit: boundedInteger(limit, 100, 1, 500),
      offset: boundedInteger(offset, 0, 0, Number.MAX_SAFE_INTEGER),
      listOnly: true,
    });
    res.json(result);
  });

  app.get('/api/devices', (req, res) => {
    res.json(db.getDevices());
  });

  app.get('/api/captures/:id', (req, res) => {
    const id = parseIds(req.params.id, 1)?.[0];
    if (!id) return res.status(400).json({ error: 'Invalid capture ID' });
    const capture = db.getCaptureById(id);
    if (!capture) return res.status(404).json({ error: 'Not found' });
    res.json(capture);
  });

  app.delete('/api/captures', (req, res) => {
    db.clearCaptures();
    broadcast({ type: 'cleared' });
    res.json({ ok: true });
  });

  app.delete('/api/captures/batch', (req, res) => {
    const ids = req.body?.ids;
    if (!Array.isArray(ids) || !ids.length || ids.length > 500 ||
        !ids.every(id => Number.isSafeInteger(id) && id > 0)) {
      return res.status(400).json({ error: 'ids must contain 1 to 500 positive integers' });
    }
    db.deleteCaptures(ids);
    broadcast({ type: 'deleted', data: { ids } });
    res.json({ ok: true, deleted: ids.length });
  });

  app.get('/api/analyze', (req, res) => {
    if (!validQueryStrings(req.query, { ids: 10000, host: 256, mode: 16, limit: 20 })) {
      return res.status(400).json({ error: 'Invalid analysis query' });
    }
    const { ids, host, mode = 'summary' } = req.query;
    if (!EXPORT_MODES.has(mode)) return res.status(400).json({ error: 'Invalid export mode' });
    const maximum = maxAnalysisCaptures(mode);
    const limit = req.query.limit === undefined ? Math.min(100, maximum) : Number(req.query.limit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > maximum) {
      return res.status(400).json({ error: `limit must be an integer from 1 to ${maximum}` });
    }
    let captures;
    const summaryOnly = mode === 'summary';

    if (ids !== undefined) {
      const parsedIds = parseIds(ids, maximum);
      if (!parsedIds) return res.status(400).json({ error: `Select at most ${maximum} valid capture IDs` });
      captures = parsedIds.map(id => db.getCaptureById(id, { summaryOnly })).filter(Boolean);
    } else {
      const q = db.queryCaptures({ host, limit, summaryOnly });
      captures = q.rows;
    }

    if (!captures.length) return res.status(400).json({ error: 'No captures found' });

    const output = buildClaudeExport(captures, mode);
    res.json({ output, count: captures.length });
  });

  app.get('/api/cert', (req, res) => {
    const certPem = certManager.getCACertPem();
    res.setHeader('Content-Type', 'application/x-pem-file');
    res.setHeader('Content-Disposition', 'attachment; filename="claude-intercept-ca.crt"');
    res.send(certPem);
  });

  app.get('/api/setup/:platform', (req, res) => {
    const { getSetupInstructions } = require('../setup_wizard');
    const { lanIp, tailscaleIp } = getNetworkInfo();
    res.json(getSetupInstructions(req.params.platform, proxyPort, lanIp, tailscaleIp, {
      uiPort: dashboardPort(), lanEnabled,
    }));
  });

  // System proxy toggle (local machine only — localhost access)
  app.post('/api/proxy/on', (req, res) => {
    const sysProxy = require('../system_proxy');
    const result = sysProxy.enable(proxyPort, { ownerId: proxyOwnerId });
    if (result.error) return res.status(409).json(result);
    broadcast({ type: 'sysProxyChanged', data: { enabled: true } });
    res.json(result);
  });

  app.post('/api/proxy/off', (req, res) => {
    const sysProxy = require('../system_proxy');
    const result = sysProxy.disable({ ownerId: proxyOwnerId });
    if (result.error) return res.status(409).json(result);
    if (result.deactivated?.length) broadcast({ type: 'sysProxyChanged', data: { enabled: false } });
    res.json(result);
  });

  app.get('/api/proxy/status', (req, res) => {
    const sysProxy = require('../system_proxy');
    res.json(sysProxy.status());
  });

  // Linux automated CA trust (dashboard path → pkexec GUI prompt).
  app.post('/api/trust/linux', (req, res) => {
    try {
      const { trustCertLinux } = require('../setup_wizard');
      res.json(trustCertLinux());
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/untrust/linux', (req, res) => {
    try {
      const { untrustCertLinux } = require('../setup_wizard');
      res.json(untrustCertLinux());
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/capture/pause', (req, res) => {
    if (proxyInstance) proxyInstance.setPaused(true);
    broadcast({ type: 'capturePaused' });
    res.json({ ok: true, paused: true });
  });

  app.post('/api/capture/resume', (req, res) => {
    if (proxyInstance) proxyInstance.setPaused(false);
    broadcast({ type: 'captureResumed' });
    res.json({ ok: true, paused: false });
  });

  app.get('/api/capture/state', (req, res) => {
    res.json({ paused: proxyInstance ? proxyInstance.paused : false });
  });

  // Serve SPA for all other routes
  app.get('/{*splat}', (req, res) => {
    res.type('html').send(dashboardHtml);
  });

  function listen() {
    return new Promise((resolve, reject) => {
      httpServer.once('error', reject);
      httpServer.listen(uiPort, uiHost, () => {
        httpServer.off('error', reject);
        resolve(httpServer.address().port);
      });
    });
  }

  function close() {
    return new Promise((resolve, reject) => {
      httpServer.close(err => err ? reject(err) : resolve());
    });
  }

  return { broadcast, listen, close, app, httpServer };
}

module.exports = { createUIServer, canAccessDashboard };
