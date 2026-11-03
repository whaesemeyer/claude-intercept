'use strict';

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const os = require('os');
const net = require('net');
const QRCode = require('qrcode');
const db = require('../storage/db');
const certManager = require('../proxy/cert_manager');
const { buildClaudeExport } = require('../analyze');

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

function createUIServer({ uiPort = 7778, proxyPort = 7777, proxyInstance = null, uiHost = '127.0.0.1' }) {
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
  app.use((req, res, next) => {
    if (!allowedHost(req.headers.host) || !allowedOrigin(req)) {
      return res.status(403).end();
    }
    next();
  });
  app.use(express.json());
  app.use(express.static(path.join(__dirname, 'public')));

  const httpServer = http.createServer(app);
  const dashboardPort = () => httpServer.address()?.port || uiPort;
  const wss = new WebSocket.Server({
    server: httpServer,
    verifyClient: ({ req }) => allowedHost(req.headers.host) && allowedOrigin(req),
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
    for (const ws of clients) {
      if (ws.readyState === WebSocket.OPEN) ws.send(msg);
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
    if (!url) return res.status(400).json({ error: 'url required' });
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
    const { host, method, status, contentType, search, hasAuth, device, afterId, limit, offset } = req.query;
    const result = db.queryCaptures({
      host,
      method,
      status,
      contentType,
      search,
      hasAuth: hasAuth === 'true',
      device,
      afterId: afterId ? Number(afterId) : undefined,
      limit: Math.min(Number(limit) || 100, 500),
      offset: Number(offset) || 0,
    });
    res.json(result);
  });

  app.get('/api/devices', (req, res) => {
    res.json(db.getDevices());
  });

  app.get('/api/captures/:id', (req, res) => {
    const capture = db.getCaptureById(Number(req.params.id));
    if (!capture) return res.status(404).json({ error: 'Not found' });
    res.json(capture);
  });

  app.delete('/api/captures', (req, res) => {
    db.clearCaptures();
    broadcast({ type: 'cleared' });
    res.json({ ok: true });
  });

  app.delete('/api/captures/batch', (req, res) => {
    const { ids } = req.body;
    if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'ids required' });
    db.deleteCaptures(ids);
    broadcast({ type: 'deleted', data: { ids } });
    res.json({ ok: true, deleted: ids.length });
  });

  app.get('/api/analyze', (req, res) => {
    const { ids, host, mode = 'api-docs' } = req.query;
    let captures;

    if (ids) {
      captures = ids
        .split(',')
        .map((id) => db.getCaptureById(Number(id)))
        .filter(Boolean);
    } else {
      const q = db.queryCaptures({ host, limit: 200 });
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
    const result = sysProxy.enable(proxyPort);
    broadcast({ type: 'sysProxyChanged', data: { enabled: true } });
    res.json(result);
  });

  app.post('/api/proxy/off', (req, res) => {
    const sysProxy = require('../system_proxy');
    const result = sysProxy.disable();
    broadcast({ type: 'sysProxyChanged', data: { enabled: false } });
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
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
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

module.exports = { createUIServer };
