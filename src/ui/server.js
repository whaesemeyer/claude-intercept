'use strict';

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const os = require('os');
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

function createUIServer({ uiPort = 7778, proxyPort = 7777, proxyInstance = null }) {
  const app = express();
  app.use(express.json());
  app.use(express.static(path.join(__dirname, 'public')));

  const httpServer = http.createServer(app);
  const wss = new WebSocket.Server({ server: httpServer });

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
    res.json({
      proxy: { port: proxyPort, running: true },
      ui: { port: uiPort },
      lanIp,
      tailscaleIp,
      certUrl: `http://${lanIp}:${uiPort}/api/cert`,
      tailscaleCertUrl: tailscaleIp ? `http://${tailscaleIp}:${uiPort}/api/cert` : null,
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
    res.json(getSetupInstructions(req.params.platform, proxyPort, lanIp, tailscaleIp));
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
      httpServer.listen(uiPort, '0.0.0.0', (err) => {
        if (err) return reject(err);
        resolve(uiPort);
      });
    });
  }

  return { broadcast, listen, app };
}

module.exports = { createUIServer };
