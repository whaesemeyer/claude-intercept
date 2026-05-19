'use strict';

/**
 * Manages OS-level system proxy settings so the local machine's traffic
 * is routed through claude-intercept automatically.
 *
 * Supported: macOS (networksetup), Linux (gsettings/env), Windows (reg)
 */

const { execSync, spawnSync } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');

// Run a shell script with macOS admin elevation (GUI password prompt via osascript)
function macRunAdmin(script) {
  const tmpFile = path.join(os.tmpdir(), `ci_proxy_${Date.now()}.sh`);
  fs.writeFileSync(tmpFile, `#!/bin/sh\n${script}\n`, { mode: 0o700 });
  try {
    execSync(`osascript -e 'do shell script "${tmpFile}" with administrator privileges'`, { stdio: 'pipe' });
    return { ok: true };
  } catch (err) {
    const msg = (err.stderr || err.message || '').toString();
    if (msg.includes('User canceled')) return { ok: false, error: 'Cancelled by user' };
    return { ok: false, error: 'Permission denied — try running with sudo' };
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }
}

// ── macOS ─────────────────────────────────────────────────────────────────────

function macGetActiveServices() {
  try {
    const out = execSync('networksetup -listallnetworkservices 2>/dev/null', { encoding: 'utf8' });
    return out
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('An asterisk') && l !== '');
  } catch {
    return ['Wi-Fi', 'Ethernet'];
  }
}

function macProxyOn(port) {
  const services = macGetActiveServices();
  const errors = [];
  const activated = [];

  for (const svc of services) {
    const script = [
      `networksetup -setwebproxy "${svc}" 127.0.0.1 ${port}`,
      `networksetup -setsecurewebproxy "${svc}" 127.0.0.1 ${port}`,
      `networksetup -setwebproxystate "${svc}" on`,
      `networksetup -setsecurewebproxystate "${svc}" on`,
    ].join('\n');

    // Try without elevation first (works when already running as admin)
    let ok = false;
    try {
      execSync(`networksetup -setwebproxy "${svc}" 127.0.0.1 ${port}`, { stdio: 'pipe' });
      execSync(`networksetup -setsecurewebproxy "${svc}" 127.0.0.1 ${port}`, { stdio: 'pipe' });
      execSync(`networksetup -setwebproxystate "${svc}" on`, { stdio: 'pipe' });
      execSync(`networksetup -setsecurewebproxystate "${svc}" on`, { stdio: 'pipe' });
      ok = true;
    } catch {
      // Need elevation — prompt via macOS GUI password dialog
      const result = macRunAdmin(script);
      ok = result.ok;
      if (!result.ok) errors.push(`${svc}: ${result.error}`);
    }
    if (ok) activated.push(svc);
  }

  return { activated, errors };
}

function macProxyOff() {
  const services = macGetActiveServices();
  const deactivated = [];
  const errors = [];

  for (const svc of services) {
    const script = [
      `networksetup -setwebproxystate "${svc}" off`,
      `networksetup -setsecurewebproxystate "${svc}" off`,
    ].join('\n');

    let ok = false;
    try {
      execSync(`networksetup -setwebproxystate "${svc}" off`, { stdio: 'pipe' });
      execSync(`networksetup -setsecurewebproxystate "${svc}" off`, { stdio: 'pipe' });
      ok = true;
    } catch {
      const result = macRunAdmin(script);
      ok = result.ok;
      if (!result.ok) errors.push(`${svc}: ${result.error}`);
    }
    if (ok) deactivated.push(svc);
  }

  return { deactivated, errors };
}

function macProxyStatus() {
  const services = macGetActiveServices();
  const results = [];

  for (const svc of services) {
    try {
      const http = execSync(`networksetup -getwebproxy "${svc}" 2>/dev/null`, { encoding: 'utf8' });
      const https = execSync(`networksetup -getsecurewebproxy "${svc}" 2>/dev/null`, { encoding: 'utf8' });
      const httpEnabled = /Enabled: Yes/i.test(http);
      const httpsEnabled = /Enabled: Yes/i.test(https);
      const serverMatch = http.match(/Server: (.+)/);
      const portMatch = http.match(/Port: (\d+)/);
      results.push({
        service: svc,
        httpEnabled,
        httpsEnabled,
        server: serverMatch?.[1]?.trim() || '',
        port: portMatch?.[1] ? parseInt(portMatch[1], 10) : 0,
        pointsHere: httpEnabled && serverMatch?.[1]?.trim() === '127.0.0.1',
      });
    } catch {}
  }

  return results;
}

// ── Linux ─────────────────────────────────────────────────────────────────────

// Zero-dependency PATH scan: true if `bin` is an executable file on $PATH.
// Avoids a hard dependency on the external `which` binary (absent in minimal
// containers), which otherwise silently broke KDE config + elevation probes.
function binExists(bin) {
  const PATH = (process.env.PATH || '').split(':').filter(Boolean);
  return PATH.some(d => {
    try {
      fs.accessSync(path.join(d, bin), fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

// Pure: the env-var export lines (reused by enable + tests).
function linuxEnvLines(port) {
  return [
    `export http_proxy=http://127.0.0.1:${port}`,
    `export https_proxy=http://127.0.0.1:${port}`,
    `export HTTP_PROXY=http://127.0.0.1:${port}`,
    `export HTTPS_PROXY=http://127.0.0.1:${port}`,
    `export no_proxy=localhost,127.0.0.1`,
  ];
}

// Pure: strip surrounding quotes / parse a `gsettings get` scalar or array literal.
//   "'manual'"        → "manual"
//   "7777"            → 7777
//   "['localhost']"   → ["localhost"]
//   "@as []"          → []
function parseGsettingsValue(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (s === '' ) return '';
  if (s === '@as []' || s === '[]') return [];
  if (/^@as\s+/.test(s)) return parseGsettingsValue(s.replace(/^@as\s+/, ''));
  if (s[0] === '[' && s[s.length - 1] === ']') {
    const inner = s.slice(1, -1).trim();
    if (inner === '') return [];
    return inner
      .split(',')
      .map(v => v.trim())
      .map(v => v.replace(/^'(.*)'$/s, '$1').replace(/^"(.*)"$/s, '$1'));
  }
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (s === 'true') return true;
  if (s === 'false') return false;
  return s.replace(/^'(.*)'$/s, '$1').replace(/^"(.*)"$/s, '$1');
}

// Pure: collapse parsed gsettings values into the shared services[] entry shape.
function linuxStatusFromValues({ mode, httpHost, httpPort, httpsHost, service = 'GNOME' } = {}) {
  const manual = mode === 'manual';
  const server = httpHost || '';
  const port = Number.isFinite(httpPort) ? httpPort : (parseInt(httpPort, 10) || 0);
  const httpEnabled = manual && !!server;
  const httpsEnabled = manual && !!(httpsHost || server);
  return {
    service,
    httpEnabled,
    httpsEnabled,
    server,
    port,
    pointsHere: httpEnabled && server === '127.0.0.1',
  };
}

// Detect the desktop environment. 'gnome' if the gsettings proxy schema
// resolves, 'kde' if kwriteconfig{6,5} is present or XDG_CURRENT_DESKTOP looks
// like KDE, else null.
function detectLinuxDe() {
  try {
    const r = spawnSync('gsettings', ['list-keys', 'org.gnome.system.proxy'], { stdio: 'pipe' });
    if (r.status === 0) return 'gnome';
  } catch {}
  for (const bin of ['kwriteconfig6', 'kwriteconfig5']) {
    if (binExists(bin)) return 'kde';
  }
  if (/kde/i.test(process.env.XDG_CURRENT_DESKTOP || '')) return 'kde';
  return null;
}

// Mirror of macRunAdmin() for Linux: try pkexec (polkit GUI prompt — dashboard
// path), fall back to sudo (tty prompt — CLI path), else degrade to returning
// the exact command for a manual run. Same { ok, error } result contract.
function linuxRunAdmin(argv, { prefer } = {}) {
  const cmd = Array.isArray(argv) ? argv : ['/bin/sh', '-c', String(argv)];
  const display = cmd.join(' ');
  const order = prefer === 'sudo' ? ['sudo', 'pkexec'] : ['pkexec', 'sudo'];
  for (const elevator of order) {
    if (!binExists(elevator)) continue;
    const args = elevator === 'sudo' ? ['--', ...cmd] : [...cmd];
    const r = spawnSync(elevator, args, { stdio: ['inherit', 'pipe', 'pipe'] });
    if (r.status === 0) return { ok: true };
    const msg = ((r.stderr || '') + (r.stdout || '')).toString();
    if (/cancel|dismiss|Not authorized|authentication failed|incorrect password/i.test(msg)) {
      return { ok: false, error: 'Cancelled by user' };
    }
    if (r.status == null && r.error) continue;
    return { ok: false, error: 'Permission denied — try running with sudo' };
  }
  return { ok: false, needsManual: true, cmd: display, error: `Run manually: ${display}` };
}

// ── Linux: GNOME ──────────────────────────────────────────────────────────────

function gnomeProxyOn(port) {
  const errors = [];
  const ops = [
    ['org.gnome.system.proxy', 'mode', 'manual'],
    ['org.gnome.system.proxy.http', 'host', '127.0.0.1'],
    ['org.gnome.system.proxy.http', 'port', String(port)],
    ['org.gnome.system.proxy.https', 'host', '127.0.0.1'],
    ['org.gnome.system.proxy.https', 'port', String(port)],
    ['org.gnome.system.proxy', 'ignore-hosts', "['localhost', '127.0.0.0/8', '::1']"],
  ];
  for (const [schema, key, value] of ops) {
    const r = spawnSync('gsettings', ['set', schema, key, value], { stdio: 'pipe' });
    if (r.status !== 0) {
      const m = (r.stderr || r.error?.message || '').toString().trim();
      errors.push(`gsettings ${schema} ${key}: ${m || 'failed'}`);
    }
  }
  return { activated: errors.length ? [] : ['GNOME'], errors, envLines: linuxEnvLines(port) };
}

function gnomeProxyOff() {
  const errors = [];
  const r = spawnSync('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'none'], { stdio: 'pipe' });
  if (r.status !== 0) {
    const m = (r.stderr || r.error?.message || '').toString().trim();
    errors.push(`gsettings mode: ${m || 'failed'}`);
  }
  return { deactivated: errors.length ? [] : ['GNOME'], errors };
}

function gnomeProxyStatus() {
  function get(schema, key) {
    const r = spawnSync('gsettings', ['get', schema, key], { encoding: 'utf8', stdio: 'pipe' });
    if (r.status !== 0) return null;
    return parseGsettingsValue(r.stdout);
  }
  const mode = get('org.gnome.system.proxy', 'mode');
  const httpHost = get('org.gnome.system.proxy.http', 'host');
  const httpPort = get('org.gnome.system.proxy.http', 'port');
  const httpsHost = get('org.gnome.system.proxy.https', 'host');
  return [linuxStatusFromValues({ mode, httpHost, httpPort, httpsHost })];
}

// ── Linux: KDE ────────────────────────────────────────────────────────────────

// Pure: the kwriteconfig/kreadconfig arg vectors for a given port (unit-tested
// without shelling out). ProxyType 1 = manual, 0 = none.
function kdeProxyConfigOps(port) {
  const file = ['--file', 'kioslaverc', '--group', 'Proxy Settings'];
  return {
    on: [
      [...file, '--key', 'ProxyType', '1'],
      [...file, '--key', 'httpProxy', `http://127.0.0.1 ${port}`],
      [...file, '--key', 'httpsProxy', `http://127.0.0.1 ${port}`],
      [...file, '--key', 'NoProxyFor', 'localhost,127.0.0.1'],
    ],
    off: [
      [...file, '--key', 'ProxyType', '0'],
    ],
    readType: [...file, '--key', 'ProxyType'],
    readHttp: [...file, '--key', 'httpProxy'],
  };
}

function kdeWriteBin() {
  for (const bin of ['kwriteconfig6', 'kwriteconfig5']) {
    if (binExists(bin)) return bin;
  }
  return null;
}

function kdeReadBin() {
  for (const bin of ['kreadconfig6', 'kreadconfig5']) {
    if (binExists(bin)) return bin;
  }
  return null;
}

function kdeReloadConfig() {
  spawnSync('dbus-send', [
    '--type=signal', '/KIO/Scheduler',
    'org.kde.KIO.Scheduler.reparseSlaveConfiguration', 'string:',
  ], { stdio: 'pipe' });
}

function kdeProxyOn(port) {
  const bin = kdeWriteBin();
  const errors = [];
  if (!bin) {
    errors.push('kwriteconfig6/5 not found');
    return { activated: [], errors, envLines: linuxEnvLines(port) };
  }
  for (const args of kdeProxyConfigOps(port).on) {
    const r = spawnSync(bin, args, { stdio: 'pipe' });
    if (r.status !== 0) {
      const m = (r.stderr || r.error?.message || '').toString().trim();
      errors.push(`${bin} ${args.join(' ')}: ${m || 'failed'}`);
    }
  }
  kdeReloadConfig();
  return { activated: errors.length ? [] : ['KDE'], errors, envLines: linuxEnvLines(port) };
}

function kdeProxyOff() {
  const bin = kdeWriteBin();
  const errors = [];
  if (!bin) {
    errors.push('kwriteconfig6/5 not found');
    return { deactivated: [], errors };
  }
  for (const args of kdeProxyConfigOps(7777).off) {
    const r = spawnSync(bin, args, { stdio: 'pipe' });
    if (r.status !== 0) {
      const m = (r.stderr || r.error?.message || '').toString().trim();
      errors.push(`${bin} ${args.join(' ')}: ${m || 'failed'}`);
    }
  }
  kdeReloadConfig();
  return { deactivated: errors.length ? [] : ['KDE'], errors };
}

function kdeProxyStatus() {
  const bin = kdeReadBin();
  if (!bin) return [linuxStatusFromValues({ mode: 'none', service: 'KDE' })];
  const ops = kdeProxyConfigOps(0);
  const typeR = spawnSync(bin, ops.readType, { encoding: 'utf8', stdio: 'pipe' });
  const httpR = spawnSync(bin, ops.readHttp, { encoding: 'utf8', stdio: 'pipe' });
  const type = (typeR.stdout || '').trim();
  const http = (httpR.stdout || '').trim(); // "http://127.0.0.1 7777"
  const manual = type === '1';
  const m = http.match(/^https?:\/\/(\S+)\s+(\d+)/);
  const host = m ? m[1] : '';
  const port = m ? parseInt(m[2], 10) : 0;
  return [linuxStatusFromValues({
    mode: manual ? 'manual' : 'none',
    httpHost: host,
    httpPort: port,
    httpsHost: host,
    service: 'KDE',
  })];
}

// ── Linux: dispatch ───────────────────────────────────────────────────────────

const LINUX_DEGRADED_MSG =
  'No GNOME/KDE detected — env vars set below; configure GUI apps manually.';

function linuxProxyOn(port) {
  const de = detectLinuxDe();
  if (de === 'gnome') return gnomeProxyOn(port);
  if (de === 'kde')   return kdeProxyOn(port);
  return {
    activated: [],
    errors: [],
    envLines: linuxEnvLines(port),
    degraded: true,
    message: LINUX_DEGRADED_MSG,
  };
}

function linuxProxyOff() {
  const de = detectLinuxDe();
  if (de === 'gnome') return gnomeProxyOff();
  if (de === 'kde')   return kdeProxyOff();
  return { deactivated: [], errors: [], degraded: true, message: LINUX_DEGRADED_MSG };
}

function linuxProxyStatus() {
  const de = detectLinuxDe();
  if (de === 'gnome') return gnomeProxyStatus();
  if (de === 'kde')   return kdeProxyStatus();
  return [];
}

// ── Windows ───────────────────────────────────────────────────────────────────

function winProxyOn(port) {
  try {
    execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f`);
    execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:${port}" /f`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

function winProxyOff() {
  try {
    execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

function enable(port = 8080) {
  const plat = os.platform();
  if (plat === 'darwin') return { platform: 'macOS', ...macProxyOn(port) };
  if (plat === 'linux')  return { platform: 'linux', ...linuxProxyOn(port) };
  if (plat === 'win32')  return { platform: 'windows', ...winProxyOn(port) };
  return { platform: plat, error: 'Unsupported platform for automatic proxy configuration' };
}

function disable() {
  const plat = os.platform();
  if (plat === 'darwin') return { platform: 'macOS', ...macProxyOff() };
  if (plat === 'linux')  return { platform: 'linux', ...linuxProxyOff() };
  if (plat === 'win32')  return { platform: 'windows', ...winProxyOff() };
  return { platform: plat, error: 'Unsupported platform' };
}

function status() {
  const plat = os.platform();
  if (plat === 'darwin') return { platform: 'macOS', services: macProxyStatus() };
  if (plat === 'linux')  return { platform: 'linux', services: linuxProxyStatus() };
  return { platform: plat, services: [] };
}

function getActiveServices() {
  if (os.platform() === 'darwin') return macGetActiveServices();
  return [];
}

module.exports = {
  enable,
  disable,
  status,
  getActiveServices,
  // Linux desktop detection (used by the dashboard /api/status).
  detectLinuxDe,
  linuxRunAdmin,
  // Pure helpers — exported for unit tests (no shelling out).
  linuxEnvLines,
  parseGsettingsValue,
  linuxStatusFromValues,
  kdeProxyConfigOps,
  binExists,
};
