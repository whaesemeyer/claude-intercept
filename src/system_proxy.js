'use strict';

/**
 * Manages OS-level system proxy settings so the local machine's traffic
 * is routed through claude-intercept automatically.
 *
 * Supported: macOS (networksetup), Linux (gsettings/env), Windows (reg)
 */

const { spawnSync } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { randomBytes } = require('crypto');

const OWNER_FILE = path.join(__dirname, '../captures/system-proxy-owner.json');

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function macCommandsForService(service, port, enabled) {
  const state = enabled ? 'on' : 'off';
  const commands = [];
  if (enabled) {
    commands.push(['networksetup', '-setwebproxy', service, '127.0.0.1', String(port)]);
    commands.push(['networksetup', '-setsecurewebproxy', service, '127.0.0.1', String(port)]);
  }
  commands.push(['networksetup', '-setwebproxystate', service, state]);
  commands.push(['networksetup', '-setsecurewebproxystate', service, state]);
  return commands;
}

function runCommands(commands) {
  for (const [command, ...args] of commands) {
    const result = spawnSync(command, args, { stdio: 'pipe' });
    if (result.status !== 0) return false;
  }
  return true;
}

// Elevation is only a fallback after direct argv-based commands fail. The
// script lives in a private unpredictable directory and quotes each argument.
function macRunAdmin(commands) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-proxy-'));
  const tmpFile = path.join(tmpDir, 'apply.sh');
  const script = commands.map(argv => argv.map(shellQuote).join(' ')).join('\n');
  fs.writeFileSync(tmpFile, `#!/bin/sh\nset -e\n${script}\n`, { mode: 0o700 });
  try {
    const quotedPath = shellQuote(tmpFile);
    const appleScriptString = `"${quotedPath.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
    const result = spawnSync('osascript', ['-e', `do shell script ${appleScriptString} with administrator privileges`], { stdio: 'pipe' });
    if (result.status !== 0) throw result;
    return { ok: true };
  } catch (err) {
    const msg = (err.stderr || err.message || '').toString();
    if (msg.includes('User canceled')) return { ok: false, error: 'Cancelled by user' };
    return { ok: false, error: 'Permission denied — try running with sudo' };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ── macOS ─────────────────────────────────────────────────────────────────────

function macGetActiveServices() {
  try {
    const result = spawnSync('networksetup', ['-listallnetworkservices'], { encoding: 'utf8', stdio: 'pipe' });
    if (result.status !== 0) throw result.error || new Error('networksetup failed');
    return result.stdout
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('An asterisk') && !l.startsWith('*'));
  } catch {
    return [];
  }
}

function macProxyOn(port, services = macGetActiveServices()) {
  const errors = [];
  const activated = [];
  if (!services.length) return { activated, errors: ['No macOS network services found'] };

  for (const svc of services) {
    const commands = macCommandsForService(svc, port, true);
    // Try without elevation first (works when already running as admin)
    let ok = runCommands(commands);
    if (!ok) {
      // Need elevation — prompt via macOS GUI password dialog
      const result = macRunAdmin(commands);
      ok = result.ok;
      if (!result.ok) errors.push(`${svc}: ${result.error}`);
    }
    if (ok) activated.push(svc);
  }

  return { activated, errors };
}

function macProxyOff(plans) {
  const deactivated = [];
  const errors = [];
  if (!plans.length) return { deactivated, errors };

  for (const { service, http, https } of plans) {
    const commands = [];
    if (http) commands.push(['networksetup', '-setwebproxystate', service, 'off']);
    if (https) commands.push(['networksetup', '-setsecurewebproxystate', service, 'off']);
    let ok = runCommands(commands);
    if (!ok) {
      const result = macRunAdmin(commands);
      ok = result.ok;
      if (!result.ok) errors.push(`${service}: ${result.error}`);
    }
    if (ok) deactivated.push(service);
  }

  return { deactivated, errors };
}

function macProxyStatus() {
  const services = macGetActiveServices();
  const results = [];

  for (const svc of services) {
    try {
      const httpResult = spawnSync('networksetup', ['-getwebproxy', svc], { encoding: 'utf8', stdio: 'pipe' });
      const httpsResult = spawnSync('networksetup', ['-getsecurewebproxy', svc], { encoding: 'utf8', stdio: 'pipe' });
      const pacResult = spawnSync('networksetup', ['-getautoproxyurl', svc], { encoding: 'utf8', stdio: 'pipe' });
      const discoveryResult = spawnSync('networksetup', ['-getproxyautodiscovery', svc], { encoding: 'utf8', stdio: 'pipe' });
      const socksResult = spawnSync('networksetup', ['-getsocksfirewallproxy', svc], { encoding: 'utf8', stdio: 'pipe' });
      if ([httpResult, httpsResult, pacResult, discoveryResult, socksResult]
        .some(result => result.status !== 0)) {
        results.push({ service: svc, inspectable: false });
        continue;
      }
      const http = httpResult.stdout;
      const https = httpsResult.stdout;
      const httpEnabled = /Enabled: Yes/i.test(http);
      const httpsEnabled = /Enabled: Yes/i.test(https);
      const autoEnabled = /Enabled: Yes/i.test(pacResult.stdout) ||
        /Enabled: Yes/i.test(socksResult.stdout) ||
        /Auto Proxy Discovery: On/i.test(discoveryResult.stdout);
      const serverMatch = http.match(/Server: (.+)/);
      const portMatch = http.match(/Port: (\d+)/);
      const httpsServerMatch = https.match(/Server: (.+)/);
      const httpsPortMatch = https.match(/Port: (\d+)/);
      results.push({
        service: svc,
        httpEnabled,
        httpsEnabled,
        server: serverMatch?.[1]?.trim() || '',
        port: portMatch?.[1] ? parseInt(portMatch[1], 10) : 0,
        httpsServer: httpsServerMatch?.[1]?.trim() || '',
        httpsPort: httpsPortMatch?.[1] ? parseInt(httpsPortMatch[1], 10) : 0,
        activeProxy: httpEnabled || httpsEnabled || autoEnabled,
        inspectable: true,
        pointsHere: httpEnabled && serverMatch?.[1]?.trim() === '127.0.0.1',
      });
    } catch {
      results.push({ service: svc, inspectable: false });
    }
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
function linuxStatusFromValues({ mode, httpHost, httpPort, httpsHost, httpsPort = httpPort,
  service = 'GNOME', inspectable = true } = {}) {
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
    httpsServer: httpsHost || server,
    httpsPort: Number.isFinite(httpsPort) ? httpsPort : (parseInt(httpsPort, 10) || 0),
    activeProxy: mode !== 'none' && mode !== '',
    inspectable,
    mode,
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
  const httpsPort = get('org.gnome.system.proxy.https', 'port');
  return [linuxStatusFromValues({ mode, httpHost, httpPort, httpsHost, httpsPort,
    inspectable: mode !== null && httpHost !== null && httpPort !== null &&
      httpsHost !== null && httpsPort !== null })];
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
    readHttps: [...file, '--key', 'httpsProxy'],
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
  if (!bin) return [linuxStatusFromValues({ mode: '', service: 'KDE', inspectable: false })];
  const ops = kdeProxyConfigOps(0);
  const typeR = spawnSync(bin, ops.readType, { encoding: 'utf8', stdio: 'pipe' });
  const httpR = spawnSync(bin, ops.readHttp, { encoding: 'utf8', stdio: 'pipe' });
  const httpsR = spawnSync(bin, ops.readHttps, { encoding: 'utf8', stdio: 'pipe' });
  const type = (typeR.stdout || '').trim();
  const http = (httpR.stdout || '').trim(); // "http://127.0.0.1 7777"
  const https = (httpsR.stdout || '').trim();
  const manual = type === '1';
  const m = http.match(/^https?:\/\/(\S+)\s+(\d+)/);
  const hm = https.match(/^https?:\/\/(\S+)\s+(\d+)/);
  const host = m ? m[1] : '';
  const port = m ? parseInt(m[2], 10) : 0;
  return [linuxStatusFromValues({
    mode: type === '0' ? 'none' : manual ? 'manual' : 'auto',
    httpHost: host,
    httpPort: port,
    httpsHost: hm ? hm[1] : '',
    httpsPort: hm ? parseInt(hm[2], 10) : 0,
    service: 'KDE',
    inspectable: typeR.status === 0 && httpR.status === 0 && httpsR.status === 0 &&
      !!type && (!manual || (!!m && !!hm)),
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
  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  const server = spawnSync('reg', ['add', key, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', `127.0.0.1:${port}`, '/f'], { stdio: 'pipe' });
  if (server.status !== 0) return { ok: false, error: 'Unable to configure Windows system proxy' };
  const enable = spawnSync('reg', ['add', key, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f'], { stdio: 'pipe' });
  return enable.status === 0 && server.status === 0
    ? { ok: true }
    : { ok: false, error: 'Unable to configure Windows system proxy' };
}

function winProxyOff() {
  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  const result = spawnSync('reg', ['add', key, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'], { stdio: 'pipe' });
  return result.status === 0
    ? { ok: true }
    : { ok: false, error: 'Unable to disable Windows system proxy' };
}

// ── Public API ────────────────────────────────────────────────────────────────

function platformStatus() {
  const plat = os.platform();
  if (plat === 'darwin') return { platform: 'macOS', services: macProxyStatus() };
  if (plat === 'linux') return { platform: 'linux', services: linuxProxyStatus() };
  return { platform: plat, services: [] };
}

function readOwner() {
  const dir = fs.lstatSync(path.dirname(OWNER_FILE), { throwIfNoEntry: false });
  if (!dir) return null;
  if (!dir.isDirectory()) return { invalid: true };
  const stat = fs.lstatSync(OWNER_FILE, { throwIfNoEntry: false });
  if (!stat) return null;
  if (!stat.isFile() || (process.platform !== 'win32' && (stat.mode & 0o077))) {
    return { invalid: true };
  }
  try {
    const owner = JSON.parse(fs.readFileSync(OWNER_FILE, 'utf8'));
    if (owner.version !== 1 || !/^[0-9a-f]{64}$/.test(owner.ownerId) ||
        !Number.isSafeInteger(owner.port) || owner.port < 1 || owner.port > 65535 ||
        !['macOS', 'linux'].includes(owner.platform) ||
        !Array.isArray(owner.services) || owner.services.length === 0 ||
        !owner.services.every(name => typeof name === 'string' && name.length > 0)) {
      return { invalid: true };
    }
    return owner;
  } catch {
    return { invalid: true };
  }
}

function writeOwner(owner) {
  const dir = path.dirname(OWNER_FILE);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(dir).isDirectory()) throw new Error(`Capture path is not a directory: ${dir}`);
  fs.chmodSync(dir, 0o700);
  fs.writeFileSync(OWNER_FILE, JSON.stringify(owner), { mode: 0o600, flag: 'wx' });
}

function removeOwnerIfSame(owner) {
  const current = readOwner();
  if (current && !current.invalid && current.ownerId === owner.ownerId &&
      current.port === owner.port && current.platform === owner.platform) {
    fs.unlinkSync(OWNER_FILE);
  }
}

function usableStatus(snapshot) {
  return Array.isArray(snapshot.services) && snapshot.services.length > 0 &&
    snapshot.services.every(s => s && s.inspectable !== false && typeof s.service === 'string');
}

function matchingProtocols(service, port) {
  return {
    http: service.httpEnabled === true && service.server === '127.0.0.1' && service.port === port,
    https: service.httpsEnabled === true && service.httpsServer === '127.0.0.1' && service.httpsPort === port,
  };
}

// Pure decisions are kept separate from the OS commands so the ownership
// boundary can be tested without changing a developer's real proxy settings.
function assessEnable(snapshot, owner, port, ownerId) {
  if (!/^[0-9a-f]{64}$/.test(ownerId || '')) {
    return { ok: false, error: 'A verified running Intercept instance is required' };
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535 || !usableStatus(snapshot)) {
    return { ok: false, error: 'Cannot verify existing system proxy settings' };
  }
  if (owner) {
    if (owner.invalid) return { ok: false, error: 'System proxy ownership record is invalid' };
    const allOwned = owner.platform === snapshot.platform && owner.port === port &&
      owner.ownerId === ownerId && owner.services.every(name => {
        const service = snapshot.services.find(s => s.service === name);
        if (!service) return false;
        const match = matchingProtocols(service, port);
        return match.http && match.https;
      });
    return allOwned
      ? { ok: true, already: true }
      : { ok: false, error: 'Existing system proxy ownership does not match this instance; use proxy off or inspect settings' };
  }
  if (snapshot.services.some(s => s.activeProxy || s.httpEnabled || s.httpsEnabled)) {
    return { ok: false, error: 'An unrelated system proxy is already enabled; refusing to overwrite it' };
  }
  return { ok: true };
}

function assessDisable(snapshot, owner, ownerId) {
  if (!owner) return { ok: true, plans: [], message: 'No Intercept-owned system proxy to disable' };
  if (owner.invalid) return { ok: false, error: 'System proxy ownership record is invalid' };
  if (ownerId && owner.ownerId !== ownerId) {
    return { ok: true, plans: [], message: 'System proxy belongs to a different Intercept instance' };
  }
  if (owner.platform !== snapshot.platform || !usableStatus(snapshot)) {
    return { ok: false, error: 'Cannot verify current system proxy settings; leaving them unchanged' };
  }
  const plans = [];
  let partial = false;
  for (const name of owner.services) {
    const service = snapshot.services.find(s => s.service === name);
    if (!service) continue;
    const match = matchingProtocols(service, owner.port);
    if (snapshot.platform === 'macOS') {
      if (match.http || match.https) plans.push({ service: name, ...match });
    } else if (match.http && match.https) {
      plans.push({ service: name, ...match });
    } else if (match.http || match.https) {
      partial = true; // GNOME/KDE can only turn both protocols off together.
    }
  }
  return { ok: true, plans, partial };
}

function enable(port = 8080, { ownerId } = {}) {
  const before = platformStatus();
  if (before.platform === 'linux' && !detectLinuxDe()) {
    return { platform: 'linux', activated: [], envLines: linuxEnvLines(port),
      degraded: true, message: LINUX_DEGRADED_MSG };
  }
  const owner = readOwner();
  const decision = assessEnable(before, owner, port, ownerId);
  if (!decision.ok) return { platform: before.platform, error: decision.error };
  if (decision.already) return { platform: before.platform, activated: [], already: true };

  const record = { version: 1, ownerId, platform: before.platform, port,
    services: before.services.map(s => s.service) };
  try { writeOwner(record); }
  catch (err) { return { platform: before.platform, error: `Cannot record proxy ownership: ${err.message}` }; }
  const result = before.platform === 'macOS'
    ? macProxyOn(port, record.services)
    : before.services[0].service === 'GNOME' ? gnomeProxyOn(port) : kdeProxyOn(port);
  const after = platformStatus();
  if (usableStatus(after) && !after.services.some(s => {
    if (!record.services.includes(s.service)) return false;
    const match = matchingProtocols(s, port);
    return match.http || match.https;
  })) removeOwnerIfSame(record);
  return { platform: before.platform, ...result };
}

function disable({ ownerId } = {}) {
  const owner = readOwner();
  if (!owner) return { platform: os.platform(), deactivated: [],
    message: 'No Intercept-owned system proxy to disable' };
  if (owner.invalid) return { platform: os.platform(), error: 'System proxy ownership record is invalid' };
  if (ownerId && owner.ownerId !== ownerId) return { platform: os.platform(), deactivated: [],
    message: 'System proxy belongs to a different Intercept instance' };
  const before = platformStatus();
  const decision = assessDisable(before, owner, ownerId);
  if (!decision.ok) return { platform: before.platform, error: decision.error };
  const result = before.platform === 'macOS'
    ? macProxyOff(decision.plans)
    : decision.plans.length
      ? before.services[0].service === 'GNOME' ? gnomeProxyOff() : kdeProxyOff()
      : { deactivated: [], errors: [] };
  const after = platformStatus();
  if (usableStatus(after) && !after.services.some(s => {
    if (!owner.services.includes(s.service)) return false;
    const match = matchingProtocols(s, owner.port);
    return match.http || match.https;
  })) removeOwnerIfSame(owner);
  return { platform: before.platform, ...result,
    ...(decision.partial ? { message: 'Proxy settings changed; leaving unmatched settings unchanged' } : {}) };
}

function status() {
  const snapshot = platformStatus();
  const owner = readOwner();
  const active = owner && !owner.invalid && owner.platform === snapshot.platform &&
    usableStatus(snapshot) && owner.services.some(name => {
      const service = snapshot.services.find(s => s.service === name);
      if (!service) return false;
      const match = matchingProtocols(service, owner.port);
      return match.http || match.https;
    });
  return { ...snapshot, ownership: owner?.invalid ? { unverified: true } :
    { active: !!active, port: active ? owner.port : null } };
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
  shellQuote,
  macCommandsForService,
  assessEnable,
  assessDisable,
  matchingProtocols,
};
