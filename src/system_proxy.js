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

function linuxProxyOn(port) {
  const lines = [
    `export http_proxy=http://127.0.0.1:${port}`,
    `export https_proxy=http://127.0.0.1:${port}`,
    `export HTTP_PROXY=http://127.0.0.1:${port}`,
    `export HTTPS_PROXY=http://127.0.0.1:${port}`,
    `export no_proxy=localhost,127.0.0.1`,
  ];

  // Try GNOME gsettings
  try {
    execSync(`gsettings set org.gnome.system.proxy mode 'manual' 2>/dev/null`);
    execSync(`gsettings set org.gnome.system.proxy.http host '127.0.0.1' 2>/dev/null`);
    execSync(`gsettings set org.gnome.system.proxy.http port ${port} 2>/dev/null`);
    execSync(`gsettings set org.gnome.system.proxy.https host '127.0.0.1' 2>/dev/null`);
    execSync(`gsettings set org.gnome.system.proxy.https port ${port} 2>/dev/null`);
  } catch {}

  return { envLines: lines };
}

function linuxProxyOff() {
  try {
    execSync(`gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null`);
  } catch {}
  return { ok: true };
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
  return { platform: plat, services: [] };
}

function getActiveServices() {
  if (os.platform() === 'darwin') return macGetActiveServices();
  return [];
}

module.exports = { enable, disable, status, getActiveServices };
