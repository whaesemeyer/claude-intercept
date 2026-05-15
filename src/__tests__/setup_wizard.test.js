'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  parseOsRelease,
  getSetupInstructions,
  trustCertLinux,
} = require('../setup_wizard');

// ── parseOsRelease ────────────────────────────────────────────────────────────

test('parseOsRelease maps the real /etc/os-release to a family', () => {
  // This box is Ubuntu → debian. Use the live file as a real fixture.
  let live = '';
  try { live = fs.readFileSync('/etc/os-release', 'utf8'); } catch {}
  if (live) assert.strictEqual(parseOsRelease(live), 'debian');
});

test('parseOsRelease — ubuntu → debian', () => {
  const txt = 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n';
  assert.strictEqual(parseOsRelease(txt), 'debian');
});

test('parseOsRelease — fedora → rhel', () => {
  assert.strictEqual(parseOsRelease('ID=fedora\nID_LIKE="rhel fedora"\n'), 'rhel');
  assert.strictEqual(parseOsRelease('ID="rocky"\nID_LIKE="rhel centos fedora"\n'), 'rhel');
});

test('parseOsRelease — arch → arch', () => {
  assert.strictEqual(parseOsRelease('ID=arch\n'), 'arch');
  assert.strictEqual(parseOsRelease('ID=manjaro\nID_LIKE=arch\n'), 'arch');
});

test('parseOsRelease — empty / unknown → unknown', () => {
  assert.strictEqual(parseOsRelease(''), 'unknown');
  assert.strictEqual(parseOsRelease('ID=plan9\n'), 'unknown');
});

// ── getSetupInstructions (linux, injected env) ────────────────────────────────

function findStep(steps, fragment) {
  return steps.find(s => (s.title || '').includes(fragment));
}

test('linux instructions show the certutil install line only when missing', () => {
  const withCertutil = getSetupInstructions('linux', 7777, '10.0.0.1', null, {
    linuxEnv: { family: 'debian', hasCertutil: true, de: 'gnome' },
  });
  const withoutCertutil = getSetupInstructions('linux', 7777, '10.0.0.1', null, {
    linuxEnv: { family: 'debian', hasCertutil: false, de: 'gnome' },
  });
  const chromeWith = findStep(withCertutil.steps, 'Chrome');
  const chromeWithout = findStep(withoutCertutil.steps, 'Chrome');
  assert.ok(chromeWith && chromeWithout);
  assert.ok(!chromeWith.code.includes('libnss3-tools'),
    'certutil install line must NOT appear when certutil is present');
  assert.ok(chromeWithout.code.includes('apt-get install -y libnss3-tools'),
    'certutil install line MUST appear when certutil is missing');
});

test('linux system-store step is family-specific and flagged warning', () => {
  const deb = getSetupInstructions('linux', 7777, null, null, {
    linuxEnv: { family: 'debian', hasCertutil: true, de: 'gnome' },
  });
  const rhel = getSetupInstructions('linux', 7777, null, null, {
    linuxEnv: { family: 'rhel', hasCertutil: true, de: 'kde' },
  });
  const arch = getSetupInstructions('linux', 7777, null, null, {
    linuxEnv: { family: 'arch', hasCertutil: true, de: null },
  });
  const dStep = findStep(deb.steps, 'Install system-wide');
  const rStep = findStep(rhel.steps, 'Install system-wide');
  const aStep = findStep(arch.steps, 'Install system-wide');
  assert.strictEqual(dStep.warning, true);
  assert.ok(dStep.code.includes('update-ca-certificates'));
  assert.ok(rStep.code.includes('update-ca-trust extract'));
  assert.ok(aStep.code.includes('trust anchor --store'));
});

test('linux proxy step names the detected desktop', () => {
  const kde = getSetupInstructions('linux', 7777, null, null, {
    linuxEnv: { family: 'debian', hasCertutil: true, de: 'kde' },
  });
  assert.ok(findStep(kde.steps, 'Enable the system proxy (KDE)'));
});

// ── trustCertLinux (injected runAdmin / spawn) ────────────────────────────────

test('trustCertLinux: ordering, elevated system-store, steps 4 & 5 never elevate', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-trust-'));
  const caPath = path.join(tmp, 'ca.crt');
  fs.writeFileSync(caPath, '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-home-'));

  const adminCalls = [];
  const spawnCalls = [];
  const runAdmin = (argv) => { adminCalls.push(argv.join(' ')); return { ok: true }; };
  const spawn = (cmd, args) => {
    spawnCalls.push([cmd, ...args].join(' '));
    return { status: 0, stdout: '', stderr: '' };
  };

  const result = trustCertLinux({
    env: { family: 'debian', hasCertutil: false, de: 'gnome' },
    runAdmin,
    spawn,
    caPath,
    home,
    tmpCa: path.join(tmp, 'tmp-ca.crt'),
  });

  // System store install precedes the certutil package install (elevated, in order).
  const sysIdx = adminCalls.findIndex(c => c.includes('update-ca-certificates'));
  const pkgIdx = adminCalls.findIndex(c => c.includes('libnss3-tools'));
  assert.ok(sysIdx >= 0 && pkgIdx >= 0 && sysIdx < pkgIdx,
    'system store install must run before the certutil package install');
  assert.ok(adminCalls.some(c => c.includes('/usr/local/share/ca-certificates/claude-intercept.crt')));

  // Steps 4 & 5 use plain spawn (NOT runAdmin) — certutil never elevates.
  assert.ok(spawnCalls.some(c => c.includes('certutil') && c.includes('Claude Intercept')),
    'certutil add must run via the non-elevated spawn');
  assert.ok(!adminCalls.some(c => c.includes('certutil')),
    'certutil must NEVER be run through runAdmin (no sudo for NSS stores)');

  // It records steps and never throws.
  assert.ok(Array.isArray(result.steps) && result.steps.length >= 5);
  assert.ok(result.steps.every(s => typeof s.name === 'string' && 'ok' in s));
});

test('trustCertLinux: missing CA fails fast without elevating', () => {
  const adminCalls = [];
  const result = trustCertLinux({
    env: { family: 'debian', hasCertutil: true, de: 'gnome' },
    runAdmin: (argv) => { adminCalls.push(argv); return { ok: true }; },
    spawn: () => ({ status: 0 }),
    caPath: path.join(os.tmpdir(), 'definitely-not-here-' + Date.now(), 'ca.crt'),
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(adminCalls.length, 0);
  assert.strictEqual(result.steps[0].ok, false);
});

test('trustCertLinux: certutil already present skips the package install', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-trust2-'));
  const caPath = path.join(tmp, 'ca.crt');
  fs.writeFileSync(caPath, 'x');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-home2-'));
  const adminCalls = [];
  trustCertLinux({
    env: { family: 'debian', hasCertutil: true, de: 'gnome' },
    runAdmin: (argv) => { adminCalls.push(argv.join(' ')); return { ok: true }; },
    spawn: () => ({ status: 0, stdout: '', stderr: '' }),
    caPath,
    home,
    tmpCa: path.join(tmp, 'tmp.crt'),
  });
  assert.ok(!adminCalls.some(c => c.includes('libnss3-tools')),
    'no certutil package install when hasCertutil is true');
});
