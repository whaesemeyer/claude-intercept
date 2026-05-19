'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CA_CERT_PATH = path.join(__dirname, '../certs/ca.crt');

// Pure: map an /etc/os-release body to a package family.
function parseOsRelease(text) {
  const fields = {};
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) fields[m[1]] = m[2].replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
  }
  const hay = `${fields.ID || ''} ${fields.ID_LIKE || ''}`.toLowerCase();
  if (/\b(debian|ubuntu|linuxmint|pop|raspbian)\b/.test(hay)) return 'debian';
  if (/\b(rhel|fedora|centos|rocky|almalinux|amzn|ol)\b/.test(hay)) return 'rhel';
  if (/\b(arch|manjaro|endeavouros)\b/.test(hay)) return 'arch';
  return 'unknown';
}

// Injectable: probe the Linux environment. `deps` lets tests stub everything.
function detectLinuxEnv(deps = {}) {
  const readOsRelease = deps.readOsRelease || (() => {
    try { return fs.readFileSync('/etc/os-release', 'utf8'); } catch { return ''; }
  });
  const has = deps.has || ((bin) => {
    try { return spawnSync('which', [bin], { stdio: 'pipe' }).status === 0; } catch { return false; }
  });
  const detectDe = deps.detectDe || (() => {
    try { return require('./system_proxy').detectLinuxDe(); } catch { return null; }
  });
  return {
    family: parseOsRelease(readOsRelease()),
    hasUpdateCaCerts: has('update-ca-certificates'),
    hasUpdateCaTrust: has('update-ca-trust'),
    hasTrust: has('trust'),
    hasCertutil: has('certutil'),
    hasGsettings: has('gsettings'),
    de: detectDe(),
  };
}

// Auto cert-trust routine. `runAdmin` is the elevation helper (injectable),
// `spawn` runs non-elevated commands. Returns { steps:[{name,ok,detail}], ok }
// and never throws — each step records its own outcome.
function trustCertLinux(opts = {}) {
  const env = opts.env || detectLinuxEnv(opts.envDeps);
  const runAdmin = opts.runAdmin || ((argv) => require('./system_proxy').linuxRunAdmin(argv, { prefer: opts.prefer }));
  const spawn = opts.spawn || ((cmd, args) => spawnSync(cmd, args, { encoding: 'utf8', stdio: 'pipe' }));
  const caPath = opts.caPath || CA_CERT_PATH;
  const home = opts.home || os.homedir();
  const steps = [];
  const record = (name, ok, detail) => { steps.push({ name, ok, detail }); return ok; };

  // 1. Locate CA, copy to a temp path.
  let tmpCa = caPath;
  try {
    if (!fs.existsSync(caPath)) {
      record('Locate CA certificate', false, `Not found at ${caPath} — start the proxy once to generate it`);
      return { steps, ok: false };
    }
    tmpCa = opts.tmpCa || path.join(os.tmpdir(), `claude-intercept-ca-${Date.now()}.crt`);
    fs.copyFileSync(caPath, tmpCa);
    record('Locate CA certificate', true, caPath);
  } catch (e) {
    record('Locate CA certificate', false, e.message);
    return { steps, ok: false };
  }

  // 2. System trust store (elevated).
  let sysArgv = null;
  if (env.family === 'debian') {
    sysArgv = ['/bin/sh', '-c',
      `cp ${tmpCa} /usr/local/share/ca-certificates/claude-intercept.crt && update-ca-certificates`];
  } else if (env.family === 'rhel') {
    sysArgv = ['/bin/sh', '-c',
      `cp ${tmpCa} /etc/pki/ca-trust/source/anchors/claude-intercept.crt && update-ca-trust extract`];
  } else if (env.family === 'arch') {
    sysArgv = ['/bin/sh', '-c', `trust anchor --store ${tmpCa}`];
  }
  if (sysArgv) {
    const r = runAdmin(sysArgv);
    record('Install in system trust store', !!r.ok,
      r.ok ? `${env.family} store updated` : (r.error || 'elevation failed'));
  } else {
    record('Install in system trust store', false,
      `Unknown distro family — copy ${tmpCa} into your CA anchors manually`);
  }

  // 3. certutil bootstrap (no sudo for the nssdb itself; install needs sudo).
  if (!env.hasCertutil) {
    let installArgv = null;
    if (env.family === 'debian') installArgv = ['/bin/sh', '-c', 'apt-get install -y libnss3-tools'];
    else if (env.family === 'rhel') installArgv = ['/bin/sh', '-c', 'dnf install -y nss-tools'];
    else if (env.family === 'arch') installArgv = ['/bin/sh', '-c', 'pacman -S --noconfirm nss'];
    if (installArgv) {
      const r = runAdmin(installArgv);
      record('Install certutil (libnss3-tools)', !!r.ok,
        r.ok ? 'installed' : (r.error || 'elevation failed'));
    } else {
      record('Install certutil (libnss3-tools)', false, 'Install the NSS tools package for your distro');
    }
  } else {
    record('Install certutil (libnss3-tools)', true, 'already present');
  }

  const nssdb = path.join(home, '.pki', 'nssdb');
  if (!fs.existsSync(nssdb)) {
    try { fs.mkdirSync(nssdb, { recursive: true }); } catch {}
    const r = spawn('certutil', ['-N', '--empty-password', '-d', `sql:${nssdb}`]);
    record('Initialise ~/.pki/nssdb', r && r.status === 0,
      r && r.status === 0 ? nssdb : (r && (r.stderr || r.error?.message)) || 'certutil unavailable');
  } else {
    record('Initialise ~/.pki/nssdb', true, 'exists');
  }

  // 4. Chrome/Chromium NSS store (NEVER elevated — user db).
  {
    spawn('certutil', ['-D', '-d', `sql:${nssdb}`, '-n', 'Claude Intercept']); // idempotent delete
    const r = spawn('certutil', ['-d', `sql:${nssdb}`, '-A', '-t', 'C,,', '-n', 'Claude Intercept', '-i', tmpCa]);
    record('Trust in Chrome/Chromium (NSS)', r && r.status === 0,
      r && r.status === 0 ? nssdb : (r && (r.stderr || r.error?.message)) || 'certutil unavailable');
  }

  // 5. Firefox per-profile NSS stores (NEVER elevated — user dirs).
  {
    const ffRoot = path.join(home, '.mozilla', 'firefox');
    let profiles = [];
    try {
      profiles = fs.readdirSync(ffRoot)
        .map(d => path.join(ffRoot, d))
        .filter(d => {
          try { return fs.statSync(d).isDirectory() &&
            (fs.existsSync(path.join(d, 'cert9.db')) || fs.existsSync(path.join(d, 'cert8.db'))); }
          catch { return false; }
        });
    } catch {}
    if (!profiles.length) {
      record('Trust in Firefox profiles', true,
        'No NSS Firefox profiles found — set security.enterprise_roots.enabled=true to use the system store');
    } else {
      let allOk = true;
      const done = [];
      for (const d of profiles) {
        spawn('certutil', ['-D', '-d', `sql:${d}`, '-n', 'Claude Intercept']);
        const r = spawn('certutil', ['-d', `sql:${d}`, '-A', '-t', 'C,,', '-n', 'Claude Intercept', '-i', tmpCa]);
        if (!(r && r.status === 0)) allOk = false; else done.push(path.basename(d));
      }
      record('Trust in Firefox profiles', allOk,
        `${done.length} profile(s); also honours security.enterprise_roots.enabled`);
    }
  }

  try { if (tmpCa !== caPath) fs.unlinkSync(tmpCa); } catch {}
  const ok = steps.every(s => s.ok);
  return { steps, ok };
}

// Reverse trustCertLinux — remove the CA from every store we touched.
function untrustCertLinux(opts = {}) {
  const env = opts.env || detectLinuxEnv(opts.envDeps);
  const runAdmin = opts.runAdmin || ((argv) => require('./system_proxy').linuxRunAdmin(argv, { prefer: opts.prefer }));
  const spawn = opts.spawn || ((cmd, args) => spawnSync(cmd, args, { encoding: 'utf8', stdio: 'pipe' }));
  const home = opts.home || os.homedir();
  const steps = [];
  const record = (name, ok, detail) => { steps.push({ name, ok, detail }); return ok; };

  let sysArgv = null;
  if (env.family === 'debian') {
    sysArgv = ['/bin/sh', '-c',
      'rm -f /usr/local/share/ca-certificates/claude-intercept.crt && update-ca-certificates --fresh'];
  } else if (env.family === 'rhel') {
    sysArgv = ['/bin/sh', '-c',
      'rm -f /etc/pki/ca-trust/source/anchors/claude-intercept.crt && update-ca-trust extract'];
  } else if (env.family === 'arch') {
    sysArgv = ['/bin/sh', '-c', 'trust anchor --remove "Claude Intercept" || true'];
  }
  if (sysArgv) {
    const r = runAdmin(sysArgv);
    record('Remove from system trust store', !!r.ok, r.ok ? `${env.family} store updated` : (r.error || 'elevation failed'));
  } else {
    record('Remove from system trust store', false, 'Unknown distro family — remove the CA anchor manually');
  }

  const nssdb = path.join(home, '.pki', 'nssdb');
  if (fs.existsSync(nssdb)) {
    const r = spawn('certutil', ['-D', '-d', `sql:${nssdb}`, '-n', 'Claude Intercept']);
    record('Remove from Chrome/Chromium (NSS)', r && (r.status === 0 || r.status === 255), nssdb);
  } else {
    record('Remove from Chrome/Chromium (NSS)', true, 'no nssdb');
  }

  const ffRoot = path.join(home, '.mozilla', 'firefox');
  let profiles = [];
  try {
    profiles = fs.readdirSync(ffRoot).map(d => path.join(ffRoot, d)).filter(d => {
      try { return fs.statSync(d).isDirectory() &&
        (fs.existsSync(path.join(d, 'cert9.db')) || fs.existsSync(path.join(d, 'cert8.db'))); }
      catch { return false; }
    });
  } catch {}
  for (const d of profiles) spawn('certutil', ['-D', '-d', `sql:${d}`, '-n', 'Claude Intercept']);
  record('Remove from Firefox profiles', true, `${profiles.length} profile(s)`);

  const ok = steps.every(s => s.ok);
  return { steps, ok };
}

/**
 * Returns step-by-step setup instructions for a given platform.
 * Each step: { title, html, code?, qrUrl? }
 *
 * lanIp is passed from the server so instructions show the real IP.
 */
function getSetupInstructions(platform, proxyPort = 7777, lanIp = null, tailscaleIp = null, opts = {}) {
  const ip = lanIp || '<your-mac-ip>';
  const uiPort = 7778; // always dashboard port
  const certUrl = `http://${ip}:${uiPort}/api/cert`;
  const localCertUrl = `http://127.0.0.1:${uiPort}/api/cert`;
  const tailscaleCertUrl = tailscaleIp ? `http://${tailscaleIp}:${uiPort}/api/cert` : null;

  // Tailor the Linux tab to the actual distro/desktop. Injectable for tests.
  const lenv = opts.linuxEnv || (platform === 'linux'
    ? (opts.detectLinuxEnv || detectLinuxEnv)()
    : null);
  const sysStore = lenv && lenv.family === 'rhel'
    ? `sudo cp claude-intercept-ca.crt /etc/pki/ca-trust/source/anchors/\nsudo update-ca-trust extract`
    : lenv && lenv.family === 'arch'
    ? `sudo trust anchor --store claude-intercept-ca.crt`
    : `sudo cp claude-intercept-ca.crt /usr/local/share/ca-certificates/\nsudo update-ca-certificates`;
  const certutilPkg = lenv && lenv.family === 'rhel' ? 'sudo dnf install -y nss-tools'
    : lenv && lenv.family === 'arch' ? 'sudo pacman -S --noconfirm nss'
    : 'sudo apt-get install -y libnss3-tools';
  const deName = lenv && lenv.de === 'kde' ? 'KDE' : lenv && lenv.de === 'gnome' ? 'GNOME' : 'GNOME/KDE';

  const platforms = {
    'this-mac': [
      {
        title: 'Install the CA Certificate (one time)',
        html: `Click <strong>Download CA Certificate</strong> above to save <code>claude-intercept-ca.crt</code>, then run the command below to trust it system-wide. You only need to do this once — the cert persists across restarts.`,
        code: `sudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain \\\n  ~/Downloads/claude-intercept-ca.crt`,
      },
      {
        title: 'Enable the system proxy',
        html: `Click the <strong>Enable for This Mac</strong> button above (or use the command below). This tells macOS to route all HTTP/HTTPS traffic through claude-intercept on port <code>${proxyPort}</code>. Every app — browsers, Slack, Xcode, etc. — will be intercepted.`,
        code: `node ~/claude_intercept/src/cli.js proxy on`,
      },
      {
        title: 'Browse normally',
        html: `Open any browser or app and use it as usual. All traffic appears in the <strong>Traffic</strong> tab in real time. Apps with hard-coded certificate pinning (e.g. some banking apps) will refuse to connect — that\'s expected and normal.`,
      },
      {
        title: 'Disable when done',
        html: `Always disable the proxy when you\'re finished. Claude Intercept restores your previous network settings automatically.`,
        code: `node ~/claude_intercept/src/cli.js proxy off`,
      },
      {
        title: 'For terminal / CLI tools',
        html: `Many CLI tools (<code>curl</code>, <code>npm</code>, <code>git</code>, <code>wget</code>) use environment variables rather than the system proxy. Set these in your shell or prefix individual commands:`,
        code: `# Set for current session:\nexport http_proxy=http://127.0.0.1:${proxyPort}\nexport https_proxy=http://127.0.0.1:${proxyPort}\nexport HTTP_PROXY=http://127.0.0.1:${proxyPort}\nexport HTTPS_PROXY=http://127.0.0.1:${proxyPort}\n\n# Or for a single command:\nhttps_proxy=http://127.0.0.1:${proxyPort} curl -sk https://api.example.com/v1/me | jq .`,
      },
      {
        title: 'For Node.js apps',
        html: `Node.js ignores system proxy settings by default. Use env vars or a proxy dispatcher:`,
        code: `# Quick single-run:\nHTTPS_PROXY=http://127.0.0.1:${proxyPort} node your-app.js\n\n# Or with undici (npm i undici):\nconst { ProxyAgent, fetch } = require('undici');\nconst proxy = new ProxyAgent('http://127.0.0.1:${proxyPort}');\nconst res = await fetch('https://api.example.com', { dispatcher: proxy });`,
      },
    ],

    ios: [
      {
        title: 'Make sure your iPhone is on the same Wi-Fi as this Mac',
        html: `Your Mac\'s IP on this network is <strong><code>${ip}</code></strong>. Your iPhone must be on the same Wi-Fi network to reach the proxy. You can verify this in <strong>Settings → Wi-Fi → tap your network → IP Address</strong> — the first three octets should match (e.g. both start with <code>${ip.split('.').slice(0,3).join('.')}.</code>).`,
      },
      {
        title: 'Scan the QR code to download the CA Certificate',
        html: `Open <strong>Safari</strong> on your iPhone and scan the QR code below, or type the URL manually. <strong>Must be Safari</strong> — Chrome and Firefox on iOS cannot install certificates.<br><br>
        ${tailscaleIp
          ? `<strong>Wi-Fi (same network):</strong> <code>${certUrl}</code><br><strong>Tailscale:</strong> <code>${tailscaleCertUrl}</code><br><br>Use whichever matches how your iPhone is connected to this Mac.`
          : `<strong>URL:</strong> <code>${certUrl}</code>`
        }`,
        qrUrl: certUrl,
        qrUrlAlt: tailscaleCertUrl || null,
        qrUrlAltLabel: tailscaleIp ? `Tailscale (${tailscaleIp})` : null,
        qrUrlLabel: `Wi-Fi (${ip})`,
      },
      {
        title: 'Install the certificate profile',
        html: `After opening the URL in Safari, iOS will say <em>"This website is trying to download a configuration profile. Do you want to allow this?"</em><br><br>
        Tap <strong>Allow</strong>, then:<br>
        1. Go to <strong>Settings</strong> (Safari will prompt you, or open it manually)<br>
        2. At the top you\'ll see <strong>"Profile Downloaded"</strong> — tap it<br>
        3. Tap <strong>Install</strong> in the top right<br>
        4. Enter your passcode if prompted<br>
        5. Tap <strong>Install</strong> again on the warning screen<br>
        6. Tap <strong>Done</strong>`,
      },
      {
        title: 'Enable full trust for the certificate',
        html: `Installing the profile is not enough — you must also grant it full SSL trust.<br><br>
        Go to <strong>Settings → General → About → Certificate Trust Settings</strong><br><br>
        Under <em>"Enable Full Trust For Root Certificates"</em>, toggle on <strong>Claude Intercept CA</strong>.<br><br>
        A warning will appear — tap <strong>Continue</strong>. This is expected.`,
      },
      {
        title: 'Configure the Wi-Fi proxy on your iPhone',
        html: `Now that the certificate is trusted, point your iPhone\'s traffic through claude-intercept.<br><br>
        <strong>Settings → Wi-Fi</strong> → tap the ⓘ next to your network name → scroll down to <strong>Configure Proxy</strong> → tap <strong>Manual</strong>.<br><br>
        ${tailscaleIp
          ? `Use <strong>Wi-Fi</strong> if your iPhone is on the same local network, or <strong>Tailscale</strong> if you have it installed on your iPhone:<br><br>
            <strong>Option A — Wi-Fi (same network):</strong><br>
            &nbsp;&nbsp;<strong>Server:</strong> <code>${ip}</code><br>
            &nbsp;&nbsp;<strong>Port:</strong> <code>${proxyPort}</code><br><br>
            <strong>Option B — Tailscale:</strong><br>
            &nbsp;&nbsp;<strong>Server:</strong> <code>${tailscaleIp}</code><br>
            &nbsp;&nbsp;<strong>Port:</strong> <code>${proxyPort}</code><br><br>`
          : `Enter these values:<br>
            &nbsp;&nbsp;<strong>Server:</strong> <code>${ip}</code><br>
            &nbsp;&nbsp;<strong>Port:</strong> <code>${proxyPort}</code><br><br>`
        }
        &nbsp;&nbsp;<strong>Authentication:</strong> off<br><br>
        Tap <strong>Save</strong> in the top right.`,
      },
      {
        title: 'Verify traffic is appearing',
        html: `On your iPhone, open Safari and visit any HTTPS site (e.g. <code>https://example.com</code>). Switch to the <strong>Traffic</strong> tab in this dashboard — you should see requests appearing within a second or two.<br><br>
        <strong>Troubleshooting:</strong><br>
        • No traffic? Double-check the proxy server IP and port in Wi-Fi settings.<br>
        • "Cannot Connect to Server"? Make sure claude-intercept is running on your Mac.<br>
        • SSL errors? The certificate trust step (step 4) may have been missed.`,
      },
      {
        title: 'Verify traffic is appearing',
        html: `On your iPhone, open Safari and visit any HTTPS site (e.g. <code>https://example.com</code>). Switch to the <strong>Traffic</strong> tab in this dashboard — you should see requests appearing within a second or two.<br><br>
        <strong>Troubleshooting:</strong><br>
        • No traffic? Double-check the proxy server IP and port in Wi-Fi settings.<br>
        • "Cannot Connect to Server"? Make sure claude-intercept is running on your Mac.<br>
        • SSL errors? The certificate trust step (step 4) may have been missed.`,
      },
      {
        title: 'Disable when done',
        html: `When you\'re finished, <strong>always turn off the proxy on your iPhone before stopping claude-intercept</strong> — if the proxy stops while your phone still points to it, your iPhone will have no internet access until you disable it manually.<br><br>
        Go to <strong>Settings → Wi-Fi → ⓘ → Configure Proxy → Off</strong> → Save.<br><br>
        You can leave the certificate installed — it\'s harmless and saves time next session.`,
        warning: true,
      },
    ],
    _iosWarning: `⚠️ <strong>Important:</strong> If claude-intercept stops running while your iPhone's proxy is still set, <strong>your iPhone will lose internet access entirely</strong> until you go to <strong>Settings → Wi-Fi → ⓘ → Configure Proxy → Off</strong>. Always disable the proxy on your device before stopping claude-intercept.`,

    android: [
      {
        title: 'Connect to the same Wi-Fi',
        html: `Ensure your Android device is on the same Wi-Fi network as this Mac. Your Mac\'s IP is <strong><code>${ip}</code></strong>.`,
      },
      {
        title: 'Configure the Wi-Fi proxy',
        html: `On Android: <strong>Settings → Wi-Fi</strong> → long-press your network name → <strong>Modify network</strong> → expand <strong>Advanced options</strong>.<br><br>
        Set <strong>Proxy</strong> to <strong>Manual</strong> and enter:<br>
        &nbsp;&nbsp;<strong>Proxy hostname:</strong> <code>${ip}</code><br>
        &nbsp;&nbsp;<strong>Proxy port:</strong> <code>${proxyPort}</code><br><br>
        Tap <strong>Save</strong>. (On newer Android the path may be: tap-and-hold → <strong>Manage network settings</strong>.)`,
      },
      {
        title: 'Download the CA certificate',
        html: `Scan the QR code below in Chrome on your Android device, or type the URL manually:<br><br>
        ${tailscaleIp
          ? `<strong>Wi-Fi:</strong> <code>${certUrl}</code><br><strong>Tailscale:</strong> <code>${tailscaleCertUrl}</code>`
          : `<strong>URL:</strong> <code>${certUrl}</code>`
        }`,
        qrUrl: certUrl,
        qrUrlAlt: tailscaleCertUrl || null,
        qrUrlAltLabel: tailscaleIp ? `Tailscale (${tailscaleIp})` : null,
        qrUrlLabel: `Wi-Fi (${ip})`,
      },
      {
        title: 'Install the CA certificate',
        html: `After downloading, go to <strong>Settings → Security → More security settings → Install from device storage</strong> (exact path varies by Android version — you can also search "Install certificate" in Settings).<br><br>
        Select the downloaded <code>claude-intercept-ca.crt</code> file. When prompted for certificate type, choose <strong>CA Certificate</strong>. Give it a name like "Claude Intercept".`,
      },
      {
        title: '⚠️ Certificate pinning warning',
        html: `Android 7+ apps that target API 24 or higher <strong>ignore user-installed CA certificates by default</strong>. This affects most modern apps. Only browsers (Chrome, Firefox) and apps that explicitly opt in to user CAs will work without extra steps.<br><br>
        For full app interception on Android you need either:<br>
        • A rooted device (Magisk + MagiskTrustUserCerts module)<br>
        • A custom build of the app with <code>network_security_config.xml</code> patched<br>
        • An older Android device (API 23 or below)`,
      },
    ],

    macos: [
      {
        title: 'Download the CA Certificate',
        html: `Click the <strong>Download CA Certificate</strong> button above to get <code>claude-intercept-ca.crt</code>.`,
      },
      {
        title: 'Install the certificate in Keychain',
        html: `Open <strong>Keychain Access</strong>, drag the <code>.crt</code> file into the <strong>System</strong> keychain. Double-click it → expand <strong>Trust</strong> → set <em>"When using this certificate"</em> to <strong>Always Trust</strong>.`,
        code: `# Or via Terminal (no GUI needed):\nsudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain \\\n  ~/Downloads/claude-intercept-ca.crt`,
      },
      {
        title: 'Configure System Proxy',
        html: `<strong>System Settings → Network → select your connection → Details → Proxies</strong>.<br>Enable both <strong>Web Proxy (HTTP)</strong> and <strong>Secure Web Proxy (HTTPS)</strong>.<br>Set server to <code>127.0.0.1</code> and port to <code>${proxyPort}</code>.`,
      },
      {
        title: 'Verify it\'s working',
        html: `Browse to any HTTPS site — you should see requests appearing in the <strong>Traffic</strong> tab. The <strong>This Mac</strong> tab has a one-click toggle if you prefer that to manual proxy settings.`,
      },
    ],

    windows: [
      {
        title: 'Download the CA Certificate',
        html: `Click <strong>Download CA Certificate</strong> above to save <code>claude-intercept-ca.crt</code>.`,
      },
      {
        title: 'Install the certificate',
        html: `Double-click the file → <strong>Install Certificate</strong> → <strong>Local Machine</strong> → <em>Place all certificates in the following store</em> → <strong>Trusted Root Certification Authorities</strong> → Finish.`,
        code: `# Or via PowerShell (run as Administrator):\nImport-Certificate -FilePath .\\claude-intercept-ca.crt \`\n  -CertStoreLocation Cert:\\LocalMachine\\Root`,
      },
      {
        title: 'Configure system proxy',
        html: `<strong>Settings → Network & Internet → Proxy → Manual proxy setup</strong>.<br>Toggle on <em>Use a proxy server</em>, set address <code>127.0.0.1</code>, port <code>${proxyPort}</code>.<br>Click <strong>Save</strong>.`,
        code: `# Or via PowerShell:\nSet-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value "127.0.0.1:${proxyPort}"\nSet-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1`,
      },
      {
        title: 'Verify',
        html: `Open Edge or Chrome and browse any HTTPS site. Traffic should appear in the <strong>Traffic</strong> tab immediately.`,
      },
    ],

    linux: [
      {
        title: 'One-click install & trust (recommended)',
        html: `Click <strong>Install &amp; Trust CA</strong> above, or run <code>node ~/claude_intercept/src/cli.js trust</code>. This installs the CA into the system store (sudo prompt via your desktop's polkit dialog or the terminal), auto-installs <code>certutil</code> if missing, and trusts the cert for Chrome/Chromium and Firefox. The steps below are the manual equivalent — use them if the automated run fails or you're on a headless box.`,
      },
      {
        title: 'Download the CA Certificate',
        html: `Run this from your terminal (while claude-intercept is running):`,
        code: `curl -o claude-intercept-ca.crt ${localCertUrl}`,
      },
      {
        title: `Install system-wide${lenv ? ` (${lenv.family === 'rhel' ? 'RHEL/Fedora' : lenv.family === 'arch' ? 'Arch' : 'Debian/Ubuntu'})` : ''}`,
        html: `Adds the CA to the OS trust store used by <code>curl</code>, <code>git</code>, and most CLI tools. <strong>Requires sudo.</strong>`,
        code: sysStore,
        warning: true,
      },
      {
        title: 'Trust the CA in Chrome / Chromium',
        html: `Chrome on Linux uses its own NSS database (<code>~/.pki/nssdb</code>), not the system store.${lenv && !lenv.hasCertutil ? ` <code>certutil</code> is not installed — install the NSS tools first:` : ''}`,
        code: `${lenv && !lenv.hasCertutil ? `${certutilPkg}\n` : ''}certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Claude Intercept" -i claude-intercept-ca.crt`,
      },
      {
        title: 'Trust the CA in Firefox',
        html: `Firefox keeps its own per-profile NSS store. Either import it via <strong>Settings → Privacy &amp; Security → View Certificates → Authorities → Import</strong>, or set <code>security.enterprise_roots.enabled = true</code> in <code>about:config</code> so Firefox honours the system store, or run:`,
        code: `for d in ~/.mozilla/firefox/*.default* ~/.mozilla/firefox/*; do\n  [ -f "$d/cert9.db" ] && certutil -d sql:"$d" -A -t "C,," -n "Claude Intercept" -i claude-intercept-ca.crt\ndone`,
      },
      {
        title: `Enable the system proxy (${deName})`,
        html: `Use the <strong>Enable for This Machine</strong> button above, or the CLI. This toggles ${deName} proxy settings automatically:`,
        code: `node ~/claude_intercept/src/cli.js proxy on`,
      },
      {
        title: 'Set proxy environment variables (CLI tools)',
        html: `Many CLI tools (<code>curl</code>, <code>npm</code>, <code>git</code>) use env vars rather than the desktop proxy. Add to <code>~/.bashrc</code>/<code>~/.zshrc</code> for persistence, or set inline:`,
        code: `export http_proxy=http://127.0.0.1:${proxyPort}\nexport https_proxy=http://127.0.0.1:${proxyPort}\nexport HTTP_PROXY=http://127.0.0.1:${proxyPort}\nexport HTTPS_PROXY=http://127.0.0.1:${proxyPort}\nexport no_proxy=localhost,127.0.0.1`,
      },
      {
        title: 'Note: Google-pinned domains',
        html: `Some Google properties (and a handful of apps) pin their certificates and will fail under any MITM proxy — this is expected and not a bug. Disable the proxy for those, or accept the gaps.`,
      },
    ],

    firefox: [
      {
        title: 'Download the CA Certificate',
        html: `Click <strong>Download CA Certificate</strong> above. Firefox uses its own certificate store — the OS certificate is <strong>not</strong> shared with Firefox.`,
      },
      {
        title: 'Import the certificate into Firefox',
        html: `In Firefox: <strong>Settings → Privacy & Security</strong> → scroll to <em>Certificates</em> → <strong>View Certificates</strong> → <strong>Authorities</strong> tab → <strong>Import…</strong><br><br>Select <code>claude-intercept-ca.crt</code> and check <strong>"Trust this CA to identify websites"</strong>. Click OK.`,
      },
      {
        title: 'Configure Firefox proxy',
        html: `<strong>Settings → General</strong> → scroll to bottom → <strong>Network Settings → Settings…</strong><br><br>Select <strong>Manual proxy configuration</strong>:<br>
        &nbsp;&nbsp;<strong>HTTP Proxy:</strong> <code>127.0.0.1</code> &nbsp; Port: <code>${proxyPort}</code><br>
        &nbsp;&nbsp;Check <strong>"Also use this proxy for HTTPS"</strong><br><br>
        Click OK. Firefox is now fully intercepted.`,
      },
    ],
  };

  const steps = platforms[platform] || platforms['this-mac'];
  const topWarning = platform === 'ios' ? platforms._iosWarning :
                     platform === 'android' ? `⚠️ <strong>Important:</strong> If claude-intercept stops running while your Android proxy is still set, <strong>your device will lose internet access entirely</strong> until you go to <strong>Wi-Fi settings → your network → Proxy → None</strong>. Always disable the proxy on your device before stopping claude-intercept.` :
                     null;
  return { platform, steps, proxyPort, lanIp: ip, tailscaleIp, topWarning };
}

module.exports = {
  getSetupInstructions,
  parseOsRelease,
  detectLinuxEnv,
  trustCertLinux,
  untrustCertLinux,
};
