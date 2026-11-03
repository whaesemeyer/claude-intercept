'use strict';

const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const CERTS_DIR = path.join(__dirname, '../../certs');
const CA_CERT_PATH = path.join(CERTS_DIR, 'ca.crt');
const CA_KEY_PATH = path.join(CERTS_DIR, 'ca.key');
const LEAF_KEY_PATH = path.join(CERTS_DIR, 'leaf.key');

// Cache host certs in memory to avoid regeneration
const hostCertCache = new Map();

let caKey, caCert, leafKey, leafKeyPem;

function ensureDirs() {
  fs.mkdirSync(CERTS_DIR, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(CERTS_DIR).isDirectory()) {
    throw new Error(`Certificate path is not a directory: ${CERTS_DIR}`);
  }
  fs.chmodSync(CERTS_DIR, 0o700);
  // Older installations created private keys with the process umask (often
  // 0644). Restrict them before reading or reusing them.
  for (const keyPath of [CA_KEY_PATH, LEAF_KEY_PATH]) {
    try {
      if (!fs.lstatSync(keyPath).isFile()) {
        throw new Error(`Certificate key is not a regular file: ${keyPath}`);
      }
      fs.chmodSync(keyPath, 0o600);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }
}

function writePrivateKey(filePath, pem) {
  fs.writeFileSync(filePath, pem, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function generateCA() {
  console.log('[cert] Generating CA certificate...');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName', value: 'Claude Intercept CA' },
    { name: 'organizationName', value: 'Claude Intercept' },
    { shortName: 'OU', value: 'Security Research' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  fs.writeFileSync(CA_CERT_PATH, certPem);
  writePrivateKey(CA_KEY_PATH, keyPem);
  console.log('[cert] CA generated →', CA_CERT_PATH);

  return { cert, key: keys.privateKey };
}

function generateLeafKey() {
  console.log('[cert] Generating shared leaf key...');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const pem = forge.pki.privateKeyToPem(keys.privateKey);
  writePrivateKey(LEAF_KEY_PATH, pem);
  console.log('[cert] Leaf key generated →', LEAF_KEY_PATH);
  return { key: keys.privateKey, pem };
}

function loadOrCreateCA() {
  ensureDirs();
  if (fs.existsSync(CA_CERT_PATH) && fs.existsSync(CA_KEY_PATH)) {
    const certPem = fs.readFileSync(CA_CERT_PATH, 'utf8');
    const keyPem = fs.readFileSync(CA_KEY_PATH, 'utf8');
    return {
      cert: forge.pki.certificateFromPem(certPem),
      key: forge.pki.privateKeyFromPem(keyPem),
    };
  }
  return generateCA();
}

function loadOrCreateLeafKey() {
  ensureDirs();
  if (fs.existsSync(LEAF_KEY_PATH)) {
    const pem = fs.readFileSync(LEAF_KEY_PATH, 'utf8');
    return { key: forge.pki.privateKeyFromPem(pem), pem };
  }
  return generateLeafKey();
}

function init() {
  const ca = loadOrCreateCA();
  caKey = ca.key;
  caCert = ca.cert;

  const leaf = loadOrCreateLeafKey();
  leafKey = leaf.key;
  leafKeyPem = leaf.pem;
}

function getCertForHost(hostname) {
  if (hostCertCache.has(hostname)) return hostCertCache.get(hostname);

  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.setRsaPublicKey(leafKey.n, leafKey.e);

  cert.serialNumber = String(Date.now());
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 2);

  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);

  const altNames = [{ type: 2, value: hostname }]; // DNS
  // If it looks like an IP, also add as IP SAN
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    altNames.push({ type: 7, ip: hostname });
  }

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const result = { certPem, keyPem: leafKeyPem };
  hostCertCache.set(hostname, result);
  return result;
}

function getCACertPath() {
  return CA_CERT_PATH;
}

function getCACertPem() {
  if (!fs.existsSync(CA_CERT_PATH)) init();
  return fs.readFileSync(CA_CERT_PATH, 'utf8');
}

module.exports = { init, getCertForHost, getCACertPath, getCACertPem };
