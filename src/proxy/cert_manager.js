'use strict';

const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const net = require('node:net');
const { randomBytes } = require('node:crypto');

const CERTS_DIR = path.join(__dirname, '../../certs');
const CA_CERT_PATH = path.join(CERTS_DIR, 'ca.crt');
const CA_KEY_PATH = path.join(CERTS_DIR, 'ca.key');
const LEAF_KEY_PATH = path.join(CERTS_DIR, 'leaf.key');

// Cache host certs in memory to avoid regeneration
const hostCertCache = new Map();
const MAX_HOST_CERTS = 256;

let caKey, caCert, leafKey, leafKeyPem;
const LEAF_VALIDITY_MS = 90 * 24 * 60 * 60 * 1000;

function randomSerialNumber() {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] & 0x7f) | 0x01; // positive and nonzero
  return bytes.toString('hex');
}

function ensureDirs() {
  fs.mkdirSync(CERTS_DIR, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(CERTS_DIR).isDirectory()) {
    throw new Error(`Certificate path is not a directory: ${CERTS_DIR}`);
  }
  fs.chmodSync(CERTS_DIR, 0o700);
  // Older installations created private keys with the process umask (often
  // 0644). Restrict them before reading or reusing them.
  for (const filePath of [CA_CERT_PATH, CA_KEY_PATH, LEAF_KEY_PATH]) {
    try {
      if (!fs.lstatSync(filePath).isFile()) {
        throw new Error(`Certificate path is not a regular file: ${filePath}`);
      }
      if (filePath !== CA_CERT_PATH) fs.chmodSync(filePath, 0o600);
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
  cert.serialNumber = randomSerialNumber();
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
  const hasCert = !!fs.lstatSync(CA_CERT_PATH, { throwIfNoEntry: false });
  const hasKey = !!fs.lstatSync(CA_KEY_PATH, { throwIfNoEntry: false });
  if (hasCert !== hasKey) {
    throw new Error('CA certificate/key is incomplete; refusing to replace the trusted CA');
  }
  if (hasCert) {
    const certPem = fs.readFileSync(CA_CERT_PATH, 'utf8');
    const keyPem = fs.readFileSync(CA_KEY_PATH, 'utf8');
    let cert, key;
    try {
      cert = forge.pki.certificateFromPem(certPem);
      key = forge.pki.privateKeyFromPem(keyPem);
      if (cert.publicKey.n.compareTo(key.n) !== 0 ||
          cert.publicKey.e.compareTo(key.e) !== 0 || !cert.verify(cert)) {
        throw new Error('CA certificate and private key do not match');
      }
    } catch (err) {
      throw new Error(`Invalid CA certificate/key; refusing to replace the trusted CA: ${err.message}`);
    }
    const now = Date.now();
    if (cert.validity.notBefore.getTime() > now || cert.validity.notAfter.getTime() <= now) {
      throw new Error('CA certificate is outside its validity period; rotate and re-trust it explicitly');
    }
    return {
      cert,
      key,
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
  hostCertCache.clear();
}

function getCertForHost(hostname) {
  const cached = hostCertCache.get(hostname);
  if (cached && cached.validUntil > Date.now() + 60_000) return cached;

  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.setRsaPublicKey(leafKey.n, leafKey.e);

  cert.serialNumber = randomSerialNumber();
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + LEAF_VALIDITY_MS);

  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);

  const altNames = net.isIP(hostname)
    ? [{ type: 7, ip: hostname }]
    : [{ type: 2, value: hostname }];

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const result = { certPem, keyPem: leafKeyPem, validUntil: cert.validity.notAfter.getTime() };
  hostCertCache.set(hostname, result);
  if (hostCertCache.size > MAX_HOST_CERTS) {
    hostCertCache.delete(hostCertCache.keys().next().value);
  }
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
