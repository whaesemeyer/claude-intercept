'use strict';

// Uses built-in node:sqlite (Node.js 22.5+) — no native compilation needed.
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DB_DIR = path.join(__dirname, '../../captures');
const DB_PATH = path.join(DB_DIR, 'captures.db');
const MAX_QUERY_LIMIT = 5000;

let db;

function secureFile(filePath) {
  try {
    if (!fs.lstatSync(filePath).isFile()) {
      throw new Error(`Capture database path is not a regular file: ${filePath}`);
    }
    fs.chmodSync(filePath, 0o600);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

function init() {
  fs.mkdirSync(DB_DIR, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(DB_DIR).isDirectory()) {
    throw new Error(`Capture path is not a directory: ${DB_DIR}`);
  }
  fs.chmodSync(DB_DIR, 0o700);
  for (const filePath of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`, `${DB_PATH}-journal`]) {
    secureFile(filePath);
  }

  // SQLite does not expose a file-mode option. Pre-create the database with
  // owner-only access before SQLite opens it.
  const fd = fs.openSync(DB_PATH, 'a', 0o600);
  fs.closeSync(fd);
  secureFile(DB_PATH);

  db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS captures (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp       INTEGER NOT NULL,
      method          TEXT    NOT NULL,
      url             TEXT    NOT NULL,
      host            TEXT    NOT NULL,
      path            TEXT    NOT NULL,
      request_headers TEXT,
      request_body    TEXT,
      response_status INTEGER,
      response_headers TEXT,
      response_body   TEXT,
      content_type    TEXT,
      duration_ms     INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_host      ON captures(host);
    CREATE INDEX IF NOT EXISTS idx_method    ON captures(method);
    CREATE INDEX IF NOT EXISTS idx_status    ON captures(response_status);
    CREATE INDEX IF NOT EXISTS idx_timestamp ON captures(timestamp);
  `);

  // Migration: add device columns (safe to run on existing DBs — errors = column already exists)
  try { db.exec("ALTER TABLE captures ADD COLUMN client_ip TEXT"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN client_label TEXT"); } catch {}

  // Migration: encoding + wire-size columns (captured after decompression).
  try { db.exec("ALTER TABLE captures ADD COLUMN response_encoding TEXT DEFAULT 'identity'"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN response_body_size INTEGER DEFAULT 0"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN request_encoding TEXT DEFAULT 'identity'"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN request_body_size INTEGER DEFAULT 0"); } catch {}

  // WAL/SHM files may be created by the first schema write, after the database
  // connection opens. Match the database's owner-only permissions.
  for (const filePath of [`${DB_PATH}-wal`, `${DB_PATH}-shm`, `${DB_PATH}-journal`]) {
    secureFile(filePath);
  }

  return db;
}

function insertCapture(capture) {
  const stmt = db.prepare(`
    INSERT INTO captures
      (timestamp, method, url, host, path,
       request_headers, request_body, request_encoding, request_body_size,
       response_status, response_headers, response_body, response_encoding, response_body_size,
       content_type, duration_ms, client_ip, client_label)
    VALUES
      ($timestamp, $method, $url, $host, $path,
       $requestHeaders, $requestBody, $requestEncoding, $requestBodySize,
       $responseStatus, $responseHeaders, $responseBody, $responseEncoding, $responseBodySize,
       $contentType, $duration, $clientIp, $clientLabel)
  `);

  const result = stmt.run({
    $timestamp: capture.timestamp,
    $method: capture.method,
    $url: capture.url,
    $host: capture.host,
    $path: capture.path,
    $requestHeaders: JSON.stringify(capture.requestHeaders || {}),
    $requestBody: capture.requestBody || '',
    $requestEncoding: capture.requestEncoding || 'identity',
    $requestBodySize: capture.requestBodySize || 0,
    $responseStatus: capture.responseStatus,
    $responseHeaders: JSON.stringify(capture.responseHeaders || {}),
    $responseBody: capture.responseBody || '',
    $responseEncoding: capture.responseEncoding || 'identity',
    $responseBodySize: capture.responseBodySize || 0,
    $contentType: capture.contentType || '',
    $duration: capture.duration || 0,
    $clientIp: capture.clientIp || '',
    $clientLabel: capture.clientLabel || '',
  });

  return Number(result.lastInsertRowid);
}

function queryCaptures({
  host,
  method,
  status,
  contentType,
  search,
  hasAuth,
  device,
  afterId,
  limit = 100,
  offset = 0,
} = {}) {
  const requestedLimit = Number(limit);
  const requestedOffset = Number(offset);
  const boundedLimit = Number.isSafeInteger(requestedLimit) && requestedLimit > 0
    ? Math.min(requestedLimit, MAX_QUERY_LIMIT) : 100;
  const boundedOffset = Number.isSafeInteger(requestedOffset) && requestedOffset >= 0
    ? requestedOffset : 0;
  const conditions = [];
  const params = {};

  if (host) {
    conditions.push('host LIKE $host');
    params.$host = `%${host}%`;
  }
  if (method) {
    conditions.push('method = $method');
    params.$method = method.toUpperCase();
  }
  if (status) {
    if (String(status).endsWith('xx')) {
      const base = parseInt(status) * 100;
      conditions.push('response_status BETWEEN $statusLo AND $statusHi');
      params.$statusLo = base;
      params.$statusHi = base + 99;
    } else {
      conditions.push('response_status = $status');
      params.$status = Number(status);
    }
  }
  if (contentType) {
    conditions.push('content_type LIKE $contentType');
    params.$contentType = `%${contentType}%`;
  }
  if (search) {
    conditions.push(
      '(url LIKE $search OR request_body LIKE $search OR response_body LIKE $search)'
    );
    params.$search = `%${search}%`;
  }
  if (hasAuth) {
    conditions.push(
      "(request_headers LIKE '%authorization%' OR request_headers LIKE '%cookie%')"
    );
  }
  if (device) {
    conditions.push('client_label LIKE $device');
    params.$device = `%${device}%`;
  }
  if (afterId) {
    conditions.push('id > $afterId');
    params.$afterId = afterId;
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const total = db
    .prepare(`SELECT COUNT(*) as n FROM captures ${where}`)
    .get(params)?.n || 0;

  const rows = db
    .prepare(
      `SELECT * FROM captures ${where} ORDER BY id DESC LIMIT $limit OFFSET $offset`
    )
    .all({ ...params, $limit: boundedLimit, $offset: boundedOffset });

  return {
    total: Number(total),
    rows: rows.map(parseRow),
  };
}

function getCaptureById(id) {
  const row = db.prepare('SELECT * FROM captures WHERE id = $id').get({ $id: id });
  return row ? parseRow(row) : null;
}

function clearCaptures() {
  db.prepare('DELETE FROM captures').run();
}

function deleteCaptures(ids) {
  if (!Array.isArray(ids)) throw new TypeError('ids must be an array');
  if (ids.length === 0) return 0;
  const placeholders = ids.map(() => '?').join(',');
  return db.prepare(`DELETE FROM captures WHERE id IN (${placeholders})`).run(...ids).changes;
}

function getStats() {
  const row = db.prepare(
    `SELECT
      COUNT(*) as total,
      COUNT(DISTINCT host) as hosts,
      AVG(duration_ms) as avgDuration,
      MAX(id) as lastId
     FROM captures`
  ).get();
  return {
    total: Number(row?.total || 0),
    hosts: Number(row?.hosts || 0),
    avgDuration: row?.avgDuration || 0,
    lastId: Number(row?.lastId || 0),
  };
}

function parseRow(row) {
  return {
    id: Number(row.id),
    timestamp: Number(row.timestamp),
    method: row.method,
    url: row.url,
    host: row.host,
    path: row.path,
    requestHeaders: tryParse(row.request_headers, {}),
    requestBody: row.request_body,
    requestEncoding: row.request_encoding || 'identity',
    requestBodySize: Number(row.request_body_size || 0),
    responseHeaders: tryParse(row.response_headers, {}),
    responseBody: row.response_body,
    responseEncoding: row.response_encoding || 'identity',
    responseBodySize: Number(row.response_body_size || 0),
    responseStatus: row.response_status,
    contentType: row.content_type,
    duration: Number(row.duration_ms || 0),
    clientIp: row.client_ip || '',
    clientLabel: row.client_label || '',
  };
}

function getDevices() {
  return db
    .prepare("SELECT DISTINCT client_label FROM captures WHERE client_label != '' ORDER BY client_label")
    .all()
    .map(r => r.client_label);
}

function tryParse(str, fallback) {
  try { return JSON.parse(str); } catch { return fallback; }
}

module.exports = { init, insertCapture, queryCaptures, getCaptureById, clearCaptures, deleteCaptures, getStats, getDevices };
