'use strict';

// Uses built-in node:sqlite (Node.js 22.5+) — no native compilation needed.
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DB_DIR = path.join(__dirname, '../../captures');
const DB_PATH = path.join(DB_DIR, 'captures.db');
const MAX_QUERY_LIMIT = 5000;
const MAX_WS_QUERY_LIMIT = 100;
const MAX_WS_FRAMES_PER_CONNECTION = 200;
const MAX_WS_PAYLOAD_BYTES = 8192;
const MIB = 1024 * 1024;
const DEFAULT_CAPTURE_LIMIT_BYTES = 512 * MIB;

let db;
let pageSize = 4096;
let captureLimitPages = DEFAULT_CAPTURE_LIMIT_BYTES / pageSize;
let storageLimitReached = false;

function configuredCaptureLimit(override) {
  if (override !== undefined) {
    if (!Number.isSafeInteger(override) || override < MIB) {
      throw new RangeError('Capture database limit must be at least 1 MiB');
    }
    return override;
  }
  const setting = process.env.CLAUDE_INTERCEPT_MAX_CAPTURE_MB;
  if (setting === undefined) return DEFAULT_CAPTURE_LIMIT_BYTES;
  const mb = Number(setting);
  if (!Number.isSafeInteger(mb) || mb < 16 || mb > 8192) {
    throw new RangeError('CLAUDE_INTERCEPT_MAX_CAPTURE_MB must be an integer from 16 to 8192');
  }
  return mb * MIB;
}

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

function init({ maxCaptureBytes } = {}) {
  const limitBytes = configuredCaptureLimit(maxCaptureBytes);
  if (db) db.close();
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
  db.exec('PRAGMA foreign_keys = ON');
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
    CREATE TABLE IF NOT EXISTS ws_frames (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      connection_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
      timestamp     INTEGER NOT NULL,
      direction     TEXT    NOT NULL,
      opcode        INTEGER NOT NULL,
      is_text       INTEGER NOT NULL,
      payload       TEXT    NOT NULL,
      payload_size  INTEGER NOT NULL,
      truncated     INTEGER NOT NULL DEFAULT 0,
      compressed    INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_ws_conn ON ws_frames(connection_id);
  `);

  // Earlier preview builds may have created ws_frames before compression was tracked.
  try { db.exec('ALTER TABLE ws_frames ADD COLUMN compressed INTEGER NOT NULL DEFAULT 0'); } catch {}
  // Existing preview tables may not have a foreign key, so remove payloads
  // whose capture was deleted before this version was installed.
  db.exec('DELETE FROM ws_frames WHERE NOT EXISTS (SELECT 1 FROM captures WHERE captures.id = ws_frames.connection_id)');

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

  pageSize = db.prepare('PRAGMA page_size').get().page_size;
  const requestedPages = Math.max(1, Math.floor(limitBytes / pageSize));
  captureLimitPages = db.prepare(`PRAGMA max_page_count = ${requestedPages}`).get().max_page_count;
  db.exec(`PRAGMA journal_size_limit = ${16 * MIB}`);
  storageLimitReached = false;

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

  let result;
  try {
    result = stmt.run({
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
  } catch (err) {
    if (err.code === 'SQLITE_FULL' || /database or disk is full/i.test(err.message)) {
      storageLimitReached = true;
      const quotaError = new Error('Capture database limit or disk capacity reached');
      quotaError.code = 'CAPTURE_QUOTA_EXCEEDED';
      throw quotaError;
    }
    throw err;
  }

  storageLimitReached = false;

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
  summaryOnly = false,
  listOnly = false,
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
      `SELECT ${summaryOnly ? 'id, host, method, response_status, duration_ms'
        : listOnly ? 'id, timestamp, method, url, host, path, response_status, duration_ms, client_label'
          : '*'}
       FROM captures ${where} ORDER BY id DESC LIMIT $limit OFFSET $offset`
    )
    .all({ ...params, $limit: boundedLimit, $offset: boundedOffset });

  return {
    total: Number(total),
    rows: rows.map(summaryOnly ? parseSummaryRow : listOnly ? parseListRow : parseRow),
  };
}

function getCaptureById(id, { summaryOnly = false } = {}) {
  const columns = summaryOnly ? 'id, host, method, response_status, duration_ms' : '*';
  const row = db.prepare(`SELECT ${columns} FROM captures WHERE id = $id`).get({ $id: id });
  return row ? (summaryOnly ? parseSummaryRow(row) : parseRow(row)) : null;
}

function clearCaptures() {
  db.exec('BEGIN');
  try {
    db.prepare('DELETE FROM ws_frames').run();
    db.prepare('DELETE FROM captures').run();
    db.exec('COMMIT');
    storageLimitReached = false;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function deleteCaptures(ids) {
  if (!Array.isArray(ids)) throw new TypeError('ids must be an array');
  if (ids.length === 0) return 0;
  const placeholders = ids.map(() => '?').join(',');
  db.exec('BEGIN');
  try {
    db.prepare(`DELETE FROM ws_frames WHERE connection_id IN (${placeholders})`).run(...ids);
    const deleted = db.prepare(`DELETE FROM captures WHERE id IN (${placeholders})`).run(...ids).changes;
    db.exec('COMMIT');
    if (deleted) storageLimitReached = false;
    return deleted;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function insertWsFrame(frame) {
  if (!Number.isSafeInteger(frame.connectionId) || frame.connectionId < 1 ||
      typeof frame.payload !== 'string' ||
      Buffer.byteLength(frame.payload) > MAX_WS_PAYLOAD_BYTES) {
    throw new RangeError('Invalid or oversized WebSocket frame capture');
  }
  if (getWsFrameCount(frame.connectionId) >= MAX_WS_FRAMES_PER_CONNECTION) return null;
  let result;
  try {
    result = db.prepare(`
      INSERT INTO ws_frames
        (connection_id, timestamp, direction, opcode, is_text, payload, payload_size, truncated, compressed)
      SELECT $connectionId, $timestamp, $direction, $opcode, $isText,
        $payload, $payloadSize, $truncated, $compressed
      WHERE EXISTS (SELECT 1 FROM captures WHERE id = $connectionId)
    `).run({
      $connectionId: frame.connectionId,
      $timestamp: frame.timestamp,
      $direction: frame.direction,
      $opcode: frame.opcode,
      $isText: frame.isText ? 1 : 0,
      $payload: frame.payload,
      $payloadSize: frame.payloadSize,
      $truncated: frame.truncated ? 1 : 0,
      $compressed: frame.compressed ? 1 : 0,
    });
  } catch (err) {
    if (err.code === 'SQLITE_FULL' || /database or disk is full/i.test(err.message)) {
      storageLimitReached = true;
      const quotaError = new Error('Capture database limit or disk capacity reached');
      quotaError.code = 'CAPTURE_QUOTA_EXCEEDED';
      throw quotaError;
    }
    throw err;
  }
  if (!result.changes) return null;
  storageLimitReached = false;
  return Number(result.lastInsertRowid);
}

function getWsFrames(connectionId, { limit = MAX_WS_QUERY_LIMIT, offset = 0 } = {}) {
  const count = Number(limit);
  const start = Number(offset);
  const boundedLimit = Number.isSafeInteger(count) && count > 0
    ? Math.min(count, MAX_WS_QUERY_LIMIT) : MAX_WS_QUERY_LIMIT;
  const boundedOffset = Number.isSafeInteger(start) && start >= 0 ? start : 0;
  return db.prepare(`SELECT * FROM ws_frames WHERE connection_id = $id
    ORDER BY id ASC LIMIT $limit OFFSET $offset`)
    .all({ $id: connectionId, $limit: boundedLimit, $offset: boundedOffset })
    .map(parseFrameRow);
}

function getWsFrameCount(connectionId) {
  return Number(db.prepare('SELECT COUNT(*) AS n FROM ws_frames WHERE connection_id = $id')
    .get({ $id: connectionId })?.n || 0);
}

function finalizeWsCapture(id, { duration, responseBody, responseStatus }) {
  return db.prepare(`UPDATE captures SET duration_ms = $duration,
    response_body = $responseBody, response_status = $responseStatus WHERE id = $id`)
    .run({ $id: id, $duration: duration || 0, $responseBody: responseBody || '',
      $responseStatus: responseStatus ?? 101 }).changes;
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
  const pages = db.prepare('PRAGMA page_count').get().page_count;
  const freePages = db.prepare('PRAGMA freelist_count').get().freelist_count;
  return {
    total: Number(row?.total || 0),
    hosts: Number(row?.hosts || 0),
    avgDuration: row?.avgDuration || 0,
    lastId: Number(row?.lastId || 0),
    storageBytes: pages * pageSize,
    storageLimitBytes: captureLimitPages * pageSize,
    storageLimitReached: storageLimitReached || (pages >= captureLimitPages && freePages === 0),
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

function parseFrameRow(row) {
  return {
    id: Number(row.id),
    connectionId: Number(row.connection_id),
    timestamp: Number(row.timestamp),
    direction: row.direction,
    opcode: Number(row.opcode),
    isText: Boolean(row.is_text),
    payload: row.payload,
    payloadSize: Number(row.payload_size || 0),
    truncated: Boolean(row.truncated),
    compressed: Boolean(row.compressed),
  };
}

function parseSummaryRow(row) {
  return {
    id: Number(row.id),
    host: row.host,
    method: row.method,
    responseStatus: Number(row.response_status || 0),
    duration: Number(row.duration_ms || 0),
  };
}

function parseListRow(row) {
  return {
    id: Number(row.id),
    timestamp: Number(row.timestamp),
    method: row.method,
    url: row.url,
    host: row.host,
    path: row.path,
    responseStatus: Number(row.response_status || 0),
    duration: Number(row.duration_ms || 0),
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

module.exports = { init, insertCapture, queryCaptures, getCaptureById, clearCaptures,
  deleteCaptures, getStats, getDevices, insertWsFrame, getWsFrames, getWsFrameCount,
  finalizeWsCapture };
