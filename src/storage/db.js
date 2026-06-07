'use strict';

// Uses built-in node:sqlite (Node.js 22.5+) — no native compilation needed.
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DB_DIR = path.join(__dirname, '../../captures');
const DB_PATH = path.join(DB_DIR, 'captures.db');

let db;

function init() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

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

  // WebSocket frames: one row per application/control frame, linked back to the
  // connection-level row in `captures` (method 'WS') via connection_id. This
  // keeps the dashboard's "one row per request" model intact — the connection
  // is the request, frames expand inline underneath it.
  db.exec(`
    CREATE TABLE IF NOT EXISTS ws_frames (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      connection_id INTEGER NOT NULL,
      timestamp     INTEGER NOT NULL,
      direction     TEXT    NOT NULL,   -- 'client→server' | 'server→client'
      opcode        INTEGER NOT NULL,   -- RFC 6455 opcode
      is_text       INTEGER NOT NULL,   -- 1 = utf-8 text, 0 = base64/hex
      payload       TEXT,
      payload_size  INTEGER,            -- decoded byte length on the wire
      truncated     INTEGER DEFAULT 0,
      compressed    INTEGER DEFAULT 0   -- 1 = deflated bytes we couldn't inflate
    );
    CREATE INDEX IF NOT EXISTS idx_ws_conn ON ws_frames(connection_id);
  `);

  // Migration: add compressed column to ws_frames on pre-existing DBs.
  try { db.exec("ALTER TABLE ws_frames ADD COLUMN compressed INTEGER DEFAULT 0"); } catch {}

  // Migration: add device columns (safe to run on existing DBs — errors = column already exists)
  try { db.exec("ALTER TABLE captures ADD COLUMN client_ip TEXT"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN client_label TEXT"); } catch {}

  // Migration: encoding + wire-size columns (captured after decompression).
  try { db.exec("ALTER TABLE captures ADD COLUMN response_encoding TEXT DEFAULT 'identity'"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN response_body_size INTEGER DEFAULT 0"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN request_encoding TEXT DEFAULT 'identity'"); } catch {}
  try { db.exec("ALTER TABLE captures ADD COLUMN request_body_size INTEGER DEFAULT 0"); } catch {}

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
    .all({ ...params, $limit: limit, $offset: offset });

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
  db.prepare('DELETE FROM ws_frames').run();
}

function deleteCaptures(ids) {
  const placeholders = ids.map(() => '?').join(',');
  db.prepare(`DELETE FROM captures WHERE id IN (${placeholders})`).run(...ids);
  db.prepare(`DELETE FROM ws_frames WHERE connection_id IN (${placeholders})`).run(...ids);
}

// ── WebSocket frames ───────────────────────────────────────────────────────

function insertWsFrame(frame) {
  const stmt = db.prepare(`
    INSERT INTO ws_frames
      (connection_id, timestamp, direction, opcode, is_text, payload, payload_size, truncated, compressed)
    VALUES
      ($connectionId, $timestamp, $direction, $opcode, $isText, $payload, $payloadSize, $truncated, $compressed)
  `);
  const result = stmt.run({
    $connectionId: frame.connectionId,
    $timestamp: frame.timestamp,
    $direction: frame.direction,
    $opcode: frame.opcode,
    $isText: frame.isText ? 1 : 0,
    $payload: frame.payload || '',
    $payloadSize: frame.payloadSize || 0,
    $truncated: frame.truncated ? 1 : 0,
    $compressed: frame.compressed ? 1 : 0,
  });
  return Number(result.lastInsertRowid);
}

function getWsFrames(connectionId, { limit = 5000, offset = 0 } = {}) {
  return db
    .prepare(
      `SELECT * FROM ws_frames WHERE connection_id = $id
       ORDER BY id ASC LIMIT $limit OFFSET $offset`
    )
    .all({ $id: connectionId, $limit: limit, $offset: offset })
    .map(parseFrameRow);
}

function getWsFrameCount(connectionId) {
  const row = db
    .prepare('SELECT COUNT(*) as n FROM ws_frames WHERE connection_id = $id')
    .get({ $id: connectionId });
  return Number(row?.n || 0);
}

// Update the connection-level row once the WS closes — final duration plus a
// human summary in place of the "[capturing frames…]" placeholder.
function finalizeWsCapture(id, { duration, responseBody, responseStatus }) {
  db.prepare(
    `UPDATE captures
       SET duration_ms = $duration,
           response_body = $responseBody,
           response_status = $responseStatus
     WHERE id = $id`
  ).run({
    $id: id,
    $duration: duration || 0,
    $responseBody: responseBody || '',
    $responseStatus: responseStatus || 101,
  });
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

function parseFrameRow(row) {
  return {
    id: Number(row.id),
    connectionId: Number(row.connection_id),
    timestamp: Number(row.timestamp),
    direction: row.direction,
    opcode: Number(row.opcode),
    isText: !!row.is_text,
    payload: row.payload,
    payloadSize: Number(row.payload_size || 0),
    truncated: !!row.truncated,
    compressed: !!row.compressed,
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

module.exports = {
  init, insertCapture, queryCaptures, getCaptureById, clearCaptures, deleteCaptures,
  getStats, getDevices,
  insertWsFrame, getWsFrames, getWsFrameCount, finalizeWsCapture,
};
