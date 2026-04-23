'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const zlib = require('node:zlib');
const { tryDecodeBody } = require('../body');

const json = JSON.stringify({ hello: 'world', n: 42 });

test('empty buffer', () => {
  const r = tryDecodeBody(Buffer.alloc(0), 'application/json', '');
  assert.strictEqual(r.text, '');
  assert.strictEqual(r.encoding, 'identity');
  assert.strictEqual(r.originalSize, 0);
});

test('identity JSON passes through', () => {
  const buf = Buffer.from(json);
  const r = tryDecodeBody(buf, 'application/json', '');
  assert.strictEqual(r.text, json);
  assert.strictEqual(r.encoding, 'identity');
  assert.strictEqual(r.originalSize, buf.length);
});

test('gzip JSON decompresses', () => {
  const gz = zlib.gzipSync(json);
  const r = tryDecodeBody(gz, 'application/json', 'gzip');
  assert.strictEqual(r.text, json);
  assert.strictEqual(r.encoding, 'gzip');
  assert.strictEqual(r.originalSize, gz.length);
});

test('brotli JSON decompresses', () => {
  const br = zlib.brotliCompressSync(json);
  const r = tryDecodeBody(br, 'application/json', 'br');
  assert.strictEqual(r.text, json);
  assert.strictEqual(r.encoding, 'br');
});

test('zstd JSON decompresses', () => {
  const zs = zlib.zstdCompressSync(json);
  const r = tryDecodeBody(zs, 'application/json', 'zstd');
  assert.strictEqual(r.text, json);
  assert.strictEqual(r.encoding, 'zstd');
});

test('deflate (zlib-wrapped) decompresses', () => {
  const df = zlib.deflateSync(json);
  const r = tryDecodeBody(df, 'application/json', 'deflate');
  assert.strictEqual(r.text, json);
  assert.strictEqual(r.encoding, 'deflate');
});

test('deflate (raw) decompresses via fallback', () => {
  const df = zlib.deflateRawSync(json);
  const r = tryDecodeBody(df, 'application/json', 'deflate');
  assert.strictEqual(r.text, json);
  assert.strictEqual(r.encoding, 'deflate');
});

test('case-insensitive encoding header', () => {
  const gz = zlib.gzipSync(json);
  const r = tryDecodeBody(gz, 'application/json', 'GZIP');
  assert.strictEqual(r.text, json);
  assert.strictEqual(r.encoding, 'gzip');
});

test('corrupt gzip falls back with error prefix and no mojibake tail', () => {
  // Valid gzip magic but truncated — gunzipSync will throw.
  const corrupt = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff, 0x00]);
  const r = tryDecodeBody(corrupt, 'application/json', 'gzip');
  assert.match(r.text, /^<decompress failed: .+> <\d+ compressed bytes>$/);
  assert.strictEqual(r.encoding, 'gzip');
  assert.strictEqual(r.originalSize, corrupt.length);
});

test('unknown encoding falls back with error prefix and no mojibake tail', () => {
  const buf = Buffer.from(json);
  const r = tryDecodeBody(buf, 'application/json', 'snappy');
  assert.strictEqual(
    r.text,
    `<decompress failed: unknown encoding snappy> <${buf.length} compressed bytes>`,
  );
});

test('large binary image stays marked as binary', () => {
  // Must exceed the 4096-byte short-payload fallback to exercise the binary branch.
  const head = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
  const png = Buffer.concat([head, Buffer.alloc(5000, 0xff)]);
  const r = tryDecodeBody(png, 'image/png', '');
  assert.match(r.text, /^<binary \d+ bytes>/);
});

test('small binary-ish buffer decoded as text (short-payload fallback)', () => {
  const text = Buffer.from('short');
  const r = tryDecodeBody(text, 'application/octet-stream', '');
  assert.strictEqual(r.text, 'short');
});
