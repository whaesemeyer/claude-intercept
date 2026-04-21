'use strict';

const zlib = require('node:zlib');

// Max body size to capture (post-decompression, to keep the DB text column sane).
const MAX_BODY = 1024 * 1024;

function decompress(buffer, encoding) {
  switch (encoding) {
    case 'gzip':
    case 'x-gzip':
      return zlib.gunzipSync(buffer);
    case 'deflate':
      // HTTP "deflate" is ambiguous: RFC says zlib-wrapped, but many servers send raw.
      try { return zlib.inflateSync(buffer); }
      catch { return zlib.inflateRawSync(buffer); }
    case 'br':
      return zlib.brotliDecompressSync(buffer);
    case 'zstd':
      return zlib.zstdDecompressSync(buffer);
    case 'compress':
    case 'lzw':
      throw new Error(`legacy encoding ${encoding} not supported`);
    default:
      throw new Error(`unknown encoding ${encoding}`);
  }
}

function tryDecodeBody(buffer, contentType = '', contentEncoding = '') {
  if (!buffer || buffer.length === 0) {
    return { text: '', encoding: contentEncoding || 'identity', originalSize: 0 };
  }

  const originalSize = buffer.length;
  const enc = (contentEncoding || '').toLowerCase().trim();

  let decoded = buffer;
  let decompressError = null;
  if (enc && enc !== 'identity') {
    try {
      decoded = decompress(buffer, enc);
    } catch (err) {
      decompressError = err.message;
    }
  }

  if (decoded.length > MAX_BODY) {
    return {
      text: `<binary ${decoded.length} bytes — truncated>`,
      encoding: enc || 'identity',
      originalSize,
    };
  }

  const ct = contentType.toLowerCase();
  const isText =
    ct.includes('json') ||
    ct.includes('text') ||
    ct.includes('xml') ||
    ct.includes('javascript') ||
    ct.includes('form') ||
    ct.includes('graphql') ||
    decoded.length < 4096;

  if (!isText) {
    return {
      text: `<binary ${decoded.length} bytes>`,
      encoding: enc || 'identity',
      originalSize,
    };
  }

  try {
    const text = decoded.toString('utf8');
    return {
      text: decompressError ? `<decompress failed: ${decompressError}>\n${text}` : text,
      encoding: enc || 'identity',
      originalSize,
    };
  } catch {
    return {
      text: `<binary ${decoded.length} bytes>`,
      encoding: enc || 'identity',
      originalSize,
    };
  }
}

module.exports = { tryDecodeBody, decompress, MAX_BODY };
