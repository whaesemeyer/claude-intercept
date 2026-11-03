'use strict';

const zlib = require('node:zlib');

// Max body size to capture (post-decompression, to keep the DB text column sane).
const MAX_BODY = 1024 * 1024;

function decompress(buffer, encoding) {
  // A tiny compressed payload can expand far beyond the capture limit. Node's
  // synchronous helpers otherwise allocate the entire decompressed result.
  const options = { maxOutputLength: MAX_BODY + 1 };
  switch (encoding) {
    case 'gzip':
    case 'x-gzip':
      return zlib.gunzipSync(buffer, options);
    case 'deflate':
      // HTTP "deflate" is ambiguous: RFC says zlib-wrapped, but many servers send raw.
      try { return zlib.inflateSync(buffer, options); }
      catch (err) {
        if (err.code === 'ERR_BUFFER_TOO_LARGE') throw err;
        return zlib.inflateRawSync(buffer, options);
      }
    case 'br':
      return zlib.brotliDecompressSync(buffer, options);
    case 'zstd':
      return zlib.zstdDecompressSync(buffer, options);
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
      if (err.code === 'ERR_BUFFER_TOO_LARGE') {
        return {
          text: `<decompressed body exceeds ${MAX_BODY} byte capture limit>`,
          encoding: enc,
          originalSize,
        };
      }
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

  if (decompressError) {
    return {
      text: `<decompress failed: ${decompressError}> <${originalSize} compressed bytes>`,
      encoding: enc || 'identity',
      originalSize,
    };
  }

  try {
    return {
      text: decoded.toString('utf8'),
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
