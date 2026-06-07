'use strict';

// Minimal RFC 6455 frame parser.
//
// The proxy tunnels WebSocket bytes verbatim (see _handleWebSocketUpgrade in
// ./index.js) — this module sits *beside* that shuttle and reassembles the
// frames so we can log what actually flowed through the connection, not just
// that it happened. It does NOT modify the byte stream; the raw chunks are
// still forwarded untouched.
//
// One parser instance per direction (client→server / server→client). Feed it
// chunks via push(); it returns an array of completed application messages and
// control frames. Incomplete frames are buffered until the rest arrives.

const zlib = require('node:zlib');

const OPCODES = {
  CONTINUATION: 0x0,
  TEXT: 0x1,
  BINARY: 0x2,
  CLOSE: 0x8,
  PING: 0x9,
  PONG: 0xa,
};

// Cap a single reassembled message so a runaway fragmented stream can't grow
// the buffer without bound. The proxy applies its own per-connection caps on
// top of this when persisting.
const MAX_MESSAGE_BYTES = 1024 * 1024;

// permessage-deflate appends this trailer to every compressed message; RFC 7692
// requires it be restored before inflating with a raw-deflate context.
const DEFLATE_TAIL = Buffer.from([0x00, 0x00, 0xff, 0xff]);

class WsFrameParser {
  // `permessageDeflate` should be true when the handshake negotiated the
  // extension (see parseHandshakeResponse). When set, messages whose first
  // frame carries the RSV1 bit are inflated before being returned.
  constructor({ maxMessageBytes = MAX_MESSAGE_BYTES, permessageDeflate = false } = {}) {
    this._buf = Buffer.alloc(0);
    this._maxMessageBytes = maxMessageBytes;
    this._permessageDeflate = permessageDeflate;

    // Reassembly state for fragmented data messages.
    this._fragOpcode = null;
    this._fragChunks = [];
    this._fragSize = 0;
    this._fragTruncated = false;
    this._fragCompressed = false;
  }

  // Returns an array of completed messages:
  //   { opcode, payload: Buffer, isText, isControl, truncated, compressed }
  // `compressed` is true only when the message was deflated AND we could not
  // inflate it — the caller should then store the raw bytes as binary.
  push(chunk) {
    if (!chunk || chunk.length === 0) return [];
    this._buf = this._buf.length ? Buffer.concat([this._buf, chunk]) : Buffer.from(chunk);

    const out = [];
    let frame;
    while ((frame = this._readFrame()) !== null) {
      const msg = this._assemble(frame);
      if (msg) out.push(msg);
    }
    return out;
  }

  // Pulls one complete frame off the front of the buffer, or returns null if
  // the buffer doesn't yet hold a full frame.
  _readFrame() {
    const buf = this._buf;
    if (buf.length < 2) return null;

    const b0 = buf[0];
    const b1 = buf[1];
    const fin = (b0 & 0x80) !== 0;
    const rsv1 = (b0 & 0x40) !== 0; // permessage-deflate "compressed" bit
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let offset = 2;

    if (len === 126) {
      if (buf.length < offset + 2) return null;
      len = buf.readUInt16BE(offset);
      offset += 2;
    } else if (len === 127) {
      if (buf.length < offset + 8) return null;
      const big = buf.readBigUInt64BE(offset);
      // Lengths beyond a few MB are never legitimate WS app frames; treat as
      // the largest we'll honor so we don't try to allocate absurd buffers.
      len = big > BigInt(this._maxMessageBytes)
        ? this._maxMessageBytes
        : Number(big);
      offset += 8;
    }

    let maskKey = null;
    if (masked) {
      if (buf.length < offset + 4) return null;
      maskKey = buf.subarray(offset, offset + 4);
      offset += 4;
    }

    if (buf.length < offset + len) return null; // wait for the rest of the payload

    // Copy out of the shared buffer so we can safely advance it.
    const payload = Buffer.from(buf.subarray(offset, offset + len));
    if (masked) {
      for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i & 3];
    }

    this._buf = buf.subarray(offset + len);
    return { fin, rsv1, opcode, payload };
  }

  // Folds a raw frame into the reassembly state and emits a message when a
  // full message (or a control frame) is ready. Control frames are never
  // fragmented and are returned immediately, even mid data-message.
  _assemble(frame) {
    const { fin, rsv1, opcode, payload } = frame;

    if (opcode >= OPCODES.CLOSE) {
      return { opcode, payload, isText: false, isControl: true, truncated: false, compressed: false };
    }

    if (opcode === OPCODES.CONTINUATION) {
      if (this._fragOpcode === null) return null; // stray continuation — ignore
      this._appendFragment(payload);
    } else {
      // New data message (text or binary). RSV1 is only meaningful on the
      // first frame of a message.
      this._fragOpcode = opcode;
      this._fragChunks = [];
      this._fragSize = 0;
      this._fragTruncated = false;
      this._fragCompressed = rsv1 && this._permessageDeflate;
      this._appendFragment(payload);
    }

    if (!fin) return null;

    const opcodeFinal = this._fragOpcode;
    let payloadOut = Buffer.concat(this._fragChunks);
    let isText = opcodeFinal === OPCODES.TEXT;
    let compressedUnreadable = false;

    if (this._fragCompressed && !this._fragTruncated) {
      try {
        // permessage-deflate frames are sync-flushed, not finished, so inflate
        // must tolerate a non-final stream (Z_SYNC_FLUSH) — the default
        // Z_FINISH throws "unexpected end of file" on every real message.
        payloadOut = zlib.inflateRawSync(Buffer.concat([payloadOut, DEFLATE_TAIL]), {
          finishFlush: zlib.constants.Z_SYNC_FLUSH,
        });
      } catch {
        // Context-takeover streams can't be inflated message-by-message; keep
        // the raw deflated bytes and let the caller store them as binary.
        compressedUnreadable = true;
        isText = false;
      }
    } else if (this._fragCompressed && this._fragTruncated) {
      // Truncated + compressed = undecodable; mark binary.
      compressedUnreadable = true;
      isText = false;
    }

    const msg = {
      opcode: opcodeFinal,
      payload: payloadOut,
      isText,
      isControl: false,
      truncated: this._fragTruncated,
      compressed: compressedUnreadable,
    };

    this._fragOpcode = null;
    this._fragChunks = [];
    this._fragSize = 0;
    this._fragTruncated = false;
    this._fragCompressed = false;
    return msg;
  }

  _appendFragment(payload) {
    const remaining = this._maxMessageBytes - this._fragSize;
    if (remaining <= 0) {
      this._fragTruncated = true;
      return;
    }
    if (payload.length > remaining) {
      this._fragChunks.push(payload.subarray(0, remaining));
      this._fragSize += remaining;
      this._fragTruncated = true;
    } else {
      this._fragChunks.push(payload);
      this._fragSize += payload.length;
    }
  }
}

// Human-readable opcode names, for the dashboard / logs.
const OPCODE_NAMES = {
  0x0: 'continuation',
  0x1: 'text',
  0x2: 'binary',
  0x8: 'close',
  0x9: 'ping',
  0xa: 'pong',
};

// Parse a raw HTTP/1.1 handshake response head (the bytes up to, not including,
// the terminating CRLFCRLF) into { status, headers, permessageDeflate }.
// Header keys are lowercased.
function parseHandshakeResponse(buf) {
  const lines = buf.toString('latin1').split('\r\n');
  const m = (lines[0] || '').match(/HTTP\/\d(?:\.\d)?\s+(\d{3})/);
  const status = m ? Number(m[1]) : 0;
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx === -1) continue;
    headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
  }
  const permessageDeflate = (headers['sec-websocket-extensions'] || '')
    .toLowerCase()
    .includes('permessage-deflate');
  return { status, headers, permessageDeflate };
}

module.exports = {
  WsFrameParser,
  parseHandshakeResponse,
  OPCODES,
  OPCODE_NAMES,
  MAX_MESSAGE_BYTES,
};
