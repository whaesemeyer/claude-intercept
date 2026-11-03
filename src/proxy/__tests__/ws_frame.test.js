'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const zlib = require('node:zlib');
const { WsFrameParser, OPCODES, parseHandshakeResponse, MAX_EMITTED_MESSAGES } = require('../ws_frame');

// Build a single RFC 6455 frame for testing.
function buildFrame(opcode, payload, { fin = true, mask = false, rsv1 = false } = {}) {
  const data = Buffer.from(payload);
  const len = data.length;
  const b0 = Buffer.from([(fin ? 0x80 : 0) | (rsv1 ? 0x40 : 0) | opcode]);

  let lenBytes;
  const maskBit = mask ? 0x80 : 0;
  if (len < 126) {
    lenBytes = Buffer.from([len | maskBit]);
  } else if (len < 65536) {
    lenBytes = Buffer.alloc(3);
    lenBytes[0] = 126 | maskBit;
    lenBytes.writeUInt16BE(len, 1);
  } else {
    lenBytes = Buffer.alloc(9);
    lenBytes[0] = 127 | maskBit;
    lenBytes.writeBigUInt64BE(BigInt(len), 1);
  }

  let maskKey = Buffer.alloc(0);
  let body = data;
  if (mask) {
    maskKey = Buffer.from([0x37, 0xfa, 0x21, 0x3d]);
    body = Buffer.from(data);
    for (let i = 0; i < body.length; i++) body[i] ^= maskKey[i & 3];
  }
  return Buffer.concat([b0, lenBytes, maskKey, body]);
}

test('unmasked text frame', () => {
  const p = new WsFrameParser();
  const msgs = p.push(buildFrame(OPCODES.TEXT, 'hello'));
  assert.strictEqual(msgs.length, 1);
  assert.strictEqual(msgs[0].isText, true);
  assert.strictEqual(msgs[0].isControl, false);
  assert.strictEqual(msgs[0].payload.toString('utf8'), 'hello');
});

test('masked client text frame is unmasked', () => {
  const p = new WsFrameParser();
  const msgs = p.push(buildFrame(OPCODES.TEXT, 'secret message', { mask: true }));
  assert.strictEqual(msgs.length, 1);
  assert.strictEqual(msgs[0].payload.toString('utf8'), 'secret message');
});

test('binary frame preserves bytes', () => {
  const p = new WsFrameParser();
  const raw = Buffer.from([0x00, 0x01, 0xff, 0x80, 0x7f]);
  const msgs = p.push(buildFrame(OPCODES.BINARY, raw));
  assert.strictEqual(msgs.length, 1);
  assert.strictEqual(msgs[0].isText, false);
  assert.deepStrictEqual(msgs[0].payload, raw);
});

test('fragmented text message reassembles', () => {
  const p = new WsFrameParser();
  const f1 = buildFrame(OPCODES.TEXT, 'Hello, ', { fin: false });
  const f2 = buildFrame(OPCODES.CONTINUATION, 'world!', { fin: true });
  let msgs = p.push(f1);
  assert.strictEqual(msgs.length, 0); // not complete yet
  msgs = p.push(f2);
  assert.strictEqual(msgs.length, 1);
  assert.strictEqual(msgs[0].payload.toString('utf8'), 'Hello, world!');
  assert.strictEqual(msgs[0].isText, true);
});

test('ping and pong are control frames', () => {
  const p = new WsFrameParser();
  const ping = p.push(buildFrame(OPCODES.PING, 'hb'));
  assert.strictEqual(ping[0].isControl, true);
  assert.strictEqual(ping[0].opcode, OPCODES.PING);
  const pong = p.push(buildFrame(OPCODES.PONG, 'hb'));
  assert.strictEqual(pong[0].opcode, OPCODES.PONG);
});

test('close frame is a control frame', () => {
  const p = new WsFrameParser();
  const msgs = p.push(buildFrame(OPCODES.CLOSE, Buffer.from([0x03, 0xe8]))); // 1000
  assert.strictEqual(msgs[0].isControl, true);
  assert.strictEqual(msgs[0].opcode, OPCODES.CLOSE);
});

test('control frame interleaved between data fragments', () => {
  const p = new WsFrameParser();
  const out = [];
  out.push(...p.push(buildFrame(OPCODES.TEXT, 'part1', { fin: false })));
  out.push(...p.push(buildFrame(OPCODES.PING, 'x'))); // control in the middle
  out.push(...p.push(buildFrame(OPCODES.CONTINUATION, 'part2', { fin: true })));
  // ping comes out first (control), then the reassembled data message
  assert.strictEqual(out.length, 2);
  assert.strictEqual(out[0].opcode, OPCODES.PING);
  assert.strictEqual(out[1].payload.toString('utf8'), 'part1part2');
});

test('16-bit (126) length frame', () => {
  const p = new WsFrameParser();
  const big = 'a'.repeat(300);
  const msgs = p.push(buildFrame(OPCODES.TEXT, big));
  assert.strictEqual(msgs[0].payload.toString('utf8'), big);
});

test('64-bit (127) length frame', () => {
  const p = new WsFrameParser({ maxMessageBytes: 128 * 1024 });
  const big = 'b'.repeat(70000);
  const msgs = p.push(buildFrame(OPCODES.TEXT, big));
  assert.strictEqual(msgs[0].payload.toString('utf8'), big);
});

test('oversized frames stop capture without parsing their payload as new frames', () => {
  const p = new WsFrameParser({ maxMessageBytes: 16 });
  const large = buildFrame(OPCODES.TEXT, 'x'.repeat(100));
  assert.deepStrictEqual(p.push(large.subarray(0, 4)), []);
  assert.equal(p.stopped, true);
  assert.deepStrictEqual(p.push(large.subarray(4)), []);
  assert.deepStrictEqual(p.push(buildFrame(OPCODES.TEXT, 'later')), []);
});

test('wire observation budget stops capture while other socket work can continue', () => {
  const p = new WsFrameParser({ maxMessageBytes: 64, maxObservedBytes: 12 });
  assert.equal(p.push(buildFrame(OPCODES.TEXT, 'first'))[0].payload.toString(), 'first');
  assert.deepStrictEqual(p.push(buildFrame(OPCODES.TEXT, 'second')), []);
  assert.equal(p.stopped, true);
});

test('frame split across multiple push calls', () => {
  const p = new WsFrameParser();
  const frame = buildFrame(OPCODES.TEXT, 'streamed across chunks');
  // Feed one byte at a time — the parser must buffer until complete.
  let out = [];
  for (let i = 0; i < frame.length; i++) {
    out = out.concat(p.push(frame.subarray(i, i + 1)));
  }
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].payload.toString('utf8'), 'streamed across chunks');
});

test('two frames in a single chunk', () => {
  const p = new WsFrameParser();
  const combined = Buffer.concat([
    buildFrame(OPCODES.TEXT, 'one'),
    buildFrame(OPCODES.TEXT, 'two'),
  ]);
  const msgs = p.push(combined);
  assert.strictEqual(msgs.length, 2);
  assert.strictEqual(msgs[0].payload.toString('utf8'), 'one');
  assert.strictEqual(msgs[1].payload.toString('utf8'), 'two');
});

test('one chunk with many tiny frames emits only a bounded number of messages', () => {
  const p = new WsFrameParser();
  const tiny = buildFrame(OPCODES.TEXT, '');
  const frames = Buffer.concat(Array.from({ length: 10_000 }, () => tiny));
  const messages = p.push(frames);
  assert.equal(messages.length, MAX_EMITTED_MESSAGES);
  assert.equal(p.stopped, true);
  assert.deepStrictEqual(p.push(tiny), []);
});

test('message byte cap truncates and flags', () => {
  const p = new WsFrameParser({ maxMessageBytes: 10 });
  p.push(buildFrame(OPCODES.TEXT, 'abcdef', { fin: false }));
  const msgs = p.push(buildFrame(OPCODES.CONTINUATION, 'ghijkl'));
  assert.strictEqual(msgs[0].truncated, true);
  assert.strictEqual(msgs[0].payload.length, 10);
});

test('permessage-deflate message is inflated', () => {
  const text = JSON.stringify({ type: 'presence', users: [1, 2, 3] });
  let body = zlib.deflateRawSync(Buffer.from(text));
  // permessage-deflate strips the trailing empty-block marker; mimic that.
  const tail = Buffer.from([0x00, 0x00, 0xff, 0xff]);
  if (body.length >= 4 && body.subarray(body.length - 4).equals(tail)) {
    body = body.subarray(0, body.length - 4);
  }
  const p = new WsFrameParser({ permessageDeflate: true });
  const msgs = p.push(buildFrame(OPCODES.TEXT, body, { rsv1: true }));
  assert.strictEqual(msgs.length, 1);
  assert.strictEqual(msgs[0].compressed, false);
  assert.strictEqual(msgs[0].payload.toString('utf8'), text);
});

test('compressed payloads cannot inflate beyond the capture limit', () => {
  const body = zlib.deflateRawSync(Buffer.from('x'.repeat(5000)));
  const p = new WsFrameParser({ maxMessageBytes: 100, permessageDeflate: true });
  const msgs = p.push(buildFrame(OPCODES.TEXT, body, { rsv1: true }));
  assert.equal(msgs.length, 1);
  assert.equal(msgs[0].compressed, true);
  assert.equal(msgs[0].isText, false);
  assert.ok(msgs[0].payload.length <= 100);
});

test('deflate bit ignored when extension not negotiated', () => {
  // Without permessageDeflate the parser must not try to inflate.
  const p = new WsFrameParser();
  const raw = Buffer.from('not actually deflated');
  const msgs = p.push(buildFrame(OPCODES.TEXT, raw, { rsv1: true }));
  assert.strictEqual(msgs[0].payload.toString('utf8'), 'not actually deflated');
});

test('parseHandshakeResponse reads status and deflate extension', () => {
  const head = Buffer.from(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n'
  );
  const r = parseHandshakeResponse(head);
  assert.strictEqual(r.status, 101);
  assert.strictEqual(r.permessageDeflate, true);
});

test('parseHandshakeResponse on a rejected upgrade', () => {
  const head = Buffer.from('HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n');
  const r = parseHandshakeResponse(head);
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.permessageDeflate, false);
});
