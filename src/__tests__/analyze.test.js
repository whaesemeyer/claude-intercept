'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { buildClaudeExport, buildJsonExport } = require('../analyze');

const sample = [
  { id: 1, host: 'api.example.com', method: 'GET', url: 'https://api.example.com/v1/me' },
  { id: 2, host: 'api.example.com', method: 'POST', url: 'https://api.example.com/v1/login' },
  { id: 3, host: 'cdn.example.com', method: 'GET', url: 'https://cdn.example.com/a.js' },
];

test('buildJsonExport returns { meta, captures } shape', () => {
  const out = buildJsonExport(sample, { mode: 'full', generatedAt: 'FIXED' });
  assert.deepStrictEqual(Object.keys(out).sort(), ['captures', 'meta']);
  assert.strictEqual(out.meta.count, 3);
  assert.strictEqual(out.meta.generatedAt, 'FIXED');
});

test('meta.hosts is unique and sorted', () => {
  const out = buildJsonExport(sample, { generatedAt: 'FIXED' });
  assert.deepStrictEqual(out.meta.hosts, ['api.example.com', 'cdn.example.com']);
});

test('captures pass through unchanged', () => {
  const out = buildJsonExport(sample, { mode: 'full', generatedAt: 'FIXED' });
  assert.deepStrictEqual(out.captures, sample);
});

test('meta overrides are merged last (e.g. mode)', () => {
  const out = buildJsonExport(sample, { mode: 'auth', generatedAt: 'FIXED' });
  assert.strictEqual(out.meta.mode, 'auth');
  assert.strictEqual(out.meta.count, 3); // not clobbered by the override
});

test('empty input yields a valid, parseable document', () => {
  const out = buildJsonExport([], { mode: 'full', generatedAt: 'FIXED' });
  assert.strictEqual(out.meta.count, 0);
  assert.deepStrictEqual(out.meta.hosts, []);
  assert.deepStrictEqual(out.captures, []);
  // Round-trips through JSON.
  assert.deepStrictEqual(JSON.parse(JSON.stringify(out)), out);
});

test('default generatedAt is an ISO-8601 timestamp', () => {
  const out = buildJsonExport(sample);
  assert.strictEqual(new Date(out.meta.generatedAt).toISOString(), out.meta.generatedAt);
});

test('summary exports never include raw URLs, headers, bodies, or credentials', () => {
  const secret = 'secret-session-token-123';
  const captures = [{
    host: 'api.example.com', method: 'GET', responseStatus: 200, duration: 12,
    url: `https://api.example.com/profile?token=${secret}`,
    requestHeaders: { authorization: `Bearer ${secret}` },
    responseBody: `{"session":"${secret}"}`,
  }];
  const json = buildJsonExport(captures, { mode: 'summary', generatedAt: 'FIXED' });
  assert.deepStrictEqual(Object.keys(json).sort(), ['meta', 'summary']);
  assert.strictEqual(json.summary.requestsByHost[0].count, 1);
  assert.ok(!JSON.stringify(json).includes(secret));
  assert.ok(!JSON.stringify(json).includes('/profile'));

  const markdown = buildClaudeExport(captures, 'summary');
  assert.ok(!markdown.includes(secret));
  assert.ok(!markdown.includes('/profile'));

  const defaultJson = buildJsonExport(captures);
  const defaultMarkdown = buildClaudeExport(captures);
  assert.strictEqual(defaultJson.meta.mode, 'summary');
  assert.ok(!JSON.stringify(defaultJson).includes(secret));
  assert.ok(!defaultMarkdown.includes(secret));
});

test('empty JSON summary has a finite average response time', () => {
  const out = buildJsonExport([], { mode: 'summary', generatedAt: 'FIXED' });
  assert.strictEqual(out.summary.averageDurationMs, 0);
});

test('API documentation includes endpoint and body structure without captured values', () => {
  const secret = 'secret-session-token-123';
  const out = buildClaudeExport([{
    host: 'api.example.com', method: 'POST', path: '/login',
    url: `https://api.example.com/login?token=${secret}`,
    responseStatus: 200, duration: 3,
    contentType: 'application/json',
    requestHeaders: { authorization: `Bearer ${secret}`, cookie: `session=${secret}` },
    requestBody: JSON.stringify({ credentials: { password: secret }, remember: true }),
    responseBody: JSON.stringify({ accessToken: secret, profile: { id: 42 } }),
  }], 'api-docs');
  assert.match(out, /### POST \/login/);
  assert.match(out, /"password": "string"/);
  assert.match(out, /authorization: \[value omitted\]/);
  assert.doesNotMatch(out, /secret-session-token-123/);
});

test('API documentation JSON contains structured endpoints without raw capture values', () => {
  const secret = 'secret-session-token-123';
  const out = buildJsonExport([{
    host: 'api.example.com', method: 'POST', path: '/login',
    url: `https://api.example.com/login?token=${secret}`,
    responseStatus: 200, duration: 3, contentType: 'application/json',
    requestHeaders: { authorization: `Bearer ${secret}` },
    requestBody: JSON.stringify({ password: secret }),
    responseBody: JSON.stringify({ accessToken: secret }),
  }], { mode: 'api-docs', generatedAt: 'FIXED' });
  assert.deepStrictEqual(Object.keys(out).sort(), ['endpoints', 'meta']);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(out.endpoints[0].requestBodyStructure)), { password: 'string' });
  assert.deepStrictEqual(out.endpoints[0].requestHeaderNames, ['authorization']);
  assert.ok(!JSON.stringify(out).includes(secret));
});

test('API documentation does not expose a custom Content-Type value', () => {
  const capture = {
    host: 'api.example.com', method: 'GET', path: '/thing',
    contentType: 'application/private-token-abc123',
  };
  const markdown = buildClaudeExport([capture], 'api-docs');
  const json = buildJsonExport([capture], { mode: 'api-docs' });
  assert.doesNotMatch(markdown, /private-token-abc123/);
  assert.doesNotMatch(JSON.stringify(json), /private-token-abc123/);
  assert.equal(json.endpoints[0].contentType, '[other]');
});

test('auth JSON includes credential findings without unrelated capture bodies', () => {
  const out = buildJsonExport([{
    host: 'api.example.com', method: 'GET', path: '/',
    url: 'https://api.example.com/',
    requestHeaders: { authorization: 'Bearer credential-value-123' },
    responseBody: '{"ordinaryField":"private-unrelated-data"}',
  }], { mode: 'auth', generatedAt: 'FIXED' });
  assert.deepStrictEqual(Object.keys(out).sort(), ['findings', 'meta']);
  assert.match(out.findings, /credential-value-123/);
  assert.doesNotMatch(JSON.stringify(out), /private-unrelated-data/);
});

test('unknown JSON mode falls back to aggregate summary', () => {
  const out = buildJsonExport([{
    host: 'api.example.com', method: 'GET', responseStatus: 200,
    requestHeaders: { authorization: 'Bearer credential-value-123' },
  }], { mode: 'sumary', generatedAt: 'FIXED' });
  assert.deepStrictEqual(Object.keys(out).sort(), ['meta', 'summary']);
  assert.strictEqual(out.meta.mode, 'summary');
  assert.doesNotMatch(JSON.stringify(out), /credential-value-123/);
});

test('API documentation treats prototype property names as ordinary hosts', () => {
  const key = 'GET /audit';
  try {
    const out = buildClaudeExport([{
      host: '__proto__', method: 'GET', path: '/audit',
      responseStatus: 200, duration: 1,
    }, {
      host: 'constructor', method: 'GET', path: '/audit',
      responseStatus: 200, duration: 1,
    }], 'api-docs');
    assert.match(out, /## Host: __proto__/);
    assert.match(out, /## Host: constructor/);
    assert.strictEqual(Object.prototype[key], undefined);
    assert.strictEqual(Object[key], undefined);
  } finally {
    delete Object.prototype[key];
    delete Object[key];
  }
});
