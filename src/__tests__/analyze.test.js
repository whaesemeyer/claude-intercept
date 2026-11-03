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
