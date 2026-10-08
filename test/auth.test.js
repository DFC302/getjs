const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { JSCollector } = require('../src/collector');

test('collector preserves an explicit zero wait time', () => {
  const collector = new JSCollector({ waitTime: 0 });
  assert.equal(collector.options.waitTime, 0);
});

test('raw Cookie headers are parsed without making Cookie part of the name', () => {
  const collector = new JSCollector();
  const cookies = collector.parseRawCookieString('Cookie: one=1; two=value=2', '.example.com', true);

  assert.deepEqual(cookies, [
    { name: 'one', value: '1', domain: '.example.com', path: '/', secure: true },
    { name: 'two', value: 'value=2', domain: '.example.com', path: '/', secure: true },
  ]);
});

test('common browser cookie exports normalize to Playwright fields', () => {
  const collector = new JSCollector({ cookieDomain: 'example.com' });
  collector.targetUrl = 'https://example.com/';

  assert.deepEqual(collector.normalizeCookie({
    name: 'session',
    value: 'abc',
    domain: '.example.com',
    path: '/',
    expirationDate: 2000000000,
    httpOnly: true,
    secure: true,
    sameSite: 'no_restriction',
    storeId: '0',
  }), {
    name: 'session',
    value: 'abc',
    domain: '.example.com',
    path: '/',
    expires: 2000000000,
    httpOnly: true,
    secure: true,
    sameSite: 'None',
  });
});

test('Playwright storage state is accepted and malformed files fail closed', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-auth-'));
  const goodPath = path.join(tempDir, 'state.json');
  const badPath = path.join(tempDir, 'bad.json');
  fs.writeFileSync(goodPath, JSON.stringify({
    cookies: [{ name: 'a', value: 'b', domain: 'example.com', path: '/' }],
    origins: [{ origin: 'https://example.com', localStorage: [{ name: 'token', value: 'x' }] }],
  }));
  fs.writeFileSync(badPath, '{not-json');

  const good = new JSCollector({ storageState: goodPath });
  good.targetUrl = 'https://example.com/';
  const state = good.loadAuthState();
  assert.equal(state.cookies.length, 1);
  assert.equal(state.origins.length, 1);

  const bad = new JSCollector({ storageState: badPath });
  bad.targetUrl = 'https://example.com/';
  assert.throws(() => bad.loadAuthState(), /Invalid storage-state JSON/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('auth-domain matching does not include unrelated hosts', () => {
  const collector = new JSCollector({
    headers: { Authorization: 'Bearer secret' },
    authDomains: ['*.example.com'],
  });
  collector.targetUrl = 'https://app.example.com/';
  collector.authDomains = collector.options.authDomains;

  assert.deepEqual(collector.headersForUrl('https://api.example.com/data'), { Authorization: 'Bearer secret' });
  assert.deepEqual(collector.headersForUrl('https://third-party.test/script.js'), {});
});
