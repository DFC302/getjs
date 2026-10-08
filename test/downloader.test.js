const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { chromium } = require('playwright');

const { JSDownloader } = require('../src/collector');

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

test('downloads use collision-safe names and dedupe before writing', async () => {
  const server = await listen((request, response) => {
    response.setHeader('content-type', 'application/javascript');
    response.end(request.url.startsWith('/same') ? 'const same = true;' : `const path = ${JSON.stringify(request.url)};`);
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-download-'));

  try {
    const downloader = new JSDownloader({ outputDir: tempDir, concurrency: 3 });
    const unique = await downloader.downloadAll([
      `${base}/a/app.js`,
      `${base}/b/app.js`,
      `${base}/a/app.js?v=2`,
    ]);
    assert.equal(unique.errors.length, 0);
    assert.equal(unique.results.length, 3);
    assert.equal(new Set(unique.results.map(result => result.path)).size, 3);
    unique.results.forEach(result => assert.ok(fs.existsSync(result.path)));

    const dedupeDir = path.join(tempDir, 'dedupe');
    const deduper = new JSDownloader({ outputDir: dedupeDir, concurrency: 2 });
    const deduped = await deduper.downloadAll([
      `${base}/same/one.js`,
      `${base}/same/two.js`,
    ], true);
    assert.equal(deduped.errors.length, 0);
    assert.equal(deduped.results.length, 1);
    assert.equal(fs.readdirSync(dedupeDir).length, 1);
    assert.ok(fs.existsSync(deduped.results[0].path));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
    await close(server);
  }
});

test('HTML and oversized responses are rejected', async () => {
  const server = await listen((request, response) => {
    if (request.url === '/html.js') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><title>login</title>');
      return;
    }
    response.setHeader('content-type', 'application/javascript');
    response.end('x'.repeat(2048));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-download-'));

  try {
    const downloader = new JSDownloader({ outputDir: tempDir, maxFileSize: 1024 });
    const result = await downloader.downloadAll([`${base}/html.js`, `${base}/large.js`]);
    assert.equal(result.results.length, 0);
    assert.equal(result.errors.length, 2);
    assert.match(result.errors[0].error, /HTML instead of JavaScript/);
    assert.match(result.errors[1].error, /exceeds 1024 byte limit/);
    assert.deepEqual(fs.readdirSync(tempDir), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
    await close(server);
  }
});

test('raw redirects resolve relative URLs and strip credentials cross-origin', async () => {
  let leakedAuthorization;
  const destination = await listen((request, response) => {
    leakedAuthorization = request.headers.authorization;
    response.setHeader('content-type', 'application/javascript');
    response.end('const redirected = true;');
  });
  const destinationUrl = `http://127.0.0.1:${destination.address().port}`;

  const source = await listen((request, response) => {
    if (request.url === '/relative') {
      response.writeHead(302, { location: '/script.js' });
    } else if (request.url === '/cross-origin') {
      response.writeHead(302, { location: `${destinationUrl}/script.js` });
    } else {
      response.setHeader('content-type', 'application/javascript');
      response.end('const relative = true;');
      return;
    }
    response.end();
  });
  const sourceUrl = `http://127.0.0.1:${source.address().port}`;

  try {
    const downloader = new JSDownloader({ headers: { Authorization: 'Bearer secret' } });
    const relative = await downloader.downloadOne(`${sourceUrl}/relative`);
    assert.match(relative.content, /relative/);
    const redirected = await downloader.downloadOne(`${sourceUrl}/cross-origin`);
    assert.match(redirected.content, /redirected/);
    assert.equal(leakedAuthorization, undefined);
  } finally {
    await close(source);
    await close(destination);
  }
});

test('browser-context downloads carry context cookies and scoped headers', { timeout: 30000 }, async () => {
  let receivedCookie;
  let receivedHeader;
  let leakedCookie;
  let leakedHeader;
  const destination = await listen((request, response) => {
    leakedCookie = request.headers.cookie;
    leakedHeader = request.headers['x-auth-test'];
    response.setHeader('content-type', 'application/javascript');
    response.end('const redirected = true;');
  });
  const destinationUrl = `http://localhost:${destination.address().port}`;
  const server = await listen((request, response) => {
    if (request.url === '/redirect.js') {
      response.writeHead(302, { location: `${destinationUrl}/redirected.js` });
      response.end();
      return;
    }
    receivedCookie = request.headers.cookie;
    receivedHeader = request.headers['x-auth-test'];
    response.setHeader('content-type', 'application/javascript');
    response.end('const authenticated = true;');
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();

  try {
    await context.addCookies([{ name: 'session', value: 'abc', url: base }]);
    const downloader = new JSDownloader({
      context,
      headersForUrl: url => new URL(url).origin === base ? { 'x-auth-test': 'present' } : {},
    });
    const result = await downloader.downloadOne(`${base}/authenticated.js`);
    assert.match(result.content, /authenticated/);
    assert.match(receivedCookie, /session=abc/);
    assert.equal(receivedHeader, 'present');

    const redirected = await downloader.downloadOne(`${base}/redirect.js`);
    assert.match(redirected.content, /redirected/);
    assert.equal(leakedCookie, undefined);
    assert.equal(leakedHeader, undefined);
  } finally {
    await context.close();
    await browser.close();
    await close(server);
    await close(destination);
  }
});
