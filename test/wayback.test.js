const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

const {
  buildCdxUrl,
  parseCdxResponse,
  extractHistoricalJsUrls,
  looksLikeHistoricalJsUrl,
  fetchHistoricalJsUrls,
} = require('../src/wayback');

test('buildCdxUrl scopes to the exact host by default', () => {
  const cdx = new URL(buildCdxUrl('https://app.example.com/dashboard'));
  assert.equal(cdx.origin + cdx.pathname, 'https://web.archive.org/cdx/search/cdx');
  assert.equal(cdx.searchParams.get('url'), 'app.example.com/*');
  assert.equal(cdx.searchParams.get('matchType'), 'prefix');
  assert.equal(cdx.searchParams.get('output'), 'json');
  assert.equal(cdx.searchParams.get('collapse'), 'urlkey');
  assert.equal(cdx.searchParams.get('limit'), '5000');
});

test('buildCdxUrl with includeSubdomains matches the registrable domain', () => {
  const cdx = new URL(buildCdxUrl('https://app.example.co.uk/x', { includeSubdomains: true }));
  assert.equal(cdx.searchParams.get('url'), 'example.co.uk');
  assert.equal(cdx.searchParams.get('matchType'), 'domain');
});

test('buildCdxUrl honours limit and date bounds', () => {
  const cdx = new URL(buildCdxUrl('https://example.com', { limit: 10, from: '2020', to: '202212' }));
  assert.equal(cdx.searchParams.get('limit'), '10');
  assert.equal(cdx.searchParams.get('from'), '2020');
  assert.equal(cdx.searchParams.get('to'), '202212');
});

test('looksLikeHistoricalJsUrl recognises JS shapes and rejects others', () => {
  assert.equal(looksLikeHistoricalJsUrl('https://example.com/a.js'), true);
  assert.equal(looksLikeHistoricalJsUrl('https://example.com/a.mjs'), true);
  assert.equal(looksLikeHistoricalJsUrl('https://example.com/vendor.9f8e7d6c.js'), true);
  assert.equal(looksLikeHistoricalJsUrl('https://example.com/main.chunk.js'), true);
  assert.equal(looksLikeHistoricalJsUrl('https://example.com/loader.js?v=2'), true);
  assert.equal(looksLikeHistoricalJsUrl('https://example.com/index.html'), false);
  assert.equal(looksLikeHistoricalJsUrl('https://example.com/image.png'), false);
  assert.equal(looksLikeHistoricalJsUrl('not a url'), false);
});

test('parseCdxResponse maps rows using the header and ignores malformed input', () => {
  const body = JSON.stringify([
    ['original', 'timestamp', 'statuscode', 'mimetype'],
    ['https://example.com/app.js', '20200101', '200', 'application/javascript'],
    ['https://example.com/missing.js', '20210101', '404', 'text/html'],
  ]);
  const records = parseCdxResponse(body);
  assert.equal(records.length, 2);
  assert.equal(records[0].original, 'https://example.com/app.js');
  assert.equal(records[0].statuscode, '200');
  assert.equal(records[1].statuscode, '404');

  assert.deepEqual(parseCdxResponse('not json'), []);
  assert.deepEqual(parseCdxResponse(JSON.stringify([['original']])), []);
});

test('extractHistoricalJsUrls dedupes JS captures and drops dead/non-JS rows', () => {
  const body = JSON.stringify([
    ['original', 'timestamp', 'statuscode', 'mimetype'],
    ['https://example.com/app.js', '20200101', '200', 'application/javascript'],
    ['https://example.com/app.js', '20220101', '200', 'application/javascript'], // duplicate
    ['https://example.com/gone.js', '20210101', '404', 'text/html'],             // dead
    ['https://example.com/page.html', '20210101', '200', 'text/html'],           // not JS
    ['https://example.com/api/data', '20210101', '200', 'application/javascript'], // JS by mimetype
    ['https://example.com/revisit.js', '20210101', '-', 'warc/revisit'],         // revisit kept
    ['https://example.com/broke.js', '20210101', '500', 'application/javascript'], // server error
  ]);
  assert.deepEqual(extractHistoricalJsUrls(body), [
    'https://example.com/api/data',
    'https://example.com/app.js',
    'https://example.com/revisit.js',
  ]);
});

function startServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, endpoint: `http://127.0.0.1:${port}/cdx/search/cdx` });
    });
  });
}

test('fetchHistoricalJsUrls parses a successful CDX response', async () => {
  const body = JSON.stringify([
    ['original', 'timestamp', 'statuscode', 'mimetype'],
    ['https://example.com/old.js', '20200101', '200', 'application/javascript'],
    ['https://example.com/page.html', '20200101', '200', 'text/html'],
  ]);
  const { server, endpoint } = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  try {
    const result = await fetchHistoricalJsUrls('https://example.com', { endpoint, timeout: 2000 });
    assert.deepEqual(result.urls, ['https://example.com/old.js']);
    assert.equal(result.stats.discovered, 1);
    assert.equal(result.stats.error, null);
  } finally {
    server.close();
  }
});

test('fetchHistoricalJsUrls never throws and reports server errors', async () => {
  const { server, endpoint } = await startServer((req, res) => {
    res.writeHead(503);
    res.end('unavailable');
  });
  try {
    const result = await fetchHistoricalJsUrls('https://example.com', { endpoint, timeout: 2000 });
    assert.deepEqual(result.urls, []);
    assert.equal(result.stats.discovered, 0);
    assert.match(result.stats.error, /HTTP 503/);
  } finally {
    server.close();
  }
});
