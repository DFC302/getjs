const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

const { JSCollector } = require('../src/collector');

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

test('custom headers and localStorage stay on allowed domains', { timeout: 30000 }, async () => {
  let targetHeader;
  let thirdPartyHeader;

  const thirdParty = await listen((request, response) => {
    thirdPartyHeader = request.headers['x-getjs-secret'];
    response.setHeader('content-type', 'text/html');
    response.end('<!doctype html><title>third party</title>');
  });
  const thirdPartyPort = thirdParty.address().port;

  const target = await listen((request, response) => {
    targetHeader = request.headers['x-getjs-secret'];
    response.setHeader('content-type', 'text/html');
    response.end(`<!doctype html><iframe src="http://127.0.0.1:${thirdPartyPort}/third"></iframe>`);
  });
  const targetUrl = `http://127.0.0.1:${target.address().port}/`;

  const collector = new JSCollector({
    headers: { 'x-getjs-secret': 'present' },
    localStorage: { token: 'secret' },
  });

  try {
    await collector.init(null, targetUrl);
    await collector.page.goto(targetUrl, { waitUntil: 'load' });

    assert.equal(targetHeader, 'present');
    assert.equal(thirdPartyHeader, undefined);
    assert.equal(await collector.page.evaluate(() => localStorage.getItem('token')), 'secret');

    const thirdPartyFrame = collector.page.frames().find(frame => frame.url().includes('/third'));
    assert.ok(thirdPartyFrame);
    assert.equal(await thirdPartyFrame.evaluate(() => localStorage.getItem('token')), null);
  } finally {
    await collector.close();
    await close(target);
    await close(thirdParty);
  }
});
