const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

const { JSCollector } = require('../src/collector');

function startFixtureServer() {
  const sockets = new Set();
  const requestedPaths = new Set();
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://fixture.test').pathname;
    requestedPaths.add(pathname);

    if (pathname === '/start') {
      response.writeHead(302, { location: '/app/index.html' });
      response.end();
      return;
    }

    if (pathname === '/hang') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.write('still open');
      return;
    }

    if (pathname === '/app/index.html') {
      response.setHeader('content-type', 'text/html');
      response.end(`<!doctype html>
        <link rel="modulepreload" href="./preload.js">
        <link rel="prefetch" href="./prefetched.js">
        <script type="module" src="./main.js"></script>
        <script data-src="/deferred.js"></script>
        <script type="module">if (false) import('./inline-lazy.js')</script>
        <iframe src="/frame.html"></iframe>
        <a href="/route">safe route</a>
        <a href="/logout">must not crawl</a>
        <script>
          if (false) window.loadScript('/inline-classic.js');
          fetch('/hang').catch(() => {});
          navigator.serviceWorker.register('/sw.js').catch(() => {});
          setTimeout(() => {
            const script = document.createElement('script');
            script.src = '/dynamic.js';
            document.body.appendChild(script);
          }, 25);
        </script>`);
      return;
    }

    if (pathname === '/route') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script src="/route-only.js"></script>');
      return;
    }

    if (pathname === '/logout') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script src="/should-not-load.js"></script>');
      return;
    }

    if (pathname === '/frame.html') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script src="/frame.js"></script>');
      return;
    }

    const scripts = {
      '/app/main.js': `import './dep.js'; import './login.js'; if (false) import('./lazy.js'); if (false) import('./data.json'); if (false) new Worker('./worker.js'); const optional = './optional.js';`,
      '/app/dep.js': `export { nested } from './nested.js';`,
      '/app/nested.js': 'export const nested = true;',
      '/app/preload.js': 'export const preload = true;',
      '/app/prefetched.js': 'export const prefetched = true;',
      '/app/inline-lazy.js': 'export const inlineLazy = true;',
      '/app/lazy.js': 'export const lazy = true;',
      '/app/worker.js': 'self.onmessage = () => {};',
      '/app/optional.js': 'export const optional = true;',
      '/dynamic.js': 'window.dynamicLoaded = true;',
      '/deferred.js': 'window.deferredLoaded = true;',
      '/inline-classic.js': 'window.inlineClassicLoaded = true;',
      '/frame.js': 'window.frameLoaded = true;',
      '/route-only.js': 'window.routeLoaded = true;',
      '/should-not-load.js': 'window.badRouteLoaded = true;',
      '/sw.js': `self.addEventListener('fetch', () => {});`,
    };

    if (pathname === '/app/login.js') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><a href="/false-positive.js">sign in</a>');
      return;
    }

    if (Object.hasOwn(scripts, pathname)) {
      response.setHeader('content-type', 'application/javascript');
      response.end(scripts[pathname]);
      return;
    }

    response.writeHead(404);
    response.end('not found');
  });

  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({
      server,
      sockets,
      requestedPaths,
      url: `http://localhost:${server.address().port}`,
    }));
  });
}

test('collector continues with active requests and recursively discovers dependencies', { timeout: 30000 }, async () => {
  const fixture = await startFixtureServer();
  const collector = new JSCollector({
    timeout: 5000,
    waitTime: 100,
    scrolling: false,
    recursive: true,
    maxDepth: 3,
    maxFiles: 50,
    crawlLinks: true,
    maxPages: 5,
  });

  try {
    const results = await collector.collect(`${fixture.url}/start`);
    const paths = new Set(results.map(url => new URL(url).pathname));

    for (const expected of [
      '/app/main.js',
      '/app/dep.js',
      '/app/nested.js',
      '/app/preload.js',
      '/app/prefetched.js',
      '/app/inline-lazy.js',
      '/app/lazy.js',
      '/app/worker.js',
      '/app/optional.js',
      '/dynamic.js',
      '/deferred.js',
      '/inline-classic.js',
      '/frame.js',
      '/route-only.js',
      '/sw.js',
    ]) {
      assert.ok(paths.has(expected), `missing ${expected}`);
    }

    const metadata = collector.getMetadata();
    assert.equal(new URL(metadata.finalUrl).pathname, '/app/index.html');
    assert.ok(metadata.redirects.some(url => url.endsWith('/start')));
    assert.ok(metadata.redirects.some(url => url.endsWith('/app/index.html')));
    assert.ok(metadata.staticDiscovered >= 3);
    assert.equal(metadata.pagesCrawled, 1);
    assert.equal(fixture.requestedPaths.has('/logout'), false);
    assert.equal(paths.has('/should-not-load.js'), false);
    assert.equal(paths.has('/app/data.json'), false);
    assert.equal(paths.has('/false-positive.js'), false);
  } finally {
    await collector.close();
    for (const socket of fixture.sockets) socket.destroy();
    await new Promise(resolve => fixture.server.close(resolve));
  }
});
