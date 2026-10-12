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
  server.closeAllConnections?.();
  return new Promise(resolve => server.close(resolve));
}

test('interactive authentication keeps the live browser session and excludes pre-login scripts', { timeout: 30000 }, async () => {
  const requestedPaths = [];
  const external = await listen((request, response) => {
    response.setHeader('content-type', 'text/html');
    response.end('<!doctype html><title>external destination</title>');
  });
  const target = await listen((request, response) => {
    const pathname = new URL(request.url, 'http://fixture.test').pathname;
    requestedPaths.push(pathname);
    const authenticated = /(?:^|;\s*)session=candidate(?:;|$)/.test(request.headers.cookie || '');

    if (pathname === '/login') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script src="/login-only.js"></script>');
      return;
    }
    if (pathname === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script src="/public-only.js"></script>');
      return;
    }
    if (pathname === '/app') {
      response.setHeader('content-type', 'text/html');
      if (!authenticated) {
        response.end('<!doctype html><script src="/public-only.js"></script>');
        return;
      }
      response.end(`<!doctype html>
        <script src="/private-app.js"></script>
        <script>fetch('/api/private?view=calendar')</script>`);
      return;
    }
    if (pathname === '/manual') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script src="/manual-only.js"></script>');
      return;
    }
    if (pathname === '/api/private') {
      response.setHeader('content-type', 'application/json');
      response.end(authenticated ? '{"ok":true}' : '{"ok":false}');
      return;
    }
    if (['/login-only.js', '/public-only.js', '/private-app.js', '/manual-only.js'].includes(pathname)) {
      response.setHeader('content-type', 'application/javascript');
      response.end(`window.loaded = ${JSON.stringify(pathname)};`);
      return;
    }
    response.writeHead(404);
    response.end('not found');
  });
  const targetUrl = `http://127.0.0.1:${target.address().port}`;
  let handlerPage;
  const collector = new JSCollector({
    timeout: 5000,
    waitTime: 0,
    scrolling: false,
    recursive: false,
    sourceMaps: false,
    captureApi: true,
    sessionIdentity: 'candidate-123',
    sessionRole: 'candidate',
    sessionLabel: 'candidate-session',
    interactiveAuth: true,
    loginUrl: `${targetUrl}/login`,
    interactiveAuthHandler: async ({ page, context }) => {
      handlerPage = page;
      await context.addCookies([{ name: 'session', value: 'candidate', url: targetUrl }]);
      await page.evaluate(() => sessionStorage.setItem('login-flow-state', 'preserved'));
      await page.goto(`${targetUrl}/app`);
      return {
        page,
        savedStorageState: '/tmp/fixture-state.json',
        validation: { performed: true, passed: true, status: 200 },
      };
    },
    interactiveExploreHandler: async ({ page }) => {
      await page.goto(`${targetUrl}/manual`);
      await page.goto(`http://127.0.0.1:${external.address().port}/outside`);
    },
  });

  try {
    const results = await collector.collect(`${targetUrl}/`);
    const paths = new Set(results.map(url => new URL(url).pathname));
    assert.equal(collector.page, handlerPage);
    assert.equal(await collector.page.evaluate(() => sessionStorage.getItem('login-flow-state')), 'preserved');
    assert.equal(paths.has('/private-app.js'), true);
    assert.equal(paths.has('/manual-only.js'), true);
    assert.equal(paths.has('/login-only.js'), false);
    assert.equal(paths.has('/public-only.js'), false);

    const metadata = collector.getMetadata();
    assert.equal(metadata.authentication.mode, 'interactive');
    assert.equal(metadata.authentication.confirmed_url, `${targetUrl}/app`);
    assert.equal(metadata.authentication.saved_storage_state, '/tmp/fixture-state.json');
    assert.equal(metadata.authentication.validation.passed, true);
    assert.equal(metadata.authentication.exploration.recovered_target_page, true);
    assert.ok(metadata.authentication.exploration.javascript_observed >= 2);
    assert.ok(metadata.authentication.pre_auth.javascript_observed >= 1);

    const inventory = collector.getAPIInventory().toJSON(metadata.coverage);
    const privateEndpoint = inventory.endpoints.find(item => new URL(item.url).pathname === '/api/private');
    assert.ok(privateEndpoint);
    assert.equal(privateEndpoint.auth_contexts[0].authenticated, true);
    assert.equal(privateEndpoint.auth_contexts[0].role, 'candidate');
    assert.equal(inventory.observations.every(item => item.auth_context.authenticated), true);
    assert.ok(requestedPaths.filter(pathname => pathname === '/app').length >= 2);
  } finally {
    await collector.close();
    await close(target);
    await close(external);
  }
});

test('navigation classification tolerates requests whose frame is not created yet', () => {
  const collector = new JSCollector();
  const earlyNavigation = {
    isNavigationRequest: () => true,
    frame: () => { throw new Error('Frame for this navigation request is not available'); },
  };
  assert.equal(collector.isTopLevelNavigationRequest(earlyNavigation), false);
  assert.equal(collector.isTopLevelNavigationRequest({
    isNavigationRequest: () => true,
    frame: () => ({ parentFrame: () => null }),
  }), true);
});

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
