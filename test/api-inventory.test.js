const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  APIInventory,
  importBurp,
  importHar,
  parseRawHttpRequests,
  writeAPIInventory,
} = require('../src/api-inventory');

const cli = path.resolve(__dirname, '..', 'bin', 'getjs.js');

function runCli(args) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', status => resolve({ status, stdout, stderr }));
  });
}

test('API inventory deduplicates endpoints, records auth context, and flags role paths', () => {
  const inventory = new APIInventory('https://app.example.test/', {
    authenticated: true,
    identity: 'candidate-123',
    role: 'candidate',
    label: 'candidate-session',
  });
  inventory.add({
    url: 'https://app.example.test/app/user/recruiter/search.json?keyword=a',
    method: 'GET',
    source: 'browser',
    request_headers: { Authorization: 'Bearer secret', Accept: 'application/json' },
    status: 200,
    response_content_type: 'application/json',
  });
  inventory.add({
    url: 'https://app.example.test/app/user/recruiter/search.json?keyword=b',
    method: 'GET',
    source: 'browser',
    status: 200,
  });
  inventory.add({ url: 'https://third.example.test/api', method: 'GET' });
  inventory.add({ url: 'wss://app.example.test/socket', method: 'GET', transport: 'websocket' });

  const report = inventory.toJSON();
  assert.equal(report.summary.observations, 3);
  assert.equal(report.summary.unique_endpoints, 2);
  const recruiter = report.endpoints.find(item => item.role_signals.includes('recruiter'));
  assert.equal(recruiter.observations, 2);
  assert.deepEqual(recruiter.role_signals, ['recruiter']);
  assert.equal(recruiter.authorization_review_recommended, true);
  assert.equal(recruiter.auth_contexts[0].identity, 'candidate-123');
  assert.ok(report.observations[0].request_header_names.includes('authorization'));
  assert.equal(JSON.stringify(report).includes('Bearer secret'), false);
});

test('API inventory can start a clean authenticated observation phase', () => {
  const inventory = new APIInventory('https://app.example.test/');
  inventory.add({ url: 'https://app.example.test/api/pre-login', method: 'GET' });
  inventory.clearObservations();
  inventory.setAuthContext({ authenticated: true, role: 'candidate', label: 'candidate-session' });
  inventory.add({ url: 'https://app.example.test/api/private', method: 'GET' });

  const report = inventory.toJSON();
  assert.equal(report.summary.observations, 1);
  assert.equal(new URL(report.observations[0].url).pathname, '/api/private');
  assert.equal(report.observations[0].auth_context.authenticated, true);
  assert.equal(report.observations[0].auth_context.role, 'candidate');
});

test('HAR and Burp importers parse requests while inventory enforces target origin', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-import-'));
  const harPath = path.join(directory, 'traffic.har');
  const burpPath = path.join(directory, 'history.xml');
  try {
    fs.writeFileSync(harPath, JSON.stringify({
      log: {
        entries: [{
          startedDateTime: '2026-01-01T00:00:00.000Z',
          request: {
            url: 'https://app.example.test/api/users?q=a',
            method: 'POST',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            postData: { text: '{"limit":10}' },
          },
          response: { status: 200, headers: [], content: { mimeType: 'application/json' } },
        }],
      },
    }));
    const raw = 'GET /internal/status HTTP/1.1\r\nHost: app.example.test\r\nCookie: session=secret\r\n\r\n';
    fs.writeFileSync(burpPath, `<items><item><url>https://app.example.test/internal/status</url><request base64="true">${Buffer.from(raw).toString('base64')}</request></item></items>`);

    const har = importHar(harPath);
    const burp = importBurp(burpPath);
    assert.equal(har.length, 1);
    assert.equal(burp.length, 1);
    assert.equal(burp[0].url, 'https://app.example.test/internal/status');

    const inventory = new APIInventory('https://app.example.test/');
    [...har, ...burp].forEach(item => inventory.add(item));
    const report = inventory.toJSON();
    assert.equal(report.summary.imported_observations, 2);
    assert.ok(report.endpoints.some(item => item.role_signals.includes('internal')));
    assert.equal(JSON.stringify(report).includes('session=secret'), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('raw Burp requests and private inventory output preserve parameter names without body values', () => {
  const raw = 'POST /api/search?sort=name HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nkeyword=alice&limit=10';
  const parsed = parseRawHttpRequests(raw, 'import:burp:test');
  assert.equal(parsed.length, 1);
  const inventory = new APIInventory('https://example.test/');
  inventory.add(parsed[0]);
  const endpoint = inventory.toJSON().endpoints[0];
  assert.deepEqual(endpoint.parameters, [
    { name: 'sort', location: 'query' },
    { name: 'keyword', location: 'form' },
    { name: 'limit', location: 'form' },
  ]);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-api-output-'));
  try {
    const output = writeAPIInventory(path.join(directory, 'nested', 'api.json'), inventory);
    assert.equal(fs.statSync(output).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(output, 'utf8').includes('alice'), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI visits explicit entry points and writes split coverage plus API session context', { timeout: 30000 }, async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><p>public</p>');
      return;
    }
    if (request.url === '/app') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script>fetch("/app/user/recruiter/search.json?keyword=a")</script>');
      return;
    }
    if (request.url.startsWith('/app/user/recruiter/search.json')) {
      response.setHeader('content-type', 'application/json');
      response.end('{"results":[]}');
      return;
    }
    response.writeHead(404);
    response.end('not found');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-api-cli-'));
  const target = `http://127.0.0.1:${server.address().port}/`;
  try {
    const inventoryPath = path.join(directory, 'api.json');
    const result = await runCli([
      '-u', target,
      '--entrypoint', '/app',
      '--api-inventory', inventoryPath,
      '--session-role', 'candidate',
      '--session-identity', 'candidate-123',
      '--no-recursive',
      '--no-scroll',
      '--wait', '0',
      '--json',
      '--silent',
    ]);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout)[target];
    assert.equal(output.metadata.coverage.pages.visited, 2);
    assert.equal(output.metadata.coverage.api.unique_endpoints, 1);
    assert.equal(output.apiInventory, inventoryPath);
    const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
    assert.equal(inventory.endpoints[0].auth_contexts[0].role, 'candidate');
    assert.deepEqual(inventory.endpoints[0].role_signals, ['recruiter']);
    assert.equal(fs.statSync(inventoryPath).mode & 0o777, 0o600);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
