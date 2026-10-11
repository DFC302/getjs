const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { APIInventory, writeAPIInventory } = require('../src/api-inventory');
const { classifyComparison, loadReplayCandidates, runAuthDiff } = require('../src/auth-diff');

test('authorization comparison classifications remain conservative', () => {
  const endpoint = { role_signals: ['recruiter'] };
  assert.equal(classifyComparison(endpoint, { status: 401 }, { status: 200 }), 'candidate_access_to_role_significant_path');
  assert.equal(classifyComparison(endpoint, { status: 200, body_sha256: 'a' }, { status: 200, body_sha256: 'a' }), 'accessible_without_authentication');
  assert.equal(classifyComparison(endpoint, { status: 200, body_sha256: 'a' }, { status: 200, body_sha256: 'b' }), 'accessible_in_both_contexts');
});

test('auth-diff replays only same-origin safe GET/HEAD observations and stores no bodies', { timeout: 30000 }, async () => {
  const server = http.createServer((request, response) => {
    if (request.url.startsWith('/app/user/recruiter/search.json')) {
      if ((request.headers.cookie || '').includes('candidate=1')) {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ staff: [{ email: 'person@example.test' }] }));
      } else {
        response.writeHead(401, { 'content-type': 'application/json' });
        response.end('{"error":"unauthorized"}');
      }
      return;
    }
    response.writeHead(404);
    response.end('not found');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const target = `http://localhost:${server.address().port}/`;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-auth-diff-'));
  try {
    const inventory = new APIInventory(target);
    inventory.add({
      url: new URL('/app/user/recruiter/search.json?keyword=a', target).href,
      method: 'GET',
      source: 'browser',
    });
    inventory.add({
      url: new URL('/logout', target).href,
      method: 'GET',
      source: 'browser',
    });
    inventory.add({
      url: 'https://outside.example.test/internal',
      method: 'GET',
      source: 'browser',
    });
    const inventoryPath = writeAPIInventory(path.join(directory, 'inventory.json'), inventory);
    const replay = loadReplayCandidates(inventoryPath, target, true, 25);
    assert.equal(replay.length, 1);

    const output = path.join(directory, 'diff.json');
    const result = await runAuthDiff({
      url: target,
      input: inventoryPath,
      output,
      allSafeGet: false,
      maxEndpoints: 25,
      maxBodyBytes: 1024 * 1024,
      delayMs: 0,
      timeout: 5000,
      baseline: { headers: {}, timeout: 5000 },
      candidate: { cookies: 'candidate=1', headers: {}, label: 'candidate', timeout: 5000 },
    });
    assert.equal(result.report.comparisons.length, 1);
    assert.equal(result.report.comparisons[0].classification, 'candidate_access_to_role_significant_path');
    assert.equal(result.report.comparisons[0].requires_manual_authorization_review, true);
    assert.equal(fs.statSync(output).mode & 0o777, 0o600);
    const serialized = fs.readFileSync(output, 'utf8');
    assert.equal(serialized.includes('person@example.test'), false);
    assert.equal(serialized.includes('candidate=1'), false);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
