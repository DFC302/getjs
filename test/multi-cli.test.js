const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const projectRoot = path.resolve(__dirname, '..');
const cli = path.join(projectRoot, 'bin', 'getjs.js');

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, ...args], {
      cwd: projectRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', status => resolve({ status, stdout, stderr }));
  });
}

test('multi-target mode preserves auth state, filters downloads, and records empty targets', { timeout: 60000 }, async () => {
  const scriptRequests = new Map();
  let thirdPartyRequests = 0;
  const server = http.createServer((request, response) => {
    const hostname = request.headers.host.split(':')[0];
    const pathname = new URL(request.url, 'http://fixture.test').pathname;

    if (pathname === '/one' || pathname === '/two' || pathname === '/empty') {
      response.setHeader('set-cookie', `runtime=${pathname.slice(1)}; Path=/`);
      response.setHeader('content-type', 'text/html');
      const localScript = pathname === '/empty'
        ? ''
        : `<script src="${pathname}/app.js"></script>`;
      const thirdParty = pathname === '/one'
        ? `<script src="http://localhost:${server.address().port}/third.js"></script>`
        : '';
      response.end(`<!doctype html>${localScript}${thirdParty}`);
      return;
    }

    if (pathname.endsWith('/app.js')) {
      const entries = scriptRequests.get(pathname) || [];
      entries.push(request.headers.cookie || '');
      scriptRequests.set(pathname, entries);
      response.setHeader('content-type', 'application/javascript');
      response.end(`window.loaded = ${JSON.stringify(pathname)};`);
      return;
    }

    if (pathname === '/third.js') {
      if (hostname === 'localhost') thirdPartyRequests += 1;
      response.setHeader('content-type', 'application/javascript');
      response.end('window.thirdParty = true;');
      return;
    }

    response.writeHead(404);
    response.end('not found');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-multi-'));
  const outputDir = path.join(tempDir, 'output');
  const downloadDir = path.join(tempDir, 'downloads');
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    const result = await runCli([
      '-u', `${base}/one`,
      '-f', path.join(tempDir, 'targets.txt'),
      '--cookies', 'Cookie: seed=abc',
      '--cookie-domain', '127.0.0.1',
      '--filter-domain', '127.0.0.1',
      '--fetch-all',
      '--download-dir', downloadDir,
      '--output-dir', outputDir,
      '--no-recursive',
      '--no-scroll',
      '--wait', '0',
      '--json',
      '--silent',
    ].map((value, index, all) => {
      if (value === path.join(tempDir, 'targets.txt')) {
        fs.writeFileSync(value, `${base}/two\n${base}/empty\n`);
      }
      return value;
    }));

    assert.equal(result.status, 0, result.stderr);
    const json = JSON.parse(result.stdout);
    assert.equal(Object.keys(json).length, 3);
    assert.equal(json[`${base}/empty`].count, 0);
    assert.equal(json[`${base}/empty`].error, null);

    assert.equal(fs.readdirSync(outputDir).length, 3);
    assert.equal(fs.readdirSync(downloadDir).length, 2);
    assert.equal(thirdPartyRequests, 1, 'filtered third-party script should not be downloaded again');

    for (const pathname of ['/one/app.js', '/two/app.js']) {
      const cookies = scriptRequests.get(pathname) || [];
      assert.ok(cookies.length >= 2, `${pathname} was not downloaded after browser load`);
      assert.ok(cookies.some(cookie => cookie.includes('runtime=')), `${pathname} download lost runtime cookie`);
      assert.ok(cookies.some(cookie => cookie.includes('seed=abc')), `${pathname} lost raw input cookie`);
    }
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
    await new Promise(resolve => server.close(resolve));
  }
});
