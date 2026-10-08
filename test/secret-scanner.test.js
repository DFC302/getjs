const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  normalizeReleaseTag,
  scanDownloadedFiles,
} = require('../src/secret-scanner');

const projectRoot = path.resolve(__dirname, '..');
const cli = path.join(projectRoot, 'bin', 'getjs.js');

function makeFakeScanner(directory) {
  const scannerPath = path.join(directory, 'trufflehog-fake');
  fs.writeFileSync(scannerPath, `#!/usr/bin/env node
if (process.argv[2] === '--version') {
  console.log('trufflehog 9.9.9-test');
  process.exit(0);
}
console.log(JSON.stringify({
  DetectorName: 'TestDetector',
  Raw: 'unredacted-test-secret',
  Verified: false,
  InvocationArgs: process.argv.slice(2),
}));
`, { mode: 0o700 });
  fs.chmodSync(scannerPath, 0o700);
  return scannerPath;
}

function runCli(args) {
  return new Promise(resolve => {
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

test('scanner release versions are normalized and validated', () => {
  assert.equal(normalizeReleaseTag('3.99.0'), 'v3.99.0');
  assert.equal(normalizeReleaseTag('v3.99.0'), 'v3.99.0');
  assert.equal(normalizeReleaseTag('latest'), null);
  assert.throws(() => normalizeReleaseTag('../../bad'), /Invalid TruffleHog version/);
});

test('secret reports preserve raw findings and use private permissions', async () => {
  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-secret-unit-'));
  try {
    const scannerPath = makeFakeScanner(tempDirectory);
    const scriptPath = path.join(tempDirectory, 'app.js');
    const reportPath = path.join(tempDirectory, 'reports', 'secrets.json');
    fs.writeFileSync(scriptPath, 'const example = true;');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, 'old report', { mode: 0o644 });
    fs.chmodSync(reportPath, 0o644);

    const result = await scanDownloadedFiles([
      { path: scriptPath, url: 'https://example.test/app.js', sha256: 'abc' },
    ], {
      trufflehogPath: scannerPath,
      secretReport: reportPath,
      verifySecrets: false,
    });

    assert.equal(result.total, 1);
    assert.equal(result.unverified, 1);
    assert.equal(fs.statSync(reportPath).mode & 0o777, 0o600);
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(report.containsUnredactedSecrets, true);
    assert.equal(report.findings[0].Raw, 'unredacted-test-secret');
    assert.ok(report.findings[0].InvocationArgs.includes('--no-verification'));
    assert.ok(report.findings[0].InvocationArgs.includes('--no-update'));
  } finally {
    fs.rmSync(tempDirectory, { recursive: true, force: true });
  }
});

test('--scan-secrets performs collection, download, and unredacted scan as one pipeline', { timeout: 60000 }, async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<!doctype html><script src="/app.js"></script>');
      return;
    }
    if (request.url === '/app.js') {
      response.setHeader('content-type', 'application/javascript');
      response.end('window.pipelineLoaded = true;');
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-secret-pipeline-'));
  try {
    const scannerPath = makeFakeScanner(tempDirectory);
    const downloadDirectory = path.join(tempDirectory, 'downloads');
    const reportPath = path.join(tempDirectory, 'evidence', 'getjs-secrets.json');
    const target = `http://127.0.0.1:${server.address().port}/`;
    const result = await runCli([
      '-u', target,
      '--scan-secrets',
      '--trufflehog-path', scannerPath,
      '--secret-report', reportPath,
      '--fail-on-secret',
      '--download-dir', downloadDirectory,
      '--no-recursive',
      '--no-scroll',
      '--wait', '0',
      '--json',
      '--silent',
    ]);

    assert.equal(result.status, 3, result.stderr);
    const output = JSON.parse(result.stdout)[target];
    assert.equal(output.downloads.completed, 1, '--scan-secrets should imply --fetch-all');
    assert.equal(output.secretScan.total, 1);
    assert.equal(output.secretScan.scannedFiles, 1);
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(report.findings[0].Raw, 'unredacted-test-secret');
    assert.equal(fs.statSync(reportPath).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(tempDirectory, { recursive: true, force: true });
    await new Promise(resolve => server.close(resolve));
  }
});
