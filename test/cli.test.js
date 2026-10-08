const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { version } = require('../package.json');

const projectRoot = path.resolve(__dirname, '..');
const cli = path.join(projectRoot, 'bin', 'getjs.js');

function runCli(args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: projectRoot,
    encoding: 'utf8',
  });
}

test('default help is the collect help and includes version', () => {
  const defaultHelp = runCli(['-h']);
  const collectHelp = runCli(['collect', '-h']);

  assert.equal(defaultHelp.status, 0);
  assert.equal(collectHelp.status, 0);
  assert.equal(defaultHelp.stdout, collectHelp.stdout);
  assert.match(defaultHelp.stdout, /-V, --version/);
  assert.match(defaultHelp.stdout, /-u, --url <url>/);
});

test('version is available at both command levels', () => {
  const rootVersion = runCli(['-V']);
  const collectVersion = runCli(['collect', '-V']);

  assert.equal(rootVersion.status, 0);
  assert.equal(collectVersion.status, 0);
  assert.equal(rootVersion.stdout, collectVersion.stdout);
  assert.equal(rootVersion.stdout.trim(), version);
});

test('auth command documents secure interactive storage-state capture', () => {
  const authHelp = runCli(['auth', '-h']);
  assert.equal(authHelp.status, 0);
  assert.match(authHelp.stdout, /Capture authenticated browser state/);
  assert.match(authHelp.stdout, /-o, --output <file>/);
  assert.match(authHelp.stdout, /--force/);

  const nonInteractive = runCli([
    'auth',
    '-u', 'https://example.com/',
    '-o', path.join(os.tmpdir(), 'getjs-auth-noninteractive.json'),
  ]);
  assert.equal(nonInteractive.status, 1);
  assert.match(nonInteractive.stderr, /requires an interactive terminal/);
});

test('numeric options use decimal parsing and reject unsafe values', () => {
  const { parseInteger } = require('../bin/getjs');

  assert.equal(parseInteger('30', 'timeout', 1), 30);
  assert.equal(parseInteger('10', 'wait', 0), 10);
  assert.throws(() => parseInteger('0', 'threads', 1), /1 or greater/);
  assert.throws(() => parseInteger('-1', 'wait', 0), /must be an integer/);
  assert.throws(() => parseInteger('3x', 'threads', 1), /must be an integer/);
});

test('--no-scroll maps to the collector scrolling option', () => {
  const { createCollectorOptions } = require('../bin/getjs');
  const baseOptions = {
    headless: true,
    timeout: 30,
    wait: 0,
    scroll: false,
    header: [],
    maxFileSize: 10,
  };

  assert.equal(
    createCollectorOptions('https://example.com/', baseOptions).scrolling,
    false,
  );
  assert.equal(
    createCollectorOptions('https://example.com/', { ...baseOptions, scroll: true }).scrolling,
    true,
  );
});

test('per-target filenames distinguish routes and resume output stays deduplicated', () => {
  const { sanitizeDomainFilename, writeUrlFile } = require('../bin/getjs');
  assert.notEqual(
    sanitizeDomainFilename('https://example.com/one'),
    sanitizeDomainFilename('https://example.com/two'),
  );

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-output-'));
  const output = path.join(tempDir, 'nested', 'urls.txt');
  try {
    writeUrlFile(output, ['https://example.com/a.js', 'https://example.com/a.js']);
    writeUrlFile(output, ['https://example.com/a.js', 'https://example.com/b.js'], true);
    assert.deepEqual(fs.readFileSync(output, 'utf8').trim().split('\n'), [
      'https://example.com/a.js',
      'https://example.com/b.js',
    ]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('domain patterns are escaped safely and support wildcard labels', () => {
  const { matchDomainPattern } = require('../bin/getjs');
  assert.equal(matchDomainPattern('example.com', '*.example.com'), true);
  assert.equal(matchDomainPattern('api.example.com', '*.example.com'), true);
  assert.equal(matchDomainPattern('cdn12.example.com', 'cdn*.example.com'), true);
  assert.equal(matchDomainPattern('exampleXcom', 'example.com'), false);
  assert.equal(matchDomainPattern('anything.test', '['), false);
});
