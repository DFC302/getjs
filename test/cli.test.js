const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { version } = require('../package.json');
const { aiReportPathForTarget, filterUrls, matchDomainPattern } = require('../bin/getjs');

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
  assert.match(defaultHelp.stdout, /--ai \[provider\]/);
  assert.match(defaultHelp.stdout, /--ai-task <task>/);
  assert.match(defaultHelp.stdout, /--prompt <file>/);
  assert.match(defaultHelp.stdout, /--ai-max-inline-size <kb>/);
  assert.match(defaultHelp.stdout, /--ai-include-third-party/);
  assert.match(defaultHelp.stdout, /--openapi <file>/);
  assert.match(defaultHelp.stdout, /--openapi-html <file>/);
  assert.match(defaultHelp.stdout, /--swagger-try-it-out/);
  assert.match(defaultHelp.stdout, /--no-source-maps/);
  assert.match(defaultHelp.stdout, /--entrypoint <path\.\.\.>/);
  assert.match(defaultHelp.stdout, /--api-inventory \[file\]/);
  assert.match(defaultHelp.stdout, /--har <file\.\.\.>/);
  assert.match(defaultHelp.stdout, /--burp <file\.\.\.>/);
  assert.match(defaultHelp.stdout, /--session-role <value>/);
  assert.match(defaultHelp.stdout, /getjs ai <init\|status>/);
  assert.match(defaultHelp.stdout, /getjs openapi --input/);
});

test('auth-diff exposes bounded safe replay controls and requires candidate authentication', () => {
  const help = runCli(['auth-diff', '-h']);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /GET\/HEAD/);
  assert.match(help.stdout, /--candidate-storage-state <file>/);
  assert.match(help.stdout, /--all-safe-get/);
  assert.match(help.stdout, /--max-endpoints <n>/);
  assert.match(help.stdout, /--delay <ms>/);

  const missingAuth = runCli([
    'auth-diff',
    '-u', 'https://example.com/',
    '-i', 'missing.json',
  ]);
  assert.equal(missingAuth.status, 1);
  assert.match(missingAuth.stderr, /Provide candidate authentication/);
});

test('OpenAPI subcommand documents offline report conversion', () => {
  const help = runCli(['openapi', '--help']);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /without\s+another AI run/);
  assert.match(help.stdout, /--input <file>/);
  assert.match(help.stdout, /--output <file>/);
  assert.match(help.stdout, /--title <title>/);
  assert.match(help.stdout, /--html <file>/);
  assert.match(help.stdout, /--swagger-try-it-out/);
});

test('version is available at both command levels', () => {
  const rootVersion = runCli(['-V']);
  const collectVersion = runCli(['collect', '-V']);

  assert.equal(rootVersion.status, 0);
  assert.equal(collectVersion.status, 0);
  assert.equal(rootVersion.stdout, collectVersion.stdout);
  assert.equal(rootVersion.stdout.trim(), version);
});

test('bare apex filter scopes include subdomains without matching lookalikes', () => {
  assert.equal(matchDomainPattern('allerganaccessma.com', 'allerganaccessma.com'), true);
  assert.equal(matchDomainPattern('www.allerganaccessma.com', 'allerganaccessma.com'), true);
  assert.equal(matchDomainPattern('api.dev.allerganaccessma.com', '*.allerganaccessma.com'), true);
  assert.equal(matchDomainPattern('evilallerganaccessma.com', 'allerganaccessma.com'), false);
});

test('AI mode defaults downloads to the target registrable domain', () => {
  const filtered = filterUrls([
    'https://www.allerganaccessma.com/app.js',
    'https://api.allerganaccessma.com/runtime.js',
    'https://allerganaccessma.com/root.js',
    'https://www.googletagmanager.com/gtm.js',
  ], { ai: 'codex' }, 'https://www.allerganaccessma.com/');
  assert.deepEqual(filtered, [
    'https://www.allerganaccessma.com/app.js',
    'https://api.allerganaccessma.com/runtime.js',
    'https://allerganaccessma.com/root.js',
  ]);
});

test('AI task selection is validated and requires AI mode', () => {
  const withoutAI = runCli(['-u', 'https://example.com/', '--ai-task', 'endpoints']);
  assert.equal(withoutAI.status, 1);
  assert.match(withoutAI.stderr, /AI analysis options require --ai/);

  const invalid = runCli(['-u', 'https://example.com/', '--ai', '--ai-task', 'summary']);
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /Unsupported AI task.*full or endpoints/);
});

test('endpoint task uses distinct default report names', () => {
  const downloadDir = path.join(os.tmpdir(), 'getjs-report-name-test');
  const single = aiReportPathForTarget('https://example.com/', {
    downloadDir,
    aiSettings: { task: 'endpoints' },
  });
  assert.equal(single, path.join(downloadDir, 'getjs-ai-endpoints.json'));

  const multi = aiReportPathForTarget('https://example.com/app', {
    downloadDir,
    aiReportDir: path.join(downloadDir, 'reports'),
    aiSettings: { task: 'endpoints' },
  }, true);
  assert.match(multi, /\.endpoints\.json$/);
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

test('secret scanning and scanner management are exposed by the CLI', () => {
  const collectHelp = runCli(['-h']);
  assert.equal(collectHelp.status, 0);
  assert.match(collectHelp.stdout, /--scan-secrets/);
  assert.match(collectHelp.stdout, /--secret-report <file>/);
  assert.match(collectHelp.stdout, /--verify-secrets/);
  assert.match(collectHelp.stdout, /--install-scanner/);
  assert.match(collectHelp.stdout, /--update-scanner/);

  const scannerHelp = runCli(['scanner', '-h']);
  assert.equal(scannerHelp.status, 0);
  assert.match(scannerHelp.stdout, /install \[options\]/);
  assert.match(scannerHelp.stdout, /status \[options\]/);
  assert.match(scannerHelp.stdout, /update/);

  const invalid = runCli(['-u', 'https://example.com/', '--verify-secrets']);
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /require --scan-secrets/);
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
