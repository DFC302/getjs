const assert = require('node:assert/strict');
const test = require('node:test');

const {
  installationSkipped,
  installTruffleHog,
} = require('../scripts/install-trufflehog');
const packageJson = require('../package.json');

test('npm installation invokes the managed TruffleHog installer', () => {
  assert.equal(packageJson.scripts.postinstall, 'node scripts/install-trufflehog.js');
  assert.ok(packageJson.files.includes('scripts/'));
});

test('postinstall requests the latest managed TruffleHog release', async () => {
  const calls = [];
  const messages = [];
  const result = await installTruffleHog({
    env: {},
    install: async options => {
      calls.push(options);
      return {
        installed: true,
        path: '/managed/bin/trufflehog',
        release: 'v9.9.9',
      };
    },
    log: message => messages.push(message),
  });

  assert.deepEqual(calls, [{ version: 'latest' }]);
  assert.equal(result.release, 'v9.9.9');
  assert.match(messages.join('\n'), /Installed TruffleHog v9\.9\.9/);
});

test('postinstall supports an explicit offline opt-out', async () => {
  let called = false;
  const result = await installTruffleHog({
    env: { GETJS_SKIP_TRUFFLEHOG_INSTALL: 'true' },
    install: async () => {
      called = true;
    },
    log: () => {},
  });

  assert.equal(called, false);
  assert.deepEqual(result, { skipped: true });
  assert.equal(installationSkipped({ GETJS_SKIP_TRUFFLEHOG_INSTALL: 'YES' }), true);
  assert.equal(installationSkipped({ GETJS_SKIP_TRUFFLEHOG_INSTALL: '0' }), false);
});
