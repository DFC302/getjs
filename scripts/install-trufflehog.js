#!/usr/bin/env node

const { installManagedScanner } = require('../src/secret-scanner');

function installationSkipped(env = process.env) {
  return /^(?:1|true|yes)$/i.test(env.GETJS_SKIP_TRUFFLEHOG_INSTALL || '');
}

async function installTruffleHog({
  env = process.env,
  install = installManagedScanner,
  log = console.log,
} = {}) {
  if (installationSkipped(env)) {
    log('Skipping managed TruffleHog installation (GETJS_SKIP_TRUFFLEHOG_INSTALL is set).');
    return { skipped: true };
  }

  log('Installing the latest managed TruffleHog release...');
  const result = await install({ version: 'latest' });
  const action = result.installed ? 'Installed' : 'Using';
  log(`${action} TruffleHog ${result.release} at ${result.path}`);
  return result;
}

if (require.main === module) {
  installTruffleHog().catch(error => {
    console.error(`Unable to install TruffleHog: ${error.message}`);
    console.error('Retry with "getjs scanner install", or set GETJS_SKIP_TRUFFLEHOG_INSTALL=1 for an offline installation.');
    process.exitCode = 1;
  });
}

module.exports = { installationSkipped, installTruffleHog };
