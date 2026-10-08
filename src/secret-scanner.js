const { spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');

const { version: GETJS_VERSION } = require('../package.json');

const RELEASE_API = 'https://api.github.com/repos/trufflesecurity/trufflehog/releases';
const MAX_API_BYTES = 5 * 1024 * 1024;
const MAX_ASSET_BYTES = 250 * 1024 * 1024;

function getDataRoot() {
  const base = process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
  return path.join(base, 'getjs');
}

function getManagedScannerPath() {
  return path.join(getDataRoot(), 'bin', process.platform === 'win32' ? 'trufflehog.exe' : 'trufflehog');
}

function getManifestPath() {
  return path.join(getDataRoot(), 'scanner.json');
}

function normalizeReleaseTag(version) {
  if (!version || version === 'latest') return null;
  if (!/^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`Invalid TruffleHog version: ${version}`);
  }
  return version.startsWith('v') ? version : `v${version}`;
}

function requestBuffer(url, redirects = 0) {
  if (redirects > 5) return Promise.reject(new Error(`Too many redirects requesting ${url}`));

  return new Promise((resolve, reject) => {
    const request = https.get(url, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': `getjs/${GETJS_VERSION}`,
        'X-GitHub-Api-Version': '2022-11-28',
      },
    }, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        requestBuffer(new URL(response.headers.location, url).href, redirects + 1)
          .then(resolve, reject);
        return;
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        reject(new Error(`HTTP ${response.statusCode} requesting ${url}`));
        return;
      }

      const chunks = [];
      let received = 0;
      response.on('data', chunk => {
        received += chunk.length;
        if (received > MAX_API_BYTES) {
          response.destroy(new Error(`Response exceeds ${MAX_API_BYTES} bytes: ${url}`));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => resolve(Buffer.concat(chunks)));
    });
    request.setTimeout(30000, () => request.destroy(new Error(`Timeout requesting ${url}`)));
    request.on('error', reject);
  });
}

async function getRelease(version = 'latest') {
  const tag = normalizeReleaseTag(version);
  const endpoint = tag
    ? `${RELEASE_API}/tags/${encodeURIComponent(tag)}`
    : `${RELEASE_API}/latest`;
  let release;
  try {
    release = JSON.parse((await requestBuffer(endpoint)).toString('utf8'));
  } catch (error) {
    throw new Error(`Unable to resolve TruffleHog release: ${error.message}`);
  }
  if (!release.tag_name || !Array.isArray(release.assets)) {
    throw new Error('GitHub returned an invalid TruffleHog release record');
  }
  return release;
}

function platformAssetDetails(tagName) {
  const platforms = { linux: 'linux', darwin: 'darwin', win32: 'windows' };
  const architectures = { x64: 'amd64', arm64: 'arm64' };
  const platform = platforms[process.platform];
  const architecture = architectures[process.arch];
  if (!platform || !architecture) {
    throw new Error(`Unsupported platform for managed TruffleHog: ${process.platform}/${process.arch}`);
  }
  const version = tagName.replace(/^v/, '');
  const extension = process.platform === 'win32' ? 'zip' : 'tar.gz';
  return {
    version,
    archiveName: `trufflehog_${version}_${platform}_${architecture}.${extension}`,
    checksumName: `trufflehog_${version}_checksums.txt`,
  };
}

function findReleaseAsset(release, name) {
  const asset = release.assets.find(candidate => candidate.name === name);
  if (!asset || !asset.browser_download_url) {
    throw new Error(`TruffleHog release ${release.tag_name} does not contain ${name}`);
  }
  return asset.browser_download_url;
}

function downloadFile(url, destination, redirects = 0) {
  if (redirects > 5) return Promise.reject(new Error(`Too many redirects downloading ${url}`));

  return new Promise((resolve, reject) => {
    const request = https.get(url, {
      headers: { 'User-Agent': `getjs/${GETJS_VERSION}` },
    }, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        downloadFile(new URL(response.headers.location, url).href, destination, redirects + 1)
          .then(resolve, reject);
        return;
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        reject(new Error(`HTTP ${response.statusCode} downloading ${url}`));
        return;
      }

      const output = fs.createWriteStream(destination, { mode: 0o600 });
      const digest = crypto.createHash('sha256');
      let received = 0;
      let settled = false;
      const fail = error => {
        if (settled) return;
        settled = true;
        output.destroy();
        fs.rmSync(destination, { force: true });
        reject(error);
      };

      response.on('data', chunk => {
        received += chunk.length;
        if (received > MAX_ASSET_BYTES) {
          response.destroy(new Error(`Download exceeds ${MAX_ASSET_BYTES} bytes: ${url}`));
          return;
        }
        digest.update(chunk);
      });
      response.on('error', fail);
      output.on('error', fail);
      output.on('finish', () => {
        if (settled) return;
        settled = true;
        resolve({ sha256: digest.digest('hex'), size: received });
      });
      response.pipe(output);
    });
    request.setTimeout(60000, () => request.destroy(new Error(`Timeout downloading ${url}`)));
    request.on('error', reject);
  });
}

function checksumForAsset(checksumText, assetName) {
  for (const line of checksumText.split(/\r?\n/)) {
    const match = line.match(/^([a-f0-9]{64})\s+\*?(.+)$/i);
    if (match && match[2].trim() === assetName) return match[1].toLowerCase();
  }
  throw new Error(`Checksum file does not contain ${assetName}`);
}

function sha256File(filePath) {
  const digest = crypto.createHash('sha256');
  const descriptor = fs.openSync(filePath, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    let bytesRead;
    do {
      bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead > 0) digest.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
  } finally {
    fs.closeSync(descriptor);
  }
  return digest.digest('hex');
}

function findExtractedBinary(directory) {
  const expected = process.platform === 'win32' ? 'trufflehog.exe' : 'trufflehog';
  const pending = [directory];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const candidate = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(candidate);
      if (entry.isFile() && entry.name.toLowerCase() === expected) return candidate;
    }
  }
  throw new Error(`Downloaded archive did not contain ${expected}`);
}

function extractArchive(archivePath, destination) {
  const expected = process.platform === 'win32' ? 'trufflehog.exe' : 'trufflehog';
  const listing = spawnSync('tar', ['-tf', archivePath], {
    encoding: 'utf8',
    windowsHide: true,
  });
  if (listing.error) throw new Error(`Unable to run tar: ${listing.error.message}`);
  if (listing.status !== 0) {
    throw new Error(`Unable to inspect TruffleHog archive: ${(listing.stderr || '').trim()}`);
  }
  const members = listing.stdout.split(/\r?\n/).filter(Boolean);
  const unsafe = members.find(member => {
    const normalized = member.replace(/\\/g, '/');
    return normalized.startsWith('/') || normalized.split('/').includes('..');
  });
  if (unsafe) throw new Error(`Unsafe path in TruffleHog archive: ${unsafe}`);
  const binaryMember = members.find(member => path.posix.basename(member.replace(/\\/g, '/')).toLowerCase() === expected);
  if (!binaryMember) throw new Error(`Downloaded archive did not contain ${expected}`);

  const result = spawnSync('tar', ['-xf', archivePath, '-C', destination, binaryMember], {
    encoding: 'utf8',
    windowsHide: true,
  });
  if (result.error) throw new Error(`Unable to run tar: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`Unable to extract TruffleHog archive: ${(result.stderr || '').trim()}`);
  }
}

function writePrivateJson(filePath, value) {
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    try {
      fs.renameSync(temporary, filePath);
    } catch (error) {
      if (process.platform !== 'win32' || !['EEXIST', 'EPERM'].includes(error.code)) throw error;
      fs.rmSync(filePath, { force: true });
      fs.renameSync(temporary, filePath);
    }
    fs.chmodSync(filePath, 0o600);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
  }
}

function scannerVersion(scannerPath) {
  const result = spawnSync(scannerPath, ['--version'], {
    encoding: 'utf8',
    timeout: 10000,
    windowsHide: true,
  });
  if (result.error) throw new Error(`Unable to execute ${scannerPath}: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`TruffleHog version check failed: ${(result.stderr || result.stdout || '').trim()}`);
  }
  return (result.stdout || result.stderr || '').trim() || 'unknown';
}

function readManifest() {
  try {
    return JSON.parse(fs.readFileSync(getManifestPath(), 'utf8'));
  } catch {
    return null;
  }
}

async function installManagedScanner({ version = 'latest', force = false } = {}) {
  const release = await getRelease(version);
  const destination = getManagedScannerPath();
  const manifest = readManifest();
  const managedBinaryIsIntact = manifest?.binarySha256
    && fs.existsSync(destination)
    && sha256File(destination) === manifest.binarySha256;
  if (!force && manifest?.release === release.tag_name && managedBinaryIsIntact) {
    return {
      path: destination,
      release: release.tag_name,
      version: scannerVersion(destination),
      installed: false,
    };
  }

  const details = platformAssetDetails(release.tag_name);
  const archiveUrl = findReleaseAsset(release, details.archiveName);
  const checksumUrl = findReleaseAsset(release, details.checksumName);
  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-trufflehog-'));
  const archivePath = path.join(tempDirectory, details.archiveName);
  const stagingPath = `${destination}.new-${process.pid}`;

  try {
    const [download, checksumBuffer] = await Promise.all([
      downloadFile(archiveUrl, archivePath),
      requestBuffer(checksumUrl),
    ]);
    const expected = checksumForAsset(checksumBuffer.toString('utf8'), details.archiveName);
    if (download.sha256 !== expected) {
      throw new Error(`Checksum mismatch for ${details.archiveName}`);
    }

    extractArchive(archivePath, tempDirectory);
    const extracted = findExtractedBinary(tempDirectory);
    fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
    fs.copyFileSync(extracted, stagingPath);
    fs.chmodSync(stagingPath, 0o700);
    scannerVersion(stagingPath);
    try {
      fs.renameSync(stagingPath, destination);
    } catch (error) {
      if (process.platform !== 'win32' || !['EEXIST', 'EPERM'].includes(error.code)) throw error;
      fs.rmSync(destination, { force: true });
      fs.renameSync(stagingPath, destination);
    }

    const installedVersion = scannerVersion(destination);
    const binarySha256 = sha256File(destination);
    writePrivateJson(getManifestPath(), {
      release: release.tag_name,
      version: installedVersion,
      asset: details.archiveName,
      sha256: expected,
      binarySha256,
      installedAt: new Date().toISOString(),
      source: 'https://github.com/trufflesecurity/trufflehog/releases',
    });
    return {
      path: destination,
      release: release.tag_name,
      version: installedVersion,
      installed: true,
    };
  } finally {
    fs.rmSync(stagingPath, { force: true });
    fs.rmSync(tempDirectory, { recursive: true, force: true });
  }
}

function executableFromPath(name) {
  const extensions = process.platform === 'win32'
    ? (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';')
    : [''];
  for (const directory of (process.env.PATH || '').split(path.delimiter)) {
    if (!directory) continue;
    for (const extension of extensions) {
      const candidate = path.join(directory, `${name}${extension}`);
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {}
    }
  }
  return null;
}

function resolveScannerPath(explicitPath) {
  const requested = explicitPath || process.env.GETJS_TRUFFLEHOG_PATH;
  if (requested) {
    const resolved = path.resolve(requested);
    try {
      fs.accessSync(resolved, fs.constants.X_OK);
    } catch {
      throw new Error(`TruffleHog is not executable: ${resolved}`);
    }
    return resolved;
  }

  const managed = getManagedScannerPath();
  try {
    fs.accessSync(managed, fs.constants.X_OK);
    return managed;
  } catch {}
  return executableFromPath('trufflehog');
}

async function prepareScanner(options = {}) {
  if (options.updateScanner) {
    const installation = await installManagedScanner({ version: options.scannerVersion || 'latest' });
    return installation.path;
  }
  if (options.installScanner) {
    const installation = await installManagedScanner({ version: options.scannerVersion || 'latest' });
    return installation.path;
  }

  const scannerPath = resolveScannerPath(options.trufflehogPath);
  if (!scannerPath) {
    throw new Error(
      'TruffleHog was not found. Run "getjs scanner install" or add --install-scanner to the pipeline.',
    );
  }
  scannerVersion(scannerPath);
  return scannerPath;
}

function summarizeFindings(findings) {
  const summary = { total: findings.length, verified: 0, unverified: 0, unknown: 0 };
  for (const finding of findings) {
    if (finding.Verified === true) summary.verified += 1;
    else if (finding.VerificationError || finding.verification_error) summary.unknown += 1;
    else summary.unverified += 1;
  }
  return summary;
}

function runTruffleHog(scannerPath, files, verifySecrets) {
  const args = [
    'filesystem',
    '--json',
    '--no-update',
    '--log-level=-1',
    '--results=verified,unverified,unknown,filtered_unverified',
  ];
  if (!verifySecrets) args.push('--no-verification');
  args.push(...files);

  return new Promise((resolve, reject) => {
    const child = spawn(scannerPath, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const findings = [];
    const unparsedOutput = [];
    let stderr = '';
    const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    lines.on('line', line => {
      if (!line.trim()) return;
      try {
        findings.push(JSON.parse(line));
      } catch {
        unparsedOutput.push(line);
      }
    });
    child.stderr.on('data', chunk => {
      if (stderr.length < 1024 * 1024) stderr += chunk.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', code => {
      lines.close();
      if (code !== 0) {
        reject(new Error(`TruffleHog exited with code ${code}: ${stderr.trim()}`));
        return;
      }
      resolve({ findings, unparsedOutput, stderr: stderr.trim(), args });
    });
  });
}

async function scanDownloadedFiles(downloads, options = {}) {
  const fileRecords = [];
  const seen = new Set();
  for (const download of downloads || []) {
    if (!download?.path) continue;
    const resolved = path.resolve(download.path);
    if (seen.has(resolved) || !fs.existsSync(resolved)) continue;
    seen.add(resolved);
    fileRecords.push({ path: resolved, url: download.url, sha256: download.sha256 });
  }
  if (fileRecords.length === 0) {
    throw new Error('Secret scanning requires at least one successfully downloaded JavaScript file');
  }

  const scannerPath = await prepareScanner(options);
  const scanner = {
    path: scannerPath,
    version: scannerVersion(scannerPath),
    verificationEnabled: options.verifySecrets === true,
  };
  const result = await runTruffleHog(
    scannerPath,
    fileRecords.map(record => record.path),
    options.verifySecrets === true,
  );
  const reportPath = path.resolve(
    options.secretReport || path.join(options.downloadDir || './js-downloads', 'getjs-secrets.json'),
  );
  const report = {
    schemaVersion: 1,
    containsUnredactedSecrets: true,
    generatedAt: new Date().toISOString(),
    getjsVersion: GETJS_VERSION,
    trufflehog: scanner,
    scannedFiles: fileRecords,
    summary: summarizeFindings(result.findings),
    findings: result.findings,
    unparsedOutput: result.unparsedOutput,
    scannerStderr: result.stderr,
  };
  writePrivateJson(reportPath, report);
  return { ...report.summary, reportPath, scanner, scannedFiles: fileRecords.length };
}

function scannerStatus() {
  const managedPath = getManagedScannerPath();
  const managed = fs.existsSync(managedPath)
    ? { path: managedPath, version: scannerVersion(managedPath), manifest: readManifest() }
    : null;
  const systemPath = executableFromPath('trufflehog');
  const system = systemPath
    ? { path: systemPath, version: scannerVersion(systemPath) }
    : null;
  return { managed, system, selected: resolveScannerPath() };
}

module.exports = {
  getManagedScannerPath,
  getRelease,
  installManagedScanner,
  normalizeReleaseTag,
  prepareScanner,
  resolveScannerPath,
  scanDownloadedFiles,
  scannerStatus,
  scannerVersion,
  sha256File,
  summarizeFindings,
  writePrivateJson,
};
