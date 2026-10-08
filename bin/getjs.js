#!/usr/bin/env node

const { program, InvalidArgumentError } = require('commander');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline/promises');
const { chromium } = require('playwright');
const { JSCollector, JSDownloader } = require('../src/collector');
const { version: VERSION } = require('../package.json');

function parseInteger(value, optionName, minimum) {
  if (!/^\d+$/.test(value)) {
    throw new InvalidArgumentError(`${optionName} must be an integer`);
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    const requirement = minimum === 0 ? 'zero or greater' : `${minimum} or greater`;
    throw new InvalidArgumentError(`${optionName} must be ${requirement}`);
  }

  return parsed;
}

const parsePositiveInteger = (optionName) => (value) => parseInteger(value, optionName, 1);
const parseNonNegativeInteger = (optionName) => (value) => parseInteger(value, optionName, 0);

// Banner
const banner = `
   ██████╗ ███████╗████████╗     ██╗███████╗
  ██╔════╝ ██╔════╝╚══██╔══╝     ██║██╔════╝
  ██║  ███╗█████╗     ██║        ██║███████╗
  ██║   ██║██╔══╝     ██║   ██   ██║╚════██║
  ╚██████╔╝███████╗   ██║   ╚█████╔╝███████║
   ╚═════╝ ╚══════╝   ╚═╝    ╚════╝ ╚══════╝
                                    v${VERSION}
  JavaScript URL Extractor for Security Researchers
`;

function printBanner(silent) {
  if (!silent && process.stderr.isTTY) {
    console.error(banner);
  }
}

function log(message, silent) {
  if (!silent) {
    console.error(message);
  }
}

function validateUrl(url) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('URL must use http or https protocol');
    }
    return parsed.href;
  } catch (e) {
    throw new Error(`Invalid URL "${url}": ${e.message}`);
  }
}

function parseHeaders(headerStrings) {
  const headers = {};
  if (!headerStrings) return headers;

  for (const h of headerStrings) {
    const colonIndex = h.indexOf(':');
    if (colonIndex <= 0) throw new Error(`Invalid header "${h}"; expected "Name: Value"`);
    const key = h.substring(0, colonIndex).trim();
    const value = h.substring(colonIndex + 1).trim();
    if (!key) throw new Error(`Invalid header "${h}"; header name is empty`);
    headers[key] = value;
  }
  return headers;
}

function parseLocalStorage(storageStrings) {
  const storage = {};
  if (!storageStrings) return null;

  for (const s of storageStrings) {
    const eqIndex = s.indexOf('=');
    if (eqIndex <= 0) throw new Error(`Invalid localStorage entry "${s}"; expected "key=value"`);
    const key = s.substring(0, eqIndex);
    const value = s.substring(eqIndex + 1);
    storage[key] = value;
  }
  return Object.keys(storage).length > 0 ? storage : null;
}

// --- URL input utilities ---

function readUrlsFromFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`URL file not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, 'utf8');
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0 && !line.startsWith('#'));
}

async function readUrlsFromStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => {
      const urls = data
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0 && !line.startsWith('#'));
      resolve(urls);
    });
  });
}

function sanitizeDomainFilename(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.host.replace(/[^a-zA-Z0-9._-]/g, '_');
    const route = parsed.pathname === '/'
      ? 'root'
      : parsed.pathname.replace(/^\/+|\/+$/g, '').replace(/[^a-zA-Z0-9._-]/g, '_') || 'root';
    const hash = crypto.createHash('sha256').update(parsed.href).digest('hex').slice(0, 8);
    return `${host}_${route}_${hash}.txt`;
  } catch (e) {
    const hash = crypto.createHash('sha256').update(String(url)).digest('hex').slice(0, 8);
    return `target_${hash}.txt`;
  }
}

// --- Domain filtering ---

function matchDomainPattern(hostname, pattern) {
  const normalizedHost = String(hostname || '').toLowerCase();
  const normalizedPattern = String(pattern || '').trim().toLowerCase();
  if (!normalizedHost || !normalizedPattern) return false;
  if (normalizedPattern.startsWith('*.')) {
    const base = normalizedPattern.slice(2);
    return normalizedHost === base || normalizedHost.endsWith(`.${base}`);
  }
  if (!normalizedPattern.includes('*')) return normalizedHost === normalizedPattern;
  const regex = new RegExp(`^${normalizedPattern
    .split('*')
    .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*')}$`, 'i');
  return regex.test(normalizedHost);
}

function ensureParentDirectory(filePath) {
  const parent = path.dirname(path.resolve(filePath));
  fs.mkdirSync(parent, { recursive: true });
}

function writeUrlFile(filePath, urls, resume = false) {
  ensureParentDirectory(filePath);
  const existing = [];
  if (resume && fs.existsSync(filePath)) {
    existing.push(...fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean));
  }
  const merged = [...new Set([...existing, ...urls])];
  fs.writeFileSync(filePath, merged.length > 0 ? `${merged.join('\n')}\n` : '');
  return { total: merged.length, added: merged.length - new Set(existing).size };
}

async function captureAuthState(options) {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    throw new Error('Auth capture requires an interactive terminal');
  }

  const targetUrl = validateUrl(options.url);
  const outputPath = path.resolve(options.output);
  if (fs.existsSync(outputPath) && !options.force) {
    throw new Error(`Storage-state file already exists: ${outputPath} (use --force to overwrite)`);
  }
  ensureParentDirectory(outputPath);

  const launchOptions = { headless: false };
  if (options.proxy) launchOptions.proxy = { server: options.proxy };
  if (options.channel) launchOptions.channel = options.channel;

  const browser = await chromium.launch(launchOptions);
  const contextOptions = { ignoreHTTPSErrors: true };
  if (options.userAgent) contextOptions.userAgent = options.userAgent;

  let context;
  let prompt;
  try {
    context = await browser.newContext(contextOptions);
    const page = await context.newPage();
    page.setDefaultTimeout(options.timeout * 1000);

    try {
      await page.goto(targetUrl, {
        waitUntil: 'domcontentloaded',
        timeout: options.timeout * 1000,
      });
    } catch (error) {
      if (!page.url() || page.url() === 'about:blank') throw error;
      console.error(`[!] Initial navigation did not fully complete: ${error.message}`);
    }

    console.error('[*] Complete the login in the browser and confirm the authenticated application page is visible.');
    console.error('[*] Keep the browser open, then return to this terminal.');
    prompt = readline.createInterface({ input: process.stdin, output: process.stderr });
    await prompt.question('Press Enter to save the authenticated state... ');

    if (!browser.isConnected()) {
      throw new Error('Browser was closed before the authenticated state could be saved');
    }
    await context.storageState({ path: outputPath });
    fs.chmodSync(outputPath, 0o600);
    console.error(`[*] Authenticated state saved to ${outputPath} (mode 0600)`);
    console.error(`[*] Use it with: getjs -u ${targetUrl} --storage-state ${outputPath}`);
    return outputPath;
  } finally {
    if (prompt) prompt.close();
    if (context) await context.close().catch(() => {});
    if (browser.isConnected()) await browser.close().catch(() => {});
  }
}

function filterUrls(jsUrls, options) {
  if (!options.filterDomain && !options.excludeDomain) {
    return jsUrls;
  }

  return jsUrls.filter(jsUrl => {
    let hostname;
    try {
      hostname = new URL(jsUrl).hostname;
    } catch (e) {
      return false;
    }

    // Whitelist check
    if (options.filterDomain) {
      const patterns = Array.isArray(options.filterDomain)
        ? options.filterDomain
        : [options.filterDomain];
      const matches = patterns.some(p => matchDomainPattern(hostname, p));
      if (!matches) return false;
    }

    // Blacklist check
    if (options.excludeDomain) {
      const patterns = Array.isArray(options.excludeDomain)
        ? options.excludeDomain
        : [options.excludeDomain];
      const excluded = patterns.some(p => matchDomainPattern(hostname, p));
      if (excluded) return false;
    }

    return true;
  });
}

function createCollectorOptions(targetUrl, options, browser = null) {
  const cookieDomain = new URL(targetUrl).hostname;
  return {
    headless: options.headless,
    timeout: options.timeout * 1000,
    waitTime: options.wait * 1000,
    scrolling: options.scroll !== false,
    userAgent: options.userAgent,
    proxy: options.proxy,
    verbose: options.verbose,
    cookies: options.cookies,
    storageState: options.storageState,
    cookieDomain: options.cookieDomain || cookieDomain,
    localStorage: parseLocalStorage(options.localStorage),
    headers: parseHeaders(options.header),
    authDomains: options.authDomain,
    recursive: options.recursive,
    maxDepth: options.maxDepth,
    maxFiles: options.maxFiles,
    maxFileSize: options.maxFileSize * 1024 * 1024,
    crawlLinks: options.crawl,
    maxPages: options.maxPages,
    browser,
  };
}

function createDownloader(collector, options) {
  return new JSDownloader({
    outputDir: options.downloadDir,
    verbose: options.verbose,
    context: collector.context,
    headersForUrl: url => collector.headersForUrl(url),
    userAgent: options.userAgent,
    maxFileSize: options.maxFileSize * 1024 * 1024,
    concurrency: options.downloadConcurrency,
  });
}

async function downloadForTarget(collector, urls, options) {
  if (!options.fetchAll && !options.fetchOne) return { results: [], errors: [] };
  const downloader = createDownloader(collector, options);

  if (options.fetchOne) {
    const outputPath = path.join(options.downloadDir, downloader.sanitizeFilename(options.fetchOne));
    try {
      const result = await downloader.downloadOne(options.fetchOne, outputPath);
      return { results: [result], errors: [] };
    } catch (error) {
      return { results: [], errors: [{ url: options.fetchOne, error: error.message }] };
    }
  }

  return downloader.downloadAll(urls, options.dedupeContent || false);
}

// --- Single-URL collection ---

async function collectJS(options) {
  const targetUrl = validateUrl(options.url);
  const collector = new JSCollector(createCollectorOptions(targetUrl, options));

  try {
    log(`[*] Target: ${targetUrl}`, options.silent);
    log(`[*] Headless: ${options.headless}`, options.silent);
    log(`[*] Timeout: ${options.timeout}s`, options.silent);
    log('[*] Starting browser...', options.silent);

    const jsUrls = await collector.collect(targetUrl);

    // Apply domain filters
    const filteredUrls = filterUrls(jsUrls, options);

    if (options.filterDomain || options.excludeDomain) {
      log(`[*] Found ${jsUrls.length} JavaScript files (${filteredUrls.length} after filtering)`, options.silent);
    } else {
      log(`[*] Found ${jsUrls.length} JavaScript files`, options.silent);
    }

    if (options.fetchOne && !filteredUrls.includes(options.fetchOne)) {
      log('[!] Warning: --fetch-one URL was not in the discovered list; attempting it anyway', options.silent);
    }

    const downloads = await downloadForTarget(collector, filteredUrls, options);
    if (options.fetchAll || options.fetchOne) {
      log(`[*] Downloaded: ${downloads.results.length} files, Failed: ${downloads.errors.length}`, options.silent);
      if (downloads.errors.length > 0) {
        downloads.errors.forEach(error => log(`[!] Download failed: ${error.url}: ${error.error}`, options.silent));
        process.exitCode = 2;
      }
    }

    const metadata = collector.getMetadata();
    metadata.warnings.forEach(warning => log(`[!] ${warning}`, options.silent));

    if (options.output) {
      const result = writeUrlFile(options.output, filteredUrls, options.resume);
      log(`[*] Results saved to: ${options.output} (${result.total} URLs, ${result.added} added)`, options.silent);
    }
    if (options.outputDir) {
      const filePath = path.join(path.resolve(options.outputDir), sanitizeDomainFilename(targetUrl));
      const result = writeUrlFile(filePath, filteredUrls, options.resume);
      log(`[*] Results saved to: ${filePath} (${result.total} URLs, ${result.added} added)`, options.silent);
    }

    if (options.json) {
      const jsonOutput = {
        [targetUrl]: {
          count: filteredUrls.length,
          urls: filteredUrls,
          metadata,
          downloads: {
            completed: downloads.results.length,
            failed: downloads.errors,
          },
          error: null,
        },
      };
      console.log(JSON.stringify(jsonOutput, null, 2));
    } else if (!options.output && !options.outputDir) {
      filteredUrls.forEach(url => console.log(url));
    }

    return { targetUrl, urls: filteredUrls, metadata, downloads, error: null };
  } finally {
    await collector.close();
  }
}

// --- Multi-URL collection ---

async function collectMultipleJS(urls, options) {
  const threads = options.threads || 3;
  const allResults = new Map();
  let invalidCount = 0;
  let fetchOneClaimed = false;

  // Validate all URLs upfront
  const validUrls = [];
  for (const url of urls) {
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        log(`[!] Skipping invalid URL (bad protocol): ${url}`, options.silent);
        invalidCount += 1;
        continue;
      }
      validUrls.push(parsed.href);
    } catch (e) {
      log(`[!] Skipping invalid URL: ${url}`, options.silent);
      invalidCount += 1;
    }
  }

  if (validUrls.length === 0) {
    throw new Error('No valid URLs to process');
  }

  log(`[*] Processing ${validUrls.length} URLs with ${threads} threads`, options.silent);

  // Launch shared browser
  const launchOptions = { headless: options.headless };
  if (options.proxy) {
    launchOptions.proxy = { server: options.proxy };
  }

  const browser = await chromium.launch(launchOptions);

  try {
    // Process URLs in batches of `threads` concurrency
    for (let i = 0; i < validUrls.length; i += threads) {
      const batch = validUrls.slice(i, i + threads);
      const batchPromises = batch.map(async (targetUrl) => {
        const collector = new JSCollector(createCollectorOptions(targetUrl, options, browser));

        try {
          log(`[*] Collecting: ${targetUrl}`, options.silent);
          const jsUrls = await collector.collect(targetUrl);
          const filteredUrls = filterUrls(jsUrls, options);
          log(`[*] Found ${jsUrls.length} JS files for ${targetUrl} (${filteredUrls.length} after filtering)`, options.silent);

          let downloads = { results: [], errors: [] };
          const shouldFetchOne = options.fetchOne && !fetchOneClaimed;
          if (shouldFetchOne) fetchOneClaimed = true;
          if (options.fetchAll || shouldFetchOne) {
            const downloadOptions = shouldFetchOne ? options : { ...options, fetchOne: undefined };
            downloads = await downloadForTarget(collector, filteredUrls, downloadOptions);
            log(`[*] Downloads for ${targetUrl}: ${downloads.results.length} completed, ${downloads.errors.length} failed`, options.silent);
          }

          return {
            url: targetUrl,
            urls: filteredUrls,
            metadata: collector.getMetadata(),
            downloads,
            error: null,
          };
        } catch (error) {
          log(`[!] Error processing ${targetUrl}: ${error.message}`, options.silent);
          return {
            url: targetUrl,
            urls: [],
            metadata: collector.getMetadata(),
            downloads: { results: [], errors: [] },
            error: error.message,
          };
        } finally {
          await collector.close();
        }
      });

      const batchResults = await Promise.all(batchPromises);

      for (const result of batchResults) {
        allResults.set(result.url, result);
      }
    }

    await handleMultiOutput(allResults, options);
  } finally {
    await browser.close();
  }

  const failures = [...allResults.values()].filter(result => result.error);
  const downloadFailures = [...allResults.values()].flatMap(result => result.downloads.errors);
  if (invalidCount > 0 || failures.length > 0 || downloadFailures.length > 0) {
    process.exitCode = 2;
  }
  return allResults;
}

// --- Multi-domain output ---

async function handleMultiOutput(allResults, options) {
  const combined = [];

  for (const [targetUrl, result] of allResults) {
    combined.push(...result.urls);

    // Per-domain output file
    if (options.outputDir) {
      const filename = sanitizeDomainFilename(targetUrl);
      const dirPath = path.resolve(options.outputDir);
      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
      }
      const filePath = path.join(dirPath, filename);
      const writeResult = writeUrlFile(filePath, result.urls, options.resume);
      log(`[*] ${targetUrl} -> ${filePath} (${writeResult.total} URLs, ${writeResult.added} added)`, options.silent);
    }
  }

  // Combined output file
  if (options.output) {
    const writeResult = writeUrlFile(options.output, combined, options.resume);
    log(`[*] Combined results saved to: ${options.output} (${writeResult.total} URLs, ${writeResult.added} added)`, options.silent);
  }

  // JSON output
  if (options.json) {
    const jsonOutput = {};
    for (const [targetUrl, result] of allResults) {
      jsonOutput[targetUrl] = {
        count: result.urls.length,
        urls: result.urls,
        metadata: result.metadata,
        downloads: {
          completed: result.downloads.results.length,
          failed: result.downloads.errors,
        },
        error: result.error,
      };
    }
    console.log(JSON.stringify(jsonOutput, null, 2));
  } else if (!options.output && !options.outputDir) {
    // Default: stdout
    const deduped = [...new Set(combined)].sort();
    deduped.forEach(url => console.log(url));
  }
}

// --- CLI ---

// Main program
program
  .name('getjs')
  .description('Extract JavaScript URLs from web applications by executing them like a real browser')
  .version(VERSION);

// Collect command (default)
const collectCommand = program
  .command('collect', { isDefault: true })
  .description('Collect JavaScript URLs from target webpages')
  .version(VERSION)
  .option('-u, --url <url>', 'Target URL to analyze')
  .option('-f, --file <path>', 'File containing URLs (one per line)')
  .option('-o, --output <file>', 'Output file for JS URLs (default: stdout)')
  .option('--output-dir <dir>', 'Output directory for per-domain files')
  .option('--headless', 'Run browser in headless mode', true)
  .option('--no-headless', 'Run browser with visible UI')
  .option('-t, --timeout <seconds>', 'Page load timeout in seconds', parsePositiveInteger('timeout'), 30)
  .option('-w, --wait <seconds>', 'Additional wait time after page load', parseNonNegativeInteger('wait'), 5)
  .option('--no-scroll', 'Disable automatic scrolling')
  .option('--no-recursive', 'Disable recursive parsing of discovered JavaScript bundles')
  .option('--max-depth <n>', 'Maximum recursive import depth', parseNonNegativeInteger('max-depth'), 3)
  .option('--max-files <n>', 'Maximum scripts parsed recursively', parsePositiveInteger('max-files'), 500)
  .option('--max-file-size <mb>', 'Maximum script size parsed or downloaded in MB', parsePositiveInteger('max-file-size'), 10)
  .option('--crawl', 'Visit safe same-origin GET links to discover route-specific scripts')
  .option('--max-pages <n>', 'Maximum additional pages visited with --crawl', parsePositiveInteger('max-pages'), 10)
  .option('-A, --user-agent <string>', 'Custom User-Agent string')
  .option('-x, --proxy <url>', 'Proxy server URL (e.g., http://127.0.0.1:8080)')
  .option('-c, --cookies <file|string>', 'Cookie file (JSON) or raw cookie string (e.g., "name=val; name2=val2")')
  .option('--storage-state <file>', 'Playwright storage-state JSON with cookies and localStorage')
  .option('--cookie-domain <domain>', 'Domain assigned to raw cookie strings (default: target host)')
  .option('-H, --header <header...>', 'Extra HTTP header (format: "Name: Value")')
  .option('--local-storage <entry...>', 'Set localStorage entry (format: "key=value")')
  .option('--auth-domain <pattern...>', 'Domains allowed to receive custom headers/localStorage (default: target origin)')
  .option('--fetch-all', 'Download all discovered JS files')
  .option('--fetch-one <url>', 'Download a specific JS file')
  .option('-d, --download-dir <dir>', 'Directory for downloaded files', './js-downloads')
  .option('--download-concurrency <n>', 'Concurrent JavaScript downloads', parsePositiveInteger('download-concurrency'), 5)
  .option('--threads <n>', 'Number of concurrent threads for multi-URL', parsePositiveInteger('threads'), 3)
  .option('--filter-domain <pattern...>', 'Only include JS from matching domains (glob)')
  .option('--exclude-domain <pattern...>', 'Exclude JS from matching domains (glob)')
  .option('--json', 'Output results as JSON')
  .option('--resume', 'Skip URLs already in output file (incremental mode)')
  .option('--dedupe-content', 'Skip duplicate JS files by content hash during download')
  .option('-s, --silent', 'Suppress banner and status messages')
  .option('-v, --verbose', 'Verbose output')
  .addHelpText('after', '\nAuthentication capture:\n  getjs auth -u <url> -o <storage-state.json>')
  .action(async (options) => {
    printBanner(options.silent);

    if (options.cookies && options.storageState) {
      throw new Error('Use either --cookies or --storage-state, not both');
    }
    if (options.fetchAll && options.fetchOne) {
      throw new Error('Use either --fetch-all or --fetch-one, not both');
    }

    // Determine URL sources
    let urls = [];

    if (options.url) {
      urls.push(options.url);
    }

    if (options.file) {
      urls.push(...readUrlsFromFile(options.file));
    }

    // Check for stdin piped input
    if (!process.stdin.isTTY && !options.url && !options.file) {
      const stdinUrls = await readUrlsFromStdin();
      urls.push(...stdinUrls);
    }

    if (urls.length === 0) {
      throw new Error('Provide URLs via -u, -f, or stdin pipe');
    }

    if (urls.length === 1) {
      // Single URL mode — use existing collectJS for backward compatibility
      options.url = urls[0];
      await collectJS(options);
    } else {
      // Multi-URL mode
      await collectMultipleJS(urls, options);
    }
  });

program
  .command('auth')
  .description('Capture authenticated browser state for later scans')
  .version(VERSION)
  .requiredOption('-u, --url <url>', 'Login or application URL to open')
  .requiredOption('-o, --output <file>', 'Storage-state JSON file to create')
  .option('-t, --timeout <seconds>', 'Initial page load timeout in seconds', parsePositiveInteger('timeout'), 30)
  .option('-A, --user-agent <string>', 'Custom User-Agent string')
  .option('-x, --proxy <url>', 'Proxy server URL (e.g., http://127.0.0.1:8080)')
  .option('--channel <name>', 'Browser channel, such as chrome or msedge')
  .option('--force', 'Overwrite an existing storage-state file')
  .action(captureAuthState);

// Since collect is the default command, make top-level help describe the
// options users can actually pass to `getjs` rather than only listing the
// otherwise-redundant collect subcommand.
if (process.argv.length === 3 && ['-h', '--help'].includes(process.argv[2])) {
  process.argv.splice(2, 0, 'collect');
}

// Parse arguments
async function main() {
  try {
    await program.parseAsync();
  } catch (error) {
    console.error(`[!] Error: ${error.message}`);
    if (process.argv.includes('--verbose') || process.argv.includes('-v')) {
      console.error(error.stack);
    }
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  captureAuthState,
  createCollectorOptions,
  filterUrls,
  handleMultiOutput,
  matchDomainPattern,
  parseInteger,
  sanitizeDomainFilename,
  writeUrlFile,
};
