#!/usr/bin/env node

const { program } = require('commander');
const fs = require('fs');
const path = require('path');
const { JSCollector, JSDownloader } = require('../src/collector');

const VERSION = '2.0.0';

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
    console.error(`Error: Invalid URL - ${e.message}`);
    process.exit(1);
  }
}

function parseHeaders(headerStrings) {
  const headers = {};
  if (!headerStrings) return headers;

  for (const h of headerStrings) {
    const colonIndex = h.indexOf(':');
    if (colonIndex > 0) {
      const key = h.substring(0, colonIndex).trim();
      const value = h.substring(colonIndex + 1).trim();
      headers[key] = value;
    }
  }
  return headers;
}

function parseLocalStorage(storageStrings) {
  const storage = {};
  if (!storageStrings) return null;

  for (const s of storageStrings) {
    const eqIndex = s.indexOf('=');
    if (eqIndex > 0) {
      const key = s.substring(0, eqIndex);
      const value = s.substring(eqIndex + 1);
      storage[key] = value;
    }
  }
  return Object.keys(storage).length > 0 ? storage : null;
}

// --- URL input utilities ---

function readUrlsFromFile(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found - ${filePath}`);
    process.exit(1);
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
    return parsed.hostname.replace(/\./g, '_') + '.txt';
  } catch (e) {
    return url.replace(/[^a-zA-Z0-9._-]/g, '_') + '.txt';
  }
}

// --- Domain filtering ---

function matchDomainPattern(hostname, pattern) {
  const regexStr = pattern
    .replace(/\./g, '\\.')
    .replace(/\*/g, '.*');
  const regex = new RegExp(`^${regexStr}$`, 'i');
  return regex.test(hostname);
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

// --- Single-URL collection ---

async function collectJS(options) {
  const targetUrl = validateUrl(options.url);

  const headers = parseHeaders(options.header);
  const localStorage = parseLocalStorage(options.localStorage);

  const cookieDomain = new URL(targetUrl).hostname;

  const collector = new JSCollector({
    headless: options.headless,
    timeout: options.timeout * 1000,
    waitTime: options.wait * 1000,
    scrolling: !options.noScroll,
    userAgent: options.userAgent,
    proxy: options.proxy,
    verbose: options.verbose,
    cookies: options.cookies,
    cookieDomain: cookieDomain,
    localStorage: localStorage,
    headers: headers,
  });

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

    // Handle download options (must happen before collector.close())
    if (options.fetchAll || options.fetchOne) {
      const downloader = new JSDownloader({
        outputDir: options.downloadDir,
        verbose: options.verbose,
        context: collector.context,
      });

      if (options.fetchAll) {
        log(`[*] Downloading all ${filteredUrls.length} files to ${options.downloadDir}...`, options.silent);
        const { results, errors } = await downloader.downloadAll(filteredUrls, options.dedupeContent || false);
        log(`[*] Downloaded: ${results.length} files, Failed: ${errors.length}`, options.silent);

        if (errors.length > 0 && options.verbose) {
          console.error('[*] Failed downloads:');
          errors.forEach(e => console.error(`    - ${e.url}: ${e.error}`));
        }
      } else if (options.fetchOne) {
        const targetJs = options.fetchOne;
        if (!filteredUrls.includes(targetJs)) {
          log(`[!] Warning: URL not in discovered list, attempting download anyway`, options.silent);
        }

        const filename = path.basename(new URL(targetJs).pathname) || 'script.js';
        const outputPath = path.join(options.downloadDir, filename);

        try {
          await downloader.downloadOne(targetJs, outputPath);
          log(`[*] Downloaded: ${outputPath}`, options.silent);
        } catch (error) {
          console.error(`[!] Failed to download: ${error.message}`);
          process.exit(1);
        }
      }
    }

    // Output results
    if (options.json) {
      const jsonOutput = {
        [targetUrl]: {
          count: filteredUrls.length,
          urls: filteredUrls,
        },
      };
      console.log(JSON.stringify(jsonOutput, null, 2));
    } else if (options.output) {
      let existingUrls = new Set();
      if (options.resume && fs.existsSync(options.output)) {
        const existing = fs.readFileSync(options.output, 'utf8');
        existing.split('\n').filter(l => l.trim()).forEach(u => existingUrls.add(u));
        log(`[*] Resume mode: ${existingUrls.size} URLs already in ${options.output}`, options.silent);
      }

      const newUrls = filteredUrls.filter(u => !existingUrls.has(u));

      if (options.resume && existingUrls.size > 0) {
        if (newUrls.length > 0) {
          fs.appendFileSync(options.output, newUrls.join('\n') + '\n');
          log(`[*] Appended ${newUrls.length} new URLs to ${options.output}`, options.silent);
        } else {
          log(`[*] No new URLs to add to ${options.output}`, options.silent);
        }
      } else {
        fs.writeFileSync(options.output, filteredUrls.join('\n') + '\n');
        log(`[*] Results saved to: ${options.output}`, options.silent);
      }
    } else {
      // Output to stdout
      filteredUrls.forEach(url => console.log(url));
    }

    return filteredUrls;
  } catch (error) {
    console.error(`[!] Error: ${error.message}`);
    if (options.verbose) {
      console.error(error.stack);
    }
    process.exit(1);
  } finally {
    await collector.close();
  }
}

// --- Multi-URL collection ---

async function collectMultipleJS(urls, options) {
  const headers = parseHeaders(options.header);
  const localStorage = parseLocalStorage(options.localStorage);
  const threads = options.threads || 3;
  const allResults = new Map();

  // Validate all URLs upfront
  const validUrls = [];
  for (const url of urls) {
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        log(`[!] Skipping invalid URL (bad protocol): ${url}`, options.silent);
        continue;
      }
      validUrls.push(parsed.href);
    } catch (e) {
      log(`[!] Skipping invalid URL: ${url}`, options.silent);
    }
  }

  if (validUrls.length === 0) {
    console.error('[!] No valid URLs to process');
    process.exit(1);
  }

  log(`[*] Processing ${validUrls.length} URLs with ${threads} threads`, options.silent);

  // Launch shared browser
  const { chromium } = require('playwright');
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
        const cookieDomain = new URL(targetUrl).hostname;
        const collector = new JSCollector({
          headless: options.headless,
          timeout: options.timeout * 1000,
          waitTime: options.wait * 1000,
          scrolling: !options.noScroll,
          userAgent: options.userAgent,
          proxy: options.proxy,
          verbose: options.verbose,
          cookies: options.cookies,
          cookieDomain: cookieDomain,
          localStorage: localStorage,
          headers: headers,
          browser: browser,
        });

        try {
          log(`[*] Collecting: ${targetUrl}`, options.silent);
          const jsUrls = await collector.collect(targetUrl);
          log(`[*] Found ${jsUrls.length} JS files for ${targetUrl}`, options.silent);
          return { url: targetUrl, jsUrls, error: null };
        } catch (error) {
          log(`[!] Error processing ${targetUrl}: ${error.message}`, options.silent);
          return { url: targetUrl, jsUrls: [], error: error.message };
        } finally {
          await collector.close();
        }
      });

      const batchResults = await Promise.all(batchPromises);

      for (const result of batchResults) {
        if (result.jsUrls.length > 0) {
          allResults.set(result.url, result.jsUrls);
        }
      }
    }

    // Handle output
    await handleMultiOutput(allResults, options);

    // Handle downloads if requested
    if (options.fetchAll) {
      const allUrls = Array.from(allResults.values()).flat();
      await handleDownloads(allUrls, browser, options);
    }

  } finally {
    await browser.close();
  }
}

// --- Multi-domain output ---

async function handleMultiOutput(allResults, options) {
  const combined = [];

  for (const [targetUrl, jsUrls] of allResults) {
    const filtered = filterUrls(jsUrls, options);
    combined.push(...filtered);

    // Per-domain output file
    if (options.outputDir) {
      const filename = sanitizeDomainFilename(targetUrl);
      const dirPath = path.resolve(options.outputDir);
      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
      }
      const filePath = path.join(dirPath, filename);

      // Resume mode: read existing URLs and merge
      let existingUrls = new Set();
      if (options.resume && fs.existsSync(filePath)) {
        const existing = fs.readFileSync(filePath, 'utf8');
        existing.split('\n').filter(l => l.trim()).forEach(u => existingUrls.add(u));
      }

      const newUrls = filtered.filter(u => !existingUrls.has(u));
      if (newUrls.length > 0) {
        const content = options.resume && existingUrls.size > 0
          ? '\n' + newUrls.join('\n') + '\n'
          : filtered.join('\n') + '\n';
        const flag = options.resume && existingUrls.size > 0 ? 'a' : 'w';
        fs.writeFileSync(filePath, content, { flag });
      }

      log(`[*] ${targetUrl} -> ${filePath} (${filtered.length} URLs)`, options.silent);
    }
  }

  // Combined output file
  if (options.output) {
    let existingUrls = new Set();
    if (options.resume && fs.existsSync(options.output)) {
      const existing = fs.readFileSync(options.output, 'utf8');
      existing.split('\n').filter(l => l.trim()).forEach(u => existingUrls.add(u));
    }

    const newUrls = combined.filter(u => !existingUrls.has(u));
    const deduped = [...new Set(combined)];

    if (options.resume && existingUrls.size > 0) {
      if (newUrls.length > 0) {
        fs.appendFileSync(options.output, newUrls.join('\n') + '\n');
      }
    } else {
      fs.writeFileSync(options.output, deduped.join('\n') + '\n');
    }
    log(`[*] Combined results saved to: ${options.output} (${deduped.length} URLs)`, options.silent);
  }

  // JSON output
  if (options.json) {
    const jsonOutput = {};
    for (const [targetUrl, jsUrls] of allResults) {
      const filtered = filterUrls(jsUrls, options);
      jsonOutput[targetUrl] = {
        count: filtered.length,
        urls: filtered,
      };
    }
    console.log(JSON.stringify(jsonOutput, null, 2));
  } else if (!options.output && !options.outputDir) {
    // Default: stdout
    const deduped = [...new Set(combined)].sort();
    deduped.forEach(url => console.log(url));
  }
}

// --- Multi-domain downloads ---

async function handleDownloads(urls, browser, options) {
  // Create a temporary context for downloading
  const contextOptions = { ignoreHTTPSErrors: true };
  const headers = parseHeaders(options.header);
  if (Object.keys(headers).length > 0) {
    contextOptions.extraHTTPHeaders = headers;
  }
  const context = await browser.newContext(contextOptions);

  // Load cookies if provided
  if (options.cookies) {
    let cookies = options.cookies;
    if (typeof cookies === 'string') {
      const cookieData = fs.readFileSync(cookies, 'utf8');
      cookies = JSON.parse(cookieData);
    }
    await context.addCookies(cookies);
  }

  const downloader = new JSDownloader({
    outputDir: options.downloadDir,
    verbose: options.verbose,
    context: context,
  });

  log(`[*] Downloading ${urls.length} files to ${options.downloadDir}...`, options.silent);
  const { results, errors } = await downloader.downloadAll(urls, options.dedupeContent || false);
  log(`[*] Downloaded: ${results.length} files, Failed: ${errors.length}`, options.silent);

  if (errors.length > 0 && options.verbose) {
    console.error('[*] Failed downloads:');
    errors.forEach(e => console.error(`    - ${e.url}: ${e.error}`));
  }

  await context.close();
}

// --- CLI ---

// Main program
program
  .name('getjs')
  .description('Extract JavaScript URLs from web applications by executing them like a real browser')
  .version(VERSION);

// Collect command (default)
program
  .command('collect', { isDefault: true })
  .description('Collect JavaScript URLs from target webpages')
  .option('-u, --url <url>', 'Target URL to analyze')
  .option('-f, --file <path>', 'File containing URLs (one per line)')
  .option('-o, --output <file>', 'Output file for JS URLs (default: stdout)')
  .option('--output-dir <dir>', 'Output directory for per-domain files')
  .option('--headless', 'Run browser in headless mode (default: true)', true)
  .option('--no-headless', 'Run browser with visible UI')
  .option('-t, --timeout <seconds>', 'Page load timeout in seconds', parseInt, 30)
  .option('-w, --wait <seconds>', 'Additional wait time after page load', parseInt, 5)
  .option('--no-scroll', 'Disable automatic scrolling')
  .option('-A, --user-agent <string>', 'Custom User-Agent string')
  .option('-x, --proxy <url>', 'Proxy server URL (e.g., http://127.0.0.1:8080)')
  .option('-c, --cookies <file|string>', 'Cookie file (JSON) or raw cookie string (e.g., "name=val; name2=val2")')
  .option('-H, --header <header...>', 'Extra HTTP header (format: "Name: Value")')
  .option('--local-storage <entry...>', 'Set localStorage entry (format: "key=value")')
  .option('--fetch-all', 'Download all discovered JS files')
  .option('--fetch-one <url>', 'Download a specific JS file')
  .option('-d, --download-dir <dir>', 'Directory for downloaded files', './js-downloads')
  .option('--threads <n>', 'Number of concurrent threads for multi-URL', parseInt, 3)
  .option('--filter-domain <pattern...>', 'Only include JS from matching domains (glob)')
  .option('--exclude-domain <pattern...>', 'Exclude JS from matching domains (glob)')
  .option('--json', 'Output results as JSON')
  .option('--resume', 'Skip URLs already in output file (incremental mode)')
  .option('--dedupe-content', 'Skip duplicate JS files by content hash during download')
  .option('-s, --silent', 'Suppress banner and status messages')
  .option('-v, --verbose', 'Verbose output')
  .action(async (options) => {
    printBanner(options.silent);

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
      console.error('Error: Provide URLs via -u, -f, or stdin pipe');
      process.exit(1);
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

// Parse arguments
program.parse();
