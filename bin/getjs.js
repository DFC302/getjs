#!/usr/bin/env node

const { program } = require('commander');
const fs = require('fs');
const path = require('path');
const { JSCollector, JSDownloader } = require('../src/collector');

const VERSION = '1.0.0';

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

function printBanner() {
  if (process.stderr.isTTY) {
    console.error(banner);
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

async function collectJS(options) {
  const targetUrl = validateUrl(options.url);

  const headers = parseHeaders(options.header);
  const localStorage = parseLocalStorage(options.localStorage);

  const collector = new JSCollector({
    headless: options.headless,
    timeout: options.timeout * 1000,
    waitTime: options.wait * 1000,
    scrolling: !options.noScroll,
    userAgent: options.userAgent,
    proxy: options.proxy,
    verbose: options.verbose,
    cookies: options.cookies,
    localStorage: localStorage,
    headers: headers,
  });

  try {
    console.error(`[*] Target: ${targetUrl}`);
    console.error(`[*] Headless: ${options.headless}`);
    console.error(`[*] Timeout: ${options.timeout}s`);
    console.error('[*] Starting browser...');

    const jsUrls = await collector.collect(targetUrl);

    console.error(`[*] Found ${jsUrls.length} JavaScript files`);

    // Output results
    if (options.output) {
      fs.writeFileSync(options.output, jsUrls.join('\n') + '\n');
      console.error(`[*] Results saved to: ${options.output}`);
    } else {
      // Output to stdout
      jsUrls.forEach(url => console.log(url));
    }

    // Handle download options
    if (options.fetchAll || options.fetchOne) {
      const downloader = new JSDownloader({
        outputDir: options.downloadDir,
        verbose: options.verbose,
      });

      if (options.fetchAll) {
        console.error(`[*] Downloading all ${jsUrls.length} files to ${options.downloadDir}...`);
        const { results, errors } = await downloader.downloadAll(jsUrls);
        console.error(`[*] Downloaded: ${results.length} files, Failed: ${errors.length}`);

        if (errors.length > 0 && options.verbose) {
          console.error('[*] Failed downloads:');
          errors.forEach(e => console.error(`    - ${e.url}: ${e.error}`));
        }
      } else if (options.fetchOne) {
        const targetJs = options.fetchOne;
        if (!jsUrls.includes(targetJs)) {
          console.error(`[!] Warning: URL not in discovered list, attempting download anyway`);
        }

        const filename = path.basename(new URL(targetJs).pathname) || 'script.js';
        const outputPath = path.join(options.downloadDir, filename);

        try {
          await downloader.downloadOne(targetJs, outputPath);
          console.error(`[*] Downloaded: ${outputPath}`);
        } catch (error) {
          console.error(`[!] Failed to download: ${error.message}`);
          process.exit(1);
        }
      }
    }

    return jsUrls;
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

async function downloadJS(options) {
  const targetUrl = validateUrl(options.url);

  const downloader = new JSDownloader({
    outputDir: options.downloadDir,
    verbose: options.verbose,
  });

  try {
    const filename = path.basename(new URL(targetUrl).pathname) || 'script.js';
    const outputPath = path.join(options.downloadDir, filename);

    await downloader.downloadOne(targetUrl, outputPath);
    console.error(`[*] Downloaded: ${outputPath}`);
  } catch (error) {
    console.error(`[!] Error: ${error.message}`);
    process.exit(1);
  }
}

// Main program
program
  .name('getjs')
  .description('Extract JavaScript URLs from web applications by executing them like a real browser')
  .version(VERSION);

// Collect command (default)
program
  .command('collect', { isDefault: true })
  .description('Collect JavaScript URLs from a target webpage')
  .requiredOption('-u, --url <url>', 'Target URL to analyze')
  .option('-o, --output <file>', 'Output file for JS URLs (default: stdout)')
  .option('--headless', 'Run browser in headless mode (default: true)', true)
  .option('--no-headless', 'Run browser with visible UI')
  .option('-t, --timeout <seconds>', 'Page load timeout in seconds', parseInt, 30)
  .option('-w, --wait <seconds>', 'Additional wait time after page load', parseInt, 5)
  .option('--no-scroll', 'Disable automatic scrolling')
  .option('-A, --user-agent <string>', 'Custom User-Agent string')
  .option('-x, --proxy <url>', 'Proxy server URL (e.g., http://127.0.0.1:8080)')
  .option('-c, --cookies <file>', 'Cookie file (JSON format, Playwright or Netscape style)')
  .option('-H, --header <header...>', 'Extra HTTP header (format: "Name: Value")')
  .option('--local-storage <entry...>', 'Set localStorage entry (format: "key=value")')
  .option('--fetch-all', 'Download all discovered JS files')
  .option('--fetch-one <url>', 'Download a specific JS file')
  .option('-d, --download-dir <dir>', 'Directory for downloaded files', './js-downloads')
  .option('-v, --verbose', 'Verbose output')
  .action(async (options) => {
    printBanner();
    await collectJS(options);
  });

// Download command
program
  .command('download')
  .description('Download a JavaScript file directly')
  .requiredOption('-u, --url <url>', 'JavaScript URL to download')
  .option('-d, --download-dir <dir>', 'Directory for downloaded file', './js-downloads')
  .option('-v, --verbose', 'Verbose output')
  .action(async (options) => {
    await downloadJS(options);
  });

// Parse arguments
program.parse();
