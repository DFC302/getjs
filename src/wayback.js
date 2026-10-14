/**
 * Historical JavaScript URL discovery via the Internet Archive Wayback Machine.
 *
 * Queries the public CDX API (the same index `waybackurls` and `gau` read) for
 * archived captures of a target and returns the JavaScript URLs it has ever
 * served. These are historical *candidates*: they are not fetched or executed
 * here and may now return 404, so callers treat them like other static
 * references (subject to domain filters and download-time validation).
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const psl = require('psl');

const CDX_ENDPOINT = 'https://web.archive.org/cdx/search/cdx';
const DEFAULT_LIMIT = 5000;
const DEFAULT_TIMEOUT = 30000;
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024; // 64MB safety cap on the CDX payload

/**
 * Heuristic match for a URL that points at JavaScript source. Mirrors the
 * extension/bundle patterns used by JSCollector.isJavaScriptUrl so historical
 * results line up with live discovery.
 */
function looksLikeHistoricalJsUrl(url) {
  let pathname;
  let search;
  try {
    const parsed = new URL(url);
    pathname = parsed.pathname.toLowerCase();
    search = parsed.search;
  } catch (error) {
    return false;
  }

  if (/\.(?:js|mjs|cjs|jsx|ts|tsx)$/.test(pathname)) return true;
  if (/\.(?:chunk|bundle|vendor|main|app|runtime)\d*\.js/i.test(pathname)) return true;
  if (/\.[a-f0-9]{8,}\.js/i.test(pathname)) return true;
  if (search && pathname.includes('.js')) return true;
  return false;
}

/**
 * Build the Wayback CDX query URL for a target.
 *
 * @param {string} targetUrl - The target being collected.
 * @param {object} [options]
 * @param {boolean} [options.includeSubdomains] - Match every subdomain of the
 *   target's registrable domain instead of only the exact host.
 * @param {number} [options.limit] - Maximum number of CDX rows to request.
 * @param {string} [options.from] - Earliest capture timestamp (YYYY[MM[DD...]]).
 * @param {string} [options.to] - Latest capture timestamp.
 * @param {string} [options.endpoint] - CDX endpoint override (default: Internet
 *   Archive). Mainly for mirrors and tests.
 * @returns {string} Absolute CDX request URL.
 */
function buildCdxUrl(targetUrl, options = {}) {
  const hostname = new URL(targetUrl).hostname;
  const cdx = new URL(options.endpoint || CDX_ENDPOINT);
  const params = cdx.searchParams;

  if (options.includeSubdomains) {
    const registrable = psl.get(hostname) || hostname;
    params.set('url', registrable);
    params.set('matchType', 'domain');
  } else {
    params.set('url', `${hostname}/*`);
    params.set('matchType', 'prefix');
  }

  params.set('output', 'json');
  params.set('fl', 'original,timestamp,statuscode,mimetype');
  params.set('collapse', 'urlkey');

  const limit = Number.isInteger(options.limit) && options.limit > 0 ? options.limit : DEFAULT_LIMIT;
  params.set('limit', String(limit));

  if (options.from) params.set('from', String(options.from));
  if (options.to) params.set('to', String(options.to));

  return cdx.href;
}

/**
 * Parse a CDX JSON payload (array-of-arrays with a header row) into row objects.
 * Returns an empty array for malformed or empty input.
 */
function parseCdxResponse(body) {
  let rows;
  try {
    rows = JSON.parse(body);
  } catch (error) {
    return [];
  }
  if (!Array.isArray(rows) || rows.length < 2) return [];

  const header = rows[0].map(name => String(name));
  const originalIdx = header.indexOf('original');
  if (originalIdx === -1) return [];
  const statusIdx = header.indexOf('statuscode');
  const mimeIdx = header.indexOf('mimetype');
  const timestampIdx = header.indexOf('timestamp');

  const records = [];
  for (let i = 1; i < rows.length; i += 1) {
    const row = rows[i];
    if (!Array.isArray(row) || !row[originalIdx]) continue;
    records.push({
      original: String(row[originalIdx]),
      statuscode: statusIdx === -1 ? '' : String(row[statusIdx] ?? ''),
      mimetype: mimeIdx === -1 ? '' : String(row[mimeIdx] ?? ''),
      timestamp: timestampIdx === -1 ? '' : String(row[timestampIdx] ?? ''),
    });
  }
  return records;
}

function isJavaScriptMimetype(mimetype) {
  const value = String(mimetype || '').toLowerCase();
  return value.includes('javascript') || value.includes('ecmascript');
}

/**
 * A capture is worth keeping unless the archive explicitly recorded a client or
 * server error for it. Revisit records (statuscode '-' or empty) and successful
 * or redirecting captures are all retained.
 */
function isUsableCapture(statuscode) {
  const value = String(statuscode || '').trim();
  if (!value || value === '-') return true;
  return !/^[45]\d\d$/.test(value);
}

/**
 * Extract the deduplicated, sorted list of historical JavaScript URLs from a raw
 * CDX JSON payload.
 */
function extractHistoricalJsUrls(body) {
  const records = parseCdxResponse(body);
  const urls = new Set();
  for (const record of records) {
    if (!isUsableCapture(record.statuscode)) continue;
    const isJs = looksLikeHistoricalJsUrl(record.original) || isJavaScriptMimetype(record.mimetype);
    if (!isJs) continue;
    urls.add(record.original);
  }
  return [...urls].sort();
}

function requestCdx(cdxUrl, timeout) {
  const transport = new URL(cdxUrl).protocol === 'http:' ? http : https;
  return new Promise((resolve, reject) => {
    const request = transport.get(cdxUrl, { timeout }, (response) => {
      const status = response.statusCode || 0;
      if (status < 200 || status >= 300) {
        response.resume();
        reject(new Error(`Wayback CDX API returned HTTP ${status}`));
        return;
      }

      const chunks = [];
      let received = 0;
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_RESPONSE_BYTES) {
          request.destroy();
          reject(new Error('Wayback CDX response exceeded the size limit'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      response.on('error', reject);
    });

    request.on('timeout', () => {
      request.destroy();
      reject(new Error(`Wayback CDX request timed out after ${timeout}ms`));
    });
    request.on('error', reject);
  });
}

/**
 * Fetch historical JavaScript URLs for a target from the Wayback Machine.
 *
 * Best-effort: network or parsing failures resolve to an empty result with an
 * `error` field rather than throwing, so historical discovery never aborts a
 * collection run.
 *
 * @param {string} targetUrl
 * @param {object} [options] - buildCdxUrl options plus `timeout` (ms).
 * @returns {Promise<{urls: string[], stats: object}>}
 */
async function fetchHistoricalJsUrls(targetUrl, options = {}) {
  const timeout = Number.isInteger(options.timeout) && options.timeout > 0
    ? options.timeout
    : DEFAULT_TIMEOUT;
  const cdxUrl = buildCdxUrl(targetUrl, options);
  const stats = {
    source: 'web.archive.org/cdx',
    query: cdxUrl,
    discovered: 0,
    error: null,
  };

  try {
    const body = await requestCdx(cdxUrl, timeout);
    const urls = extractHistoricalJsUrls(body);
    stats.discovered = urls.length;
    return { urls, stats };
  } catch (error) {
    stats.error = error.message;
    return { urls: [], stats };
  }
}

module.exports = {
  CDX_ENDPOINT,
  DEFAULT_LIMIT,
  DEFAULT_TIMEOUT,
  buildCdxUrl,
  parseCdxResponse,
  extractHistoricalJsUrls,
  fetchHistoricalJsUrls,
  looksLikeHistoricalJsUrl,
};
