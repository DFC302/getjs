/**
 * getjs - JavaScript URL Extractor
 *
 * A library for extracting JavaScript URLs from web applications
 * by executing them like a real browser.
 *
 * @example
 * const { JSCollector, JSDownloader } = require('getjs');
 *
 * // Collect JS URLs
 * const collector = new JSCollector({ verbose: true });
 * const urls = await collector.collect('https://example.com');
 * await collector.close();
 *
 * // Download JS files
 * const downloader = new JSDownloader({ outputDir: './js-files' });
 * await downloader.downloadAll(urls);
 */

const { JSCollector, JSDownloader } = require('./collector');
const {
  installManagedScanner,
  scanDownloadedFiles,
  scannerStatus,
} = require('./secret-scanner');
const {
  analyzeDownloadedFiles,
  createDefaultAIConfig,
  getAIStatus,
  resolveAISettings,
} = require('./ai-analyzer');
const {
  generateOpenAPI,
  generateOpenAPIFile,
  generateSwaggerUIFile,
  renderSwaggerHTML,
} = require('./openapi-generator');
const {
  APIInventory,
  importBurp,
  importHar,
  importTraffic,
  writeAPIInventory,
} = require('./api-inventory');
const { runAuthDiff } = require('./auth-diff');

module.exports = {
  JSCollector,
  JSDownloader,
  APIInventory,
  analyzeDownloadedFiles,
  createDefaultAIConfig,
  getAIStatus,
  generateOpenAPI,
  generateOpenAPIFile,
  generateSwaggerUIFile,
  installManagedScanner,
  resolveAISettings,
  renderSwaggerHTML,
  scanDownloadedFiles,
  scannerStatus,
  importBurp,
  importHar,
  importTraffic,
  runAuthDiff,
  writeAPIInventory,
};
