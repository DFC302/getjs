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

module.exports = {
  JSCollector,
  JSDownloader,
  analyzeDownloadedFiles,
  createDefaultAIConfig,
  getAIStatus,
  installManagedScanner,
  resolveAISettings,
  scanDownloadedFiles,
  scannerStatus,
};
