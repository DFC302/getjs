const { chromium } = require('playwright');
const { URL } = require('url');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

class JSCollector {
  constructor(options = {}) {
    this.options = {
      headless: options.headless !== false,
      timeout: options.timeout || 30000,
      waitTime: options.waitTime || 5000,
      scrolling: options.scrolling !== false,
      userAgent: options.userAgent || null,
      proxy: options.proxy || null,
      verbose: options.verbose || false,
    };

    this.jsUrls = new Set();
    this.browser = null;
    this.context = null;
    this.page = null;
  }

  log(message) {
    if (this.options.verbose) {
      console.error(`[*] ${message}`);
    }
  }

  normalizeUrl(url, baseUrl) {
    try {
      // Handle protocol-relative URLs
      if (url.startsWith('//')) {
        const base = new URL(baseUrl);
        url = `${base.protocol}${url}`;
      }

      // Handle relative URLs
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = new URL(url, baseUrl).href;
      }

      // Parse and normalize
      const parsed = new URL(url);

      // Remove fragment
      parsed.hash = '';

      // Normalize path (remove trailing slashes, double slashes)
      parsed.pathname = parsed.pathname.replace(/\/+/g, '/');

      return parsed.href;
    } catch (e) {
      this.log(`Failed to normalize URL: ${url} - ${e.message}`);
      return null;
    }
  }

  isJavaScriptUrl(url, contentType = '') {
    // Check content type
    const jsContentTypes = [
      'application/javascript',
      'application/x-javascript',
      'text/javascript',
      'application/ecmascript',
      'text/ecmascript',
      'module',
    ];

    if (contentType) {
      const lowerContentType = contentType.toLowerCase();
      if (jsContentTypes.some(ct => lowerContentType.includes(ct))) {
        return true;
      }
    }

    // Check URL extension
    try {
      const parsed = new URL(url);
      const pathname = parsed.pathname.toLowerCase();

      // Common JS file patterns
      if (pathname.endsWith('.js') ||
          pathname.endsWith('.mjs') ||
          pathname.endsWith('.cjs') ||
          pathname.endsWith('.jsx') ||
          pathname.endsWith('.ts') ||
          pathname.endsWith('.tsx')) {
        return true;
      }

      // Webpack/bundler patterns (chunk files)
      if (/\.(chunk|bundle|vendor|main|app|runtime)\d*\.js/i.test(pathname)) {
        return true;
      }

      // Hash-based bundle names
      if (/\.[a-f0-9]{8,}\.js/i.test(pathname)) {
        return true;
      }

      // Dynamic import patterns with query strings
      if (parsed.search && pathname.includes('.js')) {
        return true;
      }
    } catch (e) {
      // Invalid URL
    }

    return false;
  }

  async init() {
    const launchOptions = {
      headless: this.options.headless,
    };

    if (this.options.proxy) {
      launchOptions.proxy = { server: this.options.proxy };
    }

    this.browser = await chromium.launch(launchOptions);

    const contextOptions = {
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true,
    };

    if (this.options.userAgent) {
      contextOptions.userAgent = this.options.userAgent;
    }

    this.context = await this.browser.newContext(contextOptions);
    this.page = await this.context.newPage();

    // Set default timeout
    this.page.setDefaultTimeout(this.options.timeout);
  }

  async setupInterceptors(targetUrl) {
    // Listen to all responses
    this.page.on('response', async (response) => {
      const url = response.url();
      const status = response.status();

      // Skip failed requests
      if (status >= 400) {
        return;
      }

      try {
        const headers = response.headers();
        const contentType = headers['content-type'] || '';

        if (this.isJavaScriptUrl(url, contentType)) {
          const normalizedUrl = this.normalizeUrl(url, targetUrl);
          if (normalizedUrl) {
            this.jsUrls.add(normalizedUrl);
            this.log(`Found JS: ${normalizedUrl}`);
          }
        }
      } catch (e) {
        // Response may have been disposed
      }
    });

    // Listen to script tags added dynamically
    await this.page.exposeFunction('__getjs_report_script', (src) => {
      if (src) {
        const normalizedUrl = this.normalizeUrl(src, targetUrl);
        if (normalizedUrl && this.isJavaScriptUrl(normalizedUrl)) {
          this.jsUrls.add(normalizedUrl);
          this.log(`Found dynamic script: ${normalizedUrl}`);
        }
      }
    });

    // Inject observer for dynamically added scripts
    await this.page.addInitScript(() => {
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeName === 'SCRIPT' && node.src) {
              window.__getjs_report_script(node.src);
            }
          });
        });
      });

      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });

      // Also intercept dynamic script creation
      const originalCreateElement = document.createElement.bind(document);
      document.createElement = function(tagName, options) {
        const element = originalCreateElement(tagName, options);
        if (tagName.toLowerCase() === 'script') {
          const originalSetAttribute = element.setAttribute.bind(element);
          element.setAttribute = function(name, value) {
            if (name === 'src') {
              setTimeout(() => window.__getjs_report_script(value), 0);
            }
            return originalSetAttribute(name, value);
          };

          Object.defineProperty(element, 'src', {
            set: function(value) {
              setTimeout(() => window.__getjs_report_script(value), 0);
              this.setAttribute('src', value);
            },
            get: function() {
              return this.getAttribute('src');
            }
          });
        }
        return element;
      };
    });
  }

  async scrollPage() {
    this.log('Scrolling page to trigger lazy loading...');

    await this.page.evaluate(async () => {
      const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
      const scrollHeight = document.body.scrollHeight;
      const viewportHeight = window.innerHeight;
      let currentPosition = 0;

      while (currentPosition < scrollHeight) {
        window.scrollTo(0, currentPosition);
        currentPosition += viewportHeight / 2;
        await delay(200);
      }

      // Scroll back to top
      window.scrollTo(0, 0);
    });
  }

  async triggerInteractions() {
    this.log('Triggering hover events...');

    // Hover over interactive elements to trigger lazy loading
    const interactiveSelectors = [
      'button',
      'a[href]',
      '[onclick]',
      '[data-toggle]',
      '[data-src]',
      '.lazy',
      '[class*="lazy"]',
    ];

    for (const selector of interactiveSelectors) {
      try {
        const elements = await this.page.$$(selector);
        for (const element of elements.slice(0, 10)) { // Limit to first 10
          try {
            await element.hover({ timeout: 500 });
            await this.page.waitForTimeout(100);
          } catch (e) {
            // Element may not be visible/hoverable
          }
        }
      } catch (e) {
        // Selector may not exist
      }
    }
  }

  async extractInlineModules(targetUrl) {
    this.log('Extracting module imports from inline scripts...');

    const moduleUrls = await this.page.evaluate(() => {
      const urls = [];
      const scripts = document.querySelectorAll('script[type="module"]');

      scripts.forEach((script) => {
        const content = script.textContent;
        // Match import statements
        const importRegex = /import\s+(?:[\w{}\s,*]+\s+from\s+)?['"]([^'"]+)['"]/g;
        let match;
        while ((match = importRegex.exec(content)) !== null) {
          urls.push(match[1]);
        }

        // Match dynamic imports
        const dynamicImportRegex = /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
        while ((match = dynamicImportRegex.exec(content)) !== null) {
          urls.push(match[1]);
        }
      });

      return urls;
    });

    for (const url of moduleUrls) {
      const normalizedUrl = this.normalizeUrl(url, targetUrl);
      if (normalizedUrl && this.isJavaScriptUrl(normalizedUrl)) {
        this.jsUrls.add(normalizedUrl);
        this.log(`Found module import: ${normalizedUrl}`);
      }
    }
  }

  async collect(targetUrl) {
    this.log(`Starting collection for: ${targetUrl}`);

    await this.init();
    await this.setupInterceptors(targetUrl);

    try {
      // Navigate to the target URL
      this.log('Navigating to target...');
      await this.page.goto(targetUrl, {
        waitUntil: 'networkidle',
        timeout: this.options.timeout,
      });

      // Wait for initial scripts to load
      this.log('Waiting for initial load...');
      await this.page.waitForTimeout(2000);

      // Extract script tags from DOM
      this.log('Extracting script tags from DOM...');
      const scriptSrcs = await this.page.evaluate(() => {
        const scripts = document.querySelectorAll('script[src]');
        return Array.from(scripts).map(s => s.src);
      });

      for (const src of scriptSrcs) {
        const normalizedUrl = this.normalizeUrl(src, targetUrl);
        if (normalizedUrl && this.isJavaScriptUrl(normalizedUrl)) {
          this.jsUrls.add(normalizedUrl);
        }
      }

      // Extract link preload scripts
      const preloadSrcs = await this.page.evaluate(() => {
        const links = document.querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]');
        return Array.from(links).map(l => l.href);
      });

      for (const src of preloadSrcs) {
        const normalizedUrl = this.normalizeUrl(src, targetUrl);
        if (normalizedUrl && this.isJavaScriptUrl(normalizedUrl)) {
          this.jsUrls.add(normalizedUrl);
        }
      }

      // Scroll to trigger lazy loading
      if (this.options.scrolling) {
        await this.scrollPage();
        await this.page.waitForTimeout(1000);
      }

      // Trigger interactions
      await this.triggerInteractions();
      await this.page.waitForTimeout(1000);

      // Extract module imports
      await this.extractInlineModules(targetUrl);

      // Final wait for any remaining async operations
      this.log('Final wait for async operations...');
      await this.page.waitForTimeout(this.options.waitTime);

    } catch (error) {
      if (error.message.includes('Timeout')) {
        this.log('Navigation timeout - continuing with partial results');
      } else {
        throw error;
      }
    }

    return this.getResults();
  }

  getResults() {
    return Array.from(this.jsUrls).sort();
  }

  async close() {
    if (this.browser) {
      await this.browser.close();
    }
  }
}

class JSDownloader {
  constructor(options = {}) {
    this.options = {
      outputDir: options.outputDir || './js-files',
      timeout: options.timeout || 30000,
      verbose: options.verbose || false,
      headers: options.headers || {},
    };
  }

  log(message) {
    if (this.options.verbose) {
      console.error(`[*] ${message}`);
    }
  }

  sanitizeFilename(url) {
    try {
      const parsed = new URL(url);
      let filename = path.basename(parsed.pathname);

      // If no filename, create one from URL hash
      if (!filename || filename === '/') {
        const hash = Buffer.from(url).toString('base64').slice(0, 16);
        filename = `script_${hash}.js`;
      }

      // Sanitize filename
      filename = filename.replace(/[^a-zA-Z0-9._-]/g, '_');

      // Add host prefix for uniqueness
      const host = parsed.hostname.replace(/\./g, '_');
      return `${host}_${filename}`;
    } catch (e) {
      const hash = Buffer.from(url).toString('base64').slice(0, 16);
      return `script_${hash}.js`;
    }
  }

  async downloadOne(url, outputPath = null) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const protocol = parsed.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': '*/*',
          ...this.options.headers,
        },
        timeout: this.options.timeout,
        rejectUnauthorized: false,
      };

      const req = protocol.request(options, (res) => {
        // Handle redirects
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          this.downloadOne(res.headers.location, outputPath)
            .then(resolve)
            .catch(reject);
          return;
        }

        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }

        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const content = Buffer.concat(chunks);

          if (outputPath) {
            const dir = path.dirname(outputPath);
            if (!fs.existsSync(dir)) {
              fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(outputPath, content);
            this.log(`Downloaded: ${url} -> ${outputPath}`);
          }

          resolve({
            url,
            content: content.toString('utf8'),
            size: content.length,
            path: outputPath,
          });
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Timeout downloading ${url}`));
      });

      req.end();
    });
  }

  async downloadAll(urls) {
    const results = [];
    const errors = [];

    // Ensure output directory exists
    if (!fs.existsSync(this.options.outputDir)) {
      fs.mkdirSync(this.options.outputDir, { recursive: true });
    }

    for (const url of urls) {
      try {
        const filename = this.sanitizeFilename(url);
        const outputPath = path.join(this.options.outputDir, filename);
        const result = await this.downloadOne(url, outputPath);
        results.push(result);
      } catch (error) {
        errors.push({ url, error: error.message });
        this.log(`Failed to download ${url}: ${error.message}`);
      }
    }

    return { results, errors };
  }
}

module.exports = { JSCollector, JSDownloader };
