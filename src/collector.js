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
      cookies: options.cookies || null,        // Cookie file path or array
      localStorage: options.localStorage || null, // LocalStorage key-value pairs
      headers: options.headers || {},          // Extra HTTP headers
      browser: options.browser || null,        // Shared browser instance
    };

    this.jsUrls = new Set();
    this.wsJsUrls = new Set();  // WebSocket-discovered JS
    this.swScripts = new Set(); // Service Worker scripts
    this.browser = null;
    this.context = null;
    this.page = null;
    this._ownsBrowser = true;
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

  async init(sharedBrowser = null) {
    if (sharedBrowser) {
      this.browser = sharedBrowser;
      this._ownsBrowser = false;
    } else {
      const launchOptions = {
        headless: this.options.headless,
      };

      if (this.options.proxy) {
        launchOptions.proxy = { server: this.options.proxy };
      }

      this.browser = await chromium.launch(launchOptions);
      this._ownsBrowser = true;
    }

    const defaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

    const contextOptions = {
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true,
      userAgent: this.options.userAgent || defaultUserAgent,
    };

    // Add extra HTTP headers
    if (Object.keys(this.options.headers).length > 0) {
      contextOptions.extraHTTPHeaders = this.options.headers;
    }

    this.context = await this.browser.newContext(contextOptions);

    // Load cookies if provided
    if (this.options.cookies) {
      await this.loadCookies();
    }

    this.page = await this.context.newPage();

    // Set localStorage if provided
    if (this.options.localStorage) {
      await this.setupLocalStorage();
    }

    // Set default timeout
    this.page.setDefaultTimeout(this.options.timeout);
  }

  async loadCookies() {
    let cookies = this.options.cookies;

    // If cookies is a file path, read it
    if (typeof cookies === 'string') {
      try {
        const cookieData = fs.readFileSync(cookies, 'utf8');
        cookies = JSON.parse(cookieData);
        this.log(`Loaded ${cookies.length} cookies from file`);
      } catch (e) {
        this.log(`Failed to load cookies from file: ${e.message}`);
        return;
      }
    }

    // Normalize cookie format (support both Playwright and Netscape formats)
    const normalizedCookies = cookies.map(cookie => {
      // Handle Netscape/curl format
      if (cookie.HttpOnly !== undefined) {
        return {
          name: cookie.Name || cookie.name,
          value: cookie.Value || cookie.value,
          domain: cookie.Domain || cookie.domain,
          path: cookie.Path || cookie.path || '/',
          expires: cookie.Expires ? new Date(cookie.Expires).getTime() / 1000 : -1,
          httpOnly: cookie.HttpOnly === 'true' || cookie.HttpOnly === true,
          secure: cookie.Secure === 'true' || cookie.Secure === true,
          sameSite: cookie.SameSite || 'Lax',
        };
      }
      return cookie;
    });

    await this.context.addCookies(normalizedCookies);
    this.log(`Added ${normalizedCookies.length} cookies to browser context`);
  }

  async setupLocalStorage() {
    // localStorage must be set after navigating to the domain
    // We'll inject it via addInitScript
    const storageData = this.options.localStorage;
    await this.context.addInitScript((data) => {
      for (const [key, value] of Object.entries(data)) {
        localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value));
      }
    }, storageData);
    this.log(`Configured ${Object.keys(storageData).length} localStorage entries`);
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

        // Detect Service Worker registrations
        if (url.includes('service-worker') || url.includes('sw.js') ||
            contentType.includes('javascript')) {
          try {
            const body = await response.text();
            if (body.includes('self.addEventListener') || body.includes('ServiceWorkerGlobalScope')) {
              const normalizedUrl = this.normalizeUrl(url, targetUrl);
              if (normalizedUrl) {
                this.swScripts.add(normalizedUrl);
                this.jsUrls.add(normalizedUrl);
                this.log(`Found Service Worker: ${normalizedUrl}`);
              }
            }
          } catch (e) {
            // Body may not be available
          }
        }
      } catch (e) {
        // Response may have been disposed
      }
    });

    // Monitor WebSocket frames for JS URLs
    const cdpSession = await this.context.newCDPSession(this.page);
    await cdpSession.send('Network.enable');

    cdpSession.on('Network.webSocketFrameReceived', (params) => {
      try {
        const payload = params.response.payloadData;
        // Look for JS URLs in WebSocket messages
        const urlMatches = payload.match(/https?:\/\/[^\s"'<>]+\.js[^\s"'<>]*/gi);
        if (urlMatches) {
          for (const match of urlMatches) {
            const normalizedUrl = this.normalizeUrl(match, targetUrl);
            if (normalizedUrl && this.isJavaScriptUrl(normalizedUrl)) {
              this.wsJsUrls.add(normalizedUrl);
              this.jsUrls.add(normalizedUrl);
              this.log(`Found JS via WebSocket: ${normalizedUrl}`);
            }
          }
        }
      } catch (e) {
        // Invalid payload
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

  async extractServiceWorkers(targetUrl) {
    this.log('Checking for Service Worker registrations...');

    // Extract SW registration URLs from scripts
    const swUrls = await this.page.evaluate(() => {
      const urls = [];

      // Check all scripts for navigator.serviceWorker.register calls
      const scripts = document.querySelectorAll('script');
      scripts.forEach((script) => {
        const content = script.textContent;
        // Match serviceWorker.register('url') patterns
        const swRegex = /serviceWorker\.register\s*\(\s*['"]([^'"]+)['"]/g;
        let match;
        while ((match = swRegex.exec(content)) !== null) {
          urls.push(match[1]);
        }
      });

      return urls;
    });

    for (const url of swUrls) {
      const normalizedUrl = this.normalizeUrl(url, targetUrl);
      if (normalizedUrl) {
        this.swScripts.add(normalizedUrl);
        this.jsUrls.add(normalizedUrl);
        this.log(`Found Service Worker registration: ${normalizedUrl}`);
      }
    }

    // Also check for registered service workers via CDP
    try {
      const cdpSession = await this.context.newCDPSession(this.page);
      await cdpSession.send('ServiceWorker.enable');

      // Give time for SW to register
      await this.page.waitForTimeout(1000);

      const { versions } = await cdpSession.send('ServiceWorker.getVersions') || { versions: [] };
      for (const version of versions || []) {
        if (version.scriptURL) {
          const normalizedUrl = this.normalizeUrl(version.scriptURL, targetUrl);
          if (normalizedUrl) {
            this.swScripts.add(normalizedUrl);
            this.jsUrls.add(normalizedUrl);
            this.log(`Found registered Service Worker: ${normalizedUrl}`);
          }
        }
      }
    } catch (e) {
      this.log(`Service Worker CDP check failed: ${e.message}`);
    }
  }

  async collect(targetUrl) {
    this.log(`Starting collection for: ${targetUrl}`);

    await this.init(this.options.browser || null);
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

      // Extract Service Workers
      await this.extractServiceWorkers(targetUrl);

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
    if (this.context) {
      await this.context.close();
      this.context = null;
      this.page = null;
    }
    if (this.browser && this._ownsBrowser) {
      await this.browser.close();
      this.browser = null;
    }
  }

  async resetForNewTarget() {
    // Close current context and page (but not the browser)
    if (this.context) {
      await this.context.close();
      this.context = null;
      this.page = null;
    }

    // Clear collected URLs
    this.jsUrls = new Set();
    this.wsJsUrls = new Set();
    this.swScripts = new Set();
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
    this._context = options.context || null; // Playwright BrowserContext
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
    let content;

    if (this._context) {
      // Use Playwright's request API (carries cookies/headers from browser context)
      const request = this._context.request;
      const response = await request.get(url, {
        timeout: this.options.timeout,
        ignoreHTTPSErrors: true,
      });

      if (response.status() >= 400) {
        throw new Error(`HTTP ${response.status()} for ${url}`);
      }

      content = Buffer.from(await response.body());
    } else {
      // Fallback to raw HTTP (for standalone usage without browser)
      content = await this._downloadRaw(url);
    }

    if (outputPath) {
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(outputPath, content);
      this.log(`Downloaded: ${url} -> ${outputPath}`);
    }

    return {
      url,
      content: content.toString('utf8'),
      size: content.length,
      path: outputPath,
    };
  }

  async _downloadRaw(url) {
    // Preserve original http/https fallback for when no browser context exists
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
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          this._downloadRaw(res.headers.location)
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
        res.on('end', () => resolve(Buffer.concat(chunks)));
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Timeout downloading ${url}`));
      });

      req.end();
    });
  }

  async downloadAll(urls, contentDedup = false) {
    const results = [];
    const errors = [];
    const seenHashes = new Set();

    // Ensure output directory exists
    if (!fs.existsSync(this.options.outputDir)) {
      fs.mkdirSync(this.options.outputDir, { recursive: true });
    }

    for (const url of urls) {
      try {
        const filename = this.sanitizeFilename(url);
        const outputPath = path.join(this.options.outputDir, filename);
        const result = await this.downloadOne(url, outputPath);

        if (contentDedup) {
          const crypto = require('crypto');
          const hash = crypto.createHash('sha256').update(result.content).digest('hex');
          if (seenHashes.has(hash)) {
            // Remove the duplicate file we just wrote
            fs.unlinkSync(outputPath);
            this.log(`Skipped duplicate (same content): ${url}`);
            continue;
          }
          seenHashes.add(hash);
        }

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
