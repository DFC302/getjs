const { chromium } = require('playwright');
const { URL } = require('url');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { version: packageVersion } = require('../package.json');
const { APIInventory } = require('./api-inventory');

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

function matchCollectionScope(hostname, pattern) {
  const normalizedHost = String(hostname || '').toLowerCase();
  const normalizedPattern = String(pattern || '').trim().toLowerCase();
  if (!normalizedHost || !normalizedPattern) return false;
  if (normalizedPattern.startsWith('*.')) {
    const base = normalizedPattern.slice(2);
    return normalizedHost === base || normalizedHost.endsWith(`.${base}`);
  }
  if (!normalizedPattern.includes('*')) {
    return normalizedHost === normalizedPattern || normalizedHost.endsWith(`.${normalizedPattern}`);
  }
  return matchDomainPattern(normalizedHost, normalizedPattern);
}

function normalizeSameSite(value) {
  if (!value) return undefined;

  const normalized = String(value).toLowerCase().replace(/[\s_-]/g, '');
  if (['none', 'norestriction'].includes(normalized)) return 'None';
  if (normalized === 'lax') return 'Lax';
  if (normalized === 'strict') return 'Strict';
  return undefined;
}

function booleanValue(value, fallback = false) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'string') return value.toLowerCase() === 'true';
  return Boolean(value);
}

class JSCollector {
  constructor(options = {}) {
    this.options = {
      headless: options.headless !== false,
      timeout: options.timeout ?? 30000,
      waitTime: options.waitTime ?? 5000,
      scrolling: options.scrolling !== false,
      userAgent: options.userAgent || null,
      proxy: options.proxy || null,
      verbose: options.verbose || false,
      cookies: options.cookies || null,        // Cookie file path, raw string, or array
      storageState: options.storageState || null, // Playwright storage-state file or object
      cookieDomain: options.cookieDomain || null, // Domain for raw cookie strings
      localStorage: options.localStorage || null, // LocalStorage key-value pairs
      headers: options.headers || {},          // Extra HTTP headers
      authDomains: options.authDomains || null, // Domains allowed to receive headers/localStorage
      browser: options.browser || null,        // Shared browser instance
      recursive: options.recursive !== false,
      maxDepth: options.maxDepth ?? 3,
      maxFiles: options.maxFiles ?? 500,
      maxFileSize: options.maxFileSize ?? 10 * 1024 * 1024,
      crawlLinks: options.crawlLinks === true,
      maxPages: options.maxPages ?? 10,
      sourceMaps: options.sourceMaps !== false,
      scopeDomains: Array.isArray(options.scopeDomains) ? options.scopeDomains : [],
      entrypoints: Array.isArray(options.entrypoints) ? options.entrypoints : [],
      captureApi: options.captureApi === true,
      sessionIdentity: options.sessionIdentity || null,
      sessionRole: options.sessionRole || null,
      sessionLabel: options.sessionLabel || null,
      maxInlineArtifactSize: options.maxInlineArtifactSize ?? 1024 * 1024,
      interactiveAuth: options.interactiveAuth === true,
      loginUrl: options.loginUrl || null,
      interactiveAuthHandler: options.interactiveAuthHandler || null,
    };

    this.jsUrls = new Set();
    this.wsJsUrls = new Set();  // WebSocket-discovered JS
    this.swScripts = new Set(); // Service Worker scripts
    this.sourceMapUrls = new Set(); // Valid source maps discovered from JavaScript bundles
    this.sourceMapAttempts = new Set();
    this.browser = null;
    this.context = null;
    this.page = null;
    this._ownsBrowser = true;
    this.targetUrl = null;
    this.authDomains = [];
    this.authOrigins = [];
    this.pendingTasks = new Set();
    this.initializedPages = new WeakSet();
    this.pageInitializationTasks = new WeakMap();
    this.importMap = { imports: {} };
    this.apiInventory = null;
    this.inlineArtifacts = [];
    this.inlineArtifactHashes = new Set();
    this.inlineArtifactsSkipped = 0;
    this.pageCoverage = {
      planned: [],
      visited: [],
      failed: [],
    };
    this.metadata = {
      initialUrl: null,
      finalUrl: null,
      title: null,
      redirects: [],
      failedRequests: [],
      warnings: [],
      authentication: null,
    };
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

  async init(sharedBrowser = null, targetUrl = null) {
    this.targetUrl = targetUrl || this.targetUrl;
    if (this.targetUrl) {
      const target = new URL(this.targetUrl);
      if (this.options.authDomains && this.options.authDomains.length > 0) {
        this.authDomains = [...this.options.authDomains];
        this.authOrigins = [];
      } else {
        this.authDomains = [];
        this.authOrigins = [target.origin];
      }
      this.apiInventory = new APIInventory(this.targetUrl, {
        authenticated: Boolean(this.options.cookies || this.options.storageState || Object.keys(this.options.headers).length),
        identity: this.options.sessionIdentity,
        role: this.options.sessionRole,
        label: this.options.sessionLabel,
      });
    }

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

    const contextOptions = {
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true,
    };

    if (this.options.userAgent) {
      contextOptions.userAgent = this.options.userAgent;
    }

    const authState = this.loadAuthState();
    if (authState && authState.origins) {
      contextOptions.storageState = authState;
    }

    this.context = await this.browser.newContext(contextOptions);

    if (authState && !authState.origins && authState.cookies.length > 0) {
      await this.context.addCookies(authState.cookies);
      this.log(`Added ${authState.cookies.length} cookies to browser context`);
    }

    if (Object.keys(this.options.headers).length > 0) {
      await this.setupScopedHeaders();
    }

    this.page = await this.context.newPage();

    // Set localStorage if provided
    if (this.options.localStorage) {
      await this.setupLocalStorage();
    }

    // Set default timeout
    this.page.setDefaultTimeout(this.options.timeout);
  }

  parseRawCookieString(cookieStr, domain, secure = true) {
    // Parse "name=value; name2=value2" format
    const cleaned = cookieStr.replace(/^\s*cookie\s*:\s*/i, '');
    const cookies = cleaned
      .split(';')
      .map(pair => pair.trim())
      .filter(pair => pair.includes('='))
      .map(pair => {
        const eqIndex = pair.indexOf('=');
        const name = pair.substring(0, eqIndex).trim();
        const value = pair.substring(eqIndex + 1).trim();
        return {
          name,
          value,
          domain,
          path: '/',
          secure,
        };
      });

    if (cookies.length === 0 || cookies.some(cookie => !cookie.name)) {
      throw new Error('Raw cookie string did not contain valid name=value pairs');
    }

    return cookies;
  }

  normalizeCookie(cookie) {
    const name = cookie.name ?? cookie.Name;
    const value = cookie.value ?? cookie.Value;
    if (typeof name !== 'string' || typeof value !== 'string') {
      throw new Error('Every cookie must contain string name and value fields');
    }

    const normalized = { name, value };
    const url = cookie.url ?? cookie.Url;
    const domain = cookie.domain ?? cookie.Domain ?? this.options.cookieDomain;

    if (url) {
      normalized.url = url;
    } else if (domain) {
      normalized.domain = domain;
      normalized.path = cookie.path ?? cookie.Path ?? '/';
    } else {
      throw new Error(`Cookie "${name}" is missing both url and domain`);
    }

    const expiresValue = cookie.expires ?? cookie.expirationDate ?? cookie.Expires;
    if (expiresValue !== undefined && expiresValue !== null && expiresValue !== '') {
      const parsedNumber = Number(expiresValue);
      const numericExpires = Number.isFinite(parsedNumber)
        ? parsedNumber
        : Date.parse(expiresValue) / 1000;
      if (Number.isFinite(numericExpires)) normalized.expires = numericExpires;
    }

    normalized.httpOnly = booleanValue(cookie.httpOnly ?? cookie.HttpOnly);
    normalized.secure = booleanValue(
      cookie.secure ?? cookie.Secure,
      this.targetUrl ? new URL(this.targetUrl).protocol === 'https:' : true,
    );

    const sameSite = normalizeSameSite(cookie.sameSite ?? cookie.SameSite);
    if (sameSite) normalized.sameSite = sameSite;
    if (cookie.partitionKey) normalized.partitionKey = cookie.partitionKey;

    return normalized;
  }

  parseNetscapeCookieFile(content) {
    const cookies = [];
    for (const rawLine of content.split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line || (line.startsWith('#') && !line.startsWith('#HttpOnly_'))) continue;

      let httpOnly = false;
      if (line.startsWith('#HttpOnly_')) {
        httpOnly = true;
        line = line.slice('#HttpOnly_'.length);
      }

      const fields = line.split('\t');
      if (fields.length < 7) continue;
      const [domain, , cookiePath, secure, expires, name, ...valueParts] = fields;
      cookies.push(this.normalizeCookie({
        name,
        value: valueParts.join('\t'),
        domain,
        path: cookiePath || '/',
        secure: secure.toUpperCase() === 'TRUE',
        httpOnly,
        expires: Number(expires) || -1,
      }));
    }

    if (cookies.length === 0) {
      throw new Error('Cookie file is neither valid JSON nor a Netscape cookie jar');
    }
    return cookies;
  }

  loadAuthState() {
    if (this.options.cookies && this.options.storageState) {
      throw new Error('Use either cookies or storageState, not both');
    }

    let input = this.options.storageState || this.options.cookies;
    if (!input) return null;

    if (typeof input === 'string' && fs.existsSync(input)) {
      const content = fs.readFileSync(input, 'utf8');
      try {
        input = JSON.parse(content);
      } catch (error) {
        if (this.options.storageState) {
          throw new Error(`Invalid storage-state JSON: ${error.message}`);
        }
        return { cookies: this.parseNetscapeCookieFile(content) };
      }
    } else if (this.options.storageState && typeof input === 'string') {
      throw new Error(`Storage-state file not found: ${input}`);
    } else if (typeof input === 'string') {
      if (!input.includes('=')) throw new Error(`Cookie file not found: ${input}`);
      if (!this.options.cookieDomain) {
        throw new Error('Raw cookie strings require a cookie domain');
      }
      const secure = this.targetUrl ? new URL(this.targetUrl).protocol === 'https:' : true;
      const cookies = this.parseRawCookieString(input, this.options.cookieDomain, secure);
      this.log(`Parsed ${cookies.length} cookies from raw string for domain ${this.options.cookieDomain}`);
      return { cookies };
    }

    if (Array.isArray(input)) {
      return { cookies: input.map(cookie => this.normalizeCookie(cookie)) };
    }

    if (input && Array.isArray(input.cookies)) {
      const state = {
        cookies: input.cookies.map(cookie => this.normalizeCookie(cookie)),
        origins: Array.isArray(input.origins) ? input.origins : [],
      };
      this.log(`Loaded storage state with ${state.cookies.length} cookies and ${state.origins.length} origins`);
      return state;
    }

    throw new Error('Cookie input must be a JSON cookie array, Playwright storage state, Netscape jar, or raw cookie string');
  }

  isAuthDomain(url) {
    try {
      const parsed = new URL(url);
      if (this.authOrigins.length > 0) return this.authOrigins.includes(parsed.origin);
      return this.authDomains.some(pattern => matchDomainPattern(parsed.hostname, pattern));
    } catch (error) {
      return false;
    }
  }

  headersForUrl(url) {
    return this.isAuthDomain(url) ? { ...this.options.headers } : {};
  }

  isCollectionScopeUrl(url) {
    if (this.options.scopeDomains.length === 0) return true;
    try {
      const hostname = new URL(url).hostname;
      return this.options.scopeDomains.some(pattern => matchCollectionScope(hostname, pattern));
    } catch (error) {
      return false;
    }
  }

  async setupScopedHeaders() {
    await this.context.route('**/*', async (route) => {
      const request = route.request();
      if (!this.isAuthDomain(request.url())) {
        await route.continue();
        return;
      }

      await route.continue({
        headers: {
          ...request.headers(),
          ...this.options.headers,
        },
      });
    });
  }

  async setupLocalStorage() {
    const storageData = this.options.localStorage;
    const allowedDomains = this.authDomains;
    const allowedOrigins = this.authOrigins;
    await this.context.addInitScript(({ data, domains, origins }) => {
      const hostname = window.location.hostname.toLowerCase();
      const domainAllowed = domains.some((pattern) => {
        const normalized = pattern.toLowerCase();
        if (normalized.startsWith('*.')) {
          const base = normalized.slice(2);
          return hostname === base || hostname.endsWith(`.${base}`);
        }
        if (!normalized.includes('*')) return hostname === normalized;
        const expression = normalized
          .split('*')
          .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
          .join('.*');
        return new RegExp(`^${expression}$`, 'i').test(hostname);
      });
      if (!origins.includes(window.location.origin) && !domainAllowed) return;

      for (const [key, value] of Object.entries(data)) {
        localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value));
      }
    }, { data: storageData, domains: allowedDomains, origins: allowedOrigins });
    const scopes = [...allowedOrigins, ...allowedDomains];
    this.log(`Configured ${Object.keys(storageData).length} localStorage entries for ${scopes.join(', ')}`);
  }

  recordJsUrl(url, baseUrl, source = 'network', force = false) {
    const normalizedUrl = this.normalizeUrl(url, baseUrl || this.targetUrl);
    if (!normalizedUrl || (!force && !this.isJavaScriptUrl(normalizedUrl))) return null;

    const isNew = !this.jsUrls.has(normalizedUrl);
    this.jsUrls.add(normalizedUrl);
    if (isNew) this.log(`Found JS via ${source}: ${normalizedUrl}`);
    return normalizedUrl;
  }

  trackTask(promise) {
    const task = Promise.resolve(promise)
      .catch(error => this.log(`Background collection task failed: ${error.message}`))
      .finally(() => this.pendingTasks.delete(task));
    this.pendingTasks.add(task);
    return task;
  }

  extractPayloadUrls(payload, baseUrl, source) {
    const text = Buffer.isBuffer(payload) ? payload.toString('utf8') : String(payload || '');
    const matches = text.match(/(?:https?:\/\/|\/|\.\.?\/)[^\s"'<>\\]+\.(?:mjs|cjs|js)(?:\?[^\s"'<>\\]*)?/gi) || [];
    for (const match of matches) {
      const normalized = this.recordJsUrl(match, baseUrl, source);
      if (normalized && source.startsWith('WebSocket')) this.wsJsUrls.add(normalized);
    }
  }

  async initializePage(page) {
    if (this.initializedPages.has(page)) return;
    if (this.pageInitializationTasks.has(page)) {
      return this.pageInitializationTasks.get(page);
    }

    const initialization = (async () => {
      page.on('websocket', (webSocket) => {
        if (this.options.captureApi) this.apiInventory?.observeWebSocket(webSocket, page.url() || this.targetUrl);
        const inspectFrame = event => this.extractPayloadUrls(event.payload, page.url() || this.targetUrl, 'WebSocket');
        webSocket.on('framereceived', inspectFrame);
        webSocket.on('framesent', inspectFrame);
      });

      const bindingName = `__getjs_report_script_${Math.random().toString(36).slice(2)}`;
      await page.exposeFunction(bindingName, (src, documentUrl) => {
        this.recordJsUrl(src, documentUrl || page.url() || this.targetUrl, 'DOM mutation');
      });

      await page.addInitScript(({ reportName }) => {
        const install = () => {
          if (window.__getjsObserverInstalled) return;
          window.__getjsObserverInstalled = true;
          const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
              for (const node of mutation.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;
                const scripts = [];
                if (node.matches && node.matches('script[src], script[data-src], link[rel="modulepreload"], link[rel="prefetch"], link[rel="preload"][as="script"]')) scripts.push(node);
                if (node.querySelectorAll) {
                  scripts.push(...node.querySelectorAll('script[src], script[data-src], link[rel="modulepreload"], link[rel="prefetch"], link[rel="preload"][as="script"]'));
                }
                for (const script of scripts) {
                  const candidate = script.src || script.href || script.getAttribute('data-src');
                  if (candidate) window[reportName](candidate, document.baseURI).catch(() => {});
                }
              }
            }
          });
          observer.observe(document, { childList: true, subtree: true });
        };

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', install, { once: true });
        } else {
          install();
        }
      }, { reportName: bindingName });

      this.initializedPages.add(page);
    })();

    this.pageInitializationTasks.set(page, initialization);
    try {
      await initialization;
    } catch (error) {
      this.pageInitializationTasks.delete(page);
      throw error;
    }
  }

  async setupInterceptors(targetUrl) {
    this.context.on('request', (request) => {
      if (this.options.captureApi) {
        let pageUrl = null;
        try { pageUrl = request.frame().url(); } catch {}
        this.apiInventory?.observeRequest(request, pageUrl);
      }
      if (request.resourceType() === 'script') {
        let baseUrl = targetUrl;
        try {
          baseUrl = request.frame().url() || targetUrl;
        } catch (error) {
          // Service Worker requests are not associated with a frame.
        }
        // Chromium's resource classification is authoritative for extensionless
        // script endpoints (for example, module aggregators ending in /m=root).
        this.recordJsUrl(request.url(), baseUrl, 'request', true);
      }

      if (request.isNavigationRequest() && request.frame() === this.page.mainFrame()) {
        const previous = this.metadata.redirects[this.metadata.redirects.length - 1];
        if (previous !== request.url()) this.metadata.redirects.push(request.url());
      }
    });

    this.context.on('response', (response) => {
      if (this.options.captureApi) this.apiInventory?.observeResponse(response);
      // response.allHeaders() can remain pending for streaming responses. The
      // regular header map is synchronous and includes Content-Type, which is
      // the only response header collection needs.
      const contentType = response.headers()['content-type'] || '';
      if (this.isJavaScriptUrl(response.url(), contentType)) {
        // Keep responses identified by JavaScript Content-Type even when the
        // URL has no conventional script extension.
        this.recordJsUrl(response.url(), targetUrl, 'response', true);
      }
    });

    this.context.on('requestfailed', (request) => {
      const failure = request.failure();
      this.metadata.failedRequests.push({
        url: request.url(),
        error: failure ? failure.errorText : 'unknown error',
      });
      if (request.resourceType() === 'script') {
        let baseUrl = targetUrl;
        try {
          baseUrl = request.frame().url() || targetUrl;
        } catch (error) {
          // Service Worker requests are not associated with a frame.
        }
        this.recordJsUrl(request.url(), baseUrl, 'failed request', true);
      }
    });

    this.context.on('serviceworker', (worker) => {
      const normalized = this.recordJsUrl(worker.url(), targetUrl, 'service worker', true);
      if (normalized) this.swScripts.add(normalized);
    });

    this.context.on('page', (page) => {
      this.trackTask(this.initializePage(page));
    });

    await this.initializePage(this.page);
  }

  async scrollPage(page = this.page) {
    this.log('Scrolling page to trigger lazy loading...');

    await page.evaluate(async () => {
      const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
      let currentPosition = 0;
      let stablePasses = 0;
      let previousHeight = 0;
      let steps = 0;

      while (stablePasses < 3 && steps < 200) {
        const scrollHeight = Math.max(
          document.body ? document.body.scrollHeight : 0,
          document.documentElement ? document.documentElement.scrollHeight : 0,
        );
        window.scrollTo(0, currentPosition);
        currentPosition += Math.max(window.innerHeight / 2, 200);
        await delay(200);

        if (currentPosition >= scrollHeight) {
          stablePasses = scrollHeight === previousHeight ? stablePasses + 1 : 0;
          previousHeight = scrollHeight;
          currentPosition = Math.max(0, scrollHeight - window.innerHeight);
          await delay(300);
        }
        steps += 1;
      }

      // Scroll back to top
      window.scrollTo(0, 0);
    });
  }

  async triggerInteractions(page = this.page) {
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
        const elements = await page.$$(selector);
        for (const element of elements.slice(0, 10)) { // Limit to first 10
          try {
            await element.hover({ timeout: 500 });
            await page.waitForTimeout(100);
          } catch (e) {
            // Element may not be visible/hoverable
          }
        }
      } catch (e) {
        // Selector may not exist
      }
    }
  }

  resolveImportSpecifier(specifier, baseUrl) {
    if (!specifier || /^(?:data|blob|javascript):/i.test(specifier)) return null;

    let resolvedSpecifier = specifier;
    const imports = this.importMap.imports || {};
    if (!/^(?:https?:)?\/\//i.test(specifier) &&
        !specifier.startsWith('/') &&
        !specifier.startsWith('./') &&
        !specifier.startsWith('../')) {
      if (imports[specifier]) {
        resolvedSpecifier = imports[specifier];
      } else {
        const prefix = Object.keys(imports)
          .filter(key => key.endsWith('/') && specifier.startsWith(key))
          .sort((a, b) => b.length - a.length)[0];
        if (!prefix) return null;
        resolvedSpecifier = `${imports[prefix]}${specifier.slice(prefix.length)}`;
      }
    }

    return this.normalizeUrl(resolvedSpecifier, baseUrl);
  }

  extractJavaScriptReferences(source, baseUrl) {
    const specifiers = new Set();
    const patterns = [
      /\b(?:import|export)\s*(?:[^"'`;()]*?\bfrom\s*)?["']([^"']+)["']/g,
      /import\s*\(\s*["']([^"']+)["']\s*\)/g,
      /(?:new\s+(?:Worker|SharedWorker)|serviceWorker\.register)\s*\(\s*["']([^"']+)["']/g,
      /["']((?:(?:https?:)?\/\/|\/|\.\.?\/)[^"'\\\s]+\.(?:mjs|cjs|js)(?:\?[^"'\\\s]*)?)["']/g,
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(source)) !== null) specifiers.add(match[1]);
    }

    const urls = new Set();
    for (const specifier of specifiers) {
      const resolved = this.resolveImportSpecifier(specifier, baseUrl);
      if (!resolved || !/^https?:/i.test(resolved)) continue;
      const extension = path.extname(new URL(resolved).pathname).toLowerCase();
      if (extension && !['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'].includes(extension)) continue;
      urls.add(resolved);
    }
    return urls;
  }

  sourceMapCandidates(source, scriptUrl, headers = {}) {
    if (!this.options.sourceMaps) return [];
    const candidates = new Set();
    const addCandidate = (candidate) => {
      if (typeof candidate !== 'string' || !candidate.trim() || /^data:/i.test(candidate.trim())) return;
      const normalized = this.normalizeUrl(candidate.trim().replace(/["']$/g, ''), scriptUrl);
      if (normalized && /^https?:/i.test(normalized)) candidates.add(normalized);
    };

    addCandidate(headers.sourcemap || headers['source-map'] || headers['x-sourcemap']);
    const pattern = /(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)\s*(?:\*\/)?/gi;
    let match;
    while ((match = pattern.exec(source)) !== null) addCandidate(match[1]);

    // Some production bundles publish a sibling map but omit the mapping
    // comment. Probe only target-origin scripts so this does not fan out across
    // unrelated CDNs.
    try {
      const parsedScript = new URL(scriptUrl);
      const targetOrigin = this.targetUrl ? new URL(this.targetUrl).origin : null;
      if (targetOrigin && parsedScript.origin === targetOrigin && /\.(?:mjs|cjs|js)$/i.test(parsedScript.pathname)) {
        parsedScript.pathname = `${parsedScript.pathname}.map`;
        candidates.add(parsedScript.href);
      }
    } catch (error) {
      // Invalid URLs are excluded by normal collection before this point.
    }
    return [...candidates];
  }

  async discoverSourceMaps(source, scriptUrl, headers = {}) {
    for (const candidate of this.sourceMapCandidates(source, scriptUrl, headers)) {
      if (!this.isCollectionScopeUrl(candidate)) continue;
      if (this.sourceMapAttempts.has(candidate)) continue;
      this.sourceMapAttempts.add(candidate);
      let response;
      try {
        response = await this.requestWithScopedRedirects(candidate);
        if (response.status() < 200 || response.status() >= 300) continue;
        const responseHeaders = response.headers();
        const contentType = responseHeaders['content-type'] || '';
        if (/text\/html|application\/xhtml\+xml/i.test(contentType)) continue;
        const declaredSize = Number(responseHeaders['content-length']);
        if (Number.isFinite(declaredSize) && declaredSize > this.options.maxFileSize) continue;
        const body = await response.body();
        if (body.length > this.options.maxFileSize) continue;
        const parsed = JSON.parse(body.toString('utf8'));
        if (parsed?.version !== 3 || !Array.isArray(parsed.sources)) continue;
        const normalized = this.recordJsUrl(response.url(), scriptUrl, 'source map', true);
        if (normalized) {
          this.sourceMapUrls.add(normalized);
          this.log(`Validated source map with ${parsed.sources.length} sources: ${normalized}`);
        }
      } catch (error) {
        this.log(`Source map probe did not produce a valid map (${candidate}): ${error.message}`);
      } finally {
        if (response) await response.dispose().catch(() => {});
      }
    }
  }

  async requestWithScopedRedirects(url, maxRedirects = 10) {
    let currentUrl = url;
    for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount += 1) {
      const response = await this.context.request.get(currentUrl, {
        headers: this.headersForUrl(currentUrl),
        timeout: this.options.timeout,
        failOnStatusCode: false,
        maxRedirects: 0,
      });
      const location = response.headers().location;
      if (response.status() < 300 || response.status() >= 400 || !location) return response;

      if (redirectCount === maxRedirects) {
        await response.dispose();
        throw new Error(`Too many redirects fetching ${url}`);
      }
      currentUrl = new URL(location, response.url()).href;
      await response.dispose();
    }
    throw new Error(`Too many redirects fetching ${url}`);
  }

  async crawlScriptDependencies() {
    if (!this.options.recursive) return;

    this.log(`Recursively parsing JavaScript dependencies (depth ${this.options.maxDepth}, max ${this.options.maxFiles} files)...`);
    const queue = Array.from(this.jsUrls, url => ({ url, depth: 0 }));
    const visited = new Set();
    let discovered = 0;

    while (queue.length > 0 && visited.size < this.options.maxFiles) {
      const { url, depth } = queue.shift();
      if (visited.has(url) || depth > this.options.maxDepth || !/^https?:/i.test(url)) continue;
      if (!this.isCollectionScopeUrl(url)) continue;
      visited.add(url);

      let response;
      try {
        response = await this.requestWithScopedRedirects(url);
        if (response.status() < 200 || response.status() >= 300) {
          this.log(`Dependency fetch returned HTTP ${response.status()}: ${url}`);
          continue;
        }

        const headers = response.headers();
        const contentType = headers['content-type'] || '';
        if (/text\/html|application\/xhtml\+xml|application\/json/i.test(contentType)) {
          this.log(`Skipping non-JavaScript dependency response: ${response.url()}`);
          continue;
        }

        const declaredSize = Number(headers['content-length']);
        if (Number.isFinite(declaredSize) && declaredSize > this.options.maxFileSize) {
          this.log(`Skipping dependency larger than limit: ${url}`);
          continue;
        }

        const body = await response.body();
        if (body.length > this.options.maxFileSize) {
          this.log(`Skipping dependency larger than limit after download: ${url}`);
          continue;
        }
        const prefix = body.subarray(0, 512).toString('utf8').trimStart().toLowerCase();
        if (prefix.startsWith('<!doctype html') || prefix.startsWith('<html')) {
          this.log(`Skipping HTML returned for JavaScript dependency: ${response.url()}`);
          continue;
        }

        await this.discoverSourceMaps(body.toString('utf8'), response.url(), headers);

        if (depth >= this.options.maxDepth) continue;
        const references = this.extractJavaScriptReferences(body.toString('utf8'), response.url());
        for (const reference of references) {
          const wasKnown = this.jsUrls.has(reference);
          const normalized = this.recordJsUrl(reference, response.url(), 'static analysis', true);
          if (!normalized) continue;
          if (!wasKnown) discovered += 1;
          if (!visited.has(normalized)) queue.push({ url: normalized, depth: depth + 1 });
        }
      } catch (error) {
        this.log(`Could not parse dependency ${url}: ${error.message}`);
      } finally {
        if (response) await response.dispose().catch(() => {});
      }
    }

    this.metadata.recursiveParsed = visited.size;
    this.metadata.staticDiscovered = discovered;
  }

  async waitForPendingTasks() {
    while (this.pendingTasks.size > 0) {
      await Promise.allSettled([...this.pendingTasks]);
    }
  }

  clearCollectedEvidence() {
    this.jsUrls = new Set();
    this.wsJsUrls = new Set();
    this.swScripts = new Set();
    this.sourceMapUrls = new Set();
    this.sourceMapAttempts = new Set();
    this.importMap = { imports: {} };
    this.inlineArtifacts = [];
    this.inlineArtifactHashes = new Set();
    this.inlineArtifactsSkipped = 0;
    this.pageCoverage = { planned: [], visited: [], failed: [] };
    this.apiInventory?.clearObservations();
    this.metadata.redirects = [];
    this.metadata.failedRequests = [];
    this.metadata.warnings = [];
  }

  selectAuthenticatedPage(preferredPage = null) {
    const targetOrigin = new URL(this.targetUrl).origin;
    if (preferredPage && !preferredPage.isClosed()) {
      try {
        if (new URL(preferredPage.url()).origin === targetOrigin) return preferredPage;
      } catch {}
    }
    const pages = this.context.pages().filter(page => !page.isClosed());
    return [...pages].reverse().find(page => {
      try { return new URL(page.url()).origin === targetOrigin; } catch { return false; }
    }) || null;
  }

  async performInteractiveAuthentication(targetUrl) {
    if (typeof this.options.interactiveAuthHandler !== 'function') {
      throw new Error('Interactive authentication requires an interactiveAuthHandler');
    }
    const loginUrl = this.normalizeUrl(this.options.loginUrl || targetUrl, targetUrl);
    if (!loginUrl || !/^https?:/i.test(loginUrl)) throw new Error(`Invalid interactive login URL: ${this.options.loginUrl}`);

    this.log(`Opening interactive login page: ${loginUrl}`);
    try {
      await this.page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: this.options.timeout });
    } catch (error) {
      if (!this.page.url() || this.page.url() === 'about:blank') throw error;
      this.log(`Login navigation did not fully complete: ${error.message}`);
    }
    const outcome = await this.options.interactiveAuthHandler({
      page: this.page,
      context: this.context,
      loginUrl,
      targetUrl,
      collector: this,
    }) || {};
    await this.waitForPendingTasks();

    const authenticatedPage = this.selectAuthenticatedPage(outcome.page);
    if (!authenticatedPage) {
      throw new Error('No target-origin application page remained open after interactive authentication');
    }
    const confirmedUrl = authenticatedPage.url();
    const preAuth = {
      javascript_observed: this.jsUrls.size,
      api_observations: this.apiInventory?.observations.length || 0,
      redirects: [...this.metadata.redirects],
    };
    for (const page of this.context.pages()) {
      if (page !== authenticatedPage && !page.isClosed()) await page.close().catch(() => {});
    }
    this.page = authenticatedPage;
    this.page.setDefaultTimeout(this.options.timeout);
    this.clearCollectedEvidence();
    this.pageCoverage.planned.push(confirmedUrl);
    this.apiInventory?.setAuthContext({
      authenticated: true,
      identity: this.options.sessionIdentity,
      role: this.options.sessionRole,
      label: this.options.sessionLabel || 'interactive-authenticated',
    });
    this.metadata.authentication = {
      mode: 'interactive',
      login_url: loginUrl,
      confirmed_url: confirmedUrl,
      confirmed_at: new Date().toISOString(),
      saved_storage_state: outcome.savedStorageState || null,
      validation: outcome.validation || { performed: false, passed: null },
      pre_auth: preAuth,
    };
    return confirmedUrl;
  }

  async extractInlineModules(targetUrl, page = this.page) {
    this.log('Extracting module imports from inline scripts...');

    for (const frame of page.frames()) {
      try {
        const extracted = await frame.evaluate(() => ({
          baseUrl: document.baseURI,
          modules: Array.from(
            document.querySelectorAll('script:not([src]):not([type="importmap"])'),
            script => script.textContent,
          ),
          importMaps: Array.from(document.querySelectorAll('script[type="importmap"]'), script => script.textContent),
        }));

        for (const mapText of extracted.importMaps) {
          try {
            const parsed = JSON.parse(mapText);
            Object.assign(this.importMap.imports, parsed.imports || {});
          } catch (error) {
            this.log(`Ignoring invalid import map in ${extracted.baseUrl}: ${error.message}`);
          }
        }

        for (const source of extracted.modules) {
          for (const url of this.extractJavaScriptReferences(source, extracted.baseUrl || targetUrl)) {
            this.recordJsUrl(url, extracted.baseUrl || targetUrl, 'inline module', true);
          }
        }
      } catch (error) {
        this.log(`Could not inspect frame ${frame.url()}: ${error.message}`);
      }
    }
  }

  addInlineArtifact(artifact) {
    if (!artifact?.content) return;
    if (Buffer.byteLength(artifact.content) > this.options.maxInlineArtifactSize) {
      this.inlineArtifactsSkipped += 1;
      return;
    }
    const hash = crypto.createHash('sha256').update(`${artifact.kind}\0${artifact.content}`).digest('hex');
    if (this.inlineArtifactHashes.has(hash)) return;
    this.inlineArtifactHashes.add(hash);
    this.inlineArtifacts.push({ ...artifact, sha256: hash, size: Buffer.byteLength(artifact.content) });
  }

  async extractInlineArtifacts(page = this.page) {
    this.log('Collecting inline scripts and server-rendered configuration...');
    for (const frame of page.frames()) {
      try {
        const extracted = await frame.evaluate(() => {
          const scripts = Array.from(document.querySelectorAll('script:not([src])')).map((script, index) => ({
            kind: script.type === 'application/json' || script.type === 'application/ld+json'
              ? 'inline_json'
              : 'inline_script',
            index,
            content: script.textContent || '',
            script_type: script.type || 'text/javascript',
          }));
          const configuration = {
            meta: Array.from(document.querySelectorAll('meta[name], meta[property]'))
              .map(element => ({
                name: element.getAttribute('name') || element.getAttribute('property'),
                content: element.getAttribute('content'),
              }))
              .filter(item => item.content && /(?:api|endpoint|config|environment|graphql|socket|auth|csrf|token|nonce)/i.test(`${item.name} ${item.content}`)),
            data_attributes: Array.from(document.querySelectorAll('*')).flatMap(element => (
              Array.from(element.attributes || [])
                .filter(attribute => attribute.name.startsWith('data-')
                  && /(?:api|endpoint|config|environment|graphql|socket|auth|csrf|token|nonce)/i.test(`${attribute.name} ${attribute.value}`))
                .map(attribute => ({ element: element.tagName.toLowerCase(), name: attribute.name, value: attribute.value }))
            )),
          };
          return { baseUrl: document.baseURI, scripts, configuration };
        });
        for (const script of extracted.scripts) {
          this.addInlineArtifact({
            kind: script.kind,
            pageUrl: page.url(),
            frameUrl: frame.url(),
            baseUrl: extracted.baseUrl,
            index: script.index,
            contentType: script.script_type,
            content: script.content,
          });
        }
        if (extracted.configuration.meta.length || extracted.configuration.data_attributes.length) {
          this.addInlineArtifact({
            kind: 'server_rendered_config',
            pageUrl: page.url(),
            frameUrl: frame.url(),
            baseUrl: extracted.baseUrl,
            index: 0,
            contentType: 'application/json',
            content: JSON.stringify(extracted.configuration, null, 2),
          });
        }
      } catch (error) {
        this.log(`Could not collect inline artifacts from frame ${frame.url()}: ${error.message}`);
      }
    }
  }

  async extractServiceWorkers(targetUrl, page = this.page) {
    this.log('Checking for Service Worker registrations...');

    for (const frame of page.frames()) {
      try {
        const result = await frame.evaluate(() => ({
          baseUrl: document.baseURI,
          scripts: Array.from(document.querySelectorAll('script:not([src])'), script => script.textContent),
        }));
        for (const source of result.scripts) {
          const pattern = /serviceWorker\.register\s*\(\s*["']([^"']+)["']/g;
          let match;
          while ((match = pattern.exec(source)) !== null) {
            const normalized = this.recordJsUrl(match[1], result.baseUrl || targetUrl, 'service worker registration', true);
            if (normalized) this.swScripts.add(normalized);
          }
        }
      } catch (error) {
        this.log(`Could not inspect service workers in frame ${frame.url()}: ${error.message}`);
      }
    }

    for (const worker of this.context.serviceWorkers()) {
      const normalized = this.recordJsUrl(worker.url(), targetUrl, 'registered service worker', true);
      if (normalized) this.swScripts.add(normalized);
    }
  }

  async runCollectionStep(name, operation) {
    try {
      return await operation();
    } catch (error) {
      const warning = `${name} failed: ${error.message}`;
      this.metadata.warnings.push(warning);
      this.log(warning);
      return null;
    }
  }

  async extractDomScripts(page = this.page) {
    this.log('Extracting scripts and preloads from DOM frames...');
    for (const frame of page.frames()) {
      try {
        const urls = await frame.evaluate(() => [
          ...Array.from(document.querySelectorAll('script[src]'), script => script.src),
          ...Array.from(document.querySelectorAll('script[data-src]'), script => script.getAttribute('data-src')),
          ...Array.from(
            document.querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"], link[rel="prefetch"]'),
            link => link.href,
          ),
        ].filter(Boolean));
        for (const url of urls) this.recordJsUrl(url, frame.url() || page.url(), 'DOM');
      } catch (error) {
        this.log(`Could not inspect frame ${frame.url()}: ${error.message}`);
      }
    }
  }

  isSafeCrawlUrl(candidate, allowedOrigin) {
    try {
      const parsed = new URL(candidate);
      if (parsed.origin !== allowedOrigin) return false;
      if (!['http:', 'https:'].includes(parsed.protocol)) return false;
      if (/(?:^|[\/_-])(logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|revoke)(?:[\/_-]|$)/i.test(parsed.pathname)) {
        return false;
      }
      if (/\.(?:pdf|zip|gz|tar|7z|png|jpe?g|gif|svg|webp|mp4|mp3|css|json|xml|txt|csv|js|mjs|cjs|map)$/i.test(parsed.pathname)) {
        return false;
      }
      parsed.hash = '';
      return parsed.href;
    } catch (error) {
      return false;
    }
  }

  async extractCrawlLinks(page, allowedOrigin) {
    const hrefs = await page.evaluate(() => Array.from(document.querySelectorAll('a[href]'), anchor => anchor.href));
    const links = new Set();
    for (const href of hrefs) {
      const safeUrl = this.isSafeCrawlUrl(href, allowedOrigin);
      if (safeUrl) links.add(safeUrl);
    }
    return links;
  }

  async crawlSameOriginLinks() {
    if (!this.options.crawlLinks && this.options.entrypoints.length === 0) return;

    const seedUrl = this.page.url() || this.targetUrl;
    const allowedOrigin = new URL(seedUrl).origin;
    const visited = new Set([this.normalizeUrl(seedUrl, seedUrl)]);
    const explicitEntrypoints = this.options.entrypoints.map(route => this.normalizeUrl(route, allowedOrigin));
    for (const entrypoint of explicitEntrypoints) {
      if (!entrypoint || new URL(entrypoint).origin !== allowedOrigin || !this.isSafeCrawlUrl(entrypoint, allowedOrigin)) {
        throw new Error(`Entrypoint must be a safe same-origin URL: ${entrypoint || '(invalid)'}`);
      }
    }
    const discoveredLinks = this.options.crawlLinks ? await this.extractCrawlLinks(this.page, allowedOrigin) : [];
    const queue = [...explicitEntrypoints, ...discoveredLinks]
      .filter(url => !visited.has(url));

    this.pageCoverage.planned.push(...queue.filter(url => !this.pageCoverage.planned.includes(url)));

    this.log(`Crawling up to ${this.options.maxPages} same-origin links from ${allowedOrigin}...`);
    while (queue.length > 0 && visited.size - 1 < this.options.maxPages) {
      const url = queue.shift();
      if (visited.has(url)) continue;
      visited.add(url);

      const page = await this.context.newPage();
      try {
        await this.initializePage(page);
        const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: this.options.timeout });
        this.pageCoverage.visited.push({
          requested_url: url,
          final_url: page.url(),
          outcome: 'visited',
          status_code: response?.status() || null,
        });
        await page.waitForTimeout(Math.min(this.options.waitTime, 1000));
        await this.extractDomScripts(page);
        if (this.options.scrolling) await this.scrollPage(page);
        await this.triggerInteractions(page);
        await this.extractInlineModules(page.url() || url, page);
        await this.extractInlineArtifacts(page);
        await this.extractServiceWorkers(page.url() || url, page);

        for (const link of await this.extractCrawlLinks(page, allowedOrigin)) {
          if (!visited.has(link) && !queue.includes(link)) {
            queue.push(link);
            if (!this.pageCoverage.planned.includes(link)) this.pageCoverage.planned.push(link);
          }
        }
      } catch (error) {
        const warning = `Link crawl failed for ${url}: ${error.message}`;
        this.metadata.warnings.push(warning);
        this.pageCoverage.failed.push({ url, error: error.message });
        this.log(warning);
      } finally {
        await page.close();
      }
    }

    this.metadata.pagesCrawled = Math.max(0, visited.size - 1);
  }

  async collect(targetUrl) {
    this.log(`Starting collection for: ${targetUrl}`);
    this.metadata.initialUrl = targetUrl;
    this.pageCoverage.planned.push(targetUrl);

    await this.init(this.options.browser || null, targetUrl);
    await this.setupInterceptors(targetUrl);

    const collectionUrl = this.options.interactiveAuth
      ? await this.performInteractiveAuthentication(targetUrl)
      : targetUrl;

    this.log(`Navigating to collection page: ${collectionUrl}`);
    try {
      const response = await this.page.goto(collectionUrl, {
        waitUntil: 'domcontentloaded',
        timeout: this.options.timeout,
      });
      this.pageCoverage.visited.push({
        requested_url: collectionUrl,
        final_url: this.page.url(),
        outcome: 'visited',
        status_code: response?.status() || null,
      });
    } catch (error) {
      const currentUrl = this.page.url();
      const canContinue = currentUrl && currentUrl !== 'about:blank';
      if (!canContinue) throw error;

      const warning = `Navigation did not fully complete (${error.message}); continuing from ${currentUrl}`;
      this.metadata.warnings.push(warning);
      this.log(warning);
      this.pageCoverage.failed.push({ url: collectionUrl, error: error.message });
    }

    await this.runCollectionStep('Initial load wait', () => this.page.waitForTimeout(2000));
    await this.runCollectionStep('DOM script extraction', () => this.extractDomScripts());

    if (this.options.scrolling) {
      await this.runCollectionStep('Page scrolling', () => this.scrollPage());
      await this.runCollectionStep('Post-scroll wait', () => this.page.waitForTimeout(1000));
    }

    await this.runCollectionStep('Hover interactions', () => this.triggerInteractions());
    await this.runCollectionStep('Post-interaction wait', () => this.page.waitForTimeout(1000));

    const finalBaseUrl = this.page.url() || targetUrl;
    await this.runCollectionStep('Inline module extraction', () => this.extractInlineModules(finalBaseUrl));
    await this.runCollectionStep('Inline artifact collection', () => this.extractInlineArtifacts());
    await this.runCollectionStep('Service Worker extraction', () => this.extractServiceWorkers(finalBaseUrl));
    if (this.options.entrypoints.length > 0) {
      await this.crawlSameOriginLinks();
    } else {
      await this.runCollectionStep('Same-origin link crawl', () => this.crawlSameOriginLinks());
    }

    this.log('Final wait for async operations...');
    await this.runCollectionStep('Final wait', () => this.page.waitForTimeout(this.options.waitTime));
    await this.waitForPendingTasks();
    await this.runCollectionStep('Recursive dependency parsing', () => this.crawlScriptDependencies());
    await this.waitForPendingTasks();

    this.metadata.finalUrl = this.page.url();
    this.metadata.title = await this.page.title().catch(() => null);

    const authenticationRedirect = this.metadata.redirects.find(url => /(?:^|[./_-])(login|auth|oauth|okta)(?:[./?_-]|$)/i.test(url));
    if (authenticationRedirect) {
      const warning = `Authentication-related redirect observed: ${authenticationRedirect}`;
      this.metadata.warnings.push(warning);
      this.log(warning);
    }
    this.log(`Final page: ${this.metadata.finalUrl}${this.metadata.title ? ` (${this.metadata.title})` : ''}`);

    return this.getResults();
  }

  getResults() {
    return Array.from(this.jsUrls).sort();
  }

  getMetadata() {
    return {
      ...this.metadata,
      redirects: [...this.metadata.redirects],
      failedRequests: [...this.metadata.failedRequests],
      warnings: [...this.metadata.warnings],
      sourceMaps: [...this.sourceMapUrls].sort(),
      coverage: {
        pages: {
          planned: this.pageCoverage.planned.length,
          visited: this.pageCoverage.visited.length,
          failed: this.pageCoverage.failed.length,
          entrypoints: [...this.options.entrypoints],
          visits: [...this.pageCoverage.visited],
          failures: [...this.pageCoverage.failed],
        },
        assets: {
          javascript_observed: this.jsUrls.size,
          source_maps: this.sourceMapUrls.size,
          inline_artifacts: this.inlineArtifacts.length,
          inline_artifacts_skipped: this.inlineArtifactsSkipped,
          downloaded: null,
          download_failed: null,
          ai_artifacts_analyzed: null,
          ai_artifacts_skipped: null,
        },
        api: this.apiInventory ? this.apiInventory.toJSON().summary : {
          observations: 0,
          browser_observations: 0,
          imported_observations: 0,
          unique_endpoints: 0,
          websocket_connections: 0,
        },
      },
    };
  }

  getAPIInventory() {
    return this.apiInventory;
  }

  getInlineArtifacts() {
    return this.inlineArtifacts.map(item => ({ ...item }));
  }

  async close() {
    const failures = [];
    if (this.context) {
      try {
        await this.context.close();
      } catch (error) {
        failures.push(`context: ${error.message}`);
      }
      this.context = null;
      this.page = null;
    }
    if (this.browser && this._ownsBrowser) {
      try {
        await this.browser.close();
      } catch (error) {
        failures.push(`browser: ${error.message}`);
      }
      this.browser = null;
    }
    if (failures.length > 0) this.log(`Cleanup warning (${failures.join('; ')})`);
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
    this.sourceMapUrls = new Set();
    this.sourceMapAttempts = new Set();
    this.pendingTasks = new Set();
    this.initializedPages = new WeakSet();
    this.pageInitializationTasks = new WeakMap();
    this.importMap = { imports: {} };
    this.apiInventory = null;
    this.inlineArtifacts = [];
    this.inlineArtifactHashes = new Set();
    this.inlineArtifactsSkipped = 0;
    this.pageCoverage = { planned: [], visited: [], failed: [] };
    this.targetUrl = null;
    this.authDomains = [];
    this.authOrigins = [];
    this.metadata = {
      initialUrl: null,
      finalUrl: null,
      title: null,
      redirects: [],
      failedRequests: [],
      warnings: [],
      authentication: null,
    };
  }
}

class JSDownloader {
  constructor(options = {}) {
    this.options = {
      outputDir: options.outputDir || './js-files',
      timeout: options.timeout ?? 30000,
      verbose: options.verbose || false,
      headers: options.headers || {},
      headersForUrl: options.headersForUrl || null,
      userAgent: options.userAgent || `getjs/${packageVersion}`,
      maxFileSize: options.maxFileSize ?? 10 * 1024 * 1024,
      concurrency: options.concurrency ?? 5,
      ignoreHTTPSErrors: options.ignoreHTTPSErrors !== false,
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
      const hash = crypto.createHash('sha256').update(parsed.href).digest('hex').slice(0, 12);
      const original = path.basename(parsed.pathname) || 'script.js';
      const extension = path.extname(original) || '.js';
      const stem = path.basename(original, path.extname(original)) || 'script';
      const safeStem = stem.replace(/[^a-zA-Z0-9._-]/g, '_');
      const safeExtension = extension.replace(/[^a-zA-Z0-9.]/g, '_');
      const host = parsed.host.replace(/[^a-zA-Z0-9._-]/g, '_');
      return `${host}_${safeStem}_${hash}${safeExtension}`;
    } catch (e) {
      const hash = crypto.createHash('sha256').update(String(url)).digest('hex').slice(0, 16);
      return `script_${hash}.js`;
    }
  }

  getHeaders(url) {
    if (this.options.headersForUrl) return this.options.headersForUrl(url);
    return { ...this.options.headers };
  }

  validateContent(url, finalUrl, contentType, content) {
    if (content.length > this.options.maxFileSize) {
      throw new Error(`Response exceeds ${this.options.maxFileSize} byte limit for ${url}`);
    }

    const prefix = content.subarray(0, 512).toString('utf8').trimStart().toLowerCase();
    if (/text\/html|application\/xhtml\+xml/i.test(contentType) ||
        prefix.startsWith('<!doctype html') || prefix.startsWith('<html')) {
      throw new Error(`Received HTML instead of JavaScript for ${url} (final URL: ${finalUrl})`);
    }
  }

  async fetchContextResponse(url, maxRedirects = 10) {
    let currentUrl = url;
    for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount += 1) {
      const response = await this._context.request.get(currentUrl, {
        headers: this.getHeaders(currentUrl),
        timeout: this.options.timeout,
        ignoreHTTPSErrors: this.options.ignoreHTTPSErrors,
        failOnStatusCode: false,
        maxRedirects: 0,
      });
      const location = response.headers().location;
      if (response.status() < 300 || response.status() >= 400 || !location) return response;

      if (redirectCount === maxRedirects) {
        await response.dispose();
        throw new Error(`Too many redirects downloading ${url}`);
      }
      currentUrl = new URL(location, response.url()).href;
      await response.dispose();
    }
    throw new Error(`Too many redirects downloading ${url}`);
  }

  async fetchBuffer(url) {
    if (this._context) {
      const response = await this.fetchContextResponse(url);
      try {
        if (response.status() < 200 || response.status() >= 300) {
          throw new Error(`HTTP ${response.status()} for ${url}`);
        }

        const headers = response.headers();
        const declaredSize = Number(headers['content-length']);
        if (Number.isFinite(declaredSize) && declaredSize > this.options.maxFileSize) {
          throw new Error(`Response exceeds ${this.options.maxFileSize} byte limit for ${url}`);
        }

        const content = Buffer.from(await response.body());
        this.validateContent(url, response.url(), headers['content-type'] || '', content);
        return { content, finalUrl: response.url(), contentType: headers['content-type'] || '' };
      } finally {
        await response.dispose().catch(() => {});
      }
    }

    return this._downloadRaw(url, 0, this.getHeaders(url));
  }

  async downloadOne(url, outputPath = null) {
    const { content, finalUrl, contentType } = await this.fetchBuffer(url);

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
      finalUrl,
      contentType,
    };
  }

  async _downloadRaw(url, redirectCount = 0, requestHeaders = {}) {
    if (redirectCount > 10) throw new Error(`Too many redirects downloading ${url}`);

    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const protocol = parsed.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'User-Agent': this.options.userAgent,
          'Accept': '*/*',
          ...requestHeaders,
        },
        timeout: this.options.timeout,
        rejectUnauthorized: !this.options.ignoreHTTPSErrors,
      };

      const req = protocol.request(options, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, url);
          const nextHeaders = { ...requestHeaders };
          if (redirectUrl.origin !== parsed.origin) {
            for (const name of Object.keys(nextHeaders)) {
              if (/^(?:authorization|cookie|proxy-authorization|x-api-key)$/i.test(name)) delete nextHeaders[name];
            }
          }
          res.resume();
          this._downloadRaw(redirectUrl.href, redirectCount + 1, nextHeaders)
            .then(resolve)
            .catch(reject);
          return;
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }

        const declaredSize = Number(res.headers['content-length']);
        if (Number.isFinite(declaredSize) && declaredSize > this.options.maxFileSize) {
          res.resume();
          reject(new Error(`Response exceeds ${this.options.maxFileSize} byte limit for ${url}`));
          return;
        }

        const chunks = [];
        let received = 0;
        res.on('data', (chunk) => {
          received += chunk.length;
          if (received > this.options.maxFileSize) {
            res.destroy(new Error(`Response exceeds ${this.options.maxFileSize} byte limit for ${url}`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', reject);
        res.on('end', () => {
          const content = Buffer.concat(chunks);
          const contentType = res.headers['content-type'] || '';
          try {
            this.validateContent(url, url, contentType, content);
            resolve({ content, finalUrl: url, contentType });
          } catch (error) {
            reject(error);
          }
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

  async downloadAll(urls, contentDedup = false) {
    const results = new Array(urls.length);
    const errors = new Array(urls.length);
    const seenHashes = new Set();

    // Ensure output directory exists
    if (!fs.existsSync(this.options.outputDir)) {
      fs.mkdirSync(this.options.outputDir, { recursive: true });
    }

    let nextIndex = 0;
    const worker = async () => {
      while (true) {
        const index = nextIndex;
        nextIndex += 1;
        if (index >= urls.length) return;
        const url = urls[index];

        try {
          const { content, finalUrl, contentType } = await this.fetchBuffer(url);
          const contentHash = crypto.createHash('sha256').update(content).digest('hex');
          if (contentDedup && seenHashes.has(contentHash)) {
            this.log(`Skipped duplicate (same content): ${url}`);
            continue;
          }
          seenHashes.add(contentHash);

          const filename = this.sanitizeFilename(url);
          const outputPath = path.join(this.options.outputDir, filename);
          fs.writeFileSync(outputPath, content);
          this.log(`Downloaded: ${url} -> ${outputPath}`);
          results[index] = {
            url,
            finalUrl,
            contentType,
            size: content.length,
            path: outputPath,
            sha256: contentHash,
          };
        } catch (error) {
          errors[index] = { url, error: error.message };
          this.log(`Failed to download ${url}: ${error.message}`);
        }
      }
    };

    const workerCount = Math.min(this.options.concurrency, Math.max(urls.length, 1));
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    return { results: results.filter(Boolean), errors: errors.filter(Boolean) };
  }
}

module.exports = { JSCollector, JSDownloader };
