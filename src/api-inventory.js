const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { writePrivateJson } = require('./secret-scanner');
const { version: GETJS_VERSION } = require('../package.json');

const ROLE_PATH_SEGMENTS = new Set(['admin', 'administrator', 'recruiter', 'staff', 'internal', 'employee', 'moderator', 'backoffice']);
const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'proxy-authorization', 'set-cookie', 'x-api-key']);

function headerNames(headers = {}) {
  return Object.keys(headers).map(name => name.toLowerCase()).sort();
}

function redactHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [
    name.toLowerCase(),
    SENSITIVE_HEADERS.has(name.toLowerCase()) ? '<redacted>' : String(value),
  ]));
}

function roleSignals(url) {
  try {
    const segments = new URL(url).pathname.toLowerCase().split('/').filter(Boolean);
    return [...new Set(segments.filter(segment => ROLE_PATH_SEGMENTS.has(segment)))];
  } catch {
    return [];
  }
}

function parseParameters(url, postData, contentType = '') {
  const parameters = [];
  try {
    for (const name of new URL(url).searchParams.keys()) {
      if (!parameters.some(item => item.location === 'query' && item.name === name)) {
        parameters.push({ name, location: 'query' });
      }
    }
  } catch {}

  if (!postData) return parameters;
  const type = String(contentType).toLowerCase();
  try {
    if (type.includes('application/json') || /^[\[{]/.test(postData.trim())) {
      const value = JSON.parse(postData);
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        Object.keys(value).forEach(name => parameters.push({ name, location: 'json_body' }));
      }
    } else if (type.includes('application/x-www-form-urlencoded')) {
      for (const name of new URLSearchParams(postData).keys()) {
        if (!parameters.some(item => item.location === 'form' && item.name === name)) {
          parameters.push({ name, location: 'form' });
        }
      }
    } else if (type.includes('multipart/form-data')) {
      const names = [...postData.matchAll(/name="([^"]+)"/g)].map(match => match[1]);
      [...new Set(names)].forEach(name => parameters.push({ name, location: 'multipart' }));
    }
  } catch {}
  return parameters;
}

function endpointKey(record) {
  try {
    const parsed = new URL(record.url);
    const queryNames = [...new Set(parsed.searchParams.keys())].sort();
    parsed.search = queryNames.map(name => `${encodeURIComponent(name)}={${name}}`).join('&');
    return `${record.transport}|${record.method}|${parsed.href}`;
  } catch {
    return `${record.transport}|${record.method}|${record.url}`;
  }
}

function summarizeEndpoint(record) {
  let templateUrl = record.url;
  try {
    const parsed = new URL(record.url);
    const names = [...new Set(parsed.searchParams.keys())].sort();
    parsed.search = '';
    names.forEach(name => parsed.searchParams.append(name, `{${name}}`));
    templateUrl = parsed.href;
  } catch {}
  return {
    id: `api-${crypto.createHash('sha256').update(endpointKey(record)).digest('hex').slice(0, 12)}`,
    url: templateUrl,
    method: record.method,
    transport: record.transport,
    parameters: record.parameters || [],
    request_content_types: record.request_content_type ? [record.request_content_type] : [],
    response_content_types: record.response_content_type ? [record.response_content_type] : [],
    request_header_names: record.request_header_names || [],
    statuses: Number.isInteger(record.status) ? [record.status] : [],
    sources: [record.source],
    pages: record.page_url ? [record.page_url] : [],
    role_signals: record.role_signals || [],
    authorization_review_recommended: (record.role_signals || []).length > 0,
    auth_contexts: record.auth_context ? [record.auth_context] : [],
    events: record.messages?.sample_event_names || [],
    message_counts: record.messages ? { sent: record.messages.sent, received: record.messages.received } : null,
    observations: 1,
  };
}

function mergeEndpoint(target, source) {
  const merge = key => { target[key] = [...new Set([...(target[key] || []), ...(source[key] || [])])]; };
  for (const key of ['request_content_types', 'response_content_types', 'request_header_names', 'statuses', 'sources', 'pages', 'role_signals', 'events']) merge(key);
  const parameterKeys = new Set(target.parameters.map(item => `${item.location}:${item.name}`));
  for (const parameter of source.parameters) {
    const key = `${parameter.location}:${parameter.name}`;
    if (!parameterKeys.has(key)) {
      target.parameters.push(parameter);
      parameterKeys.add(key);
    }
  }
  const authKeys = new Set(target.auth_contexts.map(item => JSON.stringify(item)));
  for (const context of source.auth_contexts) {
    const key = JSON.stringify(context);
    if (!authKeys.has(key)) {
      target.auth_contexts.push(context);
      authKeys.add(key);
    }
  }
  target.authorization_review_recommended ||= source.authorization_review_recommended;
  if (source.message_counts) {
    target.message_counts ||= { sent: 0, received: 0 };
    target.message_counts.sent += source.message_counts.sent;
    target.message_counts.received += source.message_counts.received;
  }
  target.observations += source.observations;
}

class APIInventory {
  constructor(targetUrl, options = {}) {
    this.targetUrl = new URL(targetUrl).href;
    this.targetOrigin = new URL(targetUrl).origin;
    this.authContext = {
      authenticated: Boolean(options.authenticated),
      identity: options.identity || null,
      role: options.role || null,
      label: options.label || (options.authenticated ? 'authenticated' : 'unauthenticated'),
    };
    this.observations = [];
    this.imported = 0;
    this.requestRecords = new WeakMap();
    this.websockets = new Map();
  }

  isSameOrigin(url) {
    try {
      const candidate = new URL(url);
      const target = new URL(this.targetUrl);
      const normalizeProtocol = protocol => ({ 'ws:': 'http:', 'wss:': 'https:' }[protocol] || protocol);
      const effectivePort = value => value.port || ({ 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443' }[value.protocol] || '');
      return normalizeProtocol(candidate.protocol) === normalizeProtocol(target.protocol)
        && candidate.hostname.toLowerCase() === target.hostname.toLowerCase()
        && effectivePort(candidate) === effectivePort(target);
    } catch { return false; }
  }

  setAuthContext(context = {}) {
    this.authContext = {
      authenticated: Boolean(context.authenticated),
      identity: context.identity || null,
      role: context.role || null,
      label: context.label || (context.authenticated ? 'authenticated' : 'unauthenticated'),
    };
  }

  clearObservations() {
    this.observations = [];
    this.imported = 0;
    this.requestRecords = new WeakMap();
    this.websockets = new Map();
  }

  add(record) {
    if (!record?.url || !this.isSameOrigin(record.url)) return null;
    const headers = record.request_headers || {};
    const contentType = record.request_content_type
      || headers['content-type']
      || headers['Content-Type']
      || null;
    const normalized = {
      observed_at: record.observed_at || new Date().toISOString(),
      source: record.source || 'browser',
      page_url: record.page_url || null,
      url: new URL(record.url).href,
      method: String(record.method || 'GET').toUpperCase(),
      transport: record.transport || 'http',
      resource_type: record.resource_type || null,
      status: Number.isInteger(record.status) ? record.status : null,
      request_content_type: contentType,
      response_content_type: record.response_content_type || null,
      request_header_names: record.request_header_names || headerNames(headers),
      response_header_names: record.response_header_names || headerNames(record.response_headers),
      parameters: record.parameters || parseParameters(record.url, record.post_data, contentType),
      role_signals: roleSignals(record.url),
      authorization_review_recommended: roleSignals(record.url).length > 0,
      auth_context: record.auth_context || this.authContext,
    };
    this.observations.push(normalized);
    if (String(normalized.source).startsWith('import:')) this.imported += 1;
    return normalized;
  }

  observeRequest(request, pageUrl = null) {
    if (!['xhr', 'fetch', 'eventsource'].includes(request.resourceType())) return;
    const record = this.add({
      source: 'browser',
      page_url: pageUrl,
      url: request.url(),
      method: request.method(),
      transport: request.resourceType() === 'eventsource' ? 'sse' : 'http',
      resource_type: request.resourceType(),
      request_headers: request.headers(),
      post_data: request.postData(),
    });
    if (record) this.requestRecords.set(request, record);
  }

  observeResponse(response) {
    const record = this.requestRecords.get(response.request());
    if (!record) return;
    record.status = response.status();
    record.response_content_type = response.headers()['content-type'] || null;
    record.response_header_names = headerNames(response.headers());
  }

  observeWebSocket(webSocket, pageUrl = null) {
    if (!this.isSameOrigin(webSocket.url())) return;
    const record = this.add({
      source: 'browser',
      page_url: pageUrl,
      url: webSocket.url(),
      method: 'GET',
      transport: 'websocket',
      resource_type: 'websocket',
    });
    if (!record) return;
    record.messages = { sent: 0, received: 0, sample_event_names: [] };
    const noteFrame = direction => event => {
      record.messages[direction] += 1;
      const text = Buffer.isBuffer(event.payload) ? event.payload.toString('utf8') : String(event.payload || '');
      if (text.length > 4096) return;
      try {
        const parsed = JSON.parse(text);
        const eventName = parsed.event || parsed.type || parsed.action || parsed.method;
        if (typeof eventName === 'string' && !record.messages.sample_event_names.includes(eventName)) {
          record.messages.sample_event_names.push(eventName);
        }
      } catch {}
    };
    webSocket.on('framesent', noteFrame('sent'));
    webSocket.on('framereceived', noteFrame('received'));
    this.websockets.set(webSocket, record);
  }

  getSummary() {
    const endpoints = [];
    const byKey = new Map();
    for (const observation of this.observations) {
      const summary = summarizeEndpoint(observation);
      const key = endpointKey(observation);
      if (byKey.has(key)) mergeEndpoint(byKey.get(key), summary);
      else {
        byKey.set(key, summary);
        endpoints.push(summary);
      }
    }
    return endpoints.sort((a, b) => a.url.localeCompare(b.url) || a.method.localeCompare(b.method));
  }

  toJSON(coverage = null) {
    return {
      schema_version: '1.0',
      generated_at: new Date().toISOString(),
      getjs_version: GETJS_VERSION,
      target: this.targetUrl,
      scope: { same_origin: this.targetOrigin },
      auth_context: this.authContext,
      coverage,
      summary: {
        observations: this.observations.length,
        browser_observations: this.observations.length - this.imported,
        imported_observations: this.imported,
        unique_endpoints: this.getSummary().length,
        websocket_connections: this.observations.filter(item => item.transport === 'websocket').length,
      },
      endpoints: this.getSummary(),
      observations: this.observations,
      limitations: [
        'This inventory contains only traffic observed or imported for the target origin; it is not a complete application route list.',
        'Authentication identity and role are user-supplied labels and are not independently verified by getjs.',
        'Sensitive request-header values and request-body values are not stored in this inventory.',
      ],
    };
  }
}

function decodeXml(value) {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

function parseRawHttpRequests(content, source, fallbackUrl = null) {
  const records = [];
  const pattern = /(?:^|\r?\n)(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)\s+HTTP\/\d(?:\.\d)?\r?\n([\s\S]*?)(?=(?:\r?\n){2}(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+\S+\s+HTTP\/|$)/gi;
  let match;
  while ((match = pattern.exec(content)) !== null) {
    const [, method, requestTarget, raw] = match;
    const split = raw.split(/\r?\n\r?\n/);
    const headerLines = split.shift().split(/\r?\n/);
    const headers = {};
    for (const line of headerLines) {
      const index = line.indexOf(':');
      if (index > 0) headers[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
    let url;
    try {
      url = new URL(requestTarget).href;
    } catch {
      const host = headers.Host || headers.host;
      if (!host && !fallbackUrl) continue;
      const scheme = fallbackUrl ? new URL(fallbackUrl).protocol : 'https:';
      url = new URL(requestTarget, host ? `${scheme}//${host}` : fallbackUrl).href;
    }
    records.push({ source, url, method, request_headers: headers, post_data: split.join('\n\n') || null });
  }
  return records;
}

function importHar(filePath) {
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!Array.isArray(parsed?.log?.entries)) throw new Error(`HAR file has no log.entries array: ${filePath}`);
  return parsed.log.entries.map(entry => ({
    source: `import:har:${path.basename(filePath)}`,
    observed_at: entry.startedDateTime || null,
    page_url: entry.pageref || null,
    url: entry.request?.url,
    method: entry.request?.method,
    request_headers: Object.fromEntries((entry.request?.headers || []).map(item => [item.name, item.value])),
    post_data: entry.request?.postData?.text || null,
    status: entry.response?.status,
    response_content_type: entry.response?.content?.mimeType || null,
    response_headers: Object.fromEntries((entry.response?.headers || []).map(item => [item.name, item.value])),
    transport: /^wss?:/i.test(entry.request?.url || '') ? 'websocket' : 'http',
  })).filter(item => item.url);
}

function importBurp(filePath, fallbackUrl = null) {
  const content = fs.readFileSync(filePath, 'utf8');
  if (!/<items(?:\s|>)/i.test(content)) {
    return parseRawHttpRequests(content, `import:burp:${path.basename(filePath)}`, fallbackUrl);
  }
  const records = [];
  for (const match of content.matchAll(/<item>([\s\S]*?)<\/item>/gi)) {
    const item = match[1];
    const urlMatch = item.match(/<url>([\s\S]*?)<\/url>/i);
    const requestMatch = item.match(/<request(?:\s+base64="(true|false)")?>([\s\S]*?)<\/request>/i);
    if (!requestMatch) continue;
    let raw = decodeXml(requestMatch[2]);
    if (requestMatch[1]?.toLowerCase() === 'true') raw = Buffer.from(raw.replace(/\s+/g, ''), 'base64').toString('utf8');
    const parsedRequests = parseRawHttpRequests(
      raw,
      `import:burp:${path.basename(filePath)}`,
      urlMatch ? decodeXml(urlMatch[1]) : fallbackUrl,
    );
    const statusMatch = item.match(/<status>(\d+)<\/status>/i);
    const mimeMatch = item.match(/<mimetype>([\s\S]*?)<\/mimetype>/i);
    for (const record of parsedRequests) {
      if (statusMatch) record.status = Number(statusMatch[1]);
      if (mimeMatch) record.response_content_type = decodeXml(mimeMatch[1]);
      records.push(record);
    }
  }
  return records;
}

function importTraffic(inventory, options = {}) {
  const failures = [];
  for (const [kind, files, importer] of [
    ['HAR', options.harFiles || [], importHar],
    ['Burp', options.burpFiles || [], file => importBurp(file, inventory.targetUrl)],
  ]) {
    for (const file of files) {
      try {
        for (const record of importer(path.resolve(file))) inventory.add(record);
      } catch (error) {
        failures.push({ type: kind, file: path.resolve(file), error: error.message });
      }
    }
  }
  return failures;
}

function writeAPIInventory(filePath, inventory, coverage = null) {
  const resolved = path.resolve(filePath);
  writePrivateJson(resolved, inventory.toJSON(coverage));
  return resolved;
}

module.exports = {
  APIInventory,
  importBurp,
  importHar,
  importTraffic,
  parseParameters,
  parseRawHttpRequests,
  redactHeaders,
  roleSignals,
  writeAPIInventory,
};
