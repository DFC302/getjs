const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const psl = require('psl');

const { version: GETJS_VERSION } = require('../package.json');
const { BUILTIN_SCHEMA_PATH, validateAgainstSchema } = require('./ai-analyzer');
const { writePrivateJson } = require('./secret-scanner');

const HTTP_METHODS = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']);
const PARAMETER_LOCATIONS = new Set(['path', 'query', 'header', 'cookie']);
const BODY_LOCATIONS = new Set(['json_body', 'form', 'multipart']);

function unique(values) {
  return [...new Set((values || []).filter(value => value !== null && value !== undefined && value !== ''))];
}

function targetDetails(target) {
  try {
    const parsed = new URL(target);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('unsupported protocol');
    return {
      origin: parsed.origin,
      protocol: parsed.protocol,
      hostname: parsed.hostname.toLowerCase(),
      registrableDomain: psl.get(parsed.hostname.toLowerCase()) || parsed.hostname.toLowerCase(),
    };
  } catch (error) {
    throw new Error(`AI report target must be an absolute HTTP(S) URL: ${target}`);
  }
}

function scopeForHostname(hostname, target) {
  const normalized = String(hostname || '').toLowerCase();
  const registrable = psl.get(normalized) || normalized;
  return registrable === target.registrableDomain;
}

function cleanTemplateName(value, fallback = 'value') {
  const cleaned = String(value || '')
    .replace(/^\$?\{\{?\s*|\s*\}\}?$/g, '')
    .replace(/[^A-Za-z0-9_.-]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return cleaned || fallback;
}

function normalizeTemplates(value) {
  return String(value || '')
    .replace(/\$\{([^{}]+)\}/g, (_, name) => `{${cleanTemplateName(name)}}`)
    .replace(/\{\{\s*([^{}]+?)\s*\}\}/g, (_, name) => `{${cleanTemplateName(name)}}`)
    .replace(/(^|\/)\:([A-Za-z_][A-Za-z0-9_.-]*)(?=\/|$|\?)/g, '$1{$2}');
}

function splitPathAndQuery(value) {
  const withoutFragment = value.split('#', 1)[0];
  const queryIndex = withoutFragment.indexOf('?');
  return queryIndex === -1
    ? { pathname: withoutFragment, query: '' }
    : { pathname: withoutFragment.slice(0, queryIndex), query: withoutFragment.slice(queryIndex + 1) };
}

function queryParameters(query, evidenceIds) {
  if (!query) return [];
  return query.split('&').filter(Boolean).map((part, index) => {
    const equals = part.indexOf('=');
    const rawName = equals === -1 ? part : part.slice(0, equals);
    const rawValue = equals === -1 ? '' : part.slice(equals + 1);
    let decodedName = rawName;
    let decodedValue = rawValue;
    try { decodedName = decodeURIComponent(rawName); } catch {}
    try { decodedValue = decodeURIComponent(rawValue); } catch {}
    const template = decodedValue.match(/^\{([^{}]+)\}$/);
    return {
      name: cleanTemplateName(decodedName, `query${index + 1}`),
      location: 'query',
      required: false,
      inferred_type: 'string',
      example_or_default: template || decodedValue === '' ? null : decodedValue,
      description: template ? `Value inferred from template ${decodedValue}.` : null,
      evidence_ids: evidenceIds,
    };
  });
}

function endpointLocation(endpoint, target) {
  const original = normalizeTemplates(endpoint.url).trim();
  if (!original) return { reason: 'empty_url' };
  if (endpoint.url_kind === 'dynamic' && /^\{[^{}]+\}(?:\?.*)?$/.test(original)) {
    return { reason: 'unresolved_dynamic_url' };
  }
  if (/\{[^{}]*[()][^{}]*\}/.test(String(endpoint.url))) {
    return { reason: 'unresolved_dynamic_path' };
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(original) && !/^https?:\/\//i.test(original)) {
    return { reason: 'non_http_url' };
  }

  let rawPath = original;
  let server = target.origin;
  let hostname = target.hostname;
  const absolute = original.match(/^(https?):\/\/([^/]+)(.*)$/i);
  const protocolRelative = original.match(/^\/\/([^/]+)(.*)$/);
  if (absolute || protocolRelative) {
    const authority = absolute ? absolute[2] : protocolRelative[1];
    rawPath = (absolute ? absolute[3] : protocolRelative[2]) || '/';
    if (authority.includes('{') || authority.includes('}')) return { reason: 'dynamic_host' };
    try {
      const parsed = new URL(`${absolute ? `${absolute[1]}:` : target.protocol}//${authority}`);
      hostname = parsed.hostname.toLowerCase();
      server = parsed.origin;
    } catch {
      return { reason: 'invalid_absolute_url' };
    }
  } else if (endpoint.base_url) {
    const normalizedBase = normalizeTemplates(endpoint.base_url);
    if (normalizedBase.includes('{') || normalizedBase.includes('}')) return { reason: 'dynamic_base_url' };
    try {
      const parsed = new URL(normalizedBase, target.origin);
      hostname = parsed.hostname.toLowerCase();
      server = parsed.origin;
      if (!rawPath.startsWith('/')) {
        const base = parsed.href.endsWith('/') ? parsed.href : `${parsed.href}/`;
        const resolved = new URL(rawPath.replace(/\{/g, '__GETJS_OPEN__').replace(/\}/g, '__GETJS_CLOSE__'), base);
        rawPath = `${resolved.pathname}${resolved.search}`
          .replace(/__GETJS_OPEN__/g, '{')
          .replace(/__GETJS_CLOSE__/g, '}');
      }
    } catch {
      return { reason: 'invalid_base_url' };
    }
  }

  if (!scopeForHostname(hostname, target)) {
    return { reason: 'outside_target_scope', server };
  }

  const split = splitPathAndQuery(rawPath);
  let pathname = split.pathname.trim();
  if (!pathname || pathname === '.') pathname = '/';
  if (!pathname.startsWith('/')) pathname = `/${pathname}`;
  pathname = pathname.replace(/\/+/g, '/');
  if (pathname.length > 1) pathname = pathname.replace(/\/+$/, '');
  if (/\{[^{}]*[()\/][^{}]*\}/.test(pathname) || /\$\{|\{\{/.test(pathname)) {
    return { reason: 'unresolved_dynamic_path', server };
  }
  if (/\s/.test(pathname)) return { reason: 'invalid_path_whitespace', server };

  return {
    path: pathname,
    server: server === target.origin ? null : server,
    queryParameters: queryParameters(split.query, endpoint.evidence_ids || []),
  };
}

function schemaForType(inferredType, example = null) {
  const normalized = String(inferredType || '').trim().toLowerCase();
  let schema;
  if (['integer', 'int', 'int32', 'int64', 'long'].includes(normalized)) schema = { type: 'integer' };
  else if (['number', 'float', 'double', 'decimal'].includes(normalized)) schema = { type: 'number' };
  else if (['boolean', 'bool'].includes(normalized)) schema = { type: 'boolean' };
  else if (normalized.includes('file') || normalized.includes('blob') || normalized === 'binary') {
    schema = { type: 'string', format: 'binary' };
  } else if (normalized.includes('array') || normalized.endsWith('[]')) schema = { type: 'array', items: {} };
  else if (['object', 'json', 'map', 'dictionary'].includes(normalized)) schema = { type: 'object' };
  else schema = { type: 'string' };

  if (example !== null && example !== undefined && example !== '') {
    let converted = example;
    if (schema.type === 'boolean' && /^(true|false)$/i.test(example)) converted = example.toLowerCase() === 'true';
    if (schema.type === 'integer' && /^-?\d+$/.test(example)) converted = Number.parseInt(example, 10);
    if (schema.type === 'number' && /^-?(?:\d+\.?\d*|\.\d+)$/.test(example)) converted = Number(example);
    schema.example = converted;
  }
  if (inferredType && normalized && schema.type === 'string' && normalized !== 'string' && normalized !== 'identifier') {
    schema['x-getjs-inferred-type'] = inferredType;
  }
  return schema;
}

function parameterObject(parameter, forceRequired = false) {
  const location = parameter.location;
  const result = {
    name: cleanTemplateName(parameter.name),
    in: location,
    required: location === 'path' ? true : forceRequired || parameter.required === true,
    schema: schemaForType(parameter.inferred_type, parameter.example_or_default),
    'x-getjs-evidence': unique(parameter.evidence_ids),
  };
  if (parameter.description) result.description = parameter.description;
  return result;
}

function dedupeParameters(parameters) {
  const byKey = new Map();
  for (const parameter of parameters) {
    const key = `${parameter.in}\0${parameter.name}`;
    const current = byKey.get(key);
    if (!current) {
      byKey.set(key, parameter);
      continue;
    }
    current.required ||= parameter.required;
    current['x-getjs-evidence'] = unique([
      ...(current['x-getjs-evidence'] || []),
      ...(parameter['x-getjs-evidence'] || []),
    ]);
    if (!current.description && parameter.description) current.description = parameter.description;
  }
  return [...byKey.values()].sort((a, b) => `${a.in}:${a.name}`.localeCompare(`${b.in}:${b.name}`));
}

function requestBody(parameters, endpoint) {
  const byLocation = new Map();
  for (const parameter of parameters.filter(item => BODY_LOCATIONS.has(item.location))) {
    if (!byLocation.has(parameter.location)) byLocation.set(parameter.location, []);
    byLocation.get(parameter.location).push(parameter);
  }
  if (byLocation.size === 0 && !endpoint.request_body_shape && endpoint.request_content_types.length === 0) return null;

  const content = {};
  const mappings = [
    ['json_body', 'application/json'],
    ['form', 'application/x-www-form-urlencoded'],
    ['multipart', 'multipart/form-data'],
  ];
  for (const [location, mediaType] of mappings) {
    const fields = byLocation.get(location);
    if (!fields) continue;
    const properties = {};
    const required = [];
    for (const field of fields) {
      const name = cleanTemplateName(field.name);
      properties[name] = schemaForType(field.inferred_type, field.example_or_default);
      if (field.description) properties[name].description = field.description;
      properties[name]['x-getjs-evidence'] = unique(field.evidence_ids);
      if (field.required === true) required.push(name);
    }
    content[mediaType] = { schema: { type: 'object', properties } };
    if (required.length > 0) content[mediaType].schema.required = unique(required);
  }

  if (Object.keys(content).length === 0) {
    const types = endpoint.request_content_types.length > 0
      ? endpoint.request_content_types
      : ['application/json'];
    for (const mediaType of types) content[mediaType] = { schema: { type: 'object' } };
  }
  const result = {
    required: parameters.some(parameter => BODY_LOCATIONS.has(parameter.location) && parameter.required === true),
    content,
  };
  if (endpoint.request_body_shape) {
    result.description = endpoint.request_body_shape;
    result['x-getjs-inferred-shape'] = endpoint.request_body_shape;
  }
  return result;
}

function operationId(method, openapiPath, used) {
  const base = `${method}_${openapiPath}`
    .replace(/\{([^{}]+)\}/g, 'by_$1')
    .replace(/[^A-Za-z0-9_]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '') || method;
  let candidate = base;
  let suffix = 2;
  while (used.has(candidate)) {
    candidate = `${base}_${suffix}`;
    suffix += 1;
  }
  used.add(candidate);
  return candidate;
}

function tagForPath(openapiPath) {
  const segments = openapiPath.split('/').filter(Boolean);
  const staticSegment = segment => !segment.includes('{') && !segment.includes('}');
  if (segments[0]?.toLowerCase() === 'api') {
    if (segments[1]?.toLowerCase() === 'admin' && segments[2] && staticSegment(segments[2])) {
      return `admin / ${segments[2]}`;
    }
    if (segments[1] && staticSegment(segments[1])) return segments[1];
  }
  return segments.find(staticSegment) || 'dynamic endpoints';
}

function buildOperation(endpoint, method, location, usedOperationIds) {
  const targetPathNames = [...location.path.matchAll(/\{([^{}]+)\}/g)].map(match => cleanTemplateName(match[1]));
  const sourcePathNames = [...(location.sourcePath || location.path).matchAll(/\{([^{}]+)\}/g)]
    .map(match => cleanTemplateName(match[1]));
  const mappedPathParameters = [];
  const unmappedPathParameters = [];
  for (const parameter of endpoint.parameters.filter(item => item.location === 'path')) {
    const name = cleanTemplateName(parameter.name);
    let sourceIndex = sourcePathNames.indexOf(name);
    if (sourceIndex === -1) {
      sourceIndex = sourcePathNames.findIndex(candidate => (
        candidate.endsWith(`.${name}`) || candidate.endsWith(`_${name}`)
      ));
    }
    if (sourceIndex === -1 && sourcePathNames.length === 1) sourceIndex = 0;
    if (sourceIndex === -1 || !targetPathNames[sourceIndex]) {
      unmappedPathParameters.push(parameter);
      continue;
    }
    mappedPathParameters.push({ ...parameter, name: targetPathNames[sourceIndex] });
  }
  const parameters = [
    ...endpoint.parameters.filter(parameter => PARAMETER_LOCATIONS.has(parameter.location) && parameter.location !== 'path'),
    ...mappedPathParameters,
    ...location.queryParameters,
  ].map(parameter => parameterObject(parameter));
  const existingPathNames = new Set(
    parameters.filter(parameter => parameter.in === 'path').map(parameter => parameter.name),
  );
  for (const match of location.path.matchAll(/\{([^{}]+)\}/g)) {
    const name = cleanTemplateName(match[1]);
    if (!existingPathNames.has(name)) {
      parameters.push(parameterObject({
        name,
        location: 'path',
        required: true,
        inferred_type: 'string',
        example_or_default: null,
        description: 'Path parameter inferred from the endpoint template.',
        evidence_ids: endpoint.evidence_ids,
      }));
    }
  }

  const responseDescription = endpoint.response_clues.length > 0
    ? endpoint.response_clues.join(' ')
    : 'Response inferred from client-side JavaScript; status and schema were not established.';
  const operation = {
    operationId: operationId(method, location.path, usedOperationIds),
    summary: `${method.toUpperCase()} ${location.path} (inferred)`,
    tags: [tagForPath(location.path)],
    parameters: dedupeParameters(parameters),
    responses: { default: { description: responseDescription } },
    'x-getjs-endpoint-id': endpoint.id,
    'x-getjs-original-url': endpoint.url,
    'x-getjs-url-kind': endpoint.url_kind,
    'x-getjs-transport': endpoint.transport,
    'x-getjs-confidence': endpoint.confidence,
    'x-getjs-evidence': unique(endpoint.evidence_ids),
    'x-getjs-authentication': unique(endpoint.authentication),
    'x-getjs-credential-mode': endpoint.credential_mode,
    'x-getjs-headers': unique(endpoint.headers),
    'x-getjs-notes': unique(endpoint.notes),
  };
  if (location.sourcePath && location.sourcePath !== location.path) {
    operation['x-getjs-source-path'] = location.sourcePath;
  }
  if (unmappedPathParameters.length > 0) {
    operation['x-getjs-unmapped-path-parameters'] = unmappedPathParameters;
  }
  if (parameters.length === 0) delete operation.parameters;
  const body = requestBody(endpoint.parameters, endpoint);
  if (body && !['get', 'head', 'trace'].includes(method)) operation.requestBody = body;
  if (location.server !== null) operation.servers = [{ url: location.server }];
  return operation;
}

function unresolvedRecord(endpoint, reason, methods = endpoint.methods) {
  return {
    id: endpoint.id,
    url: endpoint.url,
    methods: unique(methods),
    transport: endpoint.transport,
    reason,
    confidence: endpoint.confidence,
    evidence_ids: unique(endpoint.evidence_ids),
    notes: unique(endpoint.notes),
  };
}

function mergeOperation(existing, incoming, endpoint) {
  existing.parameters = dedupeParameters([...(existing.parameters || []), ...(incoming.parameters || [])]);
  if (existing.parameters.length === 0) delete existing.parameters;
  existing['x-getjs-evidence'] = unique([
    ...(existing['x-getjs-evidence'] || []),
    ...(incoming['x-getjs-evidence'] || []),
  ]);
  existing['x-getjs-alternatives'] = [
    ...(existing['x-getjs-alternatives'] || []),
    {
      endpoint_id: endpoint.id,
      original_url: endpoint.url,
      source_path: incoming['x-getjs-source-path'] || null,
      confidence: endpoint.confidence,
      evidence_ids: unique(endpoint.evidence_ids),
      authentication: unique(endpoint.authentication),
      credential_mode: endpoint.credential_mode,
      request_body_shape: endpoint.request_body_shape,
      response_clues: unique(endpoint.response_clues),
      notes: unique(endpoint.notes),
    },
  ];
}

function generateOpenAPI(report, options = {}) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('AI analysis report must be a JSON object');
  }
  if (!report.inventory || !Array.isArray(report.inventory.endpoints)) {
    throw new Error('AI analysis report must contain inventory.endpoints');
  }
  const target = targetDetails(report.target);
  const paths = {};
  const canonicalPaths = new Map();
  const unresolved = [];
  const tags = new Set();
  const usedOperationIds = new Set();
  let operations = 0;

  for (const endpoint of report.inventory.endpoints) {
    const location = endpointLocation(endpoint, target);
    if (!location.path) {
      unresolved.push(unresolvedRecord(endpoint, location.reason));
      continue;
    }
    const validMethods = unique(endpoint.methods.map(method => String(method).toLowerCase()))
      .filter(method => HTTP_METHODS.has(method));
    const invalidMethods = unique(endpoint.methods.map(method => String(method).toUpperCase()))
      .filter(method => !HTTP_METHODS.has(method.toLowerCase()));
    if (invalidMethods.length > 0) unresolved.push(unresolvedRecord(endpoint, 'unsupported_http_method', invalidMethods));
    if (validMethods.length === 0) {
      if (invalidMethods.length === 0) unresolved.push(unresolvedRecord(endpoint, 'missing_http_method'));
      continue;
    }

    const pathSignature = location.path.replace(/\{[^{}]+\}/g, '{}');
    const canonicalPath = canonicalPaths.get(pathSignature);
    if (canonicalPath) {
      location.sourcePath = location.path;
      location.path = canonicalPath;
    } else {
      canonicalPaths.set(pathSignature, location.path);
    }

    if (!paths[location.path]) paths[location.path] = {};
    for (const method of validMethods) {
      const operation = buildOperation(endpoint, method, location, usedOperationIds);
      operation.tags.forEach(tag => tags.add(tag));
      if (paths[location.path][method]) mergeOperation(paths[location.path][method], operation, endpoint);
      else {
        paths[location.path][method] = operation;
        operations += 1;
      }
    }
  }

  const title = options.title || `getjs inferred API: ${target.hostname}`;
  return {
    openapi: '3.1.0',
    info: {
      title,
      version: report.run?.getjs_version || GETJS_VERSION,
      description: 'Inferred from client-side JavaScript by getjs. Treat this as reconnaissance data, not server-authoritative API documentation.',
    },
    servers: [{ url: target.origin }],
    tags: [...tags].sort().map(name => ({ name })),
    paths: Object.fromEntries(Object.entries(paths).sort(([left], [right]) => left.localeCompare(right))),
    'x-getjs': {
      generator_version: GETJS_VERSION,
      source_schema_version: report.schema_version,
      source_target: report.target,
      source_generated_at: report.run?.generated_at || null,
      source_provider: report.run?.provider || null,
      coverage: report.coverage,
      generated_operations: operations,
      unresolved_endpoints: unresolved.length,
      limitations: unique([
        'Paths, methods, parameters, bodies, authentication, and response clues are inferred from client-side code and may be incomplete or unreachable.',
        ...(report.global_limitations || []),
      ]),
    },
    'x-getjs-unresolved-endpoints': unresolved,
  };
}

function defaultOpenAPIPath(inputPath) {
  const resolved = path.resolve(inputPath);
  return resolved.toLowerCase().endsWith('.json')
    ? `${resolved.slice(0, -5)}.openapi.json`
    : `${resolved}.openapi.json`;
}

function defaultSwaggerHTMLPath(openapiPath) {
  const resolved = path.resolve(openapiPath);
  return resolved.toLowerCase().endsWith('.json')
    ? `${resolved.slice(0, -5)}.html`
    : `${resolved}.html`;
}

function writePrivateText(filePath, content) {
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, content);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    try {
      fs.renameSync(temporary, filePath);
    } catch (error) {
      if (process.platform !== 'win32' || !['EEXIST', 'EPERM'].includes(error.code)) throw error;
      fs.rmSync(filePath, { force: true });
      fs.renameSync(temporary, filePath);
    }
    fs.chmodSync(filePath, 0o600);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
  }
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeJsonForHtml(value) {
  return JSON.stringify(value)
    .replace(/&/g, '\\u0026')
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function escapeInlineAsset(value, closingTag) {
  return value.replace(new RegExp(`</${closingTag}`, 'gi'), `<\\/${closingTag}`);
}

function readSwaggerAssets() {
  let bundlePath;
  let cssPath;
  try {
    bundlePath = require.resolve('swagger-ui-dist/swagger-ui-bundle.js');
    cssPath = require.resolve('swagger-ui-dist/swagger-ui.css');
  } catch (error) {
    throw new Error(`Unable to load the bundled Swagger UI assets: ${error.message}`);
  }
  return {
    bundle: fs.readFileSync(bundlePath, 'utf8'),
    css: fs.readFileSync(cssPath, 'utf8'),
  };
}

function renderSwaggerHTML(document, options = {}) {
  if (!document || document.openapi !== '3.1.0' || !document.paths) {
    throw new Error('Swagger UI generation requires a generated OpenAPI 3.1 document');
  }
  const allowTryItOut = options.tryItOut === true;
  const assets = options.assets || readSwaggerAssets();
  const title = document.info?.title || 'getjs inferred API';
  const modeText = allowTryItOut
    ? 'Live requests are enabled. Confirm authorization and scope before sending any request.'
    : 'Read-only mode. Live requests are disabled; regenerate with --swagger-try-it-out to enable them.';
  const modeClass = allowTryItOut ? 'live' : 'readonly';
  const connectSource = allowTryItOut ? 'https: http:' : "'none'";
  const methods = allowTryItOut
    ? '["get","put","post","delete","options","head","patch","trace"]'
    : '[]';
  const spec = escapeJsonForHtml(document);
  const css = escapeInlineAsset(assets.css, 'style');
  const bundle = escapeInlineAsset(assets.bundle, 'script');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src ${connectSource}; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>${escapeHtml(title)} — Swagger UI</title>
  <style>${css}
    html { box-sizing: border-box; overflow-y: scroll; }
    body { margin: 0; background: #fafafa; }
    .getjs-notice { position: sticky; top: 0; z-index: 1000; padding: 10px 18px; border-bottom: 1px solid #c7d2fe; background: #eef2ff; color: #1e1b4b; font: 600 13px/1.45 system-ui, sans-serif; }
    .getjs-notice.live { border-color: #f59e0b; background: #fffbeb; color: #78350f; }
    .getjs-notice code { font-weight: 700; }
  </style>
</head>
<body>
  <div class="getjs-notice ${modeClass}"><strong>getjs inferred API:</strong> ${escapeHtml(modeText)}</div>
  <div id="swagger-ui"></div>
  <script type="application/json" id="getjs-openapi">${spec}</script>
  <script>${bundle}</script>
  <script>
    (() => {
      'use strict';
      const spec = JSON.parse(document.getElementById('getjs-openapi').textContent);
      window.ui = SwaggerUIBundle({
        spec,
        dom_id: '#swagger-ui',
        deepLinking: true,
        filter: true,
        displayOperationId: true,
        displayRequestDuration: true,
        docExpansion: 'list',
        persistAuthorization: false,
        showExtensions: true,
        showCommonExtensions: true,
        tryItOutEnabled: false,
        supportedSubmitMethods: ${methods},
        validatorUrl: null,
        queryConfigEnabled: false,
        presets: [SwaggerUIBundle.presets.apis]
      });
    })();
  </script>
</body>
</html>
`;
}

function generateSwaggerUIFile(document, outputPath, options = {}) {
  const resolvedOutput = path.resolve(outputPath);
  const html = renderSwaggerHTML(document, options);
  writePrivateText(resolvedOutput, html);
  return {
    outputPath: resolvedOutput,
    tryItOut: options.tryItOut === true,
    bytes: Buffer.byteLength(html),
  };
}

function generateOpenAPIFile(inputPath, outputPath = null, options = {}) {
  const resolvedInput = path.resolve(inputPath);
  let report;
  try {
    report = JSON.parse(fs.readFileSync(resolvedInput, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to read AI analysis report ${resolvedInput}: ${error.message}`);
  }
  const schema = JSON.parse(fs.readFileSync(BUILTIN_SCHEMA_PATH, 'utf8'));
  validateAgainstSchema(report, schema, schema);
  const document = generateOpenAPI(report, options);
  const resolvedOutput = path.resolve(outputPath || defaultOpenAPIPath(resolvedInput));
  if (resolvedOutput === resolvedInput) throw new Error('OpenAPI output must not overwrite the source AI analysis report');
  const resolvedHtml = options.htmlPath ? path.resolve(options.htmlPath) : null;
  if (resolvedHtml && [resolvedInput, resolvedOutput].includes(resolvedHtml)) {
    throw new Error('Swagger UI output must not overwrite the source report or OpenAPI document');
  }
  const swaggerHtml = resolvedHtml
    ? renderSwaggerHTML(document, { tryItOut: options.tryItOut })
    : null;
  writePrivateJson(resolvedOutput, document);
  let swaggerUI = null;
  if (resolvedHtml && swaggerHtml) {
    writePrivateText(resolvedHtml, swaggerHtml);
    swaggerUI = {
      outputPath: resolvedHtml,
      tryItOut: options.tryItOut === true,
      bytes: Buffer.byteLength(swaggerHtml),
    };
  }
  return {
    inputPath: resolvedInput,
    outputPath: resolvedOutput,
    paths: Object.keys(document.paths).length,
    operations: document['x-getjs'].generated_operations,
    unresolved: document['x-getjs'].unresolved_endpoints,
    ...(swaggerUI && { swaggerUI }),
  };
}

module.exports = {
  defaultOpenAPIPath,
  defaultSwaggerHTMLPath,
  endpointLocation,
  generateOpenAPI,
  generateOpenAPIFile,
  generateSwaggerUIFile,
  normalizeTemplates,
  renderSwaggerHTML,
  schemaForType,
};
