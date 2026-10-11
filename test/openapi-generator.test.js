const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  defaultOpenAPIPath,
  generateOpenAPI,
  generateOpenAPIFile,
} = require('../src/openapi-generator');

const projectRoot = path.resolve(__dirname, '..');
const cli = path.join(projectRoot, 'bin', 'getjs.js');

function endpoint(overrides) {
  return {
    id: 'ENDP-001',
    url: '/api/users',
    url_kind: 'relative',
    base_url: null,
    transport: 'http',
    methods: ['GET'],
    parameters: [],
    request_content_types: [],
    headers: [],
    authentication: [],
    credential_mode: null,
    request_body_shape: null,
    response_clues: [],
    confidence: 'high',
    evidence_ids: ['EVID-001'],
    notes: [],
    ...overrides,
  };
}

function parameter(overrides) {
  return {
    name: 'id',
    location: 'path',
    required: true,
    inferred_type: 'identifier',
    example_or_default: null,
    description: null,
    evidence_ids: ['EVID-001'],
    ...overrides,
  };
}

function report() {
  return {
    schema_version: '1.0',
    run: {
      generated_at: '2026-10-11T00:00:00.000Z',
      getjs_version: '2.4.0',
      provider: 'codex',
      provider_version: 'test',
      model: null,
      prompt_source: 'builtin',
      prompt_sha256: 'a'.repeat(64),
      schema_sha256: 'b'.repeat(64),
      contains_unredacted_secrets: true,
    },
    target: 'https://www.example.com/start',
    executive_summary: [],
    coverage: {
      files_provided: 1,
      files_analyzed: ['app.js'],
      files_skipped: [],
      bytes_provided: 100,
      bytes_analyzed: 100,
      complete: true,
      notes: [],
    },
    evidence: [{
      id: 'EVID-001',
      file: 'app.js',
      source_url: 'https://www.example.com/app.js',
      line: 1,
      column: 1,
      byte_offset: 0,
      snippet: 'fetch("/api/users")',
      explanation: 'Test evidence.',
    }],
    inventory: {
      endpoints: [
        endpoint({
          id: 'ENDP-001',
          url: 'api/users/${userId}?expand=roles',
          url_kind: 'template',
          parameters: [parameter({ name: 'userId', inferred_type: 'integer' })],
          response_clues: ['A user object.'],
        }),
        endpoint({
          id: 'ENDP-002',
          url: '/api/users',
          methods: ['POST'],
          parameters: [parameter({
            name: 'email',
            location: 'json_body',
            inferred_type: 'string',
            example_or_default: 'user@example.com',
          })],
          request_content_types: ['application/json'],
          request_body_shape: '{ email }',
          authentication: ['Bearer token'],
        }),
        endpoint({
          id: 'ENDP-003',
          url: 'https://api.example.com/v1/items/:id',
          url_kind: 'absolute',
          methods: ['DELETE'],
          parameters: [parameter()],
        }),
        endpoint({
          id: 'ENDP-004',
          url: 'https://www.google.com/recaptcha/api.js',
          url_kind: 'absolute',
        }),
        endpoint({
          id: 'ENDP-005',
          url: '${runtimeUrl}',
          url_kind: 'dynamic',
        }),
        endpoint({ id: 'ENDP-006', url: '/api/unknown', methods: [] }),
      ],
      graphql_operations: [],
      realtime_channels: [],
      routes_and_features: [],
      data_entities: [],
      secrets: [],
      technologies: [],
      third_party_integrations: [],
    },
    findings: [],
    hunt_plan: [],
    global_limitations: ['Test limitation.'],
  };
}

test('OpenAPI generation maps inferred operations and preserves uncertainty', () => {
  const document = generateOpenAPI(report());

  assert.equal(document.openapi, '3.1.0');
  assert.equal(document.servers[0].url, 'https://www.example.com');
  const getUser = document.paths['/api/users/{userId}'].get;
  assert.equal(getUser.operationId, 'get_api_users_by_userId');
  assert.equal(getUser.parameters.find(item => item.name === 'userId').required, true);
  assert.equal(getUser.parameters.find(item => item.name === 'userId').schema.type, 'integer');
  assert.equal(getUser.parameters.find(item => item.name === 'expand').schema.example, 'roles');

  const createUser = document.paths['/api/users'].post;
  assert.equal(createUser.requestBody.content['application/json'].schema.properties.email.example, 'user@example.com');
  assert.deepEqual(createUser['x-getjs-authentication'], ['Bearer token']);

  const deleteItem = document.paths['/v1/items/{id}'].delete;
  assert.deepEqual(deleteItem.servers, [{ url: 'https://api.example.com' }]);
  assert.ok(deleteItem.parameters.every(item => typeof item.required === 'boolean'));

  assert.deepEqual(
    document['x-getjs-unresolved-endpoints'].map(item => item.reason).sort(),
    ['missing_http_method', 'outside_target_scope', 'unresolved_dynamic_url'],
  );
  assert.equal(document['x-getjs'].generated_operations, 3);
});

test('equivalent templated paths are canonicalized without invalid path parameters', () => {
  const input = report();
  input.inventory.endpoints = [
    endpoint({
      id: 'ENDP-A',
      url: '/api/orders/${data.orderId}/',
      url_kind: 'template',
      parameters: [parameter({ name: 'orderId' })],
    }),
    endpoint({
      id: 'ENDP-B',
      url: '/api/orders/${action}',
      url_kind: 'template',
      parameters: [parameter({ name: 'action' })],
    }),
  ];

  const document = generateOpenAPI(input);
  assert.deepEqual(Object.keys(document.paths), ['/api/orders/{data.orderId}']);
  const operation = document.paths['/api/orders/{data.orderId}'].get;
  assert.deepEqual(
    operation.parameters.filter(item => item.in === 'path').map(item => item.name),
    ['data.orderId'],
  );
  assert.equal(operation['x-getjs-alternatives'][0].endpoint_id, 'ENDP-B');
});

test('protocol-relative and path-bearing base URLs retain their in-scope servers and paths', () => {
  const input = report();
  input.target = 'http://www.example.com/';
  input.inventory.endpoints = [
    endpoint({ id: 'ENDP-A', url: '//api.example.com/v2/items', url_kind: 'protocol_relative' }),
    endpoint({
      id: 'ENDP-B',
      url: 'users/${id}',
      url_kind: 'template',
      base_url: 'http://api.example.com/v3',
      methods: ['POST'],
      parameters: [parameter()],
    }),
  ];

  const document = generateOpenAPI(input);
  assert.deepEqual(document.paths['/v2/items'].get.servers, [{ url: 'http://api.example.com' }]);
  assert.deepEqual(document.paths['/v3/users/{id}'].post.servers, [{ url: 'http://api.example.com' }]);
});

test('file generation validates input, writes privately, and refuses to overwrite the source', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-openapi-'));
  try {
    const input = path.join(directory, 'analysis.json');
    fs.writeFileSync(input, JSON.stringify(report()));
    const result = generateOpenAPIFile(input);
    assert.equal(result.outputPath, defaultOpenAPIPath(input));
    assert.equal(result.operations, 3);
    assert.equal(fs.statSync(result.outputPath).mode & 0o777, 0o600);
    assert.equal(JSON.parse(fs.readFileSync(result.outputPath, 'utf8')).openapi, '3.1.0');
    assert.throws(() => generateOpenAPIFile(input, input), /must not overwrite/);

    fs.writeFileSync(path.join(directory, 'invalid.json'), '{}');
    assert.throws(
      () => generateOpenAPIFile(path.join(directory, 'invalid.json')),
      /missing required field schema_version/,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('offline CLI generation succeeds without an AI executable on PATH', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'getjs-openapi-cli-'));
  try {
    const input = path.join(directory, 'analysis.json');
    const output = path.join(directory, 'openapi.json');
    fs.writeFileSync(input, JSON.stringify(report()));
    const result = spawnSync(process.execPath, [cli, 'openapi', '--input', input, '--output', output], {
      cwd: projectRoot,
      encoding: 'utf8',
      env: { ...process.env, PATH: '' },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /3 operations across 3 paths/);
    assert.ok(fs.existsSync(output));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
