const assert = require('node:assert/strict');
const test = require('node:test');

const { JSCollector } = require('../src/collector');

test('bundle parser resolves common JavaScript references without adding non-JS imports', () => {
  const collector = new JSCollector();
  collector.importMap.imports.alias = './mapped.js';
  const references = collector.extractJavaScriptReferences(`
    import value from './one.js';
    import{two}from"./two.mjs";
    export * from './three.js';
    if (false) import('./lazy.js');
    if (false) import('./data.json');
    if (false) new Worker('./worker.js');
    import 'alias';
    const optional = '/assets/optional.js?v=1';
  `, 'https://example.com/app/main.js');

  assert.deepEqual([...references].sort(), [
    'https://example.com/app/lazy.js',
    'https://example.com/app/mapped.js',
    'https://example.com/app/one.js',
    'https://example.com/app/three.js',
    'https://example.com/app/two.mjs',
    'https://example.com/app/worker.js',
    'https://example.com/assets/optional.js?v=1',
  ]);
});
