const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { JSCollector } = require('./collector');
const { roleSignals } = require('./api-inventory');
const { writePrivateJson } = require('./secret-scanner');
const { version: GETJS_VERSION } = require('../package.json');

function loadReplayCandidates(inventoryPath, targetUrl, allSafeGet = false, maxEndpoints = 25) {
  const report = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
  const origin = new URL(targetUrl).origin;
  const candidates = [];
  const seen = new Set();
  const source = Array.isArray(report.observations) ? report.observations : [];
  for (const item of source) {
    if (!item?.url || !['GET', 'HEAD'].includes(String(item.method).toUpperCase())) continue;
    let parsed;
    try { parsed = new URL(item.url); } catch { continue; }
    if (parsed.origin !== origin || !['http:', 'https:'].includes(parsed.protocol)) continue;
    if (/(?:^|[\/_-])(logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|revoke)(?:[\/_-]|$)/i.test(parsed.pathname)) continue;
    const signals = roleSignals(parsed.href);
    if (!allSafeGet && signals.length === 0) continue;
    parsed.hash = '';
    const key = `${String(item.method).toUpperCase()} ${parsed.href}`;
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push({ method: String(item.method).toUpperCase(), url: parsed.href, role_signals: signals });
    if (candidates.length >= maxEndpoints) break;
  }
  return candidates;
}

async function responseFingerprint(response, maxBodyBytes) {
  const headers = response.headers();
  const declared = Number(headers['content-length']);
  const result = {
    status: response.status(),
    location: headers.location || null,
    content_type: headers['content-type'] || null,
    body_bytes: null,
    body_sha256: null,
    body_omitted: false,
  };
  if (Number.isFinite(declared) && declared > maxBodyBytes) {
    result.body_bytes = declared;
    result.body_omitted = true;
    return result;
  }
  try {
    const body = await response.body();
    result.body_bytes = body.length;
    if (body.length <= maxBodyBytes) result.body_sha256 = crypto.createHash('sha256').update(body).digest('hex');
    else result.body_omitted = true;
  } catch {
    result.body_omitted = true;
  }
  return result;
}

function classifyComparison(candidate, baseline, session) {
  const success = result => result && result.status >= 200 && result.status < 300;
  const denied = result => result && [401, 403].includes(result.status);
  if (success(baseline) && success(session)) {
    if (baseline.body_sha256 && baseline.body_sha256 === session.body_sha256) return 'accessible_without_authentication';
    return 'accessible_in_both_contexts';
  }
  if ((denied(baseline) || baseline?.status >= 300) && success(session)) {
    return candidate.role_signals.length > 0
      ? 'candidate_access_to_role_significant_path'
      : 'authenticated_access_only';
  }
  if (!success(baseline) && !success(session)) return 'inaccessible_in_both_contexts';
  return 'behavior_differs';
}

async function createSession(targetUrl, options) {
  const collector = new JSCollector({
    headless: true,
    timeout: options.timeout,
    scrolling: false,
    recursive: false,
    cookies: options.cookies || null,
    storageState: options.storageState || null,
    cookieDomain: new URL(targetUrl).hostname,
    headers: options.headers || {},
    authDomains: [new URL(targetUrl).hostname],
  });
  await collector.init(null, targetUrl);
  return collector;
}

async function runAuthDiff(options) {
  const targetUrl = new URL(options.url).href;
  const candidates = loadReplayCandidates(
    path.resolve(options.input),
    targetUrl,
    Boolean(options.allSafeGet),
    options.maxEndpoints,
  );
  if (candidates.length === 0) {
    throw new Error('No eligible same-origin safe GET/HEAD observations were found in the API inventory');
  }

  const baseline = await createSession(targetUrl, options.baseline || { timeout: options.timeout });
  const candidateSession = await createSession(targetUrl, options.candidate);
  const comparisons = [];
  try {
    for (const endpoint of candidates) {
      const observations = {};
      for (const [label, collector] of [['unauthenticated', baseline], ['candidate', candidateSession]]) {
        let response;
        try {
          response = await collector.context.request.fetch(endpoint.url, {
            method: endpoint.method,
            headers: collector.headersForUrl(endpoint.url),
            failOnStatusCode: false,
            maxRedirects: 0,
            timeout: options.timeout,
          });
          observations[label] = await responseFingerprint(response, options.maxBodyBytes);
        } catch (error) {
          observations[label] = { error: error.message };
        } finally {
          if (response) await response.dispose().catch(() => {});
        }
      }
      comparisons.push({
        ...endpoint,
        observations,
        classification: classifyComparison(endpoint, observations.unauthenticated, observations.candidate),
        requires_manual_authorization_review: endpoint.role_signals.length > 0
          && observations.candidate?.status >= 200 && observations.candidate?.status < 300,
      });
      if (options.delayMs > 0 && comparisons.length < candidates.length) {
        await new Promise(resolve => setTimeout(resolve, options.delayMs));
      }
    }
  } finally {
    await Promise.all([baseline.close(), candidateSession.close()]);
  }

  const report = {
    schema_version: '1.0',
    generated_at: new Date().toISOString(),
    getjs_version: GETJS_VERSION,
    target: targetUrl,
    input_inventory: path.resolve(options.input),
    safety: {
      explicit_command_required: true,
      same_origin_only: true,
      allowed_methods: ['GET', 'HEAD'],
      max_endpoints: options.maxEndpoints,
      max_body_bytes_hashed: options.maxBodyBytes,
      delay_ms_between_endpoint_pairs: options.delayMs,
      response_bodies_stored: false,
    },
    sessions: {
      baseline: { label: 'unauthenticated', authenticated: false },
      candidate: { label: options.candidate.label || 'candidate', authenticated: true },
    },
    summary: Object.fromEntries([...new Set(comparisons.map(item => item.classification))]
      .map(classification => [classification, comparisons.filter(item => item.classification === classification).length])),
    comparisons,
    limitations: [
      'A response difference is a testing lead, not proof of an authorization vulnerability.',
      'Only previously observed same-origin GET/HEAD requests were replayed; state-changing methods were excluded.',
      'Candidate identity and role are user-supplied context labels and are not independently verified.',
      'Response bodies were hashed for comparison and were not stored.',
    ],
  };
  const outputPath = path.resolve(options.output);
  writePrivateJson(outputPath, report);
  return { outputPath, report };
}

module.exports = { classifyComparison, loadReplayCandidates, runAuthDiff };
