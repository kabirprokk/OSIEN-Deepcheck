'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { parseVerdict, getSourceContext, verifyFinding, reviewFindings, MODEL } = require('../electron/ai-review.cjs');

test('validates supported JSON verdicts and bounds fields', () => {
  const parsed = parseVerdict(JSON.stringify({ verdict: 'likely_real', confidence: 150, rationale: 'Evidence found', evidence: 'line 2' }));
  assert.equal(parsed.verdict, 'likely_real');
  assert.equal(parsed.confidence, 100);
  assert.equal(parsed.evidence, 'line 2');
  const fractional = parseVerdict('{"verdict":"uncertain","confidence":0.75,"rationale":"Limited context","evidence":["line 1","line 2"]}');
  assert.equal(fractional.confidence, 50);
  assert.equal(fractional.evidence, 'line 1; line 2');
  assert.throws(() => parseVerdict('{"verdict":"maybe","rationale":"x"}'), /unsupported verdict/);
  assert.throws(() => parseVerdict('{"verdict":"uncertain"}'), /no explanation/);
});

test('source context cannot escape project via traversal or symlink', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ai-'));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-out-'));
  t.after(() => Promise.all([fs.rm(root, { recursive: true, force: true }), fs.rm(outside, { recursive: true, force: true })]));
  await fs.writeFile(path.join(root, 'app.js'), 'one\ntwo\nthree');
  await fs.writeFile(path.join(outside, 'secret.js'), 'secret');
  assert.match((await getSourceContext(root, 'app.js', 2)).context, /2: two/);
  await assert.rejects(getSourceContext(root, path.relative(root, path.join(outside, 'secret.js')), 1), /outside/);
  try {
    await fs.symlink(path.join(outside, 'secret.js'), path.join(root, 'linked.js'));
    await assert.rejects(getSourceContext(root, 'linked.js', 1), /outside/);
  } catch (error) {
    if (error.code !== 'EPERM' && error.code !== 'ENOTSUP') throw error;
  }
});

test('sends a local CPU-only Ollama request and parses response', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ai-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'app.js'), 'const value = input;');
  let request;
  const result = await verifyFinding(root, { file: 'app.js', line: 1, title: 'Unsafe input' }, {
    fetch: async (url, init) => {
      request = { url, body: JSON.parse(init.body) };
      return { ok: true, json: async () => ({ message: { content: '{"verdict":"uncertain","confidence":55,"rationale":"Context is limited"}' } }) };
    },
  });
  assert.equal(request.url, 'http://127.0.0.1:11434/api/chat');
  assert.equal(request.body.model, MODEL);
  assert.equal(request.body.options.num_gpu, 0);
  assert.equal(request.body.options.temperature, 0);
  assert.equal(request.body.think, false);
  assert.equal(result.verdict, 'uncertain');
  assert.equal(result.confidence, 50);
});

test('automatically reviews findings in separate fresh, snippet-only requests', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ai-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = Array.from({ length: 20 }, (_, index) => `const line${index + 1} = 1;`);
  source[0] = 'const firstMarker = 1;';
  source[19] = 'const secondMarker = 2;';
  await fs.writeFile(path.join(root, 'app.js'), source.join('\n'));
  const findings = [
    { file: 'app.js', line: 1, title: 'First finding', excerpt: source[0] },
    { file: 'app.js', line: 20, title: 'Second finding', excerpt: source[19] },
  ];
  const requests = [];
  const summary = await reviewFindings(root, findings, {
    fetch: async (_url, init) => {
      const body = JSON.parse(init.body);
      requests.push(body);
      return { ok: true, json: async () => ({ message: { content: '{"verdict":"uncertain","confidence":99,"rationale":"Not confirmed from this snippet."}' } }) };
    },
  });
  assert.deepEqual(summary, { reviewed: 2, failed: 0 });
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request.messages.length === 2));
  assert.match(requests[0].messages[1].content, /firstMarker/);
  assert.doesNotMatch(requests[0].messages[1].content, /secondMarker/);
  assert.match(requests[1].messages[1].content, /secondMarker/);
  assert.doesNotMatch(requests[1].messages[1].content, /firstMarker/);
  assert.ok(findings.every((finding) => finding.aiAssessment.confidence === 50));
});
