'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { scanProjectRoot, rulesForKind, kinds } = require('../electron/scanner.cjs');

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

async function fixture(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content, 'utf8');
  }
  return root;
}

const titles = (result) => result.findings.map((f) => f.title);

const VULNERABLE_SITE = `<!doctype html>
<html>
<head>
  <title>Broken</title>
</head>
<body>
  <img src="/hero.png">
  <a href="javascript:alert(1)">bad</a>
  <a href="https://example.test" target="_blank">external</a>
  <table><tr><td>no caption</td></tr></table>
  <button onclick="go()">go</button>
  <script src="https://cdn.example.test/lib.js"></script>
  <script>var answer = 42</script>
</body>
</html>
`;

const CLEAN_SITE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Clean</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <main>
    <img src="/a.png" alt="A diagram" width="640" height="480">
    <table><caption>Prices</caption><tr><td>1</td></tr></table>
  </main>
  <script src="/app.js" defer></script>
</body>
</html>
`;

test('rule catalog is well formed and covers every category', () => {
  for (const kind of kinds) {
    const catalog = rulesForKind(kind);
    assert.ok(catalog.length >= 120, `${kind} should have a broad catalog`);
    for (const rule of catalog) {
      assert.equal(typeof rule.id, 'string');
      assert.ok(SEVERITIES.has(rule.severity));
      assert.ok(rule.pattern instanceof RegExp);
    }
  }
});

test('detects the deliberate bugs in the broken website', async () => {
  const root = await fixture({ 'index.html': VULNERABLE_SITE, 'app.js': "'use strict';\n" });
  const result = await scanProjectRoot(root, 'Website');
  const found = titles(result);

  for (const expected of [
    'Missing alt attribute',
    'JavaScript URL',
    'Target blank without rel',
    'Table without a caption',
    'Inline event handler',
    'External script without integrity',
    'Inline script',
    'Inline script',
  ]) {
    assert.ok(found.includes(expected), `expected to detect "${expected}"`);
  }
});

test('does not invent findings on clean source', async () => {
  const root = await fixture({
    'index.html': CLEAN_SITE,
    'app.js': "'use strict';\nconst total = (a, b) => a + b;\nmodule.exports = { total };\n",
    'component.tsx': 'export const Sum = ({ a, b }: { a: number; b: number }) => <span>{a + b}</span>;\n',
  });
  const result = await scanProjectRoot(root, 'Website');
  assert.ok(!result.findings.some((f) => f.severity === 'critical' || f.severity === 'high'));
  assert.ok(!titles(result).includes('Missing alt attribute'));
  assert.ok(!titles(result).includes('JavaScript URL'));
  assert.ok(!titles(result).includes('Unsafe HTML injection'));
});

test('reports the exact line a finding sits on', async () => {
  const root = await fixture({
    'app.cjs': ["'use strict';", '', '// setup', 'eval(userInput);', ''].join('\n'),
  });
  const result = await scanProjectRoot(root, 'Software');
  const finding = result.findings.find((f) => f.title === 'Dynamic code evaluation');
  assert.ok(finding, 'eval is detected');
  assert.equal(finding.line, 4);
  assert.equal(finding.excerpt, 'eval(userInput);');
});

test('skips dependencies, build output and lockfiles', async () => {
  const root = await fixture({
    'node_modules/left-pad/index.js': 'eval(hacked);\n',
    'dist/bundle.js': 'eval(hacked);\n',
    'package-lock.json': '{"scripts":{"test":"eval(hacked)"}}',
  });
  const result = await scanProjectRoot(root, 'Software');
  assert.equal(result.filesScanned, 0);
  assert.deepEqual(result.findings, []);
});

test('honors .deepcheckignore glob patterns', async () => {
  const root = await fixture({
    '.deepcheckignore': 'samples/**\n*.generated.js\n',
    'samples/broken.js': 'eval(input);\n',
    'src/broken.generated.js': 'eval(input);\n',
    'src/real.js': "'use strict';\nconst safe = true;\n",
  });
  const result = await scanProjectRoot(root, 'Software');
  assert.equal(result.filesScanned, 1); // only src/real.js remains after excludes
  assert.equal(result.findings.some((f) => f.file.includes('samples/')), false);
  assert.equal(result.findings.some((f) => f.file.includes('generated')), false);
});

test('supports file, line, and next-line rule suppressions', async () => {
  const root = await fixture({
    'file.cjs': [
      '// deepcheck-disable-file js-eval',
      'eval(fileSuppressed);',
      '// deepcheck-disable-next-line js-eval',
      'eval(nextLineSuppressed);',
      'eval(visible); // deepcheck-disable-line js-eval',
      'eval(stillVisible);',
    ].join('\n'),
    'line.cjs': [
      "'use strict';",
      '// deepcheck-disable-next-line js-eval',
      'eval(hidden);',
      'eval(visible); // deepcheck-disable-line js-eval',
      'eval(shown);',
    ].join('\n'),
  });
  const result = await scanProjectRoot(root, 'Software');
  const evalFindings = result.findings.filter((finding) => finding.ruleId === 'js-eval');
  assert.deepEqual(evalFindings.map((finding) => finding.excerpt), ['eval(shown);']);
});

test('reports provider secrets once and ignores obvious placeholders', async () => {
  const root = await fixture({
    'secrets.js': [
      "const apiKey = 'example';",
      "const apiKey = 'sk_live_9f2c8b71d4';",
      "const stripeKey = 'sk_live_9f2c8b71d4';",
    ].join('\n'),
  });
  const result = await scanProjectRoot(root, 'Software');
  assert.equal(result.findings.filter((f) => f.ruleId === 'secret-generic-credential').length, 1);
  assert.equal(result.findings.filter((f) => f.ruleId === 'secret-stripe-key').length, 0);
});

test('scanner is deterministic apart from duration and timestamp fields', async () => {
  const root = await fixture({ 'app.js': "'use strict';\neval(input);\n" });
  const first = await scanProjectRoot(root, 'Software');
  const second = await scanProjectRoot(root, 'Software');
  assert.deepEqual(first.findings, second.findings);
  assert.equal(first.filesScanned, second.filesScanned);
  assert.equal(first.rulesEvaluated, second.rulesEvaluated);
  assert.equal(first.score, second.score);
});

test('uses source-to-sink context for HTML injection confidence', async () => {
  const root = await fixture({
    'unsafe.js': [
      "'use strict';",
      'const query = new URLSearchParams(location.search).get("q");',
      'target.innerHTML = query;',
      'safe.innerHTML = "<b>Known static markup</b>";',
    ].join('\n'),
  });
  const result = await scanProjectRoot(root, 'Website');
  const htmlFindings = result.findings.filter((finding) => finding.ruleId === 'js-innerhtml');
  assert.equal(htmlFindings.length, 1);
  assert.equal(htmlFindings[0].line, 3);
  assert.equal(htmlFindings[0].confidence, 'high');
  assert.match(htmlFindings[0].reason, /untrusted input/i);
});

test('does not treat security-looking words in comments as executable code', async () => {
  const root = await fixture({
    'app.js': [
      "'use strict';",
      '// eval(userInput); this is documentation, not code',
      'const message = "eval(userInput)";',
      'console.log(message);',
    ].join('\n'),
  });
  const result = await scanProjectRoot(root, 'Software');
  assert.equal(result.findings.some((finding) => finding.ruleId === 'js-eval'), false);
});

test('does not scan JavaScript string literals as executable security issues', async () => {
  const root = await fixture({
    'samples.js': [
      "const sample = 'eval(userInput);';",
      'const sampleSecret = "const apiKey = \'sk_live_9f2c8b71d4\';";',
      "const sampleQuery = 'db.query(`SELECT * FROM users WHERE id=${userId}`);';",
    ].join('\n'),
  });
  const result = await scanProjectRoot(root, 'Software');
  assert.deepEqual(result.findings.filter((finding) =>
    ['js-eval', 'secret-generic-credential', 'js-sql-concat'].includes(finding.ruleId),
  ), []);
});

test('flags missing strict mode once per CommonJS file only', async () => {
  const root = await fixture({
    'loose.cjs': 'const a = 1;\nconst b = 2;\nconst c = 3;\n',
    'strict.cjs': "'use strict';\nconst a = 1;\n",
    'typed.ts': 'const a = 1;\n',
    'modern.mjs': 'export const a = 1;\n',
  });
  const result = await scanProjectRoot(root, 'Software');
  const strictFindings = result.findings.filter((f) => f.title === 'Missing strict mode');
  assert.equal(strictFindings.length, 1);
  assert.equal(strictFindings[0].file, 'loose.cjs');
});

test('applies category rules only to the selected category', async () => {
  const files = { 'index.html': '<button onclick="go()">go</button>\n' };
  const website = await scanProjectRoot(await fixture(files), 'Website');
  const library = await scanProjectRoot(await fixture(files), 'Library');
  assert.ok(titles(website).includes('Inline event handler'));
  assert.ok(!titles(library).includes('Inline event handler'));
});

test('caps output at 1000 findings and reports truncation', async () => {
  const root = await fixture({ 'wall.js': "eval(x);\n".repeat(1200) });
  const result = await scanProjectRoot(root, 'Software');
  assert.equal(result.findings.length, 1000);
  assert.equal(result.truncated, true);
  assert.ok(result.score >= 1, 'score never collapses to zero');
});

test('reports each rule once per line even when the catalog repeats it', async () => {
  const root = await fixture({ 'log.js': "'use strict';\nconsole.log('one value');\n" });
  const result = await scanProjectRoot(root, 'Software');
  const consoleFindings = result.findings.filter((f) => f.title === 'Console logging');
  assert.equal(consoleFindings.length, 1);
});

test('scores critical findings heavier than informational ones', async () => {
  const clean = await scanProjectRoot(await fixture({ 'a.js': "'use strict';\n" }), 'Software');
  const info = await scanProjectRoot(await fixture({ 'a.js': "'use strict';\nconsole.log(1);\n" }), 'Software');
  const critical = await scanProjectRoot(
    await fixture({ 'a.js': "'use strict';\nconst apiKey = \"super-secret-value\";\n" }),
    'Software',
  );
  assert.equal(clean.score, 100);
  assert.ok(info.score <= clean.score);
  assert.ok(critical.score < info.score);
});

test('counts every rule against every scanned file', async () => {
  const root = await fixture({ 'a.ts': 'export const a = 1;\n', 'b.ts': 'export const b = 2;\n' });
  const result = await scanProjectRoot(root, 'Library');
  assert.equal(result.filesScanned, 2);
  const distinctPerFile = rulesForKind('Library').filter((rule) => rule.lang === 'any' || rule.lang === 'js').length;
  assert.equal(result.rulesEvaluated, distinctPerFile * 2);
});

test('skips files larger than the size guard', async () => {
  const big = 'const pad = 1;\n'.repeat(80000) + 'eval(x);\n';
  const root = await fixture({ 'huge.js': "'use strict';\n" + big });
  const result = await scanProjectRoot(root, 'Software');
  assert.equal(result.filesScanned, 0);
});

// These assertions pin the scanner's real limits. If a future rule catches these,
// the test fails on purpose so the limitation list in README.md gets updated.
test('known gaps stay documented', async () => {
  const root = await fixture({
    'obfuscated.js': "'use strict';\nglobalThis['ev' + 'al'](payload);\n",
    'split-sql.py': 'query = "SELECT * FROM users WHERE id=%s" % user_id\n',
  });
  const result = await scanProjectRoot(root, 'Software');
  assert.ok(!titles(result).includes('Dynamic code evaluation'), 'obfuscated eval is not detected yet');
  assert.ok(!titles(result).includes('SQL string concatenation'), 'generic variable-built SQL without an execute call is not detected yet');
});

test('detects SQL built with template interpolation', async () => {
  const root = await fixture({
    'db.ts': 'const rows = db.query(`SELECT * FROM users WHERE id=${userId}`);\n',
  });
  const result = await scanProjectRoot(root, 'API / backend');
  assert.ok(titles(result).includes('SQL string concatenation'));
});

test('scans the DeepCheck repo itself without crashing', async () => {
  const root = path.resolve(__dirname, '..');
  const result = await scanProjectRoot(root, 'Software');
  assert.ok(result.filesScanned > 10, `expected a real repo scan, got ${result.filesScanned} files`);
  assert.ok(result.durationMs < 60000, `scan took ${result.durationMs}ms`);
  assert.ok(result.findings.every((f) => f.file && typeof f.line === 'number'));
  assert.ok(result.findings.some((f) => f.title.length > 0));
});
