'use strict';

// Every rule in the catalog is exercised against its own samples through the
// real scanner. A rule without samples, a dead pattern, or a pattern that fires
// on its clean counterpart fails the build.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { shared, categoryRules, SEVERITIES } = require('../electron/rules.cjs');
const { scanProjectRoot, rulesForKind, kinds } = require('../electron/scanner.cjs');

const FILE_FOR_LANG = {
  js: 'sample.js',
  py: 'sample.py',
  html: 'sample.html',
  css: 'sample.css',
  json: 'sample.json',
  yaml: 'sample.yml',
  sh: 'sample.sh',
  sql: 'sample.sql',
  any: 'sample.js',
};

const allRules = [...shared];
const categoryOf = new Map();
for (const kind of kinds) {
  for (const rule of categoryRules[kind] || []) {
    allRules.push(rule);
    if (!categoryOf.has(rule.id)) categoryOf.set(rule.id, kind);
  }
}

async function scanSample(sample, lang, kind) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-rule-'));
  await fs.writeFile(path.join(root, FILE_FOR_LANG[lang]), `${sample}\n`, 'utf8');
  return scanProjectRoot(root, kind);
}

test('catalog: every rule carries full metadata and samples', () => {
  const ids = new Set();
  for (const rule of allRules) {
    assert.equal(typeof rule.id, 'string', 'rule has an id');
    assert.ok(!ids.has(rule.id), `duplicate rule id ${rule.id}`);
    ids.add(rule.id);
    assert.ok(rule.title.length > 3, `${rule.id} has a title`);
    assert.ok(SEVERITIES.includes(rule.severity), `${rule.id} severity is ${rule.severity}`);
    assert.match(rule.cwe, /^CWE-\d+$/, `${rule.id} has a CWE id`);
    assert.ok(rule.hint && rule.hint.length > 10, `${rule.id} has a remediation hint`);
    assert.ok(FILE_FOR_LANG[rule.lang], `${rule.id} declares a known language`);
    assert.ok(rule.pattern instanceof RegExp, `${rule.id} pattern is a RegExp`);
    assert.ok(typeof rule.bad === 'string' && rule.bad.length > 0, `${rule.id} has a positive sample`);
    assert.ok(typeof rule.good === 'string' && rule.good.length > 0, `${rule.id} has a negative sample`);
    assert.ok(rule.bad !== rule.good, `${rule.id} samples differ`);
    assert.doesNotThrow(() => rule.pattern.test('sample text'), `${rule.id} regex runs`);
  }
  assert.ok(allRules.length >= 130, `expected a large catalog, got ${allRules.length}`);
});

test('catalog: each category evaluates a large rule set', () => {
  for (const kind of kinds) {
    const count = rulesForKind(kind).length;
    assert.ok(count >= 120, `${kind} evaluates ${count} rules`);
  }
});

// One generated test per rule so a failure names the exact rule.
for (const rule of allRules) {
  const kind = rule.kinds ? rule.kinds[0] : (categoryOf.get(rule.id) || 'Software');
  test(`rule ${rule.id}: fires on its positive sample`, async () => {
    const result = await scanSample(rule.bad, rule.lang, kind);
    const hit = result.findings.find((finding) => finding.ruleId === rule.id);
    assert.ok(hit, `${rule.id} did not flag: ${JSON.stringify(rule.bad)}`);
    assert.equal(hit.severity, rule.severity);
    assert.ok(hit.line >= 1);
  });

  test(`rule ${rule.id}: silent on its negative sample`, async () => {
    const result = await scanSample(rule.good, rule.lang, kind);
    const hit = result.findings.find((finding) => finding.ruleId === rule.id);
    assert.ok(!hit, `${rule.id} false positive on: ${JSON.stringify(rule.good)}`);
  });
}
