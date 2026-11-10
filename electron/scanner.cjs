'use strict';

// Scanning engine. Pure Node, no Electron import, so it can be tested directly.
//
// Pipeline per file: read -> pick language -> strip comments (code view) ->
// run line rules -> run whole-file rules -> apply suppressions.

const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');
const { shared, categoryRules, SEVERITY_WEIGHT } = require('./rules.cjs');

const kinds = ['Website', 'Software', 'API / backend', 'Mobile app', 'Library', 'Data / ML'];

const MAX_FINDINGS = 1000;
const MAX_FILES = 6000;
const MAX_FILE_BYTES = 1024 * 1024;
const MIN_SECRET_ENTROPY = 3.0;
// These rules need literal values to distinguish safe from unsafe code, but
// still must ignore lines that are only code samples inside source strings.
const rawCodeRuleIds = new Set([
  'js-timeout-string', 'js-dynamic-require', 'py-subprocess-string',
  'py-sql-fstring', 'py-sql-percent', 'sw-env-secret-fallback', 'api-no-rate-limit',
]);

const ignoredDirs = new Set([
  '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.turbo', '.cache',
  'vendor', 'target', '.venv', 'venv', 'out', 'bin', 'obj', '.idea', '.gradle',
]);
const ignoredFiles = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'composer.lock',
  'poetry.lock', 'Cargo.lock', 'Gemfile.lock', 'go.sum', '.ds_store',
]);

const langByExt = {
  '.js': 'js', '.jsx': 'js', '.cjs': 'js', '.mjs': 'js', '.ts': 'js', '.tsx': 'js',
  '.vue': 'js', '.svelte': 'js',
  '.py': 'py',
  '.html': 'html', '.htm': 'html',
  '.css': 'css', '.scss': 'css', '.sass': 'css', '.less': 'css',
  '.json': 'json',
  '.yml': 'yaml', '.yaml': 'yaml',
  '.sh': 'sh', '.bash': 'sh', '.zsh': 'sh', '.ps1': 'sh',
  '.sql': 'sql',
};

const sourceExt = new Set(Object.keys(langByExt));

const PLACEHOLDER = /^(?:example|sample|changeme|change-me|your[-_].*|placeholder|dummy|fake|xxxx+|<.*>|\$\{.*\}|process\.env.*|os\.environ.*|password|passwd|secret|token|abc123|foo|bar|none|null)$/i;

function looksLikePlaceholder(value) {
  return PLACEHOLDER.test(value) || /^\*+$/.test(value);
}

function entropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
  let result = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    result -= p * Math.log2(p);
  }
  return result;
}

// Replace comment bodies (and optionally string contents) with spaces so code
// rules never fire on prose, while keeping every offset and line number intact.
// Quote characters survive, so rules about string usage still see the quotes.
function mask(text, lang, blankStrings) {
  if (!['js', 'py', 'css', 'sh', 'sql', 'html'].includes(lang)) return text;
  const lineMarker = lang === 'py' || lang === 'sh' ? '#' : lang === 'sql' ? '--' : lang === 'css' ? null : '//';
  const supportsBlock = lang === 'js' || lang === 'css' || lang === 'html';
  const ranges = [];
  let state = 'code';
  let quote = '';
  let commentStart = -1;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const next = text[i + 1];
    if (state === 'code') {
      if (lang !== 'html' && (char === '"' || char === "'" || char === '`')) { state = 'string'; quote = char; continue; }
      if (lineMarker && text.startsWith(lineMarker, i)) { state = 'line'; commentStart = i; continue; }
      if (lang === 'html' && text.startsWith('<!--', i)) { state = 'block'; commentStart = i; i += 3; continue; }
      if ((lang === 'js' || lang === 'css') && char === '/' && next === '*') { state = 'block'; commentStart = i; i++; continue; }
      continue;
    }
    if (state === 'string') {
      if (char === '\\') { i++; continue; }
      if (char === quote) { state = 'code'; continue; }
      continue;
    }
    if (state === 'line') {
      if (char === '\n') { ranges.push([commentStart, i]); state = 'code'; }
      continue;
    }
    if (state === 'block') {
      if (lang === 'html' && text.startsWith('-->', i)) { ranges.push([commentStart, i + 3]); state = 'code'; i += 2; continue; }
      if (lang !== 'html' && char === '*' && next === '/') { ranges.push([commentStart, i + 2]); state = 'code'; i++; }
    }
  }
  if (state === 'line') ranges.push([commentStart, text.length]);
  if (state === 'block') ranges.push([commentStart, text.length]);
  if (blankStrings || ranges.length === 0) return blankStrings ? maskCommentsThenStrings(text, lang, ranges) : text;
  const chunks = [];
  let cursor = 0;
  for (const [start, end] of ranges) {
    chunks.push(text.slice(cursor, start), text.slice(start, end).replace(/[^\n]/g, ' '));
    cursor = end;
  }
  chunks.push(text.slice(cursor));
  return chunks.join('');
}

function maskCommentsThenStrings(text, lang, ranges) {
  const chunks = [];
  let cursor = 0;
  for (const [start, end] of ranges) {
    chunks.push(text.slice(cursor, start), text.slice(start, end).replace(/[^\n]/g, ' '));
    cursor = end;
  }
  chunks.push(text.slice(cursor));
  const uncommented = chunks.join('');
  const output = [];
  let state = 'code';
  let quote = '';
  for (let i = 0; i < uncommented.length; i++) {
    const char = uncommented[i];
    if (state === 'code' && (char === '"' || char === "'" || char === '`')) { output.push(' '); state = 'string'; quote = char; continue; }
    if (state === 'string' && char === '\\') {
      output.push(' ');
      if (i + 1 < uncommented.length) output.push(uncommented[++i] === '\n' ? '\n' : ' ');
      continue;
    }
    if (state === 'string' && char === quote) { output.push(' '); state = 'code'; continue; }
    output.push(state === 'string' && char !== '\n' ? ' ' : char);
  }
  return output.join('');
}

function stripComments(text, lang, blankStrings = false) {
  return mask(text, lang, blankStrings);
}

function suppressionMap(lines) {
  const byLine = new Map();
  const fileWide = new Set();
  const allLines = { value: false };

  const add = (lineNumber, ids) => {
    const set = byLine.get(lineNumber) || new Set();
    if (!ids.length) set.add('*');
    for (const id of ids) set.add(id);
    byLine.set(lineNumber, set);
  };

  for (let i = 0; i < Math.min(lines.length, 20); i++) {
    const match = lines[i].match(/deepcheck-disable-file\b(.*)$/);
    if (!match) continue;
    const ids = match[1].replace(/[/*-]+$/, '').split(/[\s,]+/).filter(Boolean);
    if (!ids.length) allLines.value = true;
    for (const id of ids) fileWide.add(id);
  }
  lines.forEach((line, index) => {
    const next = line.match(/deepcheck-disable-next-line\b(.*)$/);
    if (next) add(index + 2, next[1].replace(/[/*-]+$/, '').split(/[\s,]+/).filter(Boolean));
    const current = line.match(/deepcheck-disable-line\b(.*)$/);
    if (current) {
      const ids = current[1].replace(/[/*-]+$/, '').trim().split(/[\s,]+/).filter(Boolean);
      add(index + 1, ids);
    }
  });
  return { byLine, fileWide, allLines };
}

function suppressed(suppressions, lineNumber, ruleId) {
  if (suppressions.allLines.value) return true;
  if (suppressions.fileWide.has(ruleId)) return true;
  const set = suppressions.byLine.get(lineNumber);
  return Boolean(set && (set.has('*') || set.has(ruleId)));
}

function globToRegExp(glob) {
  let pattern = glob.trim().replace(/\\/g, '/');
  const directoryOnly = pattern.endsWith('/');
  pattern = pattern.replace(/\/+$/, '');
  if (!pattern) return null;
  let source = '';
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === '*') {
      if (pattern[i + 1] === '*') {
        source += '.*';
        i++;
        if (pattern[i + 1] === '/') { source += '?'; i++; }
      } else source += '[^/]*';
    } else if (char === '?') {
      source += '.';
    } else if ('\\^$.|+()[]{}'.includes(char)) {
      source += `\\${char}`;
    } else {
      source += char;
    }
  }
  const prefix = pattern.includes('/') ? '^' : '(?:^|.*/)';
  const suffix = directoryOnly ? '(?:/.*)?$' : '$';
  return new RegExp(`${prefix}${source}${suffix}`);
}

async function readIgnorePatterns(root) {
  const raw = await fs.readFile(path.join(root, '.deepcheckignore'), 'utf8').catch(() => '');
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map(globToRegExp)
    .filter(Boolean);
}

function makeFinding(rule, file, line, excerpt, context = {}) {
  return {
    id: `${file}:${line}:${rule.id}`,
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    cwe: rule.cwe,
    hint: rule.hint,
    confidence: context.confidence || 'medium',
    reason: context.reason || 'Pattern match; validate the code context.',
    file,
    line,
    excerpt: String(excerpt || '').trim().slice(0, 220),
  };
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.file}:${finding.line}:${finding.ruleId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function rulesForKind(kind) {
  const all = [...shared, ...(categoryRules[kind] || [])];
  const seen = new Set();
  return all.filter((rule) => {
    if (seen.has(rule.id)) return false;
    if (rule.kinds && !rule.kinds.includes(kind)) return false;
    seen.add(rule.id);
    return true;
  });
}

function appliesTo(rule, lang) {
  if (rule.lang !== 'any' && rule.lang !== lang) return false;
  return true;
}

function secretAllowed(rule, line) {
  if (!rule.secretGroup) return true;
  const match = rule.pattern.exec(line);
  const value = match && match[rule.secretGroup];
  if (!value) return false;
  const normalized = value.replace(/^(?:sk|rk)_(?:live|test)_/, '');
  return !looksLikePlaceholder(value) && entropy(normalized) >= MIN_SECRET_ENTROPY;
}

function scoreFor(findings) {
  const penalty = findings.reduce((total, finding) => total + (SEVERITY_WEIGHT[finding.severity] || 0), 0);
  return Math.max(1, Math.round((100 * 100) / (100 + penalty)));
}

const USER_INPUT = /(?:req\.(?:body|query|params)|request\.(?:body|query|params)|searchParams\.|URLSearchParams|location\.(?:search|hash)|event\.target\.value|e\.target\.value|process\.argv|stdin|userInput|user_input|untrusted|payload|message)/i;
const INPUT_NAME = /(?:user|input|query|param|request|payload|message|comment|content|body|search|value)/i;

function evaluateTaint(lines, lang) {
  const tainted = new Set();
  const taintedAt = new Map();
  const byLine = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (lang === 'js') {
      const assignment = line.match(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;]+)/);
      if (assignment) {
        const [, name, rhs] = assignment;
        if (USER_INPUT.test(rhs) || [...tainted].some((source) => new RegExp(`\\b${source.replace(/[$]/g, '\\$')}\\b`).test(rhs))) {
          tainted.add(name);
          taintedAt.set(name, taintedAt.get(name) || i + 1);
        }
      }
    } else if (lang === 'py') {
      const assignment = line.match(/^\s*([A-Za-z_]\w*)\s*=\s*(.+)$/);
      if (assignment && USER_INPUT.test(assignment[2])) {
        tainted.add(assignment[1]);
        taintedAt.set(assignment[1], i + 1);
      }
    }
    byLine.push(new Set(tainted));
  }
  return { byLine, taintedAt };
}

function contextFor(rule, line, taintedNames) {
  const sourceMatch = USER_INPUT.test(line) || [...taintedNames].some((name) =>
    new RegExp(`\\b${name.replace(/[$]/g, '\\$')}\\b`).test(line),
  );

  if (['js-innerhtml', 'js-outerhtml', 'js-document-write', 'js-insert-adjacent-html'].includes(rule.id)) {
    const rhs = line.split(/(?:innerHTML|outerHTML)\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(/i).slice(1).join(' ');
    const staticMarkup = /^\s*["'][^"']*["']\s*\)?\s*;?\s*$/.test(rhs);
    if (staticMarkup) return { report: false };
    return { report: true, confidence: sourceMatch ? 'high' : 'medium', reason: sourceMatch ? 'Untrusted input reaches an HTML sink.' : 'Dynamic content reaches an HTML sink; source is not proven.' };
  }

  if (rule.id === 'js-react-dangerous-html') {
    if (!sourceMatch && /__html\s*:\s*["'][^"']*["']/.test(line)) return { report: false };
    return { report: true, confidence: sourceMatch ? 'high' : 'medium', reason: sourceMatch ? 'Untrusted input is rendered as HTML.' : 'HTML rendering bypasses React escaping; inspect the value.' };
  }

  if (rule.id === 'js-sql-concat' || rule.id === 'py-sql-fstring' || rule.id === 'py-sql-percent') {
    return { report: true, confidence: sourceMatch || INPUT_NAME.test(line) ? 'high' : 'medium', reason: sourceMatch ? 'User-controlled value appears in SQL construction.' : 'Dynamic SQL construction detected; verify parameter binding.' };
  }

  return { report: true, confidence: rule.severity === 'critical' || rule.severity === 'high' ? 'medium' : 'low', reason: 'Pattern match; validate the code context.' };
}

function rawMatchHasCode(rule, rawText, codeText, matchIndex, matchLength) {
  const matchEnd = matchIndex + matchLength;
  for (let i = matchIndex; i < matchEnd; i++) {
    if (codeText[i] && !/\s/.test(codeText[i])) return true;
  }
  if (['js-todo', 'js-fixme', 'js-hack', 'js-commented-code', 'py-todo'].includes(rule.id)) return true;
  if (rule.id === 'js-http-url' || rule.id === 'py-http-url') return /\b(?:fetch|requests?\.(?:get|post|put|delete)|axios|request|https?\.|url\s*\(|src\s*=|href\s*=)/i.test(codeText);
  if (rule.id === 'js-hardcoded-ip') return /\b(?:host|hostname|ip|address|endpoint)\w*\s*[:=]/i.test(codeText);
  if (rule.id === 'secret-basic-auth-url') return /\b(?:fetch|axios|request|https?\.)/i.test(codeText);
  if (rule.id.startsWith('secret-')) {
    if (/\b(?:sample|fixture|example|test)[\w$]*\s*[:=]/i.test(codeText)) return false;
    return /\b(?:key|token|secret|password|passwd|auth|credential|stripe|aws|github|slack|hook|url|database|connection)\w*\s*[:=]/i.test(codeText);
  }
  if (rule.id === 'js-sql-concat') return /\b(?:query|execute|prepare)\s*\(/i.test(codeText);
  return false;
}

function detectTestCommand(root) {
  return fs.readFile(path.join(root, 'package.json'), 'utf8').then((raw) => {
    const pkg = JSON.parse(raw);
    return pkg.scripts && pkg.scripts.test ? 'npm test' : null;
  }).catch(() => null);
}

async function scanProjectRoot(root, kind, options = {}) {
  if (!kinds.includes(kind)) throw new Error(`Unknown category "${kind}"`);
  const scanRoot = path.resolve(root);
  const catalog = rulesForKind(kind);
  const ignorePatterns = await readIgnorePatterns(scanRoot);
  const findings = [];
  const queue = [scanRoot];
  let filesScanned = 0;
  let rulesEvaluated = 0;
  let truncated = false;
  const startedAt = Date.now();

  while (queue.length && filesScanned < MAX_FILES && !truncated) {
    const dir = queue.pop();
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(scanRoot, full);
      const ignorePath = rel.replace(/\\/g, '/');
      if (entry.isDirectory()) {
        const name = entry.name.toLowerCase();
        if (ignoredDirs.has(name) || ignorePatterns.some((rx) => rx.test(ignorePath))) continue;
        queue.push(full);
        continue;
      }
      if (!entry.isFile() || ignoredFiles.has(entry.name.toLowerCase())) continue;
       if (ignorePatterns.some((rx) => rx.test(ignorePath))) continue;
      const extName = path.extname(entry.name).toLowerCase();
      if (!sourceExt.has(extName)) continue;
      let stat;
      try { stat = await fs.stat(full); } catch { continue; }
      if (stat.size > MAX_FILE_BYTES) continue;
      let raw;
      try { raw = await fs.readFile(full, 'utf8'); } catch { continue; }
      if (raw.includes('\u0000')) continue;

      const lang = langByExt[extName];
      const applicable = catalog.filter((rule) => appliesTo(rule, lang));
      const lines = raw.split(/\r?\n/);
      const commentLines = lang === 'js' || lang === 'py' || lang === 'css' || lang === 'sh' || lang === 'sql'
        ? stripComments(raw, lang).split(/\r?\n/)
        : lines;
      const codeLines = lang === 'js' || lang === 'py' || lang === 'css' || lang === 'sh' || lang === 'sql'
        ? stripComments(raw, lang, true).split(/\r?\n/)
        : lines;
      const suppressions = suppressionMap(lines);
      const taint = evaluateTaint(codeLines, lang);
      filesScanned++;
      rulesEvaluated += applicable.length;

      // CommonJS only: ESM syntax and .mjs/.ts files are strict by definition.
      if (['.js', '.cjs'].includes(extName) && !/^\s*(?:import|export)\s/m.test(raw) && !/(['"])use strict\1/.test(raw)) {
        const rule = { id: 'js-missing-strict', title: 'Missing strict mode', severity: 'low', cwe: 'CWE-710', hint: 'Add "use strict" so accidental globals throw.' };
        if (!suppressed(suppressions, 1, rule.id)) findings.push(makeFinding(rule, rel, 1, lines[0]));
      }

      for (const rule of applicable) {
        if (rule.absent && rule.absent.test(raw)) continue;
        const searchLines = rule.view === 'code'
          ? (rawCodeRuleIds.has(rule.id) ? commentLines : codeLines)
          : rule.lang === 'html' ? lines : commentLines;
        const foundLines = new Set();
        if (rule.multi) {
          const rawTextLines = lines.map((line, index) =>
            (rule.view === 'raw' || rawCodeRuleIds.has(rule.id)) && !codeLines[index].trim() ? line.replace(/[^\n]/g, ' ') : line,
          );
          const text = (rule.view === 'raw' || rawCodeRuleIds.has(rule.id) ? rawTextLines : searchLines).join('\n');
          const match = rule.pattern.exec(text);
          if (!match) continue;
          if ((rule.view === 'raw' || rawCodeRuleIds.has(rule.id)) && !rawMatchHasCode(rule, text, codeLines.join('\n'), match.index, match[0].length)) continue;
          const line = text.slice(0, match.index).split('\n').length;
          if (suppressed(suppressions, line, rule.id)) continue;
          if (rule.secretGroup) {
            const value = match[rule.secretGroup];
            const normalized = value && value.replace(/^(?:sk|rk)_(?:live|test)_/, '');
            if (!value || looksLikePlaceholder(value) || entropy(normalized) < MIN_SECRET_ENTROPY) continue;
          }
          const key = `${rel}:${line}`;
          if (foundLines.has(key)) continue;
          foundLines.add(key);
          findings.push(makeFinding(rule, rel, line, lines[line - 1]));
          if (findings.length >= MAX_FINDINGS) { truncated = true; break; }
          continue;
        }
        const rawSearchLines = rule.view === 'raw' || ['js-todo', 'js-fixme', 'js-hack', 'js-commented-code', 'py-todo'].includes(rule.id)
          ? lines
          : searchLines;
        for (let i = 0; i < rawSearchLines.length; i++) {
          const line = rawSearchLines[i];
          if (rule.exclude && rule.exclude.test(line)) continue;
          rule.pattern.lastIndex = 0;
          if (!rule.pattern.test(line)) continue;
          if (rule.view === 'raw' || rawCodeRuleIds.has(rule.id)) {
            rule.pattern.lastIndex = 0;
            const match = rule.pattern.exec(line);
            rule.pattern.lastIndex = 0;
            if (!match || !rawMatchHasCode(rule, line, codeLines[i] || '', match.index, match[0].length)) continue;
          }
          if (!secretAllowed(rule, line)) continue;
          if (suppressed(suppressions, i + 1, rule.id)) continue;
          const context = contextFor(rule, lines[i], taint.byLine[i] || new Set());
          if (!context.report) continue;
          const key = `${rel}:${i + 1}`;
          if (foundLines.has(key)) continue;
          foundLines.add(key);
          findings.push(makeFinding(rule, rel, i + 1, lines[i], context));
          if (findings.length >= MAX_FINDINGS) { truncated = true; break; }
        }
        if (truncated) break;
      }
      if (truncated) break;
    }
  }

  let testCommand = await detectTestCommand(scanRoot);
  if (!testCommand && await fs.stat(path.join(scanRoot, 'pyproject.toml')).catch(() => null)) testCommand = 'python -m pytest';
  if (!testCommand && await fs.stat(path.join(scanRoot, 'Cargo.toml')).catch(() => null)) testCommand = 'cargo test';
  if (!testCommand && await fs.stat(path.join(scanRoot, 'go.mod')).catch(() => null)) testCommand = 'go test ./...';

  const uniqueFindings = dedupeFindings(findings);
  const selected = options.maxFindings ? uniqueFindings.slice(0, options.maxFindings) : uniqueFindings;
  return {
    id: `scan-${Date.now()}`,
    projectId: null,
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    filesScanned,
    rulesEvaluated,
    rulesAvailable: catalog.length,
    languagesScanned: [...new Set([...Object.keys(langByExt)])],
    findings: selected.slice(0, MAX_FINDINGS),
    truncated: truncated || selected.length > MAX_FINDINGS,
    testCommand,
    score: scoreFor(selected),
  };
}

module.exports = {
  scanProjectRoot,
  scoreFor,
  dedupeFindings,
  rulesForKind,
  stripComments,
  entropy,
  globToRegExp,
  kinds,
  shared,
  categoryRules,
  MAX_FINDINGS,
  MAX_FILES,
  MAX_FILE_BYTES,
};
