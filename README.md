# DeepCheck

Windows desktop app for importing local folders or Git repositories, scanning source for bug patterns, and reviewing findings offline.

## Run

```powershell
npm install
npm run dev
```

If Electron is blocked by a Windows Application Control policy, launch the executable directly:

```powershell
Start-Process -FilePath '.\node_modules\electron\dist\electron.exe' -ArgumentList '.' -WorkingDirectory 'C:\Users\VIVOBOOK\deepcheck'
```

For Git URLs, DeepCheck clones into its local application-data folder, scans the clone, and then shows detected test commands. Test commands are never run automatically; use Run tests and confirm the prompt. If Git is missing, DeepCheck attempts to install it with winget and otherwise shows an installation link.

## What the scanner actually does

Static source checks only. No project code is executed during a scan. Rule catalog: `electron/rules.cjs`; matching, ignore handling and inline suppressions: `electron/scanner.cjs`.

Findings include a confidence label and a short explanation. For HTML sinks, the scanner tracks simple same-file JavaScript assignments from common request/browser input sources. Statically assigned HTML strings are excluded; dynamic HTML sinks are reported, with higher confidence when an input source is visible. This is deliberately shallow data-flow analysis, not a JavaScript parser or proof of exploitability.

- **Rule catalog:** 100+ stable-ID rules with CWE IDs, remediation hints, and positive/negative samples. Categories cover JavaScript/TypeScript, Python, HTML, CSS, JSON, YAML, shell, and SQL. Each category has over 120 applicable rules, but only rules matching a file's detected language are evaluated.
- **Categories:** Website, Software, API / backend, Mobile app, Library, Data / ML.
- **Rule checks:** applicable language/category rules × files scanned. This is a workload metric, not a test count.
- **Skips:** `node_modules`, `dist`, `build`, `coverage`, `.git`, `target`, `.venv`, `vendor`, lockfiles, and files over 1 MB. Scans stop at 6,000 files or 1,000 findings and set `truncated`.
- **Inline suppression:** `deepcheck-disable-file`, `deepcheck-disable-line`, and `deepcheck-disable-next-line`, optionally followed by rule IDs. `.deepcheckignore` supports simple glob patterns.
- **Secret checks:** common provider formats plus entropy-filtered generic credentials; obvious placeholders are excluded.
- **Score:** `100 × 100 / (100 + weighted penalty)`, weights critical 18, high 10, medium 4, low 1, info 0. It is a triage indicator, not a quality guarantee.

## Proving it works

```powershell
npm test
```

`npm test` runs over 340 assertions against the real scanner. `tests/rules.test.cjs` generates positive and negative tests for every rule; `tests/scanner.test.cjs` covers end-to-end behavior, source-to-sink context, comment handling, suppressions, secrets, ignore globs and repeatability:

| Test | What it proves |
| --- | --- |
| Per-rule positive/negative samples | Each catalog rule catches its intentionally bad sample and ignores its good sample |
| Detects broken website bugs | Injected bugs are reported by name |
| Clean-source regressions | Clean source has no critical/high findings and no known unsafe patterns |
| Exact line reporting | A finding reports the line and excerpt it came from |
| Skips dependencies and lockfiles | `node_modules`, `dist`, lock content is not scanned |
| Strict mode once per CommonJS file | One finding per file, not per line; ESM and TS are exempt |
| Category scoping | Website-only rules do not fire for other categories |
| Finding cap | Output caps at 1,000 with `truncated` set |
| Deduplication | Repeated catalog entries report once per line |
| Score weighting | critical < info < clean, and the score has a floor |
| Language-aware rule accounting | `rulesEvaluated` equals applicable language rules × files |
| Size guard | Files over 1 MB are skipped |
| Known gaps | Obfuscated calls and context-dependent data flow are not claimed as detected |
| SQL template injection | Backtick SQL with `${}` is detected |
| Self-scan | The repo scans end to end without crashing |

Command-line audit, same engine the UI uses:

```powershell
npm run audit -- C:\path\to\project "Website"
```

## Known limits (read before trusting a result)

1. **Heuristic, not proof.** A finding means a pattern matched. It does not confirm exploitability. Treat critical/high as "inspect this first", not "this is exploitable".
2. **False negatives are real.** Obfuscated calls (`globalThis['ev'+'al']`), `%`/`.format` SQL building, framework-specific sinks, and cross-file data flow are not modelled.
3. **False positives exist.** Rules run per line without knowing the language or framework. `console.log` in a build script, `var` in generated code, and test fixtures containing sample bugs all get reported.
4. **Test fixtures count.** If a repo stores deliberately broken sample files, they are scanned and reported like production code.
5. **No real test execution in a scan.** Detected test commands run only after you confirm the prompt.
6. **Binary and generated files** are skipped by extension, size, or ignore list.

## UI registry and MCP

`components.json` registers React Bits as `@react-bits`. The SplitText component was added with:

```powershell
npx shadcn@latest add @react-bits/SplitText-JS-CSS
```

`opencode.json` enables the shadcn MCP server. Restart OpenCode from this project directory to load it.

## Design credit

UI design guidance adapted from [unslop](https://github.com/heydamir/unslop) by Damir Sokolovsky, licensed CC BY 4.0.
