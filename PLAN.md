# SPC (Space Proof Code) — Full Project Improvement Plan

## Overview

**Project**: `@putervision/spc` — Zero-dependency static analysis tool enforcing NASA Power of Ten rules across 20 programming languages.
**Target Release**: v1.3.0 (bumping by +0.1.0 from 1.2.0)
**Goal**: Improve performance, security, code quality, documentation, website, and distribution for the v1.3.0 release.

**Recommended Approach**: Execute phases sequentially (Critical → High → Medium). Each phase is independently verifiable. Steps marked `[parallel]` can run concurrently.

---

## Phase 1 — Critical Fixes & Version Bump (Block Next Release)

### 1.0 Version Bump to 1.3.0 Across All Configs & Docs

**Files**:
- `package.json` (`"version": "1.3.0"`)
- `package-lock.json` (`"version": "1.3.0"` in root and packages)
- `lib/formatter.js` (default parameter `VERSION = '1.3.0'`)
- `README.md` (update release tag links to `1.3.0`)
- `SECURITY.md` (add `| v1.3.x  | :white_check_mark: |` to supported version table)
- `docs/index.html` (update release badge to `RELEASE v1.3.0`)

**Verification**:
```bash
grep -rn "1.3.0" package.json lib/formatter.js docs/index.html SECURITY.md README.md
node bin/cli.js --version # should output spc v1.3.0
```

---

### 1.1 Complete README & API Documentation

**File**: `README.md` (Note: Base README sections and Security Rules are present, now adding Programmatic API usage & Rule Coverage Table)

**What to do**:
1. Add **Programmatic Usage & API Reference** section detailing `scanCodebase()` usage.
2. Add **Rule Coverage by Language** matrix table covering all 20 supported languages.
3. Update tag links from `1.2.0` to `1.3.0`.
4. Verify table of contents links match headers.

**Verification**:
- `node bin/cli.js --help` — version matches README
- Verify API examples run successfully via Node script.

---

### 1.2 Remove `null` Patterns from Language Configs

**Files**: All 20 files in `lib/lang/`

**Problem**: Several patterns are set to `null` (e.g., Fortran `try_catch`, Ada `unrestricted_cors`, Haskell `unrestricted_cors`). When `scanner.js` iterates with `Object.entries(langConfig.patterns)`, `null` values cause `content.matchAll(null)` to throw a `TypeError`.

**What to do**:
1. In each language file, find all pattern values set to `null`
2. **Remove** those key-value pairs entirely from the `patterns` object (do not leave `null` values)
3. Specifically check these files:
   - `fortran.js` — `try_catch: null`, `network_call: null`, `unrestricted_cors: null`
   - `ada.js` — `unrestricted_cors: null`
   - `haskell.js` — `unrestricted_cors: null`
   - `scala.js` — `unrestricted_cors: null`
   - `swift.js` — `unrestricted_cors: null`
   - `ruby.js` — `unrestricted_cors: null`
   - `kotlin.js` — `unrestricted_cors: null`
   - `elixir.js` — no nulls expected, but verify
   - `julia.js` — no nulls expected, but verify
   - `zig.js` — no nulls expected, but verify
   - `lua.js` — no nulls expected, but verify
   - `php.js` — no nulls expected, but verify
   - `ruby.js` — no nulls expected, but verify
   - `bash.js` — no nulls expected, but verify
   - `c.js` — no nulls expected, but verify
   - `cs.js` — no nulls expected, but verify
   - `go.js` — no nulls expected, but verify
   - `java.js` — no nulls expected, but verify
   - `javascript.js` — no nulls expected, but verify
   - `python.js` — no nulls expected, but verify
   - `rust.js` — no nulls expected, but verify

**Verification**:
```bash
# This should not throw any errors
node -e "const s = require('./lib/scanner'); s.scanCodebase('./lib').then(r => console.log('OK:', r.length, 'files'));"
```
- Run `npm test` — all existing tests pass
- Scan a Fortran file: `node bin/cli.js ./test/examples/bad_example.f90` — should complete without TypeError

---

### 1.3 Add `files` Field to package.json

**File**: `package.json`

**Problem**: The npm package will include everything (tests, `.git/`, `.agents/`, `.cursor/`, `.state-memory-mcp/`, `.vision-memory-mcp/`, `.vscode/`, `node_modules/`, etc.), bloating the published package.

**What to do**:
Add a `"files"` array to `package.json` that explicitly lists what to publish:
```json
"files": [
  "bin/",
  "lib/",
  "docs/",
  "LICENSE",
  "README.md"
]
```

**Verification**:
```bash
npm pack --dry-run
```
- Output should only show `bin/`, `lib/`, `docs/`, `LICENSE`, `README.md`
- Should NOT show `test/`, `.git/`, `.agents/`, `.cursor/`, `.vscode/`, `.state-memory-mcp/`, `.vision-memory-mcp/`

---

### 1.4 Add `checksums.sha256.txt` to `.gitignore`

**File**: `.gitignore`

**Problem**: `checksums.sha256.txt` is a generated artifact that should never be version-controlled. It is currently present in the workspace root and likely committed.

**What to do**:
Add to `.gitignore`:
```
checksums.sha256.txt
```

**Verification**:
```bash
git status checksums.sha256.txt
```
- Should show the file as untracked (if not already committed) or staged for deletion (if already committed)
- If already committed, run: `git rm --cached checksums.sha256.txt`

---

### 1.5 Fix `multiple_returns` Regex for Nested Braces

**Files**: All 20 language files in `lib/lang/`

**Problem**: The `multiple_returns` pattern uses `[^}]*` to match between returns, which breaks when functions contain nested braces (e.g., inner functions, objects, strings with `}`).

**Examples of broken patterns**:
- JavaScript: `/function\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g`
- C: `/\w+\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g`
- Java: `/public\s+\w+\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g`
- Go: `/func\s+\w+\s*\([^)]*\)\s*\w+\s*\{[^}]*return[^}]*return/g`
- Rust: `/fn\s+\w+\s*\([^)]*\)\s*->\s*\w+\s*\{[^}]*return[^}]*return/g`

**What to do**:
Replace the `[^}]*return[^}]*return` pattern with a more robust approach. Since we cannot use an AST parser (zero-dependency constraint), use a two-pass approach:

1. **Option A (preferred)**: Change the regex to match across multiple lines with a simpler pattern:
   ```
   /function\s+\w+\s*\([^)]*\)\s*{[\s\S]*?return[\s\S]*?return/g
   ```
   This uses `[\s\S]*?` (non-greedy, matches any character including newlines) instead of `[^}]*`.

2. **Option B**: Keep the current regex but add a comment noting the limitation and that it may miss returns in functions with nested braces.

Apply this fix to ALL 20 language files. The pattern varies per language but the principle is the same.

**Verification**:
Create a test file with a function containing nested braces and multiple returns:
```javascript
function test(x) {
  if (x) {
    const obj = { a: 1 };
    return 1;
  }
  return 0;
}
```
Run: `node bin/cli.js <test-file>` — should detect `multiple_returns`

---

## Phase 2 — High Priority Improvements

### 2.1 Expand Test Coverage

**File**: `test/scanner.test.js` (currently has only 3 tests)

**What to do**: Add comprehensive tests for:

1. **Formatter tests** (add a new file `test/formatter.test.js`):
   - `formatResults` with `format: 'json'` — verify valid JSON output with correct structure
   - `formatResults` with `format: 'md'` — verify Markdown table structure
   - `formatResults` with `format: 'table'` — verify returns `null`
   - Test with empty results array
   - Test with multiple files and issues

2. **Scanner tests** (add to `test/scanner.test.js`):
   - `.spcignore` file loading — create a temp `.spcignore` and verify files are excluded
   - Inline suppression (`spc-disable-line`) — verify suppressed issues are filtered
   - Checksum mismatch detection — create a checksums file with a wrong hash
   - Checksum creation (`createSums: true`) — verify checksums file is generated
   - Language detection — verify correct language is identified for each extension
   - Path traversal prevention — verify symlink escapes are blocked
   - `analyzeFile` for each language — test at least 2 patterns per language

3. **CLI tests** (add a new file `test/cli.test.js`):
   - Argument parsing: `--format json`, `-o output.json`, `--max-severity 4`, `--fail-on-issue`, `--create-sums`, `--help`, `--version`
   - Invalid directory handling
   - Output file writing

4. **Pattern validation** (add a new file `test/patterns.test.js`):
   - Verify all 20 language configs have required fields (`extensions`, `patterns`, `function_regex`, `ignore_functions`, `critical_functions`, `void_return_indicator`)
   - Verify no pattern value is `null`
   - Verify all regex patterns compile without error
   - Verify all pattern keys exist in `PATTERN_INFO`

**Verification**:
```bash
npm test
npm run test:coverage
```
- Target: >80% coverage on `lib/scanner.js`, `lib/formatter.js`, `bin/cli.js`
- All tests pass

---

### 2.2 Add `--exclude` CLI Flag

**File**: `bin/cli.js` and `lib/scanner.js`

**What to do**:
1. In `cli.js`, add argument parsing for `--exclude <pattern>`:
   ```javascript
   if (arg === '--exclude') {
     const pattern = args[++i];
     if (pattern) extraExcludes.push(pattern);
     continue;
   }
   ```
2. Pass `extraExcludes` through to `scanCodebase()` in `scanner.js`
3. Merge with `IGNORE_PATTERNS_DEFAULT` and `.spcignore` rules in `scanCodebase()`

**Verification**:
```bash
node bin/cli.js . --exclude node_modules --format json | head -20
```
- Should not include any files from `node_modules/`

---

### 2.3 Add GitHub Actions CI/CD Workflow

**File**: `.github/workflows/ci.yml` (create new)

**What to do**:
Create a GitHub Actions workflow that:
1. Triggers on: `push`, `pull_request` to `main` and `develop` branches
2. Jobs:
   - **Test**: Run on `ubuntu-latest` with Node.js 18, 20, 22 (matrix)
     - `npm ci`
     - `npm test`
     - `npm run format:check`
   - **Scan Self**: Run `node bin/cli.js ./lib ./bin` to verify the tool works on its own codebase
   - **Lint**: Run ESLint (after adding ESLint in step 2.4)

**Verification**:
- Push a commit to trigger the workflow
- Verify all jobs pass in GitHub Actions UI
- Verify the workflow file is valid YAML: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`

---

### 2.4 Add ESLint Configuration

**Files to create/modify**:
- `package.json` — add `eslint` and related packages to `devDependencies`, add `lint` script
- `.eslintrc.json` (create new) — ESLint configuration

**What to do**:
1. Add to `package.json` `devDependencies`:
   ```json
   "eslint": "^8.56.0",
   "eslint-config-prettier": "^9.1.0"
   ```
2. Add to `package.json` `scripts`:
   ```json
   "lint": "eslint \"**/*.js\"",
   "lint:fix": "eslint \"**/*.js\" --fix"
   ```
3. Create `.eslintrc.json`:
   ```json
   {
     "env": {
       "node": true,
       "es2022": true,
       "jest": true
     },
     "extends": ["eslint:recommended", "prettier"],
     "parserOptions": {
       "ecmaVersion": 2022,
       "sourceType": "module"
     },
     "rules": {
       "no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
       "no-console": "off",
       "strict": ["error", "global"]
     }
   }
   ```

**Verification**:
```bash
npm run lint
```
- Should report zero errors (or only pre-existing warnings that can be fixed)
- Run `npm run lint:fix` to auto-fix any fixable issues

---

### 2.5 Complete the Website

**File**: `docs/index.html` (currently truncated mid-element)

**What to do**:
1. **Complete the truncated HTML** — the file cuts off at `<div class="feature-icon">⚙️</div>`. Add the remaining content:
   - Complete the features grid (add the 5th feature card for "CI/CD Integration")
   - Add the **Languages Section** (`#languages`) — a grid showing all 20 supported languages with icons/names
   - Add the **Rules Section** (`#rules`) — expandable cards for each rule (performance + security)
   - Add the **Quickstart Section** (`#quickstart`) — installation commands, usage examples, CI/CD snippets
   - Add the **Security & Legal Section** (`#security`) — license info, zero-dependency statement, contact
   - Add a **Footer** — copyright, links to GitHub, npm, PuterVision

2. **Add missing assets**:
   - Verify `spc-icon.png` and `putervision-icon.png` exist in `docs/`
   - If missing, create placeholder SVG icons or note they need to be added

3. **Add Open Graph / Twitter Card meta tags** (in `<head>`):
   ```html
   <meta property="og:title" content="Space Proof Code (SPC)">
   <meta property="og:description" content="Zero-dependency static analysis tool enforcing NASA Power of Ten rules across 20 languages.">
   <meta property="og:type" content="website">
   <meta property="og:url" content="https://putervision.com">
   <meta name="twitter:card" content="summary_large_image">
   ```

4. **Add structured data (JSON-LD)** (in `<head>`):
   ```html
   <script type="application/ld+json">
   {
     "@context": "https://schema.org",
     "@type": "SoftwareApplication",
     "name": "Space Proof Code",
     "applicationCategory": "DeveloperApplication",
     "operatingSystem": "Any",
     "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" }
   }
   </script>
   ```

5. **Accessibility audit**:
   - Verify contrast ratios meet WCAG 2.1 AA (use a tool like axe DevTools or Lighthouse)
   - Add `aria-label` attributes to navigation links
   - Ensure all images have descriptive `alt` text
   - Add skip-to-content link

**Verification**:
- Open `docs/index.html` in a browser — page should render completely with no missing sections
- Run `npx pa11y docs/index.html` (or manual Lighthouse audit) — no critical accessibility errors
- Social share preview should show correct title, description, and image

---

### 2.6 Document Security Rules in README

**File**: `README.md`

**What to do**:
Add a new "Security Rules" section after the "Performance and Reliability Rules" section. For each security rule, follow the same format as existing rules:

1. **unsafe_input** (severity 4)
   - Description: Detects unvalidated user inputs that could lead to injection attacks
   - Examples per language (C: `scanf`, Python: `sys.argv`, JS: `req.body`)
   - Remedy: Validate/sanitize all inputs
   - Reference: OWASP Top 10

2. **network_call** (severity 3)
   - Description: Detects network calls that could be entry points for untrusted data
   - Examples: `fetch()`, `requests.get()`, `socket()`
   - Remedy: Validate destinations, use TLS

3. **weak_crypto** (severity 4)
   - Description: Detects weak cryptographic functions (MD5, SHA1, Math.random)
   - Examples: `md5()`, `hashlib.md5()`, `Math.random()`
   - Remedy: Use SHA-256+, `crypto.randomBytes()`

4. **unsafe_file_op** (severity 3)
   - Description: Detects file operations without error handling
   - Examples: `fs.readFile()`, `fopen()`, `open()`
   - Remedy: Always check return values, use try-catch

5. **insufficient_logging** (severity 2)
   - Description: Detects endpoints/functions without logging
   - Examples: Express routes without `console.log`/`logger`
   - Remedy: Add logging to all entry points

6. **unsanitized_exec** (severity 5)
   - Description: Detects command execution with unsanitized user input
   - Examples: `exec(\`cmd ${input}\`)`, `system(input)`
   - Remedy: Use parameterized commands, avoid shell injection

7. **exposed_secrets** (severity 5)
   - Description: Detects hardcoded secrets, keys, passwords in source code
   - Examples: `const apiKey = "xyz123"`, `password = "admin"`
   - Remedy: Use environment variables, secret managers

8. **unrestricted_cors** (severity 4)
   - Description: Detects CORS configurations allowing all origins
   - Examples: `cors({ origin: "*" })`
   - Remedy: Restrict to known domains

9. **import_risk** (severity 3, Python only)
   - Description: Wildcard imports that pollute namespace
   - Example: `from os import *`
   - Remedy: Explicit imports

10. **checksum_mismatch** (severity 4)
    - Description: File content does not match stored checksum
    - Remedy: Verify file integrity

11. **unchecked_func_return_crit** (severity 4)
    - Description: Unchecked return from security-critical functions
    - Remedy: Always check returns from critical functions

---

### 2.7 Add Programmatic API Documentation

**File**: `README.md` — add a new "Programmatic Usage" section

**What to do**:
Add documentation for using SPC as a library (not just CLI):

```markdown
## Programmatic Usage

You can use SPC as a library in your own Node.js projects:

```javascript
const { scanCodebase } = require('@putervision/spc/lib/scanner');

async function analyze(codePath) {
  const results = await scanCodebase(codePath, false, []);
  results.forEach(({ file, language, issues }) => {
    console.log(`${file} (${language}): ${issues.length} issues`);
  });
}

analyze('./my-project').catch(console.error);
```

### API Reference

#### `scanCodebase(directory, createSums, ignorePatterns)`

- `directory` (string): Path to the codebase to scan
- `createSums` (boolean, optional): Whether to generate a checksums file (default: `false`)
- `ignorePatterns` (string[], optional): Additional patterns to ignore (default: `[]`)
- Returns: `Promise<Array<{file, relativePath, language, issues}>>`

Each issue object contains:
- `message` (string): Description of the issue
- `issueType` (string): Rule identifier (e.g., `recursion`, `unbounded_loops`)
- `lineNum` (number|null): Line number where the issue was found
```

**Verification**:
- Create a test script that imports `scanCodebase` and runs it
- Verify the API returns the documented structure

---

## Phase 3 — Medium Priority Improvements

### 3.1 Add `.spc.config.json` Configuration File Support

**Files to create/modify**:
- `lib/config.js` (create new) — configuration loading and validation
- `lib/scanner.js` — integrate config loading
- `bin/cli.js` — add `--config` flag
- `README.md` — document the config file format

**What to do**:
1. Create `lib/config.js`:
   ```javascript
   const fs = require('fs').promises;
   const path = require('path');

   const DEFAULT_CONFIG = {
     maxFunctionLines: 60,
     rules: {}, // { ruleName: { enabled: true, severity: 4 } }
     ignorePatterns: [],
   };

   async function loadConfig(directory) {
     const configPath = path.join(directory, '.spc.config.json');
     try {
       const content = await fs.readFile(configPath, 'utf-8');
       const userConfig = JSON.parse(content);
       return { ...DEFAULT_CONFIG, ...userConfig };
     } catch {
       return DEFAULT_CONFIG;
     }
   }

   module.exports = { loadConfig };
   ```

2. Add `--config <path>` flag to `cli.js` to specify a custom config location

3. Document the config format in README:
   ```json
   {
     "maxFunctionLines": 50,
     "rules": {
       "recursion": { "enabled": true, "severity": 4 },
       "exposed_secrets": { "enabled": false }
     },
     "ignorePatterns": ["vendor/", "third-party/"]
   }
   ```

**Verification**:
```bash
# Create a test config
echo '{"maxFunctionLines": 30}' > .spc.config.json
node bin/cli.js . --format json | grep maxFunctionLines
# Should reflect the custom value
```

---

### 3.2 Add Progress Indicator

**File**: `bin/cli.js`

**What to do**:
1. Add `--verbose` / `-v` flag (note: `-v` is currently used for `--version`; rename version to `--version` only, or use `-V`)
2. Add `--progress` flag that prints files as they are scanned:
   ```javascript
   if (arg === '--progress' || arg === '-p') {
     showProgress = true;
     continue;
   }
   ```
3. In `scanDirectory()`, when `showProgress` is true:
   ```javascript
   const totalFiles = files.length;
   let processed = 0;
   // Inside the batch loop:
   processed += batch.length;
   console.error(`Scanning... ${processed}/${totalFiles} files`);
   ```

**Verification**:
```bash
node bin/cli.js . --progress
```
- Should print progress updates to stderr

---

### 3.3 Add JSDoc Type Annotations

**Files**: All core files (`lib/scanner.js`, `lib/formatter.js`, `bin/cli.js`, all `lib/lang/*.js`)

**What to do**:
Add JSDoc type annotations to all exported functions and key internal functions:

1. `lib/scanner.js`:
   ```javascript
   /**
    * @param {string} directory - Path to scan
    * @param {boolean} createSums - Whether to generate checksums
    * @param {string[]} ignorePatterns - Patterns to exclude
    * @returns {Promise<Array<{file: string, relativePath: string, language: string|null, issues: Array<{message: string, issueType: string, lineNum: number|null}>}>>}
    */
   async function scanCodebase(directory, createSums, ignorePatterns) { ... }
   ```

2. `lib/formatter.js`:
   ```javascript
   /**
    * @param {Array<{file: string, language: string|null, issues: Array, relativePath: string}>} results
    * @param {{format: 'table'|'json'|'md', CLI_NAME: string, VERSION: string, timeDiff: number}} options
    * @returns {string|null}
    */
   function formatResults(results, options) { ... }
   ```

3. Add type definitions for language patterns in `lib/lang/*.js`:
   ```javascript
   /**
    * @typedef {Object} LanguagePatterns
    * @property {string[]} extensions
    * @property {Object.<string, RegExp>} patterns
    * @property {RegExp} function_regex
    * @property {string[]} ignore_functions
    * @property {string[]} critical_functions
    * @property {string} void_return_indicator
    */
   ```

**Verification**:
- Open any file in VS Code — hover over functions to see type hints
- Run `npm run lint` — no JSDoc-related warnings

---

### 3.4 Consolidate Ignore Pattern Logic

**Files to create/modify**:
- `lib/ignore.js` (create new) — shared ignore logic
- `bin/cli.js` — remove `IGNORE_PATTERNS_DEFAULT`, import from `lib/ignore.js`
- `lib/scanner.js` — import from `lib/ignore.js`

**What to do**:
1. Create `lib/ignore.js`:
   ```javascript
   const DEFAULT_IGNORE_PATTERNS = [
     'node_modules[/\\\\]',
     '__pycache__[/\\\\]',
     '\\.git[/\\\\]',
     // ... all patterns from cli.js IGNORE_PATTERNS_DEFAULT
   ];

   function buildIgnorePatterns(spcIgnoreRules = []) {
     return [...DEFAULT_IGNORE_PATTERNS, ...spcIgnoreRules];
   }

   function isPathIgnored(filePath, ignorePatterns) {
     if (!ignorePatterns?.length) return false;
     // ... ignore matching logic from scanner.js
   }

   module.exports = { DEFAULT_IGNORE_PATTERNS, buildIgnorePatterns, isPathIgnored };
   ```

2. Update `cli.js` to import and use `buildIgnorePatterns`
3. Update `scanner.js` to import and use `buildIgnorePatterns` and `isPathIgnored`

**Verification**:
- Run `npm test` — all tests pass
- Run `node bin/cli.js . --format json` — same results as before consolidation

---

### 3.5 Add Open Graph Tags to Website

**File**: `docs/index.html`

**What to do**:
Add to the `<head>` section (after existing meta tags):
```html
<!-- Open Graph / Facebook -->
<meta property="og:type" content="website">
<meta property="og:url" content="https://putervision.com/">
<meta property="og:title" content="Space Proof Code (SPC) — NASA Power of Ten Static Analyzer">
<meta property="og:description" content="Zero-dependency static analysis tool enforcing NASA Power of Ten reliability & security rules across 20 programming languages.">
<meta property="og:image" content="https://putervision.com/spc-og-image.png">

<!-- Twitter -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:url" content="https://putervision.com/">
<meta name="twitter:title" content="Space Proof Code (SPC)">
<meta name="twitter:description" content="Zero-dependency static analysis tool enforcing NASA Power of Ten rules across 20 languages.">
<meta name="twitter:image" content="https://putervision.com/spc-og-image.png">
```

**Verification**:
- Use [Facebook Sharing Debugger](https://developers.facebook.com/tools/debug/) to verify OG tags
- Use [Twitter Card Validator](https://cards-dev.twitter.com/validator/) to verify Twitter cards

---

### 3.6 Fix `void_return_indicator` Heuristic Documentation

**Files**: All 20 language files in `lib/lang/`

**What to do**:
1. Add a comment above each `void_return_indicator` explaining its purpose and limitation:
   ```javascript
   // Void return type indicator. Functions whose lines contain this string
   // are NOT flagged as "unchecked function return". This is a heuristic
   // and may produce false negatives (e.g., Python's 'print' indicator means
   // lines with 'print' are not checked, which could miss unchecked returns
   // in functions that also call print).
   void_return_indicator: 'print',
   ```

2. Specifically review and document for:
   - Python: `void_return_indicator: 'print'` — problematic heuristic
   - JavaScript: `void_return_indicator: 'console.'` — may miss cases
   - C: `void_return_indicator: 'void'` — matches `void` keyword, not return values
   - Go: `void_return_indicator: ''` — empty string means no filtering
   - Rust: `void_return_indicator: ''` — same

**Verification**:
- No code changes required; this is documentation only
- Verify the comments appear in the source files

---

### 3.7 Add Pattern Cross-Language Consistency Documentation

**File**: `README.md` — add a new "Rule Coverage by Language" table

**What to do**:
Create a markdown table showing which rules apply to which languages:

```markdown
## Rule Coverage by Language

| Rule | JS/TS | Python | C/C++ | Go | Rust | Java | Ada | C# | Fortran | Bash | Ruby | Swift | Kotlin | Lua | PHP | Scala | Haskell | Zig | Julia | Elixir |
|------|-------|--------|-------|----|----|------|-----|----|---------|------|------|-------|--------|-----|-----|-------|---------|-----|-------|--------|
| recursion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| dynamic_memory | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
```

Fill in the table by checking each language file for which patterns are defined (not `null`/removed).

**Verification**:
- Cross-reference the table with actual language files
- Ensure the table is accurate and up-to-date

---

## Phase 4 — Architecture / Nice-to-Have

### 4.1 Add Inline Suppression Documentation

**File**: `README.md`

**What to do**:
Expand the "Ignoring Files & Inline Suppression" section:

```markdown
### Inline Suppression Directives

SPC supports three inline suppression directives:

1. **`spc-disable-line`** — Suppresses issues on the current line:
   ```javascript
   // spc-disable-line recursion
   function factorial(n) { return factorial(n - 1); }
   ```

2. **`spc-disable-next-line`** — Suppresses issues on the next line:
   ```javascript
   // spc-disable-next-line unbounded_loops
   while (true) { checkTermination(); }
   ```

3. **`spc-disable`** — Suppresses issues for a block (until `spc-enable`):
   ```javascript
   // spc-disable recursion
   function recursiveA() { recursiveB(); }
   function recursiveB() { recursiveA(); }
   // spc-enable
   ```

You can suppress specific rules or all rules:
```javascript
// spc-disable-line recursion,unbounded_loops  // Specific rules
// spc-disable-line all  // All rules on this line
```
```

**Verification**:
- Test each directive with a sample file
- Verify `isLineSuppressed()` in `scanner.js` handles all three variants

---

### 4.2 Add `--quiet` Flag

**File**: `bin/cli.js`

**What to do**:
1. Add `--quiet` / `-q` flag parsing
2. When `quiet` is true, skip all `console.log` output except:
   - Error messages (`console.error`)
   - File save confirmation (`Report successfully saved to ...`)
   - Final exit code indication

**Verification**:
```bash
node bin/cli.js . --quiet
```
- Should produce no stdout output (only stderr for errors)

---

### 4.3 Add `--color` / `--no-color` Flags

**File**: `bin/cli.js`

**What to do**:
1. Add `--color` / `--no-color` flag parsing
2. When `--no-color` is set, strip ANSI color codes from table output
3. When `--color` is set (or auto-detect terminal support), use ANSI colors:
   - Red for high severity (4-5)
   - Yellow for medium severity (2-3)
   - Green for low severity (1)

**Verification**:
```bash
node bin/cli.js . --no-color
node bin/cli.js . --color
```

---

### 4.4 Add `--max-issue-severity` Flag

**File**: `bin/cli.js` and `lib/scanner.js`

**What to do**:
1. Add `--max-issue-severity <N>` flag that fails if ANY individual issue has severity >= N
2. This complements `--max-severity` which checks the *average* risk level
3. In `scanDirectory()`, after scanning:
   ```javascript
   const maxIssueSeverity = Math.max(...results.flatMap(r => r.issues.map(i => PATTERN_INFO[i.issueType]?.severity ?? 0)), 0);
   if (maxIssueSeverityFlag !== null && maxIssueSeverity >= maxIssueSeverityFlag) {
     console.error(`CI Quality Gate Failed: max issue severity ${maxIssueSeverity} >= ${maxIssueSeverityFlag}`);
     process.exitCode = 1;
   }
   ```

**Verification**:
```bash
node bin/cli.js . --max-issue-severity 3
```
- Should fail if any issue has severity >= 3

---

### 4.5 Add Plugin Architecture (Future)

**File**: `lib/plugin.js` (create new) — skeleton for future plugin system

**What to do**:
Create a basic plugin loader that can be extended later:
```javascript
const fs = require('fs').promises;
const path = require('path');

async function loadPlugins(pluginDir) {
  const plugins = [];
  try {
    const files = await fs.readdir(pluginDir);
    for (const file of files) {
      if (file.endsWith('.js')) {
        const plugin = require(path.join(pluginDir, file));
        if (plugin.extensions && plugin.patterns) {
          plugins.push(plugin);
        }
      }
    }
  } catch {
    // No plugins directory or no plugins found
  }
  return plugins;
}

module.exports = { loadPlugins };
```

**Note**: This is a skeleton. Full implementation (plugin discovery, configuration, merging with built-in patterns) can be done in a future release.

**Verification**:
- No breaking changes to existing functionality
- `loadPlugins()` returns empty array when no plugins directory exists

---

## Execution Order & Dependencies

```
Phase 1 (Critical) — Must complete before any other work:
  1.1 Complete README                    (no dependencies)
  1.2 Remove null patterns              (no dependencies)
  1.3 Add files field to package.json   (no dependencies)
  1.4 Add checksums to .gitignore       (no dependencies)
  1.5 Fix multiple_returns regex        (no dependencies)

Phase 2 (High) — Can start after Phase 1:
  2.1 Expand test coverage              (depends on 1.2, 1.5)
  2.2 Add --exclude flag                (no dependencies)
  2.3 Add GitHub Actions CI             (depends on 2.1, 2.4)
  2.4 Add ESLint                        (no dependencies)
  2.5 Complete website                  (no dependencies)
  2.6 Document security rules in README (depends on 1.1)
  2.7 Add API documentation             (depends on 1.1)

Phase 3 (Medium) — Can start after Phase 2:
  3.1 Add .spc.config.json support      (no dependencies)
  3.2 Add progress indicator            (no dependencies)
  3.3 Add JSDoc types                   (no dependencies)
  3.4 Consolidate ignore logic          (no dependencies)
  3.5 Add Open Graph tags               (depends on 2.5)
  3.6 Fix void_return_indicator docs    (no dependencies)
  3.7 Add rule coverage table           (depends on 1.2)

Phase 4 (Nice-to-Have) — Optional, can be done in parallel:
  4.1 Add inline suppression docs       (depends on 1.1)
  4.2 Add --quiet flag                  (no dependencies)
  4.3 Add --color flags                 (no dependencies)
  4.4 Add --max-issue-severity flag     (no dependencies)
  4.5 Add plugin architecture skeleton  (no dependencies)
```

---

## Testing Checklist (Run After All Phases)

```bash
# 1. Run all tests
npm test

# 2. Check test coverage
npm run test:coverage

# 3. Run linter
npm run lint

# 4. Check formatting
npm run format:check

# 5. Self-scan the project
npm run self-check

# 6. Scan test examples
npm run scan:test

# 7. Verify package contents
npm pack --dry-run

# 8. Test all output formats
node bin/cli.js ./lib --format table
node bin/cli.js ./lib --format json -o /tmp/spc-test.json
node bin/cli.js ./lib --format md
node bin/cli.js ./lib --format json -o /tmp/spc-test.json && cat /tmp/spc-test.json

# 9. Test CLI flags
node bin/cli.js --help
node bin/cli.js --version
node bin/cli.js . --fail-on-issue
node bin/cli.js . --max-severity 3

# 10. Verify website HTML is well-formed
python3 -c "from html.parser import HTMLParser; HTMLParser().parse(open('docs/index.html').read()); print('HTML OK')"
```

---

## Files to Modify (Complete List)

### Core Source Files
| File | Changes |
|------|---------|
| `lib/scanner.js` | Remove null pattern handling, consolidate ignore logic, add config loading |
| `lib/formatter.js` | Add JSDoc types |
| `bin/cli.js` | Add `--exclude`, `--quiet`, `--color`, `--max-issue-severity`, `--progress` flags; consolidate ignore logic; add JSDoc types |
| `lib/info.js` | Add JSDoc types |

### Language Pattern Files (20 files)
| File | Changes |
|------|---------|
| `lib/lang/ada.js` | Remove `unrestricted_cors: null`, fix `multiple_returns` regex, add JSDoc |
| `lib/lang/bash.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/c.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/cs.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/elixir.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/fortran.js` | Remove `try_catch: null`, `network_call: null`, `unrestricted_cors: null`; fix `multiple_returns` regex, add JSDoc |
| `lib/lang/go.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/haskell.js` | Remove `unrestricted_cors: null`; fix `multiple_returns` regex, add JSDoc |
| `lib/lang/java.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/javascript.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/julia.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/kotlin.js` | Remove `unrestricted_cors: null`; fix `multiple_returns` regex, add JSDoc |
| `lib/lang/lua.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/php.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/python.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/ruby.js` | Remove `unrestricted_cors: null`; fix `multiple_returns` regex, add JSDoc |
| `lib/lang/rust.js` | Fix `multiple_returns` regex, add JSDoc |
| `lib/lang/scala.js` | Remove `unrestricted_cors: null`; fix `multiple_returns` regex, add JSDoc |
| `lib/lang/swift.js` | Remove `unrestricted_cors: null`; fix `multiple_returns` regex, add JSDoc |
| `lib/lang/zig.js` | Fix `multiple_returns` regex, add JSDoc |

### New Files to Create
| File | Purpose |
|------|---------|
| `lib/ignore.js` | Consolidated ignore pattern logic |
| `lib/config.js` | Configuration file loading |
| `lib/plugin.js` | Plugin architecture skeleton |
| `test/formatter.test.js` | Formatter unit tests |
| `test/cli.test.js` | CLI argument parsing tests |
| `test/patterns.test.js` | Pattern validation tests |
| `.github/workflows/ci.yml` | GitHub Actions CI/CD workflow |
| `.eslintrc.json` | ESLint configuration |

### Documentation Files to Modify/Create
| File | Changes |
|------|---------|
| `README.md` | Complete truncated content, add security rules, add missing sections, add API docs, add rule coverage table |
| `CONTRIBUTING.md` | **Create** — contribution guidelines |
| `CHANGELOG.md` | **Create** — version history |
| `docs/index.html` | Complete truncated HTML, add OG/Twitter tags, add structured data |

### Configuration Files to Modify
| File | Changes |
|------|---------|
| `package.json` | Add `files` field, add ESLint deps, add `lint`/`lint:fix` scripts |
| `.gitignore` | Add `checksums.sha256.txt` |

---

## Estimated Effort

| Phase | Estimated Time | Complexity |
|-------|---------------|------------|
| Phase 1 (Critical) | 2-3 hours | Low — straightforward fixes |
| Phase 2 (High) | 6-8 hours | Medium — requires testing and coordination |
| Phase 3 (Medium) | 4-6 hours | Medium — requires design decisions |
| Phase 4 (Nice-to-Have) | 3-4 hours | Low-Medium — incremental improvements |
| **Total** | **15-21 hours** | |

---

## Notes for the Executing Agent

1. **Always run `npm test` after making changes** to ensure no regressions
2. **Commit changes in logical chunks** — one phase at a time, with passing tests at each step
3. **When fixing `multiple_returns` regex**, test against the example files in `test/examples/` to verify detection still works
4. **When completing the README**, maintain the existing format and tone (technical, NASA-themed, with external references)
5. **When completing the website**, maintain the existing dark theme, glass-morphism design, and CSS variable system
6. **Do NOT add any npm dependencies** — the zero-dependency constraint is a core project requirement
7. **All new code should follow the existing style**: single quotes, semicolons, 2-space indent (enforced by Prettier config)
8. **When in doubt about a pattern's accuracy**, add a comment noting the limitation rather than removing the rule entirely
