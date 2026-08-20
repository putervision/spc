# SPC Programmatic Node.js API Reference

`@putervision/spc` can be integrated programmatically into Node.js applications, CI build tools, or custom agent security auditing pipelines.

---

## Installation

```bash
npm install @putervision/spc
```

---

## Quick Example

```javascript
const { scanCodebase, formatResults } = require('@putervision/spc');

async function auditProject() {
  // Scan target directory
  const results = await scanCodebase('./src', false, ['node_modules/**']);

  // Generate Markdown report
  const markdownReport = formatResults(results, { format: 'md' });
  console.log(markdownReport);

  // Generate SARIF report for GitHub Code Scanning
  const sarifReport = formatResults(results, { format: 'sarif' });
  // write to file...
}

auditProject().catch(console.error);
```

---

## Exported API Surface

### `scanCodebase(directory, createSums, ignorePatterns, options)`
Executes the full static analysis scan across 20 programming languages and AI agent configuration files.

- **`directory`** *(string)*: Absolute or relative directory path to scan.
- **`createSums`** *(boolean, default: false)*: Generate `checksums.sha256.txt` manifest.
- **`ignorePatterns`** *(string[], default: [])*: Array of custom ignore regex or glob pattern strings.
- **`options`** *(Object, optional)*:
  - `options.category` *(string)*: Filter checks by category (`"nasa"`, `"security"`, `"quality"`, `"agent"`).
  - `options.aiOnly` *(boolean)*: Scan only AI Agent skills, prompt instructions, MCP configs, and model files.
  - `options.skipAi` *(boolean)*: Skip AI agent checks, scan only code languages.
  - `options.configPath` *(string)*: Path to custom `.spc.config.json`.
  - `options.pluginsDir` *(string)*: Path to custom plugins folder.
- **Returns**: `Promise<Array<{ file: string, relativePath: string, language: string, issues: Array<Issue> }>>`

---

### `formatResults(results, options)`
Formats scan findings into machine-readable or display formats.

- **`results`** *(Array)*: Scan output array from `scanCodebase()`.
- **`options`** *(Object, optional)*:
  - `options.format` *(string)*: Output format (`"table"`, `"json"`, `"md"`, `"sarif"`).
  - `options.CLI_NAME` *(string)*: Tool identifier name.
  - `options.VERSION` *(string)*: Tool version string.
- **Returns**: `string` (formatted report output string).

---

### `PATTERN_INFO`
Object map containing severity, category, and documentation URIs for all 63+ supported rules.

```javascript
const { PATTERN_INFO } = require('@putervision/spc');
console.log(PATTERN_INFO.prompt_injection_hazard);
// { url: 'docs/ai-agent-rules.md#prompt-injection-hazard', severity: 5, category: 'agent' }
```

---

### `RULE_CATEGORIES`
Enum object mapping rule category labels:

```javascript
const { RULE_CATEGORIES } = require('@putervision/spc');
// { NASA: 'nasa', SECURITY: 'security', QUALITY: 'quality', AGENT: 'agent' }
```

---

### `loadConfig(configPath)`
Loads and parses `.spc.config.json` settings merged with default configurations.

- **`configPath`** *(string)*: File path or directory containing `.spc.config.json`.
- **Returns**: `Promise<Object>` (Configuration object containing `maxFunctionLines`, `rules`, `ignorePatterns`).
