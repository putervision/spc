# SPC CLI Reference & Integration Guide

This document covers CLI command usage, output formats, CI/CD quality gate enforcement, ignore configuration, and suppression directives for `@putervision/spc` (Space Proof Code).

---

## Command Usage & Arguments

```bash
spc [directory] [options]
# or: space-proof-code [directory] [options]
```

### CLI Arguments Reference

| Option | Flag | Description | Default |
|---|---|---|---|
| `--help` | `-h` | Displays the help menu | N/A |
| `--version` | `-v`, `-V` | Displays the version number | N/A |
| `--format <type>` | N/A | Output report format (`table`, `json`, `md`, `sarif`) | `table` |
| `--output <file>` | `-o` | Saves output report to a specified file path | N/A |
| `--category <name>` | N/A | Filters rules by category (`nasa`, `security`, `quality`, `agent`) | All |
| `--ai-only` | N/A | Scans only AI Agent skills, prompt instructions, MCP configs, and model files | `false` |
| `--skip-ai` | N/A | Skips AI agent checks; scans only traditional programming languages | `false` |
| `--list-rules` | N/A | Prints all 63+ supported rules, severities, and categories | N/A |
| `--create-sums` | `-cs` | Generates a SHA-256 `checksums.sha256.txt` manifest in target directory | `false` |
| `--exclude <pattern>` | N/A | Excludes files matching comma-separated glob patterns | `[]` |
| `--config <path>` | N/A | Specifies custom path to `.spc.config.json` configuration file | Root `.spc.config.json` |
| `--progress` | `-p` | Displays real-time scanning progress file by file | `false` |
| `--quiet` | `-q` | Suppresses standard log outputs (only outputs error logs) | `false` |
| `--max-severity <N>` | N/A | Fails run (exit code 1) if average severity risk level >= N | N/A |
| `--max-issue-severity <N>` | N/A | Fails run (exit code 1) if any single issue severity >= N | N/A |
| `--fail-on-issue` | N/A | Fails run (exit code 1) if any space-proofing or security issues are found | `false` |
| `--color` | N/A | Forces colored ANSI terminal output | Auto-detect |
| `--no-color` | N/A | Disables colored ANSI terminal output (honors `NO_COLOR`) | Auto-detect |

---

## Output Formats

### 1. Table Output (`--format table`)
Formated console output with summary risk calculations and tabular findings per file.

```bash
spc ./src
```

### 2. Machine-Readable JSON (`--format json`)
Outputs structured JSON data including scan metadata, scan time, summary statistics, issue counts, and file-level findings.

```bash
spc ./src --format json -o spc-report.json
```

### 3. Markdown PR Summary (`--format md`)
Generates GitHub-flavored Markdown tables for integration into PR comments or automated build summaries.

```bash
spc ./src --format md -o report.md
```

### 4. SARIF v2.1.0 Output (`--format sarif`)
Generates OASIS SARIF output for native integration with GitHub Code Scanning Security Alerts and IDE SARIF viewers.

```bash
spc ./src --format sarif -o spc-results.sarif
```

---

## CI/CD Pipeline Quality Gates

Enforce quality thresholds in GitHub Actions, GitLab CI, or Jenkins:

```bash
# Fail build if average severity >= 4.0
spc . --max-severity 4.0

# Fail build if any critical issue (severity 5) is found
spc . --max-issue-severity 5

# Fail build if any issue is detected
spc . --fail-on-issue
```

---

## Ignoring Files & Suppression

### `.spcignore` File
Place a `.spcignore` file in your root project directory:
```gitignore
# Exclude build output and third-party dependencies
vendor/
dist/
*.test.js
```

### Inline Directive (`spc-disable-line`)
Suppress rules for a specific line of code:
```javascript
// spc-disable-line recursion
function recursiveHelper(n) { return recursiveHelper(n - 1); }
```

### Block-Level Directive (`spc-disable` / `spc-enable`)
Suppress rules across a block of code:
```javascript
/* spc-disable unbounded_loops, eval_usage */
while (legacyCondition) {
  eval(legacyScript);
}
/* spc-enable */
```

---

## SHA-256 Checksums Manifest

Generate checksum manifests to ensure code integrity across deployments:

```bash
# Generate checksums file in target path (checksums.sha256.txt)
spc /path/to/code --create-sums

# Subsequent scans automatically compare file hashes against manifest
spc /path/to/code
```
