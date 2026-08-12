# Changelog

All notable changes to the `@putervision/spc` (Space Proof Code) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-08-12

### Added
- **AI / Agent / MCP / Model Security Scanner**:
  - Expanded static analysis engine to scan AI Agent skills (`SKILL.md`), prompt instructions (`AGENTS.md`, `.windsurfrules`, `.cursorrules`, `*.prompt`), MCP server configs (`mcp.json`, `config.json`), and LLM model deployment configs (`model_config.json`).
  - Added specialized rule modules: `lib/lang/agent.js`, `lib/lang/mcp.js`, `lib/lang/model.js`.
  - Added CLI flags `--ai-only` and `--skip-ai`.
- **Output Formats & Programmatic API**:
  - Added `--format sarif` for GitHub Code Scanning and IDE integration.
  - Added root `index.js` exporting `{ scanCodebase, formatResults, PATTERN_INFO, loadConfig }`.
  - Added `--category <nasa|security|quality|agent>` and `--list-rules` filtering options.
- **PuterVision Branding Overhaul**:
  - Decomposed README into concise hub (~150 lines) with 7 specialized sub-documents in `docs/`.
  - Redesigned `docs/index.html` with PuterVision cyber-glass aesthetic and interactive rule explorer.

### Fixed
- Wired `.spc.config.json` rule toggles and line limits into `scanner.js`.
- Implemented block-level comment suppression (`spc-disable` / `spc-enable`).
- Integrated `plugin.js` rule loader.
- Populated severity levels and URLs for all unlisted rules in `PATTERN_INFO`.
- Routed status/progress logs to `stderr` to ensure clean stdout for JSON and SARIF formats.

## [1.3.0] - 2026-07-30

### Added
- **New CLI Flags**:
  - `--exclude <pattern>`: Add custom file/directory exclusion patterns.
  - `--config <path>`: Load repository-level `.spc.config.json` settings.
  - `--progress, -p`: Print scanned files and issue counts in real time.
  - `--quiet, -q`: Suppress non-essential log outputs for silent execution.
  - `--max-issue-severity <N>`: CI quality gate option failing when any single issue severity >= N.
  - `--color / --no-color`: Enable or disable ANSI terminal output colors.
- **Config & Ignore Modules**:
  - Created `lib/config.js` for `.spc.config.json` rule & line limit loading.
  - Created `lib/ignore.js` for centralized pattern filtering.
  - Created `lib/plugin.js` skeleton for future plugin extensibility.
- **Documentation & Website Enhancements**:
  - Added Programmatic Usage (`scanCodebase()`) section and Rule Coverage Matrix table to `README.md`.
  - Added Open Graph (`og:*`), Twitter Card (`twitter:*`), and JSON-LD (`SoftwareApplication`) structured data to `docs/index.html`.
  - Created `CONTRIBUTING.md` and `CHANGELOG.md`.
- **Test Suite**: Added test suites for formatter (`test/formatter.test.js`), CLI args (`test/cli.test.js`), and language pattern validation (`test/patterns.test.js`).

### Fixed
- Fixed fatal `TypeError` caused by `null` pattern values across 8 language configuration files (`ada.js`, `fortran.js`, `haskell.js`, `kotlin.js`, `lua.js`, `ruby.js`, `scala.js`, `swift.js`).
- Fixed `multiple_returns` regex pattern across all 20 language files to correctly match across multiline blocks and nested braces.
- Added `files` array to `package.json` to prevent publishing test assets, `.agents/`, and local caches to npm.
- Added `checksums.sha256.txt` to `.gitignore`.

---

## [1.2.0] - 2026-07-29

### Added
- Multi-language expansion to **20 programming languages** (added Zig, Julia, Elixir, and Bash/Shell support).
- Multi-format output reporting (`--format table|json|md`).
- Quality gate enforcement flags (`--max-severity`, `--fail-on-issue`).
- Standardized package structure and keywords.
