# Changelog

All notable changes to the `@putervision/spc` (Space Proof Code) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-08-20

### Added
- **Zero-Phantom Rule Engine Parity & CI Integrity Guard**:
  - Implemented concrete regular expression detection engines for all 16 previously uninstantiated rules across JavaScript, Python, C/C++, C#, Java, Go, PHP, Ruby, Rust, Swift, and Zig.
  - Reached 100% parity across all 63 registered rules in `PATTERN_INFO`.
  - Added automated build-time integrity assertion in `scripts/build.js` and dedicated `test/integrity.test.js` to permanently prevent phantom rule regressions.
- **Performance & High-Throughput Optimization**:
  - Replaced $O(N)$ string slicing line calculations with precomputed binary search line offset lookup ($O(\log L)$).
  - Added precompiled regular expression caching in `lib/ignore.js`.
  - Added conditional SHA-256 file hashing (skips expensive hashing when checksum flags are inactive).
  - Added `DEFAULT_MAX_FILE_SIZE` (5 MB) protection guard to prevent out-of-memory errors on giant binaries or generated bundles.
  - Added `scripts/benchmark.js` benchmarking tool achieving >550 files/sec scan throughput.
- **Security Hardening & ReDoS Safety**:
  - Eliminated nested quantifier catastrophic backtracking risks across all 23 language engines and added `test/redos_safety.test.js`.
  - Enforced path traversal containment and schema structure validation in `lib/plugin.js`.
  - Upgraded engine compatibility floor to Node.js `>=18.17.0` in `package.json`.
  - Made environment `IGNORE_PATTERNS` additive alongside default ignore patterns, with `--no-default-ignores` toggle support.
  - Added strict 64-hex SHA-256 regex enforcement in `lib/checksum.js`.
- **Packaging, Multi-Target CLI & Subpath Exports**:
  - Added multi-target directory scanning support to `bin/cli.js` (`spc dir1 dir2 ...`).
  - Added standard `exports` map in `package.json` for modular subpath imports (`@putervision/spc/info`, `@putervision/spc/scanner`, etc.).
  - Added `--color` and `--no-color` CLI flag support with `NO_COLOR` / `FORCE_COLOR` environment variable precedence.
  - Fixed `getCapabilities().ruleCategories` export in `lib/info.js`.

### Fixed
- Fixed positional target directory overwrite bug in `bin/cli.js` and `.github/workflows/ci.yml`.
- Fixed `package.json` main entry point and updated `self-check` script.
- Fixed non-regex `function_regex` in `lib/lang/model.js` and `lib/lang/mcp.js`.
- Fixed permission error detection in `safeRealPath` (`EACCES`).

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
