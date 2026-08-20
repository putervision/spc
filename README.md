# Space Proof Code 🛡️ (`@putervision/spc`)

> High-performance zero-dependency static analysis tool enforcing NASA Power of Ten reliability rules across 20 programming languages, plus AI agent skill, MCP server config, prompt template, and LLM model configuration security auditing.

[![npm version](https://img.shields.io/npm/v/@putervision/spc.svg)](https://www.npmjs.com/package/@putervision/spc)
[![Website](https://img.shields.io/badge/Website-putervision.com-06b6d4.svg)](https://putervision.com)
[![License](https://img.shields.io/npm/l/@putervision/spc.svg)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/putervision/spc)
[![AI Agent Auditing](https://img.shields.io/badge/AI%20Agent-Auditing%20Enabled-a855f7.svg)](docs/ai-agent-rules.md)

---

## ⚡ Quick Start & Installation

Install `@putervision/spc` globally via npm:

```bash
npm install -g @putervision/spc
```

### Basic Scan Commands

```bash
# Scan current directory for space-proofing & security issues
spc .

# Export SARIF report for GitHub Code Scanning integration
spc ./src --format sarif -o spc-report.sarif

# Audit AI agent skills, prompts, MCP configs & model files only
spc . --ai-only --format json -o agent-audit.json

# Enforce quality gate in CI/CD pipeline (fail if risk level >= 4.0)
spc . --max-severity 4.0 --fail-on-issue
```

---

## 🌟 Key Highlights

- 🚀 **NASA Power of Ten Rules**: Enforces safety-critical code rules (bounded loops, no recursion, static memory allocation, assertion density, and restricted control flow).
- 🤖 **AI / Agent / MCP Security Scanner**: Audits AI Agent skills (`SKILL.md`), prompt instructions (`AGENTS.md`, `.windsurfrules`), MCP server configs (`mcp.json`), and LLM model deployment configs (`model_config.json`) for prompt injection and security flaws.
- 🌐 **20 Supported Languages**: Native static analysis for Ada, Bash, C/C++, C#, Elixir, Fortran, Go, Haskell, Java, JavaScript/TypeScript, Julia, Kotlin, Lua, PHP, Python, Ruby, Rust, Scala, Swift, and Zig.
- 🔒 **Zero External Dependencies**: Engineered 100% locally from scratch with zero third-party library risks or supply-chain vulnerabilities.
- 📊 **Multi-Format Reporting**: Supports formatted console tables, machine-readable JSON, GitHub Markdown PR comments, and SARIF v2.1.0 output.
- ⚡ **Local Privacy Guarantee**: Runs 100% locally on your machine or runner. Zero network calls, zero telemetry tracking, and zero source code collection.

---

## 📚 Documentation Directory

Explore detailed documentation and reference guides:

| Document | Description |
|---|---|
| 🛠️ [CLI Reference Guide](docs/cli-reference.md) | Command options, output formats, CI/CD integration, inline suppression, checksum manifests |
| 🤖 [Agent Tools & Schema](docs/agent-tools.md) | AI Agent tool specifications, operations, capabilities, and MCP tool schemas |
| 🚀 [NASA Power of Ten Rules](docs/nasa-rules.md) | High-reliability code rules inspired by NASA space flight standards |
| 🔒 [Traditional Security Rules](docs/security-rules.md) | Vulnerability detection patterns across 20 programming languages |
| 🤖 [AI Agent & MCP Rules](docs/ai-agent-rules.md) | Agent skill, prompt injection, MCP server config, and model config auditing rules |
| 💻 [API Reference](docs/api-reference.md) | Programmatic Node.js API usage (`scanCodebase`, `formatResults`, `PATTERN_INFO`) |
| 📊 [Rule Coverage Matrix](docs/rule-coverage.md) | Complete language × rule matrix covering all 63+ checks |
| 🏗️ [Architecture & Extensibility](docs/architecture.md) | Internal scan pipeline, pattern engine schema, and custom plugin development |

---

## 🧪 Testing

Run the automated test suite and check code coverage:

```bash
# Run unit & integration tests
npm test

# Run NVM matrix test across Node.js versions (18.x, 20.x, 22.x)
npm run test:matrix

# Run tests with coverage report
npm run test:coverage

# Perform self-scan on SPC codebase
npm run self-check
```

---

## ⚖️ PuterVision Legal & Usage Disclaimers

> [!IMPORTANT]
> **Data Privacy & Local Execution Guarantee**  
> `spc` (Space Proof Code) is engineered by PuterVision with a strict **local-first privacy architecture**. All static analysis, regex parsing, and vulnerability scanning run 100% locally on your machine. No source code, directory structures, or scan results are ever transmitted, telemetry-tracked, or collected by PuterVision.

> [!WARNING]
> **Static Analysis & Safety Disclaimer**  
> `spc` enforces static code rules inspired by NASA's Power of Ten reliability guidelines. While `spc` helps identify critical security anti-patterns (e.g., unchecked return values, unsafe pointer math, recursion hazards, and hardcoded credentials), static analysis cannot guarantee the total absence of runtime defects or mission failures. Developers are advised to complement `spc` with dynamic testing, fuzzing, and formal verification in safety-critical production systems.

> [!NOTE]
> **Trademarks & Non-Affiliation Notice**  
> All product names, trademarks, service marks, logos, and brands (such as NASA, ISO/IEC, MISRA, Node.js, and GitHub) referenced in this documentation are the property of their respective owners. References to NASA's Power of Ten rules or third-party guidelines are for educational and compatibility identification purposes only, and do not imply endorsement, sponsorship, or affiliation with PuterVision.

---

<p align="center">
  Developed and maintained by <a href="https://putervision.com" target="_blank" rel="noopener noreferrer">PuterVision</a>. Released under the <a href="./LICENSE">MIT License</a>.
</p>