# SPC AI Agent Tool Specifications & Integration Guide

`@putervision/spc` provides dedicated tool specifications, capabilities endpoints, and CLI options for AI agents, subagents, LLM tool-calling frameworks, and MCP (Model Context Protocol) servers.

---

## 1. CLI Agent Tools Command

AI agents can query `spc` for its full operational tool specification and schema directly via CLI:

```bash
spc --agent-tools
# or: spc --schema
```

### JSON Output Example (`spc --agent-tools`)

```json
{
  "name": "space-proof-code",
  "version": "1.5.0",
  "description": "High-performance zero-dependency static analysis tool enforcing NASA Power of Ten reliability rules across 20 programming languages, plus AI agent skill, MCP server config, prompt template, and LLM model configuration security auditing.",
  "operations": [
    {
      "name": "scanCodebase",
      "description": "Scans a directory for NASA Power of Ten rules, traditional security vulnerabilities, and AI agent flaw patterns.",
      "parameters": {
        "type": "object",
        "properties": {
          "directory": { "type": "string", "description": "Directory path to scan (default: current directory)" },
          "format": { "type": "string", "enum": ["table", "json", "md", "sarif"], "default": "table", "description": "Output format" },
          "category": { "type": "string", "enum": ["nasa", "security", "quality", "agent"], "description": "Filter rules by category" },
          "aiOnly": { "type": "boolean", "default": false, "description": "Scan only AI Agent skills, prompts, MCP configs & model files" },
          "skipAi": { "type": "boolean", "default": false, "description": "Skip AI agent checks, scan traditional code languages only" },
          "maxSeverityThreshold": { "type": "number", "description": "Exit non-zero if average severity risk level >= N" },
          "maxIssueSeverityThreshold": { "type": "number", "description": "Exit non-zero if any single issue severity >= N" },
          "failOnIssue": { "type": "boolean", "default": false, "description": "Exit non-zero if any issues are detected" },
          "createSums": { "type": "boolean", "default": false, "description": "Generate SHA-256 checksum manifest file" }
        }
      }
    },
    {
      "name": "listRules",
      "description": "Lists all 63+ supported rules with severities, categories, and documentation URIs."
    },
    {
      "name": "getCapabilities",
      "description": "Returns supported languages, AI domains, total rules, and output formats."
    }
  ]
}
```

---

## 2. Programmatic Agent API

AI agents running inside Node.js environments can inspect capabilities and execute scans programmatically:

```javascript
const {
  scanCodebase,
  formatResults,
  getCapabilities,
  getAgentToolSchema,
} = require('@putervision/spc');

// Query tool capabilities
const capabilities = getCapabilities();
console.log(`SPC Version: ${capabilities.version}, Total Rules: ${capabilities.totalRules}`);

// Query tool specification schema
const schema = getAgentToolSchema();
console.log(JSON.stringify(schema, null, 2));

// Run automated AI agent security audit
async function runAgentAudit(targetDir) {
  const results = await scanCodebase(targetDir, false, [], { aiOnly: true });
  const sarifReport = formatResults(results, { format: 'sarif' });
  return sarifReport;
}
```

---

## 3. MCP (Model Context Protocol) Server Integration

To register `spc` as a tool inside an MCP server (e.g. `state-memory-mcp`, `vision-memory-mcp`, or custom MCP sidecars):

```json
{
  "name": "spc_scan",
  "description": "Enforces static code rules and AI agent security audits using @putervision/spc.",
  "parameters": {
    "type": "object",
    "properties": {
      "directory": { "type": "string", "description": "Target project directory path to scan" },
      "aiOnly": { "type": "boolean", "description": "Audit only AI Agent skills, prompt templates, MCP configs & model files" },
      "category": { "type": "string", "enum": ["nasa", "security", "quality", "agent"], "description": "Category filter" }
    },
    "required": ["directory"]
  }
}
```

---

## 4. Agent CLI Flags Quick Reference

- `spc --agent-tools`: Outputs agent tool schema JSON.
- `spc --ai-only --format json`: Runs AI agent skill/prompt/MCP audit and returns JSON findings.
- `spc --category agent`: Audits only AI Agent and MCP security rules.
- `spc --category nasa`: Audits only NASA Power of Ten reliability rules.
- `spc --format sarif`: Generates OASIS SARIF v2.1.0 output for automated security pipeline ingest.
