# AI Agent, Skill, MCP Config & Model Rules

`@putervision/spc` provides static security auditing for **AI Agent Skills (`SKILL.md`)**, **Prompt Instructions (`AGENTS.md`, `.windsurfrules`, `.cursorrules`)**, **MCP Server Configs (`mcp.json`, `config.json`)**, and **LLM Model Deployment Configs (`model_config.json`, Ollama files)**.

---

## AI Agent Skill & Prompt Rules

### Prompt Injection Hazard (`prompt_injection_hazard`)
- **Severity**: `5/5` | **Category**: `agent`
- **Description**: Unescaped user variable interpolation in system prompt instructions, or explicit jailbreak keywords (`ignore previous instructions`, `bypass safety`).
- **Remedy**: Sanitize input variables before template insertion; separate user input into distinct message roles.

---

### Unsafe Skill Command (`unsafe_skill_command`)
- **Severity**: `5/5` | **Category**: `agent`
- **Description**: Unsafe shell invocations in skill scripts or documentation code samples (`curl | bash`, `rm -rf /`, `chmod 777`).
- **Remedy**: Remove dynamic shell downloads; pin package dependencies with explicit checksums.

---

### Unbounded Agent Loop (`unbounded_agent_loop`)
- **Severity**: `4/5` | **Category**: `agent`
- **Description**: Agent task execution or subagent dispatch without maximum iteration caps (`max_iterations: -1`, `while(true)` agent loops).
- **Remedy**: Enforce strict upper bounds on agent iteration counts and task auto-retry steps.

---

### Hardcoded Agent Secret (`hardcoded_agent_secret`)
- **Severity**: `5/5` | **Category**: `agent`
- **Description**: Hardcoded API keys (`sk-...`, `ghp_...`), bearer tokens, or private keys inside prompt templates or skill metadata.
- **Remedy**: Inject secrets at runtime via environment variables or secure secret managers.

---

### Overly Broad Tool Grant (`overly_broad_tool_grant`)
- **Severity**: `4/5` | **Category**: `agent`
- **Description**: Granting agent execution access to all system tools without explicit permission scoping (`allow: ["*"]`, `command(*)`).
- **Remedy**: Scope agent permissions strictly to the minimal required tool handles.

---

### Missing Agent Guardrails (`missing_agent_guardrails`)
- **Severity**: `3/5` | **Category**: `agent`
- **Description**: System prompts or agent definitions explicitly disabling refusal policies or safety constraints.
- **Remedy**: Include explicit refusal criteria and safety boundaries in prompt instructions.

---

### Data Exfiltration Pattern (`data_exfiltration_pattern`)
- **Severity**: `5/5` | **Category**: `agent`
- **Description**: Prompt patterns instructing agents to dump memory contents, environment variables, or private files to external webhooks.
- **Remedy**: Restrict network egress boundaries for agent execution environments.

---

## MCP (Model Context Protocol) Server Config Rules

### Overly Permissive MCP Grant (`overly_permissive_mcp_grant`)
- **Severity**: `5/5` | **Category**: `agent`
- **Description**: Wildcard permission grants in `mcp.json` or `.gemini/config/config.json` (e.g., `"command(.*)"`, `"write_file(.*)"`).
- **Remedy**: Restrict command grants to explicit commands and specify exact path patterns.

---

### Unencrypted MCP Env Secret (`unencrypted_mcp_env_secret`)
- **Severity**: `5/5` | **Category**: `agent`
- **Description**: Plaintext API keys or tokens embedded in MCP server `env` configuration blocks.
- **Remedy**: Reference system environment variables instead of hardcoding secret strings in JSON configs.

---

### Unsafe MCP Tool Schema (`unsafe_mcp_tool_schema`)
- **Severity**: `4/5` | **Category**: `agent`
- **Description**: Tool schema definitions accepting unconstrained string parameters for direct command-line execution.
- **Remedy**: Enforce enum value constraints or strict regex validation patterns on tool schema properties.

---

### Exposed MCP Endpoint (`exposed_mcp_endpoint`)
- **Severity**: `4/5` | **Category**: `agent`
- **Description**: MCP server listening on `0.0.0.0` or public network interfaces without access control.
- **Remedy**: Bind MCP servers to `127.0.0.1` (localhost) or enforce mutual TLS/token authentication.

---

## LLM & Model Deployment Config Rules

### Unsafe Model Deserialization (`unsafe_model_deserialization`)
- **Severity**: `5/5` | **Category**: `agent`
- **Description**: PyTorch / Pickle model loading flags with `weights_only=False` or unverified pickle modules.
- **Remedy**: Set `weights_only=True` or convert model weights to `safetensors` format.

---

### Insecure Model Endpoint (`insecure_model_endpoint`)
- **Severity**: `4/5` | **Category**: `agent`
- **Description**: Ollama or model serving HTTP endpoints listening on `0.0.0.0` without authentication headers.
- **Remedy**: Enable reverse proxy authentication or bind endpoints to localhost.

---

### Unauthenticated Model Download (`unauthenticated_model_download`)
- **Severity**: `4/5` | **Category**: `agent`
- **Description**: Downloading model weight binaries (`.bin`, `.safetensors`, `.gguf`) over unencrypted `http://` URLs.
- **Remedy**: Use `https://` URLs with SHA-256 integrity verification hashes.

---

### Unsafe Model Temperature (`unsafe_model_temperature`)
- **Severity**: `2/5` | **Category**: `quality`
- **Description**: Temperature setting > 1.5 in safety-critical agent execution configs causing non-deterministic outputs.
- **Remedy**: Use lower temperature settings (0.0 - 0.7) for deterministic structured output tasks.
