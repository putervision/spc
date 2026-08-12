# Rule Coverage Matrix by Language & File Type

`@putervision/spc` provides rule-based static analysis across 20 programming languages plus 3 AI configuration domains, including modern web frameworks (`.vue`, `.svelte`), Dockerfiles, `.env` manifests, and YAML/JSON infrastructure files.

---

## Language & Domain Coverage Matrix

| Rule Name | Category | JS/TS | Python | C/C++ | Go | Rust | Java | Ada | C# | Fortran | Bash | Ruby | Swift | Kotlin | Lua | PHP | Scala | Haskell | Zig | Julia | Elixir | Agent/Skill | MCP Config | Model Config |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `recursion` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `unbounded_loops` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `dynamic_memory` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `async_risk` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | | | | ✓ | ✓ | | | ✓ | | | | | | | |
| `global_vars` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `exceeds_max_func_lines` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `unchecked_func_return` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `eval_usage` | `security` | ✓ | ✓ | | | | ✓ | | | | ✓ | ✓ | | | ✓ | ✓ | | | | | | | | |
| `unsafe_input` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `sql_injection` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | | | ✓ | ✓ | ✓ | | ✓ | ✓ | | ✓ | ✓ | | | | |
| `ssrf_risk` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | | | ✓ | ✓ | ✓ | | ✓ | ✓ | | ✓ | ✓ | | | | |
| `exposed_secrets` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `unsanitized_exec` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | | ✓ | ✓ | ✓ | ✓ | | ✓ | ✓ | | ✓ | ✓ | ✓ | | | |
| `weak_crypto` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | |
| `prompt_injection_hazard` | `agent` | | | | | | | | | | | | | | | | | | | | | ✓ | | |
| `unsafe_skill_command` | `agent` | | | | | | | | | | | | | | | | | | | | | ✓ | | |
| `unbounded_agent_loop` | `agent` | | | | | | | | | | | | | | | | | | | | | ✓ | | |
| `hardcoded_agent_secret` | `agent` | | | | | | | | | | | | | | | | | | | | | ✓ | | |
| `overly_permissive_mcp_grant` | `agent` | | | | | | | | | | | | | | | | | | | | | | ✓ | |
| `unencrypted_mcp_env_secret` | `agent` | | | | | | | | | | | | | | | | | | | | | | ✓ | |
| `unsafe_mcp_tool_schema` | `agent` | | | | | | | | | | | | | | | | | | | | | | ✓ | |
| `exposed_mcp_endpoint` | `agent` | | | | | | | | | | | | | | | | | | | | | | ✓ | |
| `unsafe_model_deserialization` | `agent` | | | | | | | | | | | | | | | | | | | | | | | ✓ |
| `insecure_model_endpoint` | `agent` | | | | | | | | | | | | | | | | | | | | | | | ✓ |
| `unauthenticated_model_download` | `agent` | | | | | | | | | | | | | | | | | | | | | | | ✓ |
| `exposed_model_api_key` | `agent` | | | | | | | | | | | | | | | | | | | | | | | ✓ |
