# Rule Coverage Matrix by Language & File Type

@putervision/spc provides rule-based static analysis across 20 programming languages plus 3 AI configuration domains, including modern web frameworks (.vue, .svelte), Dockerfiles, .env manifests, and YAML/JSON infrastructure files.

---

## Language & Domain Coverage Matrix

| Rule Name | Category | JS/TS | Python | C/C++ | Go | Rust | Java | Ada | C# | Fortran | Bash | Ruby | Swift | Kotlin | Lua | PHP | Scala | Haskell | Zig | Julia | Elixir | Agent | MCP | Model |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `recursion` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `dynamic_memory` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `complex_flow` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `async_risk` | `nasa` | ✓ |  |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `unbounded_loops` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `global_vars` | `nasa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `try_catch` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `set_timeout` | `nasa` | ✓ |  |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ | ✓ |  | ✓ | ✓ | ✓ |  |  |  |
| `multiple_returns` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `nested_conditionals` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `exceeds_max_func_lines` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `unchecked_func_return` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `unchecked_func_return_crit` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `eval_usage` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `unsafe_input` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `network_call` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `weak_crypto` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `unsafe_file_op` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `insufficient_logging` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |  |  |  |
| `unsanitized_exec` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |  |  |  |
| `exposed_secrets` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| `unrestricted_cors` | `security` | ✓ |  |  |  |  | ✓ |  | ✓ |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |  |  |
| `checksum_mismatch` | `quality` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `import_risk` | `security` |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `buffer_overflow_risk` | `security` |  |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `unsafe_atom` | `quality` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |  |
| `unsafe_pointer` | `security` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |  |  |  |
| `prototype_pollution` | `security` | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `xss_risk` | `security` | ✓ |  |  |  |  | ✓ |  | ✓ |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |  |  |
| `sql_injection` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ |  | ✓ | ✓ |  |  |  | ✓ |  |  |  |  |  |  |  |  |
| `ssrf_risk` | `security` | ✓ | ✓ |  | ✓ |  | ✓ |  |  |  |  | ✓ |  |  |  | ✓ |  |  |  |  |  |  |  |  |
| `pickle_deserialize` | `security` |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `yaml_load` | `security` |  | ✓ |  |  |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |
| `format_string` | `security` |  |  | ✓ | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |  |  |  |
| `use_after_free` | `security` |  |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |  |  |  |
| `race_condition` | `quality` | ✓ |  | ✓ |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `curl_pipe_bash` | `security` |  |  |  |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `sudo_nopasswd` | `security` |  |  |  |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `deserialization_risk` | `security` | ✓ | ✓ |  |  |  | ✓ |  | ✓ |  |  | ✓ |  |  |  | ✓ |  |  |  |  |  |  |  |  |
| `xxe_injection` | `security` |  | ✓ |  |  |  | ✓ |  | ✓ |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |  |  |
| `open_redirect` | `security` | ✓ | ✓ |  |  |  |  |  |  |  |  | ✓ |  |  |  | ✓ |  |  |  |  |  |  |  |  |
| `timing_attack` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| `insecure_random` | `security` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ |  | ✓ | ✓ | ✓ |  |  | ✓ |  |  | ✓ |  |  |  |  |  |
| `prompt_injection_hazard` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `unsafe_skill_command` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `unbounded_agent_loop` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `hardcoded_agent_secret` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `overly_broad_tool_grant` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `missing_agent_guardrails` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `data_exfiltration_pattern` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `recursive_agent_call` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |  |
| `overly_permissive_mcp_grant` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |
| `unencrypted_mcp_env_secret` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |
| `unsafe_mcp_tool_schema` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |
| `exposed_mcp_endpoint` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |
| `missing_mcp_auth` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |
| `unrestricted_mcp_scope` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |
| `unsafe_model_deserialization` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |
| `insecure_model_endpoint` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |
| `unauthenticated_model_download` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |
| `unsafe_model_temperature` | `quality` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |
| `exposed_model_api_key` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |
| `unvalidated_model_input` | `agent` |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | ✓ |
