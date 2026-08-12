/**
 * mcp.js - Static analysis rule engine for Model Context Protocol (MCP) Server Configs.
 * Audits mcp.json, config.json, settings.json, mcp_servers.json files for security flaws,
 * wildcard permission grants, unencrypted secrets, and insecure endpoints.
 */

const McpPatterns = {
  language: 'mcp',
  category: 'agent',
  filenames: [
    'mcp.json',
    'mcp_servers.json',
    'mcp.config.json',
    'config.json',
    'settings.json',
  ],
  extensions: ['.mcp.json', '.json', '.jsonc'],
  patterns: {
    // Example: "command(.*)" or "write_file(.*)" in permission grants
    // Flags wildcard permission grants allowing agents unrestricted shell/file access
    overly_permissive_mcp_grant:
      /["']?command\(\.\*\)["']?|["']?write_file\(\.\*\)["']?|["']?read_file\(\.\*\)["']?|["']?\*["']?\s*:\s*["']?\*["']?/gi,

    // Example: "env": { "API_KEY": "sk-proj-12345..." }
    // Detects unencrypted secret keys or bearer tokens stored in MCP server environment blocks
    unencrypted_mcp_env_secret:
      /["']?(api_?key|secret|password|token|auth_?token)["']?\s*:\s*["'][^"']{10,}["']/gi,

    // Example: Tool definition schema with "type": "string" and no enum/pattern bounds for eval
    // Flags unsafe MCP tool schemas that allow arbitrary execution parameters
    unsafe_mcp_tool_schema:
      /["']?commandLine["']?\s*:\s*\{\s*["']?type["']?\s*:\s*["']?string["']?\s*\}/gi,

    // Example: "host": "0.0.0.0" or "bind": "0.0.0.0"
    // Flags MCP servers listening on public network interfaces
    exposed_mcp_endpoint:
      /["']?(host|bind|listen|address)["']?\s*:\s*["']?0\.0\.0\.0["']?/gi,

    // Example: MCP server endpoint missing authentication tokens or headers
    // Flags unauthenticated MCP connections
    missing_mcp_auth:
      /["']?auth["']?\s*:\s*false|["']?no_auth["']?\s*:\s*true/gi,

    // Example: Granting full root directory access "/" or "C:\\"
    // Flags unrestricted filesystem scoping in MCP server path settings
    unrestricted_mcp_scope:
      /["']?(root|path|dir|workspace)["']?\s*:\s*["']?(\/|[a-zA-Z]:\\\\?)["']?/gi,
  },
  function_regex: /"mcpServers"\s*:\s*\{|"tools"\s*:\s*\[/,
  ignore_functions: [],
  critical_functions: ['exec', 'spawn', 'run_command'],
  void_return_indicator: 'N/A',
};

module.exports = { McpPatterns };
