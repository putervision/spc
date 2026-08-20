/**
 * info.js - Rule metadata, categories, severities, agent tool schemas, and documentation links for @putervision/spc.
 */

const packageJson = require('../package.json');

const RULE_CATEGORIES = {
  NASA: 'nasa',
  SECURITY: 'security',
  QUALITY: 'quality',
  AGENT: 'agent',
};

const PATTERN_INFO = {
  // --- NASA Power of Ten & Reliability Rules ---
  recursion: {
    url: 'docs/nasa-rules.md#recursion',
    severity: 4,
    category: RULE_CATEGORIES.NASA,
  },
  dynamic_memory: {
    url: 'docs/nasa-rules.md#dynamic-memory',
    severity: 3,
    category: RULE_CATEGORIES.NASA,
  },
  complex_flow: {
    url: 'docs/nasa-rules.md#complex-flow',
    severity: 2,
    category: RULE_CATEGORIES.NASA,
  },
  async_risk: {
    url: 'docs/nasa-rules.md#async-risk',
    severity: 4,
    category: RULE_CATEGORIES.NASA,
  },
  unbounded_loops: {
    url: 'docs/nasa-rules.md#unbounded-loops',
    severity: 5,
    category: RULE_CATEGORIES.NASA,
  },
  global_vars: {
    url: 'docs/nasa-rules.md#global-vars',
    severity: 3,
    category: RULE_CATEGORIES.NASA,
  },
  try_catch: {
    url: 'docs/nasa-rules.md#try-catch',
    severity: 2,
    category: RULE_CATEGORIES.QUALITY,
  },
  set_timeout: {
    url: 'docs/nasa-rules.md#set-timeout',
    severity: 4,
    category: RULE_CATEGORIES.NASA,
  },
  multiple_returns: {
    url: 'docs/nasa-rules.md#multiple-returns',
    severity: 2,
    category: RULE_CATEGORIES.QUALITY,
  },
  nested_conditionals: {
    url: 'docs/nasa-rules.md#nested-conditionals',
    severity: 2,
    category: RULE_CATEGORIES.QUALITY,
  },
  exceeds_max_func_lines: {
    url: 'docs/nasa-rules.md#exceeds-max-function-lines',
    severity: 3,
    category: RULE_CATEGORIES.QUALITY,
  },
  unchecked_func_return: {
    url: 'docs/nasa-rules.md#unchecked-function-return',
    severity: 2,
    category: RULE_CATEGORIES.QUALITY,
  },
  unchecked_func_return_crit: {
    url: 'docs/nasa-rules.md#unchecked-function-return-critical',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },

  // --- Traditional Code Security Rules ---
  eval_usage: {
    url: 'docs/security-rules.md#eval-usage',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  unsafe_input: {
    url: 'docs/security-rules.md#unsafe-input',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  network_call: {
    url: 'docs/security-rules.md#network-call',
    severity: 3,
    category: RULE_CATEGORIES.SECURITY,
  },
  weak_crypto: {
    url: 'docs/security-rules.md#weak-crypto',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  unsafe_file_op: {
    url: 'docs/security-rules.md#unsafe-file-op',
    severity: 3,
    category: RULE_CATEGORIES.SECURITY,
  },
  insufficient_logging: {
    url: 'docs/security-rules.md#insufficient-logging',
    severity: 2,
    category: RULE_CATEGORIES.QUALITY,
  },
  unsanitized_exec: {
    url: 'docs/security-rules.md#unsanitized-exec',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  exposed_secrets: {
    url: 'docs/security-rules.md#exposed-secrets',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  unrestricted_cors: {
    url: 'docs/security-rules.md#unrestricted-cors',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  checksum_mismatch: {
    url: 'docs/cli-reference.md#checksums',
    severity: 4,
    category: RULE_CATEGORIES.QUALITY,
  },
  import_risk: {
    url: 'docs/security-rules.md#import-risk',
    severity: 3,
    category: RULE_CATEGORIES.SECURITY,
  },
  buffer_overflow_risk: {
    url: 'docs/security-rules.md#buffer-overflow-risk',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  unsafe_atom: {
    url: 'docs/security-rules.md#unsafe-atom',
    severity: 3,
    category: RULE_CATEGORIES.QUALITY,
  },
  unsafe_pointer: {
    url: 'docs/security-rules.md#unsafe-pointer',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  prototype_pollution: {
    url: 'docs/security-rules.md#prototype-pollution',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  xss_risk: {
    url: 'docs/security-rules.md#xss-risk',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  sql_injection: {
    url: 'docs/security-rules.md#sql-injection',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  ssrf_risk: {
    url: 'docs/security-rules.md#ssrf-risk',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  pickle_deserialize: {
    url: 'docs/security-rules.md#pickle-deserialize',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  yaml_load: {
    url: 'docs/security-rules.md#yaml-load',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  format_string: {
    url: 'docs/security-rules.md#format-string',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  use_after_free: {
    url: 'docs/security-rules.md#use-after-free',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  race_condition: {
    url: 'docs/security-rules.md#race-condition',
    severity: 3,
    category: RULE_CATEGORIES.QUALITY,
  },
  curl_pipe_bash: {
    url: 'docs/security-rules.md#curl-pipe-bash',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  sudo_nopasswd: {
    url: 'docs/security-rules.md#sudo-nopasswd',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  deserialization_risk: {
    url: 'docs/security-rules.md#deserialization-risk',
    severity: 5,
    category: RULE_CATEGORIES.SECURITY,
  },
  xxe_injection: {
    url: 'docs/security-rules.md#xxe-injection',
    severity: 4,
    category: RULE_CATEGORIES.SECURITY,
  },
  open_redirect: {
    url: 'docs/security-rules.md#open-redirect',
    severity: 3,
    category: RULE_CATEGORIES.SECURITY,
  },
  timing_attack: {
    url: 'docs/security-rules.md#timing-attack',
    severity: 3,
    category: RULE_CATEGORIES.SECURITY,
  },
  insecure_random: {
    url: 'docs/security-rules.md#insecure-random',
    severity: 3,
    category: RULE_CATEGORIES.SECURITY,
  },

  // --- AI / Agent / Skill Security Rules ---
  prompt_injection_hazard: {
    url: 'docs/ai-agent-rules.md#prompt-injection-hazard',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  unsafe_skill_command: {
    url: 'docs/ai-agent-rules.md#unsafe-skill-command',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  unbounded_agent_loop: {
    url: 'docs/ai-agent-rules.md#unbounded-agent-loop',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
  hardcoded_agent_secret: {
    url: 'docs/ai-agent-rules.md#hardcoded-agent-secret',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  overly_broad_tool_grant: {
    url: 'docs/ai-agent-rules.md#overly-broad-tool-grant',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
  missing_agent_guardrails: {
    url: 'docs/ai-agent-rules.md#missing-agent-guardrails',
    severity: 3,
    category: RULE_CATEGORIES.AGENT,
  },
  data_exfiltration_pattern: {
    url: 'docs/ai-agent-rules.md#data-exfiltration-pattern',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  recursive_agent_call: {
    url: 'docs/ai-agent-rules.md#recursive-agent-call',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },

  // --- MCP (Model Context Protocol) Server Config Rules ---
  overly_permissive_mcp_grant: {
    url: 'docs/ai-agent-rules.md#overly-permissive-mcp-grant',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  unencrypted_mcp_env_secret: {
    url: 'docs/ai-agent-rules.md#unencrypted-mcp-env-secret',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  unsafe_mcp_tool_schema: {
    url: 'docs/ai-agent-rules.md#unsafe-mcp-tool-schema',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
  exposed_mcp_endpoint: {
    url: 'docs/ai-agent-rules.md#exposed-mcp-endpoint',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
  missing_mcp_auth: {
    url: 'docs/ai-agent-rules.md#missing-mcp-auth',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
  unrestricted_mcp_scope: {
    url: 'docs/ai-agent-rules.md#unrestricted-mcp-scope',
    severity: 3,
    category: RULE_CATEGORIES.AGENT,
  },

  // --- LLM & Model Config Rules ---
  unsafe_model_deserialization: {
    url: 'docs/ai-agent-rules.md#unsafe-model-deserialization',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  insecure_model_endpoint: {
    url: 'docs/ai-agent-rules.md#insecure-model-endpoint',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
  unauthenticated_model_download: {
    url: 'docs/ai-agent-rules.md#unauthenticated-model-download',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
  unsafe_model_temperature: {
    url: 'docs/ai-agent-rules.md#unsafe-model-temperature',
    severity: 2,
    category: RULE_CATEGORIES.QUALITY,
  },
  exposed_model_api_key: {
    url: 'docs/ai-agent-rules.md#exposed-model-api-key',
    severity: 5,
    category: RULE_CATEGORIES.AGENT,
  },
  unvalidated_model_input: {
    url: 'docs/ai-agent-rules.md#unvalidated-model-input',
    severity: 4,
    category: RULE_CATEGORIES.AGENT,
  },
};

/**
 * Returns structured summary of tool capabilities and supported languages.
 */
function getCapabilities() {
  return {
    tool: 'space-proof-code',
    version: packageJson.version,
    description: packageJson.description,
    supportedLanguages: [
      'ada',
      'bash',
      'c',
      'cs',
      'elixir',
      'fortran',
      'go',
      'haskell',
      'java',
      'javascript',
      'julia',
      'kotlin',
      'lua',
      'php',
      'python',
      'ruby',
      'rust',
      'scala',
      'swift',
      'zig',
    ],
    supportedAiDomains: ['agent', 'mcp', 'model'],
    totalRules: Object.keys(PATTERN_INFO).length,
    outputFormats: ['table', 'json', 'md', 'sarif'],
    categories: Object.values(RULE_CATEGORIES),
    ruleCategories: RULE_CATEGORIES,
  };
}

/**
 * Returns machine-readable agent tool specification schema for LLM/MCP tool invocation.
 */
function getAgentToolSchema() {
  return {
    name: 'space-proof-code',
    version: packageJson.version,
    description: packageJson.description,
    operations: [
      {
        name: 'scanCodebase',
        description:
          'Scans a directory for NASA Power of Ten rules, traditional security vulnerabilities, and AI agent flaw patterns.',
        parameters: {
          type: 'object',
          properties: {
            directory: {
              type: 'string',
              description:
                'Directory path to scan (default: current directory)',
            },
            format: {
              type: 'string',
              enum: ['table', 'json', 'md', 'sarif'],
              default: 'table',
              description: 'Output format',
            },
            category: {
              type: 'string',
              enum: ['nasa', 'security', 'quality', 'agent'],
              description: 'Filter rules by category',
            },
            aiOnly: {
              type: 'boolean',
              default: false,
              description:
                'Scan only AI Agent skills, prompts, MCP configs & model files',
            },
            skipAi: {
              type: 'boolean',
              default: false,
              description:
                'Skip AI agent checks, scan traditional code languages only',
            },
            maxSeverityThreshold: {
              type: 'number',
              description: 'Exit non-zero if average severity risk level >= N',
            },
            maxIssueSeverityThreshold: {
              type: 'number',
              description: 'Exit non-zero if any single issue severity >= N',
            },
            failOnIssue: {
              type: 'boolean',
              default: false,
              description: 'Exit non-zero if any issues are detected',
            },
            createSums: {
              type: 'boolean',
              default: false,
              description: 'Generate SHA-256 checksum manifest file',
            },
          },
        },
      },
      {
        name: 'listRules',
        description:
          'Lists all 63+ supported rules with severities, categories, and documentation URIs.',
      },
      {
        name: 'getCapabilities',
        description:
          'Returns supported languages, AI domains, total rules, and output formats.',
      },
    ],
  };
}

module.exports = {
  RULE_CATEGORIES,
  PATTERN_INFO,
  getCapabilities,
  getAgentToolSchema,
};
