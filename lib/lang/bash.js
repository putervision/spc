const BashPatterns = {
  extensions: ['.sh', '.bash', '.zsh', '.ksh', '.ash', '.env'],
  filenames: [
    'Dockerfile',
    'Makefile',
    'Rakefile',
    '.env',
    '.env.local',
    '.env.production',
    '.env.example',
  ],

  patterns: {
    // Recursion e.g., foo() { foo; }
    recursion: /^\s*(\w+)\s*\(\)\s*\{[^}]*?\b\1\b/gm,

    // Dynamic memory / resource allocation e.g., ulimit, dd
    dynamic_memory: /\b(ulimit|dd\s+if=)/g,

    // Complex flow control e.g., goto (rare), exit without code
    complex_flow: /\b(exit\s*$|break\s+\d+|continue\s+\d+)/gm,

    // Background job risk e.g., command & or nohup
    async_risk: /(&\s*$|nohup\s+|coproc\s+)/gm,

    // Unbounded loops e.g., while true; do ... done
    unbounded_loops: /\bwhile\s+(:\s*|true\s*);/g,

    // Command evaluation risk e.g., eval "$var", exec "$var"
    eval_usage: /\b(eval|exec)\s+["']?\$[A-Za-z0-9_]+/g,

    // Global exported variables e.g., export VAR=val
    global_vars: /\bexport\s+[A-Za-z0-9_]+=/g,

    // Suppressed errors e.g., command 2>/dev/null
    try_catch: /2>\s*\/dev\/null/g,

    // Sleep commands e.g., sleep 10
    set_timeout: /\bsleep\s+\d+/g,

    // Multiple returns / exits in a function
    multiple_returns: /(\w+)\s*\(\)\s*\{[\s\S]*?return[\s\S]*?return/g,

    // Nested conditionals e.g., if ...; then if ...; then
    nested_conditionals: /(if\s+[^;]+;\s*then[\s\S]*?if\s+[^;]+;\s*then)/g,

    // Security & Unsafe Patterns

    // Unquoted variable expansions e.g., rm -rf $DIR or cat $FILE
    unsafe_input:
      /\b(rm|cat|chmod|chown)\s+-(?:r|f|rf)*\s+\$[A-Za-z0-9_]+\b(?!\s*")/g,

    // Network commands e.g., curl, wget, nc, netcat
    network_call: /\b(curl|wget|nc|netcat|socat)\s+/g,

    // Weak hash / crypto commands e.g., md5sum, sha1sum
    weak_crypto: /\b(md5sum|sha1sum)\b/g,

    // Unsafe temp file creation e.g., /tmp/file$$
    unsafe_file_op: /\/tmp\/[A-Za-z0-9_$.*-]+/g,

    // Unsanitized execution via subshell e.g., $(cat $USER_INPUT)
    unsanitized_exec: /\$\([^)]*?\$[A-Za-z0-9_]+[^)]*?\)/g,

    // Hardcoded secrets / API keys
    exposed_secrets:
      /\b[A-Za-z0-9_]*(SECRET|KEY|PASSWORD|TOKEN|PASS)[A-Za-z0-9_]*\s*=\s*["'][^"']+["']/gi,
  },

  function_regex: /^\s*(?:function\s+)?\w+\s*\(\)\s*\{/,

  ignore_functions: ['echo', 'printf', 'sleep'],

  critical_functions: ['curl', 'wget', 'rm', 'eval'],

  void_return_indicator: 'return 0',
};

module.exports = { BashPatterns };
