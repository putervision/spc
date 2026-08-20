const LuaPatterns = {
  extensions: ['.lua'], // File extensions for Lua files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*(?:do|{)[^}]*?\b\1\s*\(/g,
    dynamic_memory: /\b(table\.create|table\.insert)\s*\(/g,
    complex_flow:
      /^.*\b(goto\s+\w+|break\s*(?:\s*(break|return))?|return\s+[^;]*(?:\s*return\s+[^;]*)?)/gm,
    async_risk: /\b(coroutine\.create|coroutine\.resume)/g,
    unbounded_loops: /\bwhile\s+true\s+do/g,
    eval_usage: /\b(load|loadstring|dofile)\s*\(/g,
    global_vars: /\b(_G\.\w+\s*=|\w+\s*=)/g,
    try_catch: /\b(pcall|xpcall)\s*\(/g,
    multiple_returns:
      /function\s+\w+\s*\([^)]*\)[^e]*\breturn\b[^e]*\breturn\b/g,
    nested_conditionals:
      /\bif\s+[^;\n]+then[^\n]*\bif\s+[^;\n]+then[^\n]*\bif\s+[^;\n]+then/g,
    unsafe_input: /\b(io\.read|os\.getenv)\s*(?![^.]*?\.(len|match|validate))/g,
    network_call: /\b(socket\.connect|http\.request)\s*\(/g,
    weak_crypto: /\b(math\.random)\s*\(/g,
    insecure_random: /\bmath\.random\s*\(/g,
    unsafe_file_op: /\b(io\.open|file:read)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(print\s*\([^;]*\))/g,
    unsanitized_exec: /\b(os\.execute\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]/gi,
  },
  function_regex: /^function\s+\w+\s*\([^)]*\)\s*(?:do|{)/,
  ignore_functions: ['print'],
  critical_functions: ['socket.connect', 'io.read'],
  void_return_indicator: 'print',
};

module.exports = { LuaPatterns };
