const LuaPatterns = {
  extensions: ['.lua'], // File extensions for Lua files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*(?:do|{)[^}]*?\b\1\s*\(/g,
    dynamic_memory: /\b(table\.create|table\.insert)\s*\(/g,
    complex_flow:
      /^.*\b(goto\s+\w+|break\s*(?:\s*(break|return))?|return\s+[^;]*(?:\s*return\s+[^;]*)?)/gm,
    async_risk: /\b(coroutine\.create|coroutine\.resume)/g,
    unbounded_loops:
      /\b(while\s+[^do]+do|for\s+[^=]+=[^,]+,[^,]+(?:,[^,]+)?\s+do)/g,
    eval_usage: /\b(load|loadstring|dofile)\s*\(/g,
    global_vars: /\b(_G\.\w+\s*=|\w+\s*=)/g,
    try_catch: /\b(pcall|xpcall)\s*\(/g,
    set_timeout: /\b(os\.sleep|socket\.select)/g,
    multiple_returns: /function\s+\w+\s*\([^)]*\)[^}]*return[^}]*return/g,
    nested_conditionals: /(if\s+[^;]+then\s*(?:[^;]*if\s+[^;]+then[^;]*){1,})/g,
    unsafe_input: /\b(io\.read|os\.getenv)\s*(?![^.]*?\.(len|match|validate))/g,
    network_call: /\b(socket\.connect|http\.request)\s*\(/g,
    weak_crypto: /\b(math\.random)\s*\(/g,
    unsafe_file_op: /\b(io\.open|file:read)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(print\s*\([^;]*\))/g, // Simplified
    unsanitized_exec: /\b(os\.execute\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    unrestricted_cors: null, // Not applicable
  },
  function_regex: /^function\s+\w+\s*\([^)]*\)\s*(?:do|{)/,
  ignore_functions: ['print'],
  critical_functions: ['socket.connect', 'io.read'],
  void_return_indicator: 'print',
};

module.exports = { LuaPatterns };
