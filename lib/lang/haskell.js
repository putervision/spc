const HaskellPatterns = {
  extensions: ['.hs', '.lhs'], // File extensions for Haskell files
  patterns: {
    recursion:
      /(\w+)\s*(?:\([^)]*\))?\s*=\s*(?:do\s*)?[^=]*?\b\1\s*(?:\([^)]*\))?/g,
    dynamic_memory: /\b(replicateM\s*\(|newArray\s*\()/g,
    complex_flow:
      /^.*\b(return\s+[^=]+(?![=>])(?:\s*return\s+[^=]+)?|throw\s+[^=]+(?:\s*(return|throw\s+[^=]+))?|case\s+[^=]+of\s*(?:[^}]*?\s*(->\s*[^;]+){2,}))/gm,
    async_risk: /\b(forkIO|async\s*\()/g,
    unbounded_loops: /\b(do\s+[^=]+<-|forever\s*\()/g,
    eval_usage: /\b(unsafePerformIO\s*\()/g,
    global_vars: /\b(\w+\s*::\s*\w+\s*=\s*[^-])/g,
    try_catch: /\b(catch\s*\()/g,
    set_timeout: /\b(threadDelay\s*\()/g,
    multiple_returns: /\b(\w+\s*=\s*do\s*[^=]*return[^=]*return)/g,
    nested_conditionals: /(if\s+[^=]+then\s*(?:[^=]*if\s+[^=]+then[^=]*){1,})/g,
    unsafe_input: /\b(getLine|readFile)\s*(?![^.]*?\.(length|null|validate))/g,
    network_call: /\b(httpGET|httpPOST)\s*\(/g,
    weak_crypto: /\b(randomIO\s*\()/g,
    unsafe_file_op: /\b(writeFile|appendFile)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(putStrLn\s*\([^;]*\))/g, // Simplified
    unsanitized_exec: /\b(system\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    unrestricted_cors: null, // Not applicable
  },
  function_regex: /^\w+\s*(?:\([^)]*\))?\s*=\s*(?:do\s*)?{/,
  ignore_functions: ['putStrLn', 'print'],
  critical_functions: ['httpGET', 'readFile'],
  void_return_indicator: 'putStrLn',
};

module.exports = { HaskellPatterns };
