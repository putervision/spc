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
    multiple_returns: /\b\w+\s*=\s*do[^=\n]*\breturn\b[^=\n]*\breturn\b/g,
    nested_conditionals:
      /\bif\s+[^=\n]+then[^\n]*\bif\s+[^=\n]+then[^\n]*\bif\s+[^=\n]+then/g,
    unsafe_input: /\b(getLine|readFile)\s*(?![^.]*?\.(length|null|validate))/g,
    network_call: /\b(httpGET|httpPOST)\s*\(/g,
    weak_crypto: /\b(randomIO\s*\()/g,
    insecure_random: /\b(randomIO|randomR)\b/g,
    unsafe_file_op: /\b(writeFile|appendFile)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(putStrLn\s*\([^;]*\))/g,
    unsanitized_exec: /\b(system\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]/gi,
  },
  function_regex: /^\w+\s*(?:\([^)]*\))?\s*=\s*(?:do\s*)?{/,
  ignore_functions: ['putStrLn', 'print'],
  critical_functions: ['httpGET', 'readFile'],
  void_return_indicator: 'putStrLn',
};

module.exports = { HaskellPatterns };
