const PHPPatterns = {
  extensions: ['.php', '.phtml'], // File extensions for PHP files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*\{[^}]*?\b\1\s*\(/g,
    dynamic_memory: /\b(array\s*\(|new\s+(ArrayObject|SplFixedArray))\s*\(/g,
    complex_flow:
      /^.*\b(goto\s+\w+|break\s+\d+|continue\s+\d+|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|throw\s+[^;]+;\s*$(?:\s*(return|throw\s+[^;]+))?|yield\s+[^;]*(?:\s*(yield|return|throw))?)/gm,
    async_risk: /\b(async\s+function|Fiber\s*\()/g,
    unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\(\s*[^;]*;\s*[^;]*;\s*\))/g,
    eval_usage: /\b(eval|create_function)\s*\(/g,
    global_vars: /\b(\$\w+\s*=|global\s+\$\w+)/g,
    try_catch: /\b(try\s*{)/g,
    set_timeout: /\b(sleep|usleep)\s*\(/g,
    multiple_returns: /function\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g,
    nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,
    unsafe_input:
      /\b(\$_GET|\$_POST|\$_REQUEST|file_get_contents)\s*(?![^.]*?\.(count|isset|validate))/g,
    network_call: /\b(curl_exec|file_get_contents\s*\(\s*['"]http)/g,
    weak_crypto: /\b(md5|sha1|rand)\s*\(/g,
    unsafe_file_op: /\b(file_put_contents|fopen)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(echo\s*\([^;]*\))/g, // Simplified
    unsanitized_exec: /\b(exec|shell_exec\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    unrestricted_cors:
      /\b(header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*['"]\s*\))/gi,
  },
  function_regex: /^function\s+\w+\s*\([^)]*\)\s*{/,
  ignore_functions: ['echo', 'print'],
  critical_functions: ['curl_exec', 'file_get_contents'],
  void_return_indicator: 'echo',
};

module.exports = { PHPPatterns };
