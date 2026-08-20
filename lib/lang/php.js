const PHPPatterns = {
  extensions: ['.php', '.phtml'], // File extensions for PHP files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*\{[^}]*?\b\1\s*\(/g,
    dynamic_memory: /\b(array\s*\(|new\s+(ArrayObject|SplFixedArray))\s*\(/g,
    complex_flow:
      /^.*\b(goto\s+\w+|break\s+\d+|continue\s+\d+|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|throw\s+[^;]+;\s*$(?:\s*(return|throw\s+[^;]+))?|yield\s+[^;]*(?:\s*(yield|return|throw))?)/gm,
    async_risk: /\b(async\s+function|Fiber\s*\()/g,
    unbounded_loops: /\b(while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))/g,
    eval_usage: /\b(eval|create_function|assert)\s*\(/g,
    global_vars: /\b(global\s+\$\w+|\$GLOBALS\[)/g,
    try_catch: /\b(try\s*{)/g,
    set_timeout: /\b(sleep|usleep)\s*\(/g,
    multiple_returns:
      /function\s+\w+\s*\([^)]*\)\s*\{[^}]*\breturn\b[^}]*\breturn\b/g,
    nested_conditionals:
      /\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)/g,
    unsafe_input:
      /\b(\$_GET|\$_POST|\$_REQUEST|file_get_contents)\s*(?![^.]*?\.(count|isset|validate))/g,
    network_call: /\b(curl_exec|file_get_contents\s*\(\s*['"]http)/g,
    weak_crypto: /\b(md5|sha1)\s*\(/g,
    insecure_random: /\b(rand|mt_rand)\s*\(/g,
    unsafe_file_op: /\b(file_put_contents|fopen)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(echo\s*\([^;]*\))/g,
    unsanitized_exec: /\b(exec|shell_exec|system|passthru)\s*\([^)]*\$/g,
    exposed_secrets:
      /\$(?:api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\s*=\s*['"][^'"]{4,}['"]/gi,
    unrestricted_cors:
      /\b(header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*['"]\s*\))/gi,
    sql_injection:
      /\b(?:mysql_query|mysqli_query|\$pdo->(?:query|exec))\s*\(\s*(?:["'][^"']*\$|\$\w+\s*\.)/g,
    xss_risk: /\b(?:echo|print)\s+[^;]*(?:\$_GET|\$_POST|\$_REQUEST)/g,
    deserialization_risk:
      /\bunserialize\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$\w+)\s*\)/g,
    ssrf_risk:
      /\b(?:curl_init|file_get_contents)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$url)\s*\)/g,
    open_redirect:
      /\bheader\s*\(\s*['"]Location:\s*['"]\s*\.\s*(?:\$_GET|\$_POST|\$_REQUEST|\$url)/g,
    xxe_injection:
      /\bsimplexml_load_string\s*\([^)]*(?:LIBXML_NOENT|LIBXML_DTDLOAD)/g,
  },
  function_regex: /^function\s+\w+\s*\([^)]*\)\s*{/,
  ignore_functions: ['echo', 'print'],
  critical_functions: ['curl_exec', 'file_get_contents'],
  void_return_indicator: 'echo',
};

module.exports = { PHPPatterns };
