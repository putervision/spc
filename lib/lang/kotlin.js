const KotlinPatterns = {
  extensions: ['.kt'], // File extensions for Kotlin files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*:\s*\w+\s*{[^}]*?\b\1\s*\(/g,
    dynamic_memory: /\b(mutableListOf|arrayOf|hashMapOf|setOf)\s*<\w+>\s*\(/g,
    complex_flow:
      /^.*\b(break\s+\w+|continue\s+\w+|return(?:\s+[^;@]+|\s*@\w+)\s*[^;]+;\s*$(?:\s*return\s+[^;]+;)?|throw\s+[^;]+;\s*$(?:\s*(return|throw\s+[^;]+))?)/gm,
    async_risk: /\b(suspend\s+|coroutineScope\s+|launch\s+)/g,
    unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\([^)]*\))/g,
    eval_usage: /\b(ScriptEngineManager\s*\()/g,
    global_vars: /\b(val|var)\s+\w+\s*:\s*\w+\s*=|^object\s+\w+/g,
    try_catch: /\b(try\s*{)/g,
    set_timeout: /\b(delay\s*\(|Thread\.sleep\s*\()/g,
    multiple_returns:
      /fun\s+\w+\s*\([^)]*\)\s*:\s*\w+\s*{[^}]*return[^}]*return/g,
    nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,
    unsafe_input:
      /\b(readLine\s*\(|BufferedReader\s*\.\s*readLine)\s*(?![^.]*?\.(length|isEmpty|validate))/g,
    network_call: /\b(HttpURLConnection|OkHttpClient\s*\.\s*newCall)\s*\(/g,
    weak_crypto: /\b(MD5|SHA1|Random\s*\.\s*next)\s*\(/g,
    unsafe_file_op: /\b(File\s*\.\s*(readText|writeText))\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(println\s*\([^;]*\))/g, // Simplified
    unsanitized_exec: /\b(Runtime\s*\.\s*exec\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(val|var)\s*\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    unrestricted_cors: null, // Less relevant, but could adapt for server frameworks
  },
  function_regex: /^fun\s+\w+\s*\([^)]*\)\s*:\s*\w+\s*{/,
  ignore_functions: ['println', 'print'],
  critical_functions: ['HttpURLConnection', 'File.readText'],
  void_return_indicator: 'println',
};

module.exports = { KotlinPatterns };
