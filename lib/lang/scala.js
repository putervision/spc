const ScalaPatterns = {
  extensions: ['.scala', '.sc'], // File extensions for Scala files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*:\s*\w+\s*=\s*{[^}]*?\b\1\s*\(/g,
    dynamic_memory: /\b(List\.fill|Array\.ofDim|Set\s*<\w+>)\s*\(/g,
    complex_flow:
      /^.*\b(break\s*(?:\s*(break|continue|return))?|continue\s*(?:\s*(break|continue|return))?|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|throw\s+[^;]+;\s*$(?:\s*(return|throw\s+[^;]+))?)/gm,
    async_risk: /\b(Future\s*{|Await\.result)/g,
    unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\([^)]*\))/g,
    eval_usage: /\b(scala\.tools\.nsc\s*\()/g,
    global_vars: /\b(val|var)\s+\w+\s*:\s*\w+\s*=|^object\s+\w+/g,
    try_catch: /\b(try\s*{)/g,
    set_timeout: /\b(Thread\.sleep\s*\()/g,
    multiple_returns:
      /def\s+\w+\s*\([^)]*\)\s*:\s*\w+\s*=\s*{[^}]*return[^}]*return/g,
    nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,
    unsafe_input:
      /\b(scala\.io\.StdIn\.readLine|Source\.fromFile)\s*(?![^.]*?\.(length|isEmpty|validate))/g,
    network_call: /\b(scala\.io\.Source\.fromURL|Http\s*\()/g,
    weak_crypto: /\b(scala\.util\.Random\.next)\s*\(/g,
    unsafe_file_op:
      /\b(scala\.io\.Source\.fromFile|Files\.write)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(println\s*\([^;]*\))/g, // Simplified
    unsanitized_exec: /\b(scala\.sys\.process\s*\.\s*!\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(val|var)\s*\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    unrestricted_cors: null, // Less relevant, but could adapt for web frameworks
  },
  function_regex: /^def\s+\w+\s*\([^)]*\)\s*:\s*\w+\s*=\s*{/,
  ignore_functions: ['println', 'print'],
  critical_functions: ['scala.io.Source.fromURL', 'Files.write'],
  void_return_indicator: 'println',
};

module.exports = { ScalaPatterns };
