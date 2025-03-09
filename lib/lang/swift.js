const SwiftPatterns = {
  extensions: ['.swift'], // File extensions for Swift files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*->\s*\w+\s*{[^}]*?\b\1\s*\(/g,
    dynamic_memory:
      /\b([A-Za-z]+\s*\(\s*capacity:\s*\d+\)|Array\s*<\w+>\s*\()/g,
    complex_flow:
      /^.*\b(break\s+\w+|continue\s+\w+|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|throw\s+[^;]+;\s*$(?:\s*(return|throw\s+[^;]+))?|fallthrough|guard\s+[^;]+else\s*{[^}]*?(break|return|throw))/gm,
    async_risk: /\b(async\s+|await\s+)/g,
    unbounded_loops: /\b(for\s+in\s+[^;]+{|while\s+[^;]+{)/g,
    eval_usage: /\b(NSExpression\s*\()/g,
    global_vars: /\b(var\s+\w+\s*:\s*\w+\s*=)/g,
    try_catch: /\b(try\s+)/g,
    set_timeout: /\b(DispatchQueue\.(asyncAfter|sync)|Thread\.sleep)/g,
    multiple_returns:
      /func\s+\w+\s*\([^)]*\)\s*->\s*\w+\s*{[^}]*return[^}]*return/g,
    nested_conditionals: /(if\s+[^;]+{\s*(?:[^}]*if\s+[^;]+{[^}]*){1,})/g,
    unsafe_input:
      /\b(readLine\s*\(|URLSession\.dataTask)\s*(?![^.]*?\.(count|isEmpty|validate))/g,
    network_call: /\b(URLSession\.dataTask|URLRequest)\s*\(/g,
    weak_crypto: /\b(SecRandomCopyBytes|arc4random)\s*\(/g,
    unsafe_file_op:
      /\b(FileManager\.default\.(contents|createFile))\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(print\s*\([^;]*\))/g, // Simplified
    unsanitized_exec: /\b(Process\s*\.\s*launch\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /\b(let|var)\s*\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    unrestricted_cors: null, // Not typically applicable
  },
  function_regex: /^func\s+\w+\s*\([^)]*\)\s*->\s*\w+\s*{/,
  ignore_functions: ['print', 'debugPrint'],
  critical_functions: ['URLSession.dataTask', 'FileManager.default.contents'],
  void_return_indicator: 'print',
};

module.exports = { SwiftPatterns };
