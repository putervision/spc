const RubyPatterns = {
  extensions: ['.rb'], // File extensions for Ruby files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*(?:do|{)[^}]*?\b\1\s*\(/g,
    dynamic_memory: /\b(Array\.new|Hash\.new)\s*\(/g,
    complex_flow:
      /^.*\b(break\s+[^;]*(?:\s*(break|next|return))?|next\s+[^;]*(?:\s*(break|next|return))?|return\s+[^;]*(?:\s*return\s+[^;]*)?|raise\s+[^;]*(?:\s*(return|raise\s+[^;]*))?|retry|redo)/gm,
    async_risk: /\b(Thread\.new|fork)/g,
    unbounded_loops: /\b(while\s+[^do]+do|loop\s+do)/g,
    eval_usage: /\b(eval|instance_eval|class_eval|module_eval)\s*\(/g,
    global_vars: /\b(\$\w+\s*=)/g,
    try_catch: /\b(rescue\s+)/g,
    set_timeout: /\b(sleep\s+\d+)/g,
    multiple_returns:
      /def\s+\w+\s*(?:\([^)]*\))?\s*(?:[^}]*return[^}]*return)/g,
    nested_conditionals: /(if\s+[^;]+(?:\s*(?:if\s+[^;]+){1,}))/g,
    unsafe_input:
      /\b(gets|ARGV|STDIN\.read)\s*(?![^.]*?\.(chomp|strip|validate))/g,
    network_call: /\b(Net::HTTP\.get|open-uri\.open)\s*\(/g,
    weak_crypto: /\b(Digest::MD5|Digest::SHA1)\s*\(/g,
    unsafe_file_op: /\b(File\.read|File\.write)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(puts\s*\([^;]*\))/g, // Simplified
    unsanitized_exec: /\b(`[^`]*\${[^}]*`)/g,
    exposed_secrets:
      /\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    unrestricted_cors: null, // Less relevant, but could adapt for Rack
  },
  function_regex: /^def\s+\w+\s*(?:\([^)]*\))?\s*(?:do|{)/,
  ignore_functions: ['puts', 'print'],
  critical_functions: ['Net::HTTP.get', 'File.read'],
  void_return_indicator: 'puts',
};

module.exports = { RubyPatterns };
