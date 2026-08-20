const RubyPatterns = {
  extensions: ['.rb'], // File extensions for Ruby files
  patterns: {
    recursion: /def\s+(\w+)\s*(?:\([^)]*\))?[^e]*?\b\1\s*\(/g,
    dynamic_memory: /\b(Array\.new|Hash\.new)\s*\(/g,
    complex_flow:
      /^.*\b(break\s+[^;]*(?:\s*(break|next|return))?|next\s+[^;]*(?:\s*(break|next|return))?|return\s+[^;]*(?:\s*return\s+[^;]*)?|raise\s+[^;]*(?:\s*(return|raise\s+[^;]*))?|retry|redo)/gm,
    async_risk: /\b(Thread\.new|fork)/g,
    unbounded_loops: /\b(while\s+true\s+do|loop\s+do)/g,
    eval_usage: /\b(eval|instance_eval|class_eval|module_eval)\s*\(/g,
    global_vars: /\b(\$\w+\s*=)/g,
    try_catch: /\b(rescue\s+)/g,
    set_timeout: /\b(sleep\s+\d+)/g,
    multiple_returns:
      /def\s+\w+\s*(?:\([^)]*\))?[^e]*\breturn\b[^e]*\breturn\b/g,
    nested_conditionals:
      /\bif\s+[^;\n]+[^\n]*\bif\s+[^;\n]+[^\n]*\bif\s+[^;\n]+/g,
    unsafe_input:
      /\b(gets|ARGV|STDIN\.read)\s*(?![^.]*?\.(chomp|strip|validate))/g,
    network_call: /\b(Net::HTTP\.get|open-uri\.open)\s*\(/g,
    weak_crypto: /\b(Digest::MD5|Digest::SHA1)\s*\(/g,
    insecure_random: /\brand\s*\(/g,
    unsafe_file_op: /\b(File\.read|File\.write)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(puts\s*\([^;]*\))/g,
    unsanitized_exec: /\b(`[^`]*\${[^}]*`)/g,
    exposed_secrets:
      /\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]/gi,
    sql_injection:
      /\b(?:find_by_sql|where|execute)\s*\(\s*(?:["'][^"']*#\{|["'][^"']*["']\s*\+)/g,
    yaml_load: /\bYAML\s*\.\s*load\s*\(/g,
    deserialization_risk: /\bMarshal\s*\.\s*load\s*\(/g,
    ssrf_risk:
      /\bNet::HTTP\.(?:get|post)\s*\(\s*(?:params\[|URI\s*\(\s*params)/g,
    open_redirect: /\bredirect_to\s+(?:params\[|url|target)\b/g,
  },
  function_regex: /^def\s+\w+\s*(?:\([^)]*\))?\s*(?:do|{)/,
  ignore_functions: ['puts', 'print'],
  critical_functions: ['Net::HTTP.get', 'File.read'],
  void_return_indicator: 'puts',
};

module.exports = { RubyPatterns };
