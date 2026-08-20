const FortranPatterns = {
  extensions: ['.f', '.f90', '.f95', '.f03'], // File extensions for Fortran files
  patterns: {
    recursion: /(?:subroutine|function)\s+(\w+)[^!\n]*call\s+\1\b/gim,
    dynamic_memory: /\b(allocate\s*\([^)]*\))/gim,
    complex_flow: /\b(go\s*to\s+\d+|exit|cycle|stop)\b/gim,
    async_risk: /\b(coarray\s+\w+|sync\s+all)/gim,
    unbounded_loops: /\bdo\s+while\s*\(\s*\.true\.\s*\)/gim,
    eval_usage: /\b(execute_command_line\s*\()/gim,
    global_vars: /\b(common\s*\/\w+\/\s*\w+)/gim,
    set_timeout: /\b(sleep\s*\()/gim,
    multiple_returns:
      /(?:subroutine|function)\s+\w+[^!\n]*\breturn\b[^!\n]*\breturn\b/gim,
    nested_conditionals:
      /\bif\s*\([^)]*\)\s*(?:then)?[^!\n]*\bif\s*\([^)]*\)\s*(?:then)?[^!\n]*\bif\s*\([^)]*\)/gim,
    unsafe_input: /\b(read\s*\([^)]*\))/gim,
    weak_crypto: /\b(random_number\s*\()/gim,
    insecure_random: /\brandom_number\s*\(/gim,
    unsafe_file_op: /\b(open\s*\([^)]*\)|write\s*\([^)]*\))/gim,
    insufficient_logging: /\b(print\s*\()/gim,
    unsanitized_exec: /\b(execute_command_line\s*\([^)]*\${[^}]*\))/gim,
    exposed_secrets:
      /\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]/gim,
  },
  function_regex:
    /^(subroutine|function)\s+\w+\s*(?:\([^)]*\))?\s*(?:result\s*\([^)]*\))?/i,
  ignore_functions: ['print', 'write'],
  critical_functions: ['read', 'open'],
  void_return_indicator: 'write',
};

module.exports = { FortranPatterns };
