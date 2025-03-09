const FortranPatterns = {
  extensions: ['.f', '.f90', '.f95', '.f03'], // File extensions for Fortran files
  patterns: {
    recursion:
      /(\w+)\s*(?:\([^)]*\))?\s*(?:result\s*\([^)]*\))?[^!]*call\s+\1/gim,
    dynamic_memory: /\b(allocate\s*\([^)]*\))/gim,
    complex_flow:
      /^.*\b(go\s+to\s+\d+|exit\s*(?:\w+)?|cycle\s*(?:\w+)?|return\s*(?:\d+)?\s*$(?:\s*return\s*(?:\d+)?)?|stop\s*(?:\d+)?\s*$(?:\s*(return|stop\s*(?:\d+)?)?))/gim,
    async_risk: /\b(coarray\s+\w+|sync\s+all)/gim,
    unbounded_loops: /\b(do\s*(?!while)[^!]*end\s+do)/gim,
    eval_usage: /\b(execute_command_line\s*\()/gim,
    global_vars: /\b(common\s*\/\w+\/\s*\w+)/gim,
    try_catch: null, // Fortran lacks traditional try-catch
    set_timeout: /\b(sleep\s*\()/gim,
    multiple_returns: /(subroutine|function)\s+\w+[^!]*return[^!]*return/gim,
    nested_conditionals:
      /(if\s*\([^)]*\)\s*(?:then\s*)?(?:[^!]*if\s*\([^)]*\)\s*(?:then\s*)?){1,})/gim,
    unsafe_input: /\b(read\s*\([^)]*\))/gim,
    network_call: null, // Limited native network support
    weak_crypto: /\b(random_number\s*\()/gim,
    unsafe_file_op: /\b(open\s*\([^)]*\)|write\s*\([^)]*\))/gim,
    insufficient_logging: /\b(print\s*\()/gim, // Simplified
    unsanitized_exec: /\b(execute_command_line\s*\([^)]*\${[^}]*\))/gim,
    exposed_secrets:
      /\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gim,
    unrestricted_cors: null, // Not applicable
  },
  function_regex:
    /^(subroutine|function)\s+\w+\s*(?:\([^)]*\))?\s*(?:result\s*\([^)]*\))?/i,
  ignore_functions: ['print', 'write'],
  critical_functions: ['read', 'open'],
  void_return_indicator: 'write',
};

module.exports = { FortranPatterns };
