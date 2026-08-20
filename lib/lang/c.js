const CPatterns = {
  extensions: ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp'],
  patterns: {
    // Example: int factorial(int n) { return factorial(n - 1); }
    // Detects recursive calls, risking stack overflow in space
    recursion:
      /\b(?:int|void|char|double|float|long|short|unsigned|bool|\w+\s*\*)\s+(\w+)\s*\([^)]*\)\s*\{[^}]*?\b\1\s*\(/g,

    // Example: int* ptr = malloc(10);
    // Flags dynamic memory allocation, risky in space constraints
    dynamic_memory: /\b(malloc|calloc|realloc|free)\s*\(/g,

    // Example: if (x) goto label;
    // Identifies complex control flow, complicating verification
    complex_flow: /\bgoto\s+\w+/g,

    // Example: while (1) {} or for(;;) {}
    // Catches unbounded loops, risking infinite execution
    unbounded_loops: /\b(while\s*\(\s*(?:1|true)\s*\)|for\s*\(\s*;\s*;\s*\))/g,

    // Example: system("command");
    // Flags dynamic execution, unpredictable in space
    eval_usage: /\b(system|exec|popen)\s*\(/g,

    // Example: int x = 5; (at file scope)
    // Detects global variables, increasing side-effect risks
    global_vars: /^(?:static\s+)?[a-zA-Z_]\w*\s+[a-zA-Z_]\w*\s*=\s*[^;]+;/gm,

    // Example: try { risky_code(); }
    // Identifies exception handling (C++), potentially masking errors
    try_catch: /\btry\s*{/g,

    // Example: int foo() { if (x) return 1; return 0; }
    // Flags multiple returns, making flow harder to verify
    multiple_returns:
      /\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*\breturn\b[^}]*\breturn\b/g,

    // Example: if (x) { if (y) { if (z) { do_something(); } } }
    // Detects nested conditionals (3+ levels), increasing complexity
    nested_conditionals:
      /\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)/g,

    // Security-specific patterns

    // Example: scanf("%s", buffer);
    // Flags unvalidated inputs, vulnerable to RF injection
    unsafe_input: /\b(gets|scanf|fgets)\s*\(/g,

    // Example: socket(AF_INET, SOCK_STREAM, 0);
    // Detects network calls, potential RF data entry points
    network_call: /\b(socket|connect|send|recv)\s*\(/g,

    // Example: DES_ecb_encrypt(...);
    // Identifies weak legacy crypto
    weak_crypto: /\b(DES_ecb_encrypt|MD5_|SHA1_)\s*\(/g,

    // Example: int r = rand();
    // Non-cryptographic PRNG
    insecure_random: /\b(rand|srand)\s*\(/g,

    // Example: FILE* f = fopen("file.txt", "r");
    // Flags file ops without error handling, risky for RF paths
    unsafe_file_op: /\b(fopen|fread|fwrite)\s*\([^)]*\)/g,

    // Example: system(input);
    // Flags unsanitized execution, vulnerable to RF injection
    unsanitized_exec: /\b(system|popen)\s*\(\s*[a-zA-Z_]\w*\s*\)/g,

    // Example: char* apiKey = "xyz123";
    // Detects hardcoded secrets, extractable via RF attacks
    exposed_secrets:
      /(?:char\s*\*|const\s+char\s*\*)\s*\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*["][^"]{4,}["]/gi,

    // Example: strcpy(dest, src);
    // Flags unsafe string ops, risking buffer overflows from RF data
    buffer_overflow_risk: /\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(/g,

    // Format string vulnerability: printf(user_buf)
    format_string:
      /\b(printf|sprintf|fprintf|snprintf|vprintf|vsprintf)\s*\(\s*([a-zA-Z_]\w*)\s*\)/g,

    // Use after free: free(ptr); ... ptr->...
    use_after_free: /\bfree\s*\(\s*(\w+)\s*\)\s*;[\s\S]{0,100}?\b\1\b/g,

    // SQL Injection in C database APIs
    sql_injection:
      /\b(sqlite3_exec|mysql_query)\s*\(\s*[^,]+,\s*(?:sprintf|strcat|\w+\s*\+)/g,

    // Timing attack on secret comparisons
    timing_attack:
      /\b(?:token|secret|password|hash|api_key|signature)\s*(?:==|!=)|(?:==|!=)\s*(?:token|secret|password|hash|api_key|signature)\b/g,

    // Race condition (TOCTOU)
    race_condition:
      /\b(access|stat)\s*\([^)]*\)[\s\S]{0,100}?\b(open|fopen|unlink|remove)\s*\(/g,

    // Example: int main() { return 0; }
    // Detects functions without logging, hindering RF tracing
    insufficient_logging:
      /\b(int|void)\s+\w+\s*\([^)]*\)\s*{(?:\s*[^}]*?(?!printf|fprintf|syslog)[^}]*?)*}/g,
  },
  // Matches function definitions for length checks (e.g., int foo() {})
  function_regex: /^\w+\s+\w+\s*\([^)]*\)\s*{/,

  // Language-specific exclusions for common void-like or safe functions
  ignore_functions: ['printf', 'fprintf', 'exit'],

  // Additional check for security-critical functions whose returns must be handled
  critical_functions: ['system', 'recv', 'send'],

  // Void return type indicator
  void_return_indicator: 'void',
};

module.exports = { CPatterns };
