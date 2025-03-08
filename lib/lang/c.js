const CPatterns = {
  extensions: ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp'],
  patterns: {
    // Example: int factorial(int n) { return factorial(n - 1); }
    // Detects recursive calls, risking stack overflow in space
    recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,

    // Example: int* ptr = malloc(10);
    // Flags dynamic memory allocation, risky in space constraints
    dynamic_memory: /\b(malloc|calloc|realloc|free)\s*\(/g,

    // Example: if (x) goto label; or return x + 1;
    // Identifies complex control flow, complicating verification
    complex_flow:
      /^.*\b(goto\s+\w+|break\s*;\s*$(?![^{]*?\b(break|continue|return))|continue\s*;\s*$(?![^{]*?\b(break|continue|return))|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?)/gm,

    // Example: while (1) {} or for(;;) {}
    // Catches unbounded loops, risking infinite execution
    unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\([^;]*;[^\n]*;[^\n]*\))/g,

    // Example: system("command");
    // Flags dynamic execution, unpredictable in space
    eval_usage: /\b(system|exec)\s*\(/g,

    // Example: int x = 5; (outside function)
    // Detects global variables, increasing side-effect risks
    global_vars: /^\w+\s+\w+\s*=/gm,

    // Example: try { risky_code(); }
    // Identifies exception handling (C++), potentially masking errors
    try_catch: /\btry\s*{/g,

    // Example: int foo() { if (x) return 1; return 0; }
    // Flags multiple returns, making flow harder to verify
    multiple_returns: /\w+\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g,

    // Example: if (x) { if (y) { do_something(); } }
    // Detects nested conditionals (2+ levels), increasing complexity
    nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,

    // Security-specific patterns

    // Example: scanf("%s", buffer);
    // Flags unvalidated inputs, vulnerable to RF injection
    unsafe_input:
      /\b(gets|fgets|scanf|cin\s*>>|read|recv|fstream\.read)\s*\([^)]*\)(?![^;{]*?(strlen|strcmp|empty|validate|parse|if\s+\w+\(|try\s+))/gi,

    // Example: socket(AF_INET, SOCK_STREAM, 0);
    // Detects network calls, potential RF data entry points
    network_call: /\b(socket|connect|send|recv)\s*\(/g,

    // Example: int r = rand();
    // Identifies weak crypto, exploitable in RF contexts
    weak_crypto: /\b(rand|srand)\s*\(/g,

    // Example: FILE* f = fopen("file.txt", "r");
    // Flags file ops without error handling, risky for RF paths
    unsafe_file_op: /\b(fopen|fread|fwrite)\s*\([^)]*\)/g,

    // Example: system(input);
    // Flags unsanitized execution, vulnerable to RF injection
    unsanitized_exec: /\b(system\s*\([^)]*[^"]\s*[^)]*\))/g,

    // Example: char* apiKey = "xyz123";
    // Detects hardcoded secrets, extractable via RF attacks
    exposed_secrets:
      /(?:char\s*\*|\w+\s*)\b(\w*(secret|key|password|token)\w*)\s*=\s*["][^"]+["]/gi,

    // Example: strcpy(dest, src);
    // Flags unsafe string ops, risking buffer overflows from RF data
    buffer_overflow_risk: /\b(strcpy|strcat|sprintf)\s*\(/g,

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
