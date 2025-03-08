const PythonPatterns = {
  extensions: ['.py', '.pyw'],
  patterns: {
    // Example: def factorial(n): return factorial(n - 1)
    // Detects recursive calls, risky for stack overflow in space systems
    recursion: /def\s+(\w+)\s*\([^)]*\):(?:[^:]*?\b\1\s*\()/g,

    // Example: data = list()
    // Flags dynamic memory allocation, problematic in constrained environments
    dynamic_memory: /\b(list|dict|set)\s*\(/g,

    // Example: while x: break or return x + y
    // Identifies complex control flow, complicating verification
    complex_flow:
      /^.*\b(break\s*$(?![^:]*?\b(break|continue|return))|continue\s*$(?![^:]*?\b(break|continue|return))|return\s+[^:]+(?:\s*return\s+[^:]+)*|raise\s+[^:]+(?:\s*(return|raise\s+[^:]+)*))/gm,

    // Example: while True: pass or for x in range(∞): pass
    // Catches unbounded loops, risking infinite execution
    unbounded_loops: /\b(while\s+[^:]+:|for\s+\w+\s+in\s+[^:]+:)$/gm,

    // Example: exec("code")
    // Flags dynamic code execution, unpredictable in space software
    eval_usage: /\b(exec|eval)\s*\(/g,

    // Example: global x
    // Detects global variables, increasing side-effect risks
    global_vars: /\bglobal\s+\w+/g,

    // Example: try: risky_code()
    // Identifies exception handling, potentially masking errors
    try_catch: /\btry:/g,

    // Example: def foo(): return 1; return 2
    // Flags multiple returns, making flow harder to verify
    multiple_returns: /def\s+\w+\s*\([^)]*\):[^:]*return[^:]*return/gm,

    // Example: if x: if y: do_something()
    // Detects nested conditionals (2+ levels), increasing complexity
    nested_conditionals: /(if\s+[^:]+:[^:]*){2,}/g,

    // Example: from os import *
    // Flags wildcard imports, bloating code and adding unpredictability
    import_risk: /\bfrom\s+.*\s+import\s+\*/gm,

    // Security-specific patterns

    // Example: user_input = sys.argv[1]
    // Flags unvalidated inputs, vulnerable to RF injection
    unsafe_input:
      /\b(input|sys\.stdin\.readline|socket\.recv|requests\.get|open\s*\([^)]*\)\.read)\b\s*(?![^.]*?\.(strip|len|isinstance|validate|parse|isdigit|isalpha)|[^;{]*?(if\s+\w+\.\w+|try\s+))/gi,

    // Example: requests.get("http://api")
    // Detects network calls, potential RF data entry points
    network_call:
      /\b(requests\.get|requests\.post|urllib\.request\.urlopen)\s*\(/g,

    // Example: hash = hashlib.md5(data)
    // Identifies weak crypto, exploitable in RF contexts
    weak_crypto: /\b(hashlib\.md5|hashlib\.sha1|random\.random)\s*\(/g,

    // Example: open("file.txt", "r")
    // Flags file ops without error handling, risky for RF paths
    unsafe_file_op: /\b(open\s*\([^)]*['"]\s*[rw]\s*['"]\))/g,

    // Example: @app.route("/data") def get(): return "OK"
    // Detects endpoints without logging, hindering RF tracing
    insufficient_logging:
      /@app\.(route|post)\s*\([^)]*\)\s*def\s+\w+\s*\([^)]*\):(?:\s+[^:]*?(?!print|logging)[^:]*?)*(?:\n|$)/gm,

    // Example: os.system(f"echo {input}")
    // Flags unsanitized execution, vulnerable to RF injection
    unsanitized_exec:
      /\b(os\.system|subprocess\.run|subprocess\.call)\s*\([^)]*%\s*[^)]*\)/g,

    // Example: api_key = "xyz123"
    // Detects hardcoded secrets, extractable via RF attacks
    exposed_secrets:
      /\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
  },
  // Matches function definitions for length checks (e.g., def foo():)
  function_regex: /^def\s+\w+\s*\([^)]*\):/,

  // Language-specific exclusions for common void-like or safe functions
  ignore_functions: ['print', 'sys.exit', 'logging.info'],

  // Additional check for security-critical functions whose returns must be handled
  critical_functions: ['requests.get', 'urllib.request.urlopen', 'os.system'],

  // Void return type indicator
  void_return_indicator: 'print',
};

module.exports = { PythonPatterns };
