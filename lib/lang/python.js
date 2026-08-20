const PythonPatterns = {
  extensions: ['.py', '.pyw'],
  patterns: {
    // Example: def factorial(n): return factorial(n - 1)
    // Detects recursive calls, risky for stack overflow in space systems
    recursion: /def\s+(\w+)\s*\([^)]*\):(?:[^:]*?\b\1\s*\()/g,

    // Example: data = list()
    // Flags dynamic memory allocation, problematic in constrained environments
    dynamic_memory: /\b(list|dict|set)\s*\(/g,

    // Example: while x: break or continue
    // Identifies complex control flow, complicating verification
    complex_flow: /\b(break|continue)\b/g,

    // Example: while True: pass
    // Catches unbounded loops, risking infinite execution
    unbounded_loops: /\b(while\s+(?:True|1)\s*:)/g,

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
    multiple_returns:
      /def\s+\w+\s*\([^)]*\):[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+return\b[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+return\b/g,

    // Example: if x: if y: if z: do_something()
    // Detects nested conditionals (3+ levels), increasing complexity
    nested_conditionals:
      /\bif\s+[^:]+:[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+if\s+[^:]+:[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+if\s+[^:]+:/g,

    // Example: from os import *
    // Flags wildcard imports, bloating code and adding unpredictability
    import_risk: /\bfrom\s+.*\s+import\s+\*/gm,

    // Security-specific patterns

    // Example: user_input = input()
    // Flags unvalidated inputs, vulnerable to RF injection
    unsafe_input: /\b(input|sys\.stdin\.readline|socket\.recv)\s*\(/g,

    // Example: requests.get("http://api")
    // Detects network calls, potential RF data entry points
    network_call:
      /\b(requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get)\s*\(/g,

    // Example: hash = hashlib.md5(data)
    // Identifies weak crypto, exploitable in security contexts
    weak_crypto: /\bhashlib\s*\.\s*(md5|sha1)\s*\(/g,

    // Example: r = random.random()
    // Insecure PRNG used in security contexts
    insecure_random:
      /\brandom\s*\.\s*(random|randint|choice|sample|randrange)\s*\(/g,

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
      /\b(os\.system|subprocess\.run|subprocess\.call|subprocess\.Popen)\s*\([^)]*(?:%|format|\+)/g,

    // Example: api_key = "xyz123"
    // Detects hardcoded secrets, extractable via RF attacks
    exposed_secrets:
      /\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]/gi,

    // Pickle unsafe deserialization
    pickle_deserialize:
      /\b(?:pickle|cPickle|_pickle)\s*\.\s*(?:loads?|Unpickler)\s*\(/g,

    // YAML load without safe loader
    yaml_load:
      /\byaml\s*\.\s*load\s*\(\s*[^,)]+\s*\)(?!\s*,\s*Loader\s*=\s*(?:yaml\.)?SafeLoader)/g,

    // SQL Injection
    sql_injection:
      /\b(?:cursor\.execute|execute_query|raw_query|session\.execute)\s*\(\s*(?:f['"][^'"]*\{|['"][^'"]*['"]\s*%|['"][^'"]*['"]\s*\.format\()/g,

    // SSRF
    ssrf_risk:
      /\b(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(\s*(?:request\.(?:GET|POST|args)|f['"]https?:\/\/\{)/g,

    // Open Redirect
    open_redirect:
      /\b(?:redirect|HttpResponseRedirect)\s*\(\s*(?:request\.(?:GET|POST|args)|url|next_url)\b/g,

    // Timing Attack
    timing_attack:
      /\b(?:token|secret|password|hash|api_key|signature)\s*(?:==|!=)|(?:==|!=)\s*(?:token|secret|password|hash|api_key|signature)\b/g,

    // XXE Injection
    xxe_injection: /\b(?:xml\.etree|lxml\.etree|xml\.dom\.minidom|xml\.sax)\b/g,

    // Deserialization Risk
    deserialization_risk: /\b(?:marshal\.loads|shelve\.open)\s*\(/g,
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
