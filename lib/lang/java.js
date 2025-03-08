const JavaPatterns = {
  extensions: ['.java'], // File extensions for Java files

  patterns: {
    // Example: public int factorial(int n) { return factorial(n - 1); }
    // Detects recursive method calls, which can overflow stack in space systems
    recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,

    // Example: int[] arr = new int[100];
    // Flags dynamic memory allocation, risky in constrained space environments
    dynamic_memory:
      /\bnew\s+(int\[\]|String\[\]|ArrayList|HashMap|HashSet|LinkedList)\s*(<[^>]*>)?\s*\(/g,

    // Example: if (x) break; or return x + y;
    // Identifies complex control flow (break, continue, multiple returns) that complicates verification
    complex_flow:
      /^.*\b(break\s+\w+|continue\s+\w+|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|throw\s+[^;]+;\s*$(?:\s*(return|throw\s+[^;]+))?)/gm,

    // Example: @Async public void foo() {} or CompletableFuture.supplyAsync(() -> bar());
    // Warns about asynchronous code, which can introduce non-determinism in real-time systems
    async_risk:
      /\b(@Async|CompletableFuture|FutureTask|ExecutorService|Thread\s*\(|Runnable\s*\()/g,

    // Example: while (true) {} or for(;;) {}
    // Catches loops without clear bounds, risking infinite execution in space
    unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\(\s*[^;]*;\s*[^;]*;\s*\))/g,

    // Example: ScriptEngine.eval("code");
    // Flags dynamic code execution, unpredictable and hard to verify in space software
    eval_usage: /\b(ScriptEngine|ScriptEngineManager)\s*\.\s*eval\s*\(/g,

    // Example: public static int x = 5;
    // Detects global (static) variables, which can lead to unintended side effects
    global_vars: /\bpublic\s+static\s+\w+\s+\w+\s*=|^static\s+\w+\s+\w+\s*=/g,

    // Example: try { riskyCode(); }
    // Identifies exception handling, which can mask errors in critical systems
    try_catch: /\btry\s*{/g,

    // Example: Thread.sleep(1000);
    // Flags timing-dependent code, non-deterministic in space real-time contexts
    set_timeout:
      /\b(Thread\s*\.\s*sleep|ScheduledExecutorService|Timer\s*\(|schedule\s*\()/g,

    // Example: public int foo() { if (x) return 1; return 2; }
    // Detects multiple return statements, making flow harder to verify
    multiple_returns:
      /public\s+\w+\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g,

    // Example: if (x) { if (y) { doSomething(); } }
    // Flags nested conditionals (2+ levels), increasing complexity and error risk
    nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,

    // Security-specific patterns

    // Example: String data = request.getParameter("payload");
    // Flags unvalidated inputs, vulnerable to RF-injected malicious data
    unsafe_input:
      /\b(request\.getParameter|System\.in\.read|BufferedReader\.readLine|Scanner\.next|FileReader|socket\.read)\s*\([^)]*\)(?![^.]*?\.(isEmpty|length|matches|validate|parse)|[^;{]*?(if\s+\w+\.\w+|try\s+))/gi,

    // Example: new URL("http://api").openConnection();
    // Detects network calls, potential entry points for untrusted RF data
    network_call:
      /\b(URL|HttpURLConnection|Socket|HttpClient|RestTemplate)\s*\.\s*(openConnection|connect|get|post)\s*\(/g,

    // Example: MessageDigest.getInstance("MD5");
    // Identifies weak crypto, exploitable in RF security contexts
    weak_crypto:
      /\b(MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA1)["']|Random\s*\()/g,

    // Example: new FileReader("file.txt");
    // Flags file ops without error handling, risky for RF-injected paths
    unsafe_file_op:
      /\b(FileReader|FileWriter|Files\.readAllBytes|Files\.write)\s*\(/g,

    // Example: public void handle(HttpServletRequest req) { resp.getWriter().write("OK"); }
    // Detects endpoints without logging, hindering RF attack tracing
    insufficient_logging:
      /\bpublic\s+\w+\s+\w+\s*\([^)]*(HttpServletRequest|ServletRequest)[^)]*\)\s*{(?:\s*[^}]*?(?!Logger|log)[^}]*?)*}/g,

    // Example: Runtime.getRuntime().exec("cmd " + input);
    // Flags unsanitized command execution, vulnerable to RF injection
    unsanitized_exec:
      /\b(Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\([^)]*\+\s*\w+\)/g,

    // Example: private String apiKey = "xyz123";
    // Detects hardcoded secrets, extractable via RF attacks or memory dumps
    exposed_secrets:
      /(?:private|public|protected)?\s*\b\w+\s+(\w*(secret|key|password|token)\w*)\s*=\s*["'][^"']+["']/gi,

    // Example: // Not directly applicable in standard Java (web frameworks like Spring may vary)
    // Flags unrestricted CORS, allowing unauthorized RF clients if web-exposed (Spring example)
    unrestricted_cors: /\b@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']\s*\)/g,
  },

  // Matches method definitions for length checks (e.g., public void foo() {})
  function_regex: /^(public|private|protected)?\s+\w+\s+\w+\s*\([^)]*\)\s*{/,

  // Language-specific exclusions for common void-like or safe methods
  ignore_functions: [
    'System.out.println',
    'System.err.println',
    'Thread.sleep',
    'logger.info',
  ],

  // Additional check for security-critical functions whose returns must be handled
  critical_functions: [
    'HttpURLConnection.connect',
    'MessageDigest.digest',
    'Cipher.doFinal',
    'Socket.connect',
  ],

  // Void return type indicator
  void_return_indicator: 'void',
};

module.exports = { JavaPatterns };
