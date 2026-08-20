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
    unbounded_loops: /\b(while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))/g,
    eval_usage: /\b(ScriptEngine|ScriptEngineManager)\s*\.\s*eval\s*\(/g,
    global_vars: /\bpublic\s+static\s+\w+\s+\w+\s*=|^static\s+\w+\s+\w+\s*=/g,
    try_catch: /\btry\s*{/g,
    set_timeout:
      /\b(Thread\s*\.\s*sleep|ScheduledExecutorService|Timer\s*\(|schedule\s*\()/g,
    multiple_returns:
      /(?:public|private|protected)?\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*\breturn\b[^}]*\breturn\b/g,
    nested_conditionals:
      /\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)/g,
    unsafe_input:
      /\b(request\.getParameter|System\.in\.read|BufferedReader\.readLine|Scanner\.next|FileReader|socket\.read)\s*\(/gi,
    network_call:
      /\b(URL|HttpURLConnection|Socket|HttpClient|RestTemplate)\s*\.\s*(openConnection|connect|get|post)\s*\(/g,
    weak_crypto: /\bMessageDigest\.getInstance\s*\(\s*["'](MD5|SHA1)["']/g,
    insecure_random: /\bnew\s+Random\s*\(\s*\)|\bMath\.random\s*\(\s*\)/g,
    unsafe_file_op:
      /\b(FileReader|FileWriter|Files\.readAllBytes|Files\.write)\s*\(/g,
    insufficient_logging:
      /\bpublic\s+\w+\s+\w+\s*\([^)]*(HttpServletRequest|ServletRequest)[^)]*\)\s*{(?:\s*[^}]*?(?!Logger|log)[^}]*?)*}/g,
    unsanitized_exec:
      /\b(Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\([^)]*\+\s*\w+\)/g,
    exposed_secrets:
      /(?:private|public|protected|final)?\s*String\s+\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*["'][^"']{4,}["']/gi,
    unrestricted_cors: /\b@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']\s*\)/g,
    sql_injection:
      /\b(?:executeQuery|executeUpdate|execute)\s*\(\s*(?:["'][^"']*["']\s*\+|\w+\s*\+)/g,
    xss_risk:
      /\b(?:response\.getWriter\(\)\.write|out\.print(?:ln)?)\s*\([^)]*(?:request\.getParameter|userInput)/g,
    deserialization_risk:
      /\b(?:ObjectInputStream\s*\.\s*readObject|XMLDecoder)\s*\(/g,
    xxe_injection:
      /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\b/g,
    ssrf_risk:
      /\b(?:HttpURLConnection|HttpClient|RestTemplate|WebClient)\b(?=[\s\S]{0,100}\b(?:request\.getParameter|userInput)\b)/g,
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
