const JavaScriptPatterns = {
  extensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.vue', '.svelte'], // File extensions for JavaScript/TypeScript files
  patterns: {
    // Example: function factorial(n) { return factorial(n - 1); }
    // Detects recursive function calls, which can overflow stack in space systems
    recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,

    // Example: let arr = new Array(100);
    // Flags dynamic memory allocation, risky in constrained space environments
    dynamic_memory: /\bnew\s+(Array|Object|Map|Set|WeakMap|WeakSet)\s*\(/g,

    // Example: if (x) break; or continue loop1;
    // Identifies complex control flow that complicates verification
    complex_flow: /\b(break\s+\w+|continue\s+\w+|goto\s+\w+)/g,

    // Example: async function foo() {} or await fetch(url);
    // Warns about asynchronous code, which can introduce non-determinism in real-time systems
    async_risk: /\b(async\s+function|await)\b/g,

    // Example: while (true) {} or for(;;) {}
    // Catches loops without clear bounds, risking infinite execution in space
    unbounded_loops: /\b(while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))/g,

    // Example: eval("code");
    // Flags dynamic code execution, unpredictable and hard to verify in space software
    eval_usage: /\b(eval|Function)\s*\(/g,

    // Example: var x = 5; or window.y = 10;
    // Detects global variables, which can lead to unintended side effects
    global_vars: /\b(var\s+\w+|window\.\w+\s*=)/g,

    // Example: try { riskyCode(); }
    // Identifies exception handling, which can mask errors in critical systems
    try_catch: /\btry\s*{/g,

    // Example: setTimeout(doSomething, 1000);
    // Flags timing-dependent code, non-deterministic in space real-time contexts
    set_timeout: /\b(setTimeout|setInterval)\s*\(/g,

    // Example: function foo() { if (x) return 1; return 2; }
    // Detects multiple return statements, making flow harder to verify
    multiple_returns:
      /function\s+\w*\s*\([^)]*\)\s*\{[^}]*\breturn\b[^}]*\breturn\b/g,

    // Example: if (x) { if (y) { if (z) { doSomething(); } } }
    // Flags nested conditionals (3+ levels), increasing complexity and error risk
    nested_conditionals:
      /\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)/g,

    // Security-specific patterns

    // Example: const data = req.body.payload;
    // Flags unvalidated inputs, vulnerable to RF-injected malicious data
    unsafe_input:
      /\b(process\.argv|req\.(?:body|query|params)|prompt|window\.prompt)\b/gi,

    // Example: fetch("http://api");
    // Detects network calls, potential entry points for untrusted RF data
    network_call: /\b(fetch|http\.get|axios|request)\s*\(/g,

    // Example: const hash = md5("data");
    // Identifies weak crypto hashes, exploitable in security contexts
    weak_crypto: /\b(md5|sha1)\s*\(/g,

    // Example: const rand = Math.random();
    // Non-cryptographic PRNG used in security-sensitive contexts
    insecure_random: /\bMath\.random\s*\(\s*\)/g,

    // Example: fs.readFile("file.txt");
    // Flags file ops without error handling, risky for RF-injected paths
    unsafe_file_op:
      /\b(fs\.readFile|fs\.writeFile|fs\.appendFile)\s*\([^,]*[^&]*\)/g,

    // Example: app.get("/data", (req, res) => res.send("OK"));
    // Detects endpoints without logging, hindering RF attack tracing
    insufficient_logging:
      /\b(app|server)\.(get|post)\s*\([^)]*function\s*\([^)]*\)\s*{(?:\s*[^}]*?(?!console\.log|logger)[^}]*?)*}/g,

    // Example: exec(`echo ${input}`);
    // Flags unsanitized command execution, vulnerable to RF injection
    unsanitized_exec:
      /\b(exec|execSync|spawn|child_process)\s*\([^)]*\${[^}]*\)/g,

    // Example: const apiKey = "xyz123";
    // Detects hardcoded secrets, extractable via RF attacks or memory dumps
    exposed_secrets:
      /(?:const|let|var)\s+\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]/gi,

    // Example: app.use(cors({ origin: "*" }));
    // Flags unrestricted CORS, allowing unauthorized RF clients if web-exposed
    unrestricted_cors:
      /(app\.use\s*\(\s*cors\s*\(\s*{[^}]*origin\s*:\s*(?:\*\s*|"[^"]*\*[^"]*"\s*)(?:,[^}]*)?}\s*\))/gi,

    // Prototype pollution: obj.__proto__ or constructor.prototype
    prototype_pollution: /\b(__proto__|constructor\.prototype)\b/g,

    // XSS: direct DOM insertion without sanitization
    xss_risk:
      /\b(innerHTML|outerHTML|document\.write(?:ln)?|dangerouslySetInnerHTML)\b/g,

    // SQL Injection: unescaped template string or concatenation in queries
    sql_injection:
      /\b(?:query|execute|raw|sql)\s*\(\s*(?:`[^`]*\${|['"][^'"]*['"]\s*\+)/g,

    // SSRF: user-controlled fetch / axios URL
    ssrf_risk:
      /\b(?:fetch|axios(?:\.get|\.post)?|http\.get|https\.get|request)\s*\(\s*(?:req\.(?:query|body|params)|`https?:\/\/\${)/g,

    // Open Redirect
    open_redirect:
      /\bres\.redirect\s*\(\s*(?:req\.(?:query|body|params)|location|url|target)\b/g,

    // Timing Attack: standard string comparison on secrets
    timing_attack:
      /\b(?:token|secret|password|hash|apiKey|signature)\s*(?:===|!==)|(?:===|!==)\s*(?:token|secret|password|hash|apiKey|signature)\b/g,

    // Deserialization Risk
    deserialization_risk: /\b(?:serialize\.unserialize|node-serialize)\b/g,

    // Race Condition (TOCTOU file access)
    race_condition:
      /\bfs\.(?:existsSync|accessSync|access)\b(?=[\s\S]{0,100}\bfs\.(?:readFileSync|writeFileSync|unlinkSync|writeFile|readFile)\b)/g,
  },
  // Matches function definitions for length checks (e.g., function foo() {})
  function_regex: /^(function|const|let|var)\s+\w+\s*=?\s*\([^)]*\)\s*{/,

  // Language-specific exclusions for common void-like or safe functions
  ignore_functions: [
    'console.log',
    'console.error',
    'setTimeout',
    'setInterval',
  ],

  // Additional check for security-critical functions whose returns must be handled
  critical_functions: ['fetch', 'crypto.', 'http.get'],

  // Void return type indicator
  void_return_indicator: 'console.',
};

module.exports = { JavaScriptPatterns };
