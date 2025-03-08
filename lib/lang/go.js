const GoPatterns = {
  extensions: ['.go'], // File extensions for Go files

  patterns: {
    // Example: func factorial(n int) int { return factorial(n-1) * n }
    recursion: /func\s+(\w+)\s*\([^)]*\)\s*(?:\w+\s*)?\{(?:[^}]*?\b\1\s*\()/g,

    // Example: arr := make([]int, 100)
    dynamic_memory: /\b(make|new)\s*\(\s*(\[\]|\*|\w+\s*\<[^>]*\>)/g,

    // Example: if x > 0 { break } or return x + y
    complex_flow:
      /\b(goto\s+\w+|break\s+\w+|continue\s+\w+|return\s+[^;]+;\s*(?:[^}]*?return\s+[^;]+;))/gm,

    // Example: go func() {} or <-ch
    async_risk: /\b(go\s+func|select\s*{|<-)/g,

    // Example: for {} or for true {}
    unbounded_loops: /\bfor\s*(?:\{\s*\}|true\s*\{)/g,

    // Example: exec.Command("sh", "-c", input)
    eval_usage: /\b(exec\.Command|os\.Exec)\s*\(/g,

    // Example: var GlobalVar int = 5
    global_vars: /\bvar\s+\w+\s+\w+\s*=|\b\w+\s*:=\s*[^;]+(?=;?\s*$)/g,

    // Example: defer func() { recover() }()
    try_catch: /\bdefer\s+func\s*\([^)]*\)\s*\{\s*recover\s*\(/g,

    // Example: time.Sleep(1 * time.Second)
    set_timeout: /\b(time\.Sleep|time\.After|time\.Tick)\s*\(/g,

    // Example: func foo() int { if x { return 1 }; return 2 }
    multiple_returns:
      /func\s+\w+\s*\([^)]*\)\s*\w+\s*\{[^}]*return[^}]*return/g,

    // Example: if x { if y { doSomething() } }
    nested_conditionals: /(if\s+[^;{]+\s*{[^}]*){2,}/g,

    // Security-specific patterns

    // Example: data := r.URL.Query().Get("key")
    unsafe_input:
      /\b(r\.URL\.Query|r\.FormValue|os\.Args|bufio\.NewReader\s*\(\s*[^)]*\)\.(ReadLine|ReadString)|net\.Conn\.Read)\b\s*(?![^.]*?\.(Len|Contains|Validate|Parse)|[^;{]*?(if\s+\w+\.\w+|error\s+\w+\s*:=))/gi,

    // Example: http.Get("http://api")
    network_call: /\b(http\.Get|http\.Post|net\.Dial|http\.Client)/g,

    // Example: hash := md5.New()
    weak_crypto: /\b(md5\.New|sha1\.New|rand\.Int)/g,

    // Example: ioutil.ReadFile("file.txt")
    unsafe_file_op: /\b(ioutil\.ReadFile|os\.Open|os\.Create)\s*\(/g,

    // Example: http.HandleFunc("/data", func(w, r) { w.Write([]byte("OK")) })
    insufficient_logging:
      /\b(http\.HandleFunc|http\.HandlerFunc)\s*\([^)]*func\s*\([^)]*\)\s*\{(?:[^}]*?(?!log\.Print)[^}]*?)*}/g,

    // Example: exec.Command("sh", "-c", input)
    unsanitized_exec: /\b(exec\.Command|os\.Exec)\s*\([^)]*\)\s*\+\s*\w+/g,

    // Example: apiKey := "xyz123"
    exposed_secrets:
      /(?:var\s+)?\b(\w*(secret|key|password|token)\w*)\s*:=\s*["'][^"']+["']/gi,
  },

  function_regex: /^func\s+\w+\s*\([^)]*\)\s*(?:\w+\s*)?\{/,

  ignore_functions: ['fmt.Println', 'log.Printf', 'time.Sleep'],

  critical_functions: ['http.Get', 'crypto/rand.Read', 'net.Dial'],

  void_return_indicator: '', // Go uses empty return for void-like functions
};

module.exports = { GoPatterns };
