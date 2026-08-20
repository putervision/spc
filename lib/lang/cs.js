const CSharpPatterns = {
  extensions: ['.cs'], // File extensions for C# files
  patterns: {
    recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,
    dynamic_memory:
      /\bnew\s+(List|Dictionary|HashSet|Queue|Stack|Array)\s*<\w+>\s*\(/g,
    complex_flow:
      /^.*\b(goto\s+\w+|break\s+\w+|continue\s+\w+|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|throw\s+[^;]+;\s*$(?:\s*(return|throw\s+[^;]+))?|yield\s+(return|break)\s+[^;]+;)/gm,
    async_risk: /\b(async\s+\w+|await\s+)/g,
    unbounded_loops: /\b(while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))/g,
    eval_usage: /\b(Assembly\.Load|Type\.InvokeMember)\s*\(/g,
    global_vars: /\b(public|static)\s+\w+\s+\w+\s*=|this\.\w+\s*=/g,
    try_catch: /\btry\s*{/g,
    set_timeout: /\b(Task\.Delay|Thread\.Sleep)\s*\(/g,
    multiple_returns:
      /(?:public|private|protected)?\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*\breturn\b[^}]*\breturn\b/g,
    nested_conditionals:
      /\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)\s*\{[^{}]*\bif\s*\([^)]*\)/g,
    unsafe_input:
      /\b(Console\.ReadLine|Request\.Form|Request\.QueryString)\s*(?![^.]*?\.(Length|Contains|Validate))/g,
    network_call: /\b(HttpClient\.GetAsync|WebRequest\.Create)\s*\(/g,
    weak_crypto: /\b(MD5|SHA1)\.Create\s*\(/g,
    insecure_random: /\bnew\s+Random\s*\(/g,
    unsafe_file_op:
      /\b(File\.ReadAllText|File\.WriteAllText)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(Trace\.WriteLine|Debug\.WriteLine)\s*\(/g,
    unsanitized_exec: /\b(Process\.Start\s*\([^)]*\${[^}]*\))/g,
    exposed_secrets:
      /(?:const|string)?\s*\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]/gi,
    unrestricted_cors:
      /\b(EnableCors\s*\(\s*{[^}]*Origin\s*=\s*\*\s*[^}]*}\s*\))/gi,
    sql_injection:
      /\b(?:SqlCommand|OleDbCommand|SqlDataAdapter)\s*\(\s*(?:\$["']|["'][^"']*["']\s*\+)/g,
    xss_risk: /\bHtml\.Raw\s*\(/g,
    deserialization_risk:
      /\b(?:BinaryFormatter|NetDataContractSerializer|ObjectStateFormatter)\b/g,
    xxe_injection: /\b(?:XmlDocument|XmlTextReader|XPathDocument)\s*\(/g,
  },
  function_regex: /^(public|private|protected)?\s+\w+\s+\w+\s*\([^)]*\)\s*{/,
  ignore_functions: ['Console.WriteLine', 'Debug.WriteLine'],
  critical_functions: ['HttpClient.GetAsync', 'File.ReadAllText'],
  void_return_indicator: 'Console.',
};

module.exports = { CSharpPatterns };
