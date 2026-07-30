const ElixirPatterns = {
  extensions: ['.ex', '.exs'],

  patterns: {
    // Recursion e.g., def factorial(n), do: factorial(n-1) * n
    recursion: /def\s+(\w+)\s*\([^)]*\)[\s\S]*?\b\1\s*\(/g,

    // Dynamic process creation / memory e.g., Agent.start, Process.spawn
    dynamic_memory:
      /\b(Agent\.start|Task\.async|Process\.spawn|Task\.Supervisor)\b/g,

    // Complex flow control e.g., throw, exit
    complex_flow: /\b(throw|exit)\s*\(/g,

    // Async / Process risk e.g., spawn, Process.send
    async_risk: /\b(spawn|spawn_link|spawn_monitor|send)\s*\(/g,

    // Unbounded loops / infinite receive e.g., receive do ... end
    unbounded_loops: /\breceive\s+do[\s\S]*?end\b/g,

    // Dynamic code execution / eval e.g., Code.eval_string(...)
    eval_usage: /\bCode\.(eval_string|eval_quoted|eval_file)\s*\(/g,

    // Global state / module attribute dynamic mutation e.g., Process.put
    global_vars: /\bProcess\.put\s*\(/g,

    // Blank catch-all rescue e.g., rescue _ -> :ok
    try_catch: /rescue\s+_\s*->/g,

    // Process sleep e.g., Process.sleep(1000)
    set_timeout: /\bProcess\.sleep\s*\(/g,

    // Multiple returns / cond statements
    multiple_returns: /def\s+\w+[\s\S]*?return[\s\S]*?return/g,

    // Nested conditionals
    nested_conditionals: /(if\s+[^do]+\s+do[\s\S]*?if\s+)/g,

    // Security & Unsafe Patterns

    // Unsafe input reading e.g., IO.gets, System.argv
    unsafe_input: /\b(IO\.gets|System\.argv)\b/g,

    // Network call e.g., HTTPoison.get, Req.get
    network_call: /\b(HTTPoison|Tesla|Req|Mint)\.(get|post|request)\b/g,

    // Weak cryptography e.g., :crypto.hash(:md5, ...), :crypto.hash(:sha, ...)
    weak_crypto: /:crypto\.hash\s*\(\s*:(md5|sha)\b/g,

    // Unsafe file operation e.g., File.write!, File.rm!
    unsafe_file_op: /\bFile\.(write|write!|rm|rm!|rm_rf)\b/g,

    // Unsafe dynamic atom creation risk e.g., String.to_atom(...)
    unsafe_atom: /\bString\.to_atom\s*\(/g,

    // Hardcoded secrets / API keys
    exposed_secrets:
      /@?\b(\w*(secret|key|password|token)\w*)\s*=\s*["'][^"']+["']/gi,
  },

  function_regex: /^\s*defp?\s+\w+\s*\(?/,

  ignore_functions: ['IO.inspect', 'IO.puts', 'Process.sleep'],

  critical_functions: ['HTTPoison.get', 'File.write', 'Req.get'],

  void_return_indicator: ':ok',
};

module.exports = { ElixirPatterns };
