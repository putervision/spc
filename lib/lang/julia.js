const JuliaPatterns = {
  extensions: ['.jl'],

  patterns: {
    // Recursion e.g., function factorial(n) return factorial(n-1) * n end
    recursion: /function\s+(\w+)\s*\([^)]*\)(?:[^end]*?\b\1\s*\()/g,

    // Dynamic memory allocations e.g., Vector{Any}(), zeros(), Array{Float64}(undef, n)
    dynamic_memory:
      /\b(Vector|Matrix|Array|zeros|ones|fill|undef)\s*(?:\{[^}]*\})?\s*\(/g,

    // Complex flow control e.g., @goto, return in multiple paths
    complex_flow: /\b(@goto|@label)\b/g,

    // Async / threading risks e.g., @async, @spawn, Fetch
    async_risk: /@\b(async|spawn|threads|distributed)\b/g,

    // Unbounded loops e.g., while true ... end
    unbounded_loops: /\bwhile\s+true\b/g,

    // Metaprogramming / eval risk e.g., eval(Meta.parse(...))
    eval_usage: /\b(eval|Meta\.parse)\s*\(/g,

    // Global variable declaration e.g., global x = 10
    global_vars: /\bglobal\s+\w+\s*=/g,

    // Try-catch without handling e.g., try ... catch end
    try_catch: /\btry\b[\s\S]*?\bcatch\s*end\b/g,

    // Sleep calls e.g., sleep(1.0)
    set_timeout: /\bsleep\s*\(/g,

    // Multiple returns in single function
    multiple_returns:
      /function\s+\w+\s*\([^)]*\)[\s\S]*?return[\s\S]*?return[\s\S]*?end/g,

    // Nested conditionals
    nested_conditionals: /(if\s+[^end]+\n\s*if\s+)/g,

    // Security & Unsafe Patterns

    // Unsafe input reading e.g., readline(), ARGS
    unsafe_input: /\b(readline|readavailable|ARGS)\b/g,

    // Network calls e.g., HTTP.get, Sockets.connect
    network_call: /\b(HTTP\.get|HTTP\.post|Sockets\.connect)\s*\(/g,

    // Weak cryptography e.g., SHA.sha1, rand() for crypto
    weak_crypto: /\b(SHA\.sha1|Random\.randstring)\b/g,

    // Unsafe file operations e.g., open(..., "w"), rm(...)
    unsafe_file_op: /\b(open|rm|mv|cp)\s*\(\s*["'][^"']+["']\s*,\s*["']w/g,

    // Hardcoded secrets / API keys
    exposed_secrets:
      /\b(\w*(secret|key|password|token)\w*)\s*=\s*["'][^"']+["']/gi,
  },

  function_regex: /^function\s+\w+\s*\([^)]*\)|^(\w+)\s*\([^)]*\)\s*=/,

  ignore_functions: ['println', 'print', 'sleep', 'display'],

  critical_functions: ['HTTP.get', 'Sockets.connect', 'open'],

  void_return_indicator: 'nothing',
};

module.exports = { JuliaPatterns };
