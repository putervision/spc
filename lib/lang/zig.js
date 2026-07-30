const ZigPatterns = {
  extensions: ['.zig'],

  patterns: {
    // Recursion e.g., fn factorial(n: u32) u32 { return factorial(n - 1); }
    recursion: /fn\s+(\w+)\s*\([^)]*\)\s*[^{\n]*\{(?:[^}]*?\b\1\s*\()/g,

    // Dynamic memory allocation e.g., allocator.create(T), allocator.alloc(T, n)
    dynamic_memory: /\b\w+\.(create|alloc|dupe|realloc|free)\s*\(/g,

    // Complex flow control e.g., goto, return inside multiple branches
    complex_flow: /\b(goto\s+\w+|break\s+:\w+)/g,

    // Async / async call risks e.g., async foo(), await frame
    async_risk: /\b(async\s+\w+|await\s+\w+|nosuspend)/g,

    // Unbounded loops e.g., while (true) {}
    unbounded_loops: /\bwhile\s*\(\s*true\s*\)\s*\{/g,

    // Unsafe eval/inline assembly e.g., asm volatile (...)
    eval_usage: /\basm\s+(?:volatile\s*)?\(/g,

    // Global mutable variables e.g., var global_var: i32 = 0;
    global_vars: /^\s*(?:pub\s+)?var\s+\w+[\w\d_]*\s*:\s*[^=]+=/gm,

    // Unhandled try / catch block suppression
    try_catch: /\bcatch\s*\|\s*_\s*\|/g,

    // Delay / sleep functions e.g., std.time.sleep(...)
    set_timeout: /\bstd\.time\.sleep\s*\(/g,

    // Multiple returns in single function
    multiple_returns:
      /fn\s+\w+\s*\([^)]*\)[^{]*\{[\s\S]*?return[\s\S]*?return/g,

    // Nested conditionals (2+ depth)
    nested_conditionals: /(if\s*\([^)]+\)\s*\{[^}]*){2,}/g,

    // Security & Unsafe Patterns

    // Unchecked user input / arguments e.g., std.process.args()
    unsafe_input: /\b(std\.process\.args|std\.io\.getStdIn)\s*\(/g,

    // Network connections e.g., std.net.StreamServer, std.net.tcpConnectToAddress
    network_call:
      /\bstd\.net\.(tcpConnectToAddress|StreamServer|connect|listen)/g,

    // Weak crypto e.g., std.crypto.hash.Md5, std.crypto.hash.Sha1
    weak_crypto: /\bstd\.crypto\.hash\.(Md5|Sha1)\b/g,

    // Unsafe file operations e.g., std.fs.cwd().openFile
    unsafe_file_op: /\bstd\.fs\.\w+\.(openFile|createFile|deleteFile)\s*\(/g,

    // Unsafe raw pointers or undefined @ptrCast / @intToPtr
    unsafe_pointer: /\b(@ptrCast|@intToPtr|@alignCast|@fieldParentPtr)\s*\(/g,

    // Hardcoded secrets / API keys
    exposed_secrets:
      /(?:const|var)\s+\w*(secret|key|password|token)\w*\s*:\s*\[\]const\s+u8\s*=\s*["'][^"']+["']/gi,
  },

  function_regex: /^\s*(?:pub\s+)?fn\s+\w+\s*\([^)]*\)/,

  ignore_functions: [
    'std.debug.print',
    'std.log.info',
    'std.log.err',
    'std.time.sleep',
  ],

  critical_functions: ['std.net.tcpConnectToAddress', 'std.fs.cwd().openFile'],

  void_return_indicator: 'void',
};

module.exports = { ZigPatterns };
