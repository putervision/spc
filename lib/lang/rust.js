const RustPatterns = {
  extensions: ['.rs'], // File extensions for Rust files

  patterns: {
    // Example: fn factorial(n: i32) -> i32 { factorial(n-1) * n }
    recursion: /fn\s+(\w+)\s*\([^)]*\)\s*->\s*\w+\s*\{(?:[^}]*?\b\1\s*\()/g,

    // Example: let v = vec![0; 100];
    dynamic_memory:
      /\b(vec!|Box::new|Vec::new|HashMap::new|HashSet::new)\s*\[/g,

    // Example: if x > 0 { break; } or return x + y;
    complex_flow:
      /^.*\b(break\s+[^;]+|continue\s+[^;]+|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|panic!\s*\([^)]*\);\s*$(?:\s*(return|panic!\s*\([^)]*\))?))/gm,

    // Example: async fn foo() {} or tokio::spawn(async {})
    async_risk: /\b(async\s+fn|await|tokio::spawn|std::thread::spawn)/g,

    // Example: loop {} or while true {}
    unbounded_loops: /\b(loop\s*\{|while\s+true\s*\{)/g,

    // Example: eval("code") not common, but unsafe {} can be similar
    eval_usage: /\bunsafe\s*\{/g,

    // Example: static mut X: i32 = 5;
    global_vars: /\bstatic\s+(mut\s+)?\w+\s*:/g,

    // Example: panic!("error") or match { Err(_) => {} }
    try_catch: /\b(panic!|match\s+[^;{]+\s*\{\s*Err\s*\()/g,

    // Example: std::thread::sleep(Duration::from_secs(1));
    set_timeout:
      /\b(std::thread::sleep|tokio::time::sleep|std::time::Duration)/g,

    // Example: fn foo() -> i32 { if x { return 1 }; return 2 }
    multiple_returns:
      /fn\s+\w+\s*\([^)]*\)\s*->\s*\w+\s*\{[^}]*return[^}]*return/g,

    // Example: if x { if y { do_something(); } }
    nested_conditionals: /(if\s+[^;{]+\s*{[^}]*){2,}/g,

    // Security-specific patterns

    // Example: let data = req.uri().query().unwrap();
    unsafe_input:
      /\b(req\.uri\(\)\.query|std::env::args|std::io::stdin\(\)\.read_line|File::open\(\)\.unwrap\(\)\.read|std::net::TcpStream::read)\b\s*(?![^.]*?\.(is_empty|len|contains|validate|parse)|[^;{]*?(if\s+\w+\.\w+|match\s+\w+\s*\{))/gi,

    // Example: reqwest::get("http://api")
    network_call: /\b(reqwest::get|std::net::TcpStream::connect|http::Client)/g,

    // Example: let hash = md5::compute("data");
    weak_crypto: /\b(md5::compute|sha1::Sha1::new|rand::random)/g,

    // Example: File::open("file.txt")
    unsafe_file_op: /\b(File::open|File::create|fs::read)/g,

    // Example: fn handle(req: Request) -> Response { Response::new("OK") }
    insufficient_logging:
      /\b(fn\s+\w+\s*\([^)]*Request[^)]*\)\s*->\s*\w+\s*\{(?:[^}]*?(?!log::)[^}]*?)*})/g,

    // Example: Command::new("sh").arg(input).spawn()
    unsanitized_exec: /\b(Command::new\s*\([^)]*\)\.arg\s*\([^)]*\+\s*\w+\))/g,

    // Example: const API_KEY: &str = "xyz123";
    exposed_secrets:
      /(?:const|static)?\s*\b(\w*(secret|key|password|token)\w*)\s*:\s*[^=]*=\s*["'][^"']+["']/gi,
  },

  function_regex: /^fn\s+\w+\s*\([^)]*\)\s*->\s*\w+\s*{/,

  ignore_functions: ['println!', 'eprintln!', 'log::info'],

  critical_functions: [
    'reqwest::get',
    'crypto::rand::random',
    'TcpStream::connect',
  ],

  void_return_indicator: '', // Rust uses () for unit type (void-like)
};

module.exports = { RustPatterns };
