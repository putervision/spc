/**
 * scanner.js - Core logic for @putervision/spc, a space-proofing code analysis tool.
 * Analyzes JavaScript/TypeScript, Python, and C/C++ codebases for patterns that compromise performance,
 * reliability, and security in high-stakes environments like space missions. Inspired by NASA's
 * Power of Ten rules, it enforces code quality through checks like bounded loops and small
 * functions, while adding security rules to detect vulnerabilities such as RF-based API
 * injection or exposed secrets. Exports `scanCodebase` to scan directories and report issues,
 * ensuring code is robust, verifiable, and secure for space-ready systems where failures
 * cannot be manually resolved.
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * Example: A function exceeding 60 lines, e.g., function processData() { // 61+ lines of code }
 * Defines the maximum allowed lines per function (60), enforcing NASA's Power of Ten Rule 4.
 * Keeps functions small and focused for readability, testability, and maintainability in space systems,
 * where long functions increase error risk and complicate verification.
 */
const MAX_FUNCTION_LINES = 60;

/**
 * Defines language-specific patterns for code quality and security checks in space-proofing.
 * Each pattern includes a regex to detect problematic code constructs, with examples showing
 * what triggers the check. Patterns are grouped by language (JavaScript/TypeScript, Python, C/C++).
 */
const LANGUAGE_PATTERNS = {
  javascript: {
    extensions: ['.js', '.ts', '.jsx'], // File extensions for JavaScript/TypeScript files
    patterns: {
      // Example: function factorial(n) { return factorial(n - 1); }
      // Detects recursive function calls, which can overflow stack in space systems
      recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,

      // Example: let arr = new Array(100);
      // Flags dynamic memory allocation, risky in constrained space environments
      dynamic_memory: /\bnew\s+(Array|Object|Map|Set|WeakMap|WeakSet)\s*\(/g,

      // Example: if (x) break; or return x + y;
      // Identifies complex control flow (break, continue, multiple returns) that complicates verification
      complex_flow: /\b(break|continue|return\s+[^;]+?;)/g,

      // Example: async function foo() {} or await fetch(url);
      // Warns about asynchronous code, which can introduce non-determinism in real-time systems
      async_risk: /\b(async\s+function|await)\b/g,

      // Example: while (true) {} or for(;;) {}
      // Catches loops without clear bounds, risking infinite execution in space
      unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\(\s*[^;]*;\s*[^;]*;\s*\))/g,

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
      multiple_returns: /function\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g,

      // Example: if (x) { if (y) { doSomething(); } }
      // Flags nested conditionals (2+ levels), increasing complexity and error risk
      nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,

      // Security-specific patterns

      // Example: const data = req.body.payload;
      // Flags unvalidated inputs, vulnerable to RF-injected malicious data
      unsafe_input:
        /\b(process\.argv|req\.body|req\.query|req\.params)\s*(?!\.\w+\s*===)/g,

      // Example: fetch("http://api");
      // Detects network calls, potential entry points for untrusted RF data
      network_call: /\b(fetch|http\.get|axios|request)\s*\(/g,

      // Example: const hash = md5("data");
      // Identifies weak crypto, exploitable in RF security contexts
      weak_crypto: /\b(md5|sha1|Math\.random)\s*\(/g,

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
        /(?:const|let|var)?\s*\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,

      // Example: app.use(cors({ origin: "*" }));
      // Flags unrestricted CORS, allowing unauthorized RF clients if web-exposed
      unrestricted_cors:
        /(app\.use\s*\(\s*cors\s*\(\s*{[^}]*origin\s*:\s*(?:\*\s*|"[^"]*\*[^"]*"\s*)(?:,[^}]*)?}\s*\))/gi,
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
  },
  python: {
    extensions: ['.py'],
    patterns: {
      // Example: def factorial(n): return factorial(n - 1)
      // Detects recursive calls, risky for stack overflow in space systems
      recursion: /def\s+(\w+)\s*\([^)]*\):(?:[^:]*?\b\1\s*\()/g,

      // Example: data = list()
      // Flags dynamic memory allocation, problematic in constrained environments
      dynamic_memory: /\b(list|dict|set)\s*\(/g,

      // Example: while x: break or return x + y
      // Identifies complex control flow, complicating verification
      complex_flow: /\b(break|continue|return\s+.+)$/gm,

      // Example: while True: pass or for x in range(∞): pass
      // Catches unbounded loops, risking infinite execution
      unbounded_loops: /\b(while\s+[^:]+:|for\s+\w+\s+in\s+[^:]+:)$/gm,

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
      multiple_returns: /def\s+\w+\s*\([^)]*\):[^:]*return[^:]*return/gm,

      // Example: if x: if y: do_something()
      // Detects nested conditionals (2+ levels), increasing complexity
      nested_conditionals: /(if\s+[^:]+:[^:]*){2,}/g,

      // Example: from os import *
      // Flags wildcard imports, bloating code and adding unpredictability
      import_risk: /\bfrom\s+.*\s+import\s+\*/gm,

      // Security-specific patterns

      // Example: user_input = sys.argv[1]
      // Flags unvalidated inputs, vulnerable to RF injection
      unsafe_input:
        /\b(sys\.argv|input|request\.form|request\.args)\s*(?!\.\w+\s*==)/g,

      // Example: requests.get("http://api")
      // Detects network calls, potential RF data entry points
      network_call:
        /\b(requests\.get|requests\.post|urllib\.request\.urlopen)\s*\(/g,

      // Example: hash = hashlib.md5(data)
      // Identifies weak crypto, exploitable in RF contexts
      weak_crypto: /\b(hashlib\.md5|hashlib\.sha1|random\.random)\s*\(/g,

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
        /\b(os\.system|subprocess\.run|subprocess\.call)\s*\([^)]*%\s*[^)]*\)/g,

      // Example: api_key = "xyz123"
      // Detects hardcoded secrets, extractable via RF attacks
      exposed_secrets:
        /\b(\w*(secret|key|password|token)\w*)\s*=\s*['"][^'"]+['"]/gi,
    },
    // Matches function definitions for length checks (e.g., def foo():)
    function_regex: /^def\s+\w+\s*\([^)]*\):/,

    // Language-specific exclusions for common void-like or safe functions
    ignore_functions: ['print', 'sys.exit', 'logging.info'],

    // Additional check for security-critical functions whose returns must be handled
    critical_functions: ['requests.get', 'urllib.request.urlopen', 'os.system'],

    // Void return type indicator
    void_return_indicator: 'print',
  },
  c: {
    extensions: ['.c', '.cpp', '.h'],
    patterns: {
      // Example: int factorial(int n) { return factorial(n - 1); }
      // Detects recursive calls, risking stack overflow in space
      recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,

      // Example: int* ptr = malloc(10);
      // Flags dynamic memory allocation, risky in space constraints
      dynamic_memory: /\b(malloc|calloc|realloc|free)\s*\(/g,

      // Example: if (x) goto label; or return x + 1;
      // Identifies complex control flow, complicating verification
      complex_flow: /\b(goto|break|continue|return\s+[^;]+;)/g,

      // Example: while (1) {} or for(;;) {}
      // Catches unbounded loops, risking infinite execution
      unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\([^;]*;[^\n]*;[^\n]*\))/g,

      // Example: system("command");
      // Flags dynamic execution, unpredictable in space
      eval_usage: /\b(system|exec)\s*\(/g,

      // Example: int x = 5; (outside function)
      // Detects global variables, increasing side-effect risks
      global_vars: /^\w+\s+\w+\s*=/gm,

      // Example: try { risky_code(); }
      // Identifies exception handling (C++), potentially masking errors
      try_catch: /\btry\s*{/g,

      // Example: int foo() { if (x) return 1; return 0; }
      // Flags multiple returns, making flow harder to verify
      multiple_returns: /\w+\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g,

      // Example: if (x) { if (y) { do_something(); } }
      // Detects nested conditionals (2+ levels), increasing complexity
      nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,

      // Security-specific patterns

      // Example: scanf("%s", buffer);
      // Flags unvalidated inputs, vulnerable to RF injection
      unsafe_input: /\b(gets|scanf|argv)\s*(?!\[\w+\]\s*==)/g,

      // Example: socket(AF_INET, SOCK_STREAM, 0);
      // Detects network calls, potential RF data entry points
      network_call: /\b(socket|connect|send|recv)\s*\(/g,

      // Example: int r = rand();
      // Identifies weak crypto, exploitable in RF contexts
      weak_crypto: /\b(rand|srand)\s*\(/g,

      // Example: FILE* f = fopen("file.txt", "r");
      // Flags file ops without error handling, risky for RF paths
      unsafe_file_op: /\b(fopen|fread|fwrite)\s*\([^)]*\)/g,

      // Example: system(input);
      // Flags unsanitized execution, vulnerable to RF injection
      unsanitized_exec: /\b(system\s*\([^)]*[^"]\s*[^)]*\))/g,

      // Example: char* apiKey = "xyz123";
      // Detects hardcoded secrets, extractable via RF attacks
      exposed_secrets:
        /(?:char\s*\*|\w+\s*)\b(\w*(secret|key|password|token)\w*)\s*=\s*["][^"]+["]/gi,

      // Example: strcpy(dest, src);
      // Flags unsafe string ops, risking buffer overflows from RF data
      buffer_overflow_risk: /\b(strcpy|strcat|sprintf)\s*\(/g,

      // Example: int main() { return 0; }
      // Detects functions without logging, hindering RF tracing
      insufficient_logging:
        /\b(int|void)\s+\w+\s*\([^)]*\)\s*{(?:\s*[^}]*?(?!printf|fprintf|syslog)[^}]*?)*}/g,
    },
    // Matches function definitions for length checks (e.g., int foo() {})
    function_regex: /^\w+\s+\w+\s*\([^)]*\)\s*{/,

    // Language-specific exclusions for common void-like or safe functions
    ignore_functions: ['printf', 'fprintf', 'exit'],

    // Additional check for security-critical functions whose returns must be handled
    critical_functions: ['system', 'recv', 'send'],

    // Void return type indicator
    void_return_indicator: 'void',
  },
};

/**
 * Counts the number of lines in a function, supporting brace-based (JS/C) and indentation-based (Python) syntax.
 * Used to enforce NASA's Power of Ten Rule 4 by limiting function size (e.g., max 60 lines) for readability
 * and verifiability in space systems, where long functions increase error risk and complicate debugging.
 *
 * Examples:
 * - JavaScript: `function foo() { console.log("x"); }` → Returns 2 (start to closing brace).
 * - Python: `def foo():\n  print("x")\nnext_line()` → Returns 2 (def line to last indented line).
 *
 * @param {string[]} lines - Array of code lines to analyze.
 * @param {number} startIdx - Index of the function’s starting line (0-based).
 * @param {string} [closingChar="}"] - Delimiter: "}" for JS/C braces, "dedent" for Python indentation.
 * @returns {number} - Number of lines in the function (endIdx - startIdx).
 */
function countFunctionLines(lines, startIdx, closingChar = '}') {
  let braceCount = 0;
  let endIdx = startIdx;

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i].trim();

    if (closingChar === '}') {
      // Count braces for JS and C
      braceCount +=
        (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
      if (braceCount === 0 && i > startIdx) {
        // Only break if we've passed the start and braces balance
        endIdx = i + 1; // Include the closing brace line
        break;
      }
    } else if (closingChar === 'dedent') {
      // Handle Python indentation
      if (i === startIdx) {
        // Skip the function def line
        continue;
      }
      if (!line) {
        // Empty line after indented block ends it
        endIdx = i;
        break;
      }
      if (!line.startsWith(' ') && i > startIdx + 1) {
        // Dedent after at least one indented line
        endIdx = i;
        break;
      }
      braceCount = line.startsWith(' ') ? 1 : 0; // Track indentation
    }
  }

  // If loop completes without breaking, use the last line
  if (endIdx === startIdx && braceCount > 0) {
    endIdx = lines.length;
  }

  return endIdx - startIdx;
}

/**
 * Checks for function calls with unchecked return values in a list of code lines.
 * Aligns with NASA's Power of Ten Rule 7: "Check return values of all non-void functions."
 * Unchecked returns can lead to silent failures, critical in space systems where errors
 * must be caught and handled explicitly (e.g., unhandled RF data responses).
 *
 * @param {string[]} lines - Array of code lines to analyze.
 * @param {string[]} ignoreList - Language-specific exclusions for common void-like or safe functions
 * @param {string[]} criticalFunctions - Additional check for security-critical functions whose returns must be handled
 * @param {string} voidReturnIndicator - String that indicates a function returns void
 * @returns {string[]} - Array of issue messages for unchecked returns.
 */
function checkReturnUsage(
  lines,
  ignoreList,
  criticalFunctions,
  voidReturnIndicator
) {
  console.log(
    'checkreutnrusage',
    lines,
    ignoreList,
    criticalFunctions,
    voidReturnIndicator
  );
  // Array to store detected issues
  const issues = [];

  // Regex to match standalone function calls (e.g., "foo();", "bar(x)")
  // - ^\w+\s*\([^)]*\)\s*[;]?$: Starts with word, optional args, optional semicolon
  const callPattern = /^\w+\s*\([^)]*\)\s*[;]?$/;

  // Regex to exclude calls assigned to variables (e.g., "x = foo()")
  const assignmentPattern = /=\s*\w+\s*\(/;

  // Iterate over each line in the code
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Skip empty lines or non-function calls
    if (!line || !callPattern.test(line) || assignmentPattern.test(line)) {
      continue;
    }

    // Check if the line should be ignored based on language-specific safe functions
    const isIgnored = (ignoreList || []).some((func) => line.includes(func));
    if (isIgnored) {
      continue;
    }

    // Check for void-like keywords (language-specific exclusions)
    const hasVoidIndicators = line.includes(voidReturnIndicator);

    if (!hasVoidIndicators) {
      // Flag as an issue if no void indicators are present
      issues.push(`Line ${i + 1}: Unchecked function return - '${line}'`);

      // Additional security check: Warn if a critical function's return is ignored
      const isCritical = (criticalFunctions || []).some((func) =>
        line.includes(func)
      );
      if (isCritical) {
        issues.push(
          `Line ${i + 1}: Security risk - Unchecked return from critical function - '${line}'`
        );
      }
    }
  }

  return issues;
}

/**
 * Analyzes a single file for space-proofing issues, checking code quality and security patterns.
 * Identifies violations like unbounded loops, exposed secrets, or insufficient logging that could
 * compromise performance, reliability, or security in space systems. Processes JavaScript, Python,
 * and C/C++ files, returning detected issues with line numbers for remediation.
 *
 * Examples:
 * - JavaScript: `function foo() { while(true) {} }` → Flags "unbounded_loops" at line 1.
 * - Python: `api_key = "xyz123"` → Flags "exposed_secrets" at line 1.
 * - C: `int x = rand();` → Flags "weak_crypto" at line 1.
 *
 * @param {string} filePath - Path to the file to analyze.
 * @param {string} language - Language of the file ("javascript", "python", "c").
 * @returns {Promise<string[]>} - Array of issue messages (e.g., "Line 1: recursion detected").
 */
async function analyzeFile(filePath, language) {
  // Read file content asynchronously, ensuring non-blocking I/O for efficiency
  const content = await fs.readFile(filePath, 'utf-8');
  const lines = content.split('\n'); // Split into lines for line-based analysis
  const issues = []; // Accumulate detected issues
  const langConfig = LANGUAGE_PATTERNS[language]; // Load language-specific patterns
  const closingChar = language === 'python' ? 'dedent' : '}'; // Set delimiter: braces for JS/C, indentation for Python

  // Check for patterns like recursion, unsafe_input, or weak_crypto
  // Iterates over regex patterns to detect code quality and security violations
  for (const [issueType, pattern] of Object.entries(langConfig.patterns)) {
    const matches = content.matchAll(pattern); // Find all matches in the file content
    for (const match of matches) {
      // Calculate 1-based line number from match index
      const lineNum = content.substring(0, match.index).split('\n').length;
      issues.push(`Line ${lineNum}: ${issueType} detected - '${match[0]}'`); // Log issue with matched code
    }
  }

  // Check function length to enforce NASA's Rule 4 (max 60 lines)
  // Ensures functions remain small and verifiable, reducing error risk in space software
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim(); // Trim whitespace for accurate regex matching
    if (langConfig.function_regex.test(line)) {
      // Extract function name (e.g., "foo" from "function foo()" or "def foo():")
      const funcMatch = line.match(/^(?:def|function|\w+\s+)?(\w+)/);
      const funcName = funcMatch ? funcMatch[1] : 'anonymous'; // Default to "anonymous" if no name
      const length = countFunctionLines(lines, i, closingChar); // Count lines in function
      if (length > MAX_FUNCTION_LINES) {
        // Flag functions exceeding the size limit
        issues.push(
          `Line ${i + 1}: Function '${funcName}' exceeds ${MAX_FUNCTION_LINES} lines (${length} lines)`
        );
      }
    }
  }

  // Check for unchecked function returns (NASA Rule 7)
  // Adds issues for ignored returns, ensuring error detection in space-critical operations
  issues.push(
    ...checkReturnUsage(
      lines,
      langConfig.ignore_functions,
      langConfig.critical_functions,
      langConfig.void_return_indicator
    )
  );

  return issues; // Return all detected issues for reporting
}

/**
 * Scans a directory recursively for space-proofing issues across multiple files.
 * Analyzes JavaScript/TypeScript, Python, and C/C++ codebases to identify performance, reliability, and
 * security violations (e.g., unbounded loops, exposed secrets) that could jeopardize space
 * systems. Returns a structured result set for reporting, enabling developers to ensure code
 * meets stringent space mission standards.
 *
 * Example:
 * - Directory: `/code` with `main.js` (`while(true) {}`) and `script.py` (`api_key = "xyz123"`)
 *   → Returns `[ { file: "/code/main.js", language: "javascript", issues: ["Line 1: unbounded_loops..."] }, ... ]`.
 *
 * @param {string} directory - Path to the directory to scan.
 * @returns {Promise<Object[]>} - Array of objects with file path, language, and detected issues.
 * @throws {Error} - If directory traversal fails (e.g., permissions denied).
 */
async function scanCodebase(directory) {
  const results = []; // Accumulate analysis results for each file

  try {
    // Read all files recursively in the directory, leveraging Node >=18 for efficiency
    const files = await fs.readdir(directory, { recursive: true });

    // Process each file to detect space-proofing issues
    for (const file of files) {
      const filePath = path.join(directory, file); // Construct full file path
      const ext = path.extname(file).toLowerCase(); // Get file extension (e.g., ".js")
      let language = null; // Initialize language as null until identified

      // Match file extension to supported languages (javascript, python, c)
      for (const [lang, config] of Object.entries(LANGUAGE_PATTERNS)) {
        if (config.extensions.includes(ext)) {
          language = lang; // Set language if extension matches
          break; // Exit loop once language is found
        }
      }

      // Analyze supported files (skip unsupported extensions like .txt)
      if (language) {
        const issues = await analyzeFile(filePath, language); // Analyze file for issues
        results.push({ file: filePath, language, issues }); // Add result with file details
      }
    }

    return results; // Return all analysis results for reporting
  } catch (err) {
    // Handle errors (e.g., inaccessible directory), ensuring clear failure reporting
    throw new Error(`Failed to scan codebase: ${err.message}`);
  }
}

module.exports = { scanCodebase };
