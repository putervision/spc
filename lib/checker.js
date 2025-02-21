const fs = require("fs").promises;
const path = require("path");

const MAX_FUNCTION_LINES = 60;

// Language-specific patterns with global flag
const LANGUAGE_PATTERNS = {
  javascript: {
    extensions: [".js"],
    patterns: {
      recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,
      dynamic_memory: /\bnew\s+(Array|Object|Map|Set|WeakMap|WeakSet)\s*\(/g,
      complex_flow: /\b(break|continue|return\s+[^;]+?;)/g,
      async_risk: /\b(async\s+function|await)\b/g,
      unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\(\s*[^;]*;\s*[^;]*;\s*\))/g,
      eval_usage: /\b(eval|Function)\s*\(/g,
      global_vars: /\b(var\s+\w+|window\.\w+\s*=)/g,
      try_catch: /\btry\s*{/g,
      set_timeout: /\b(setTimeout|setInterval)\s*\(/g,
      multiple_returns: /function\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g,
      nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,
    },
    function_regex: /^(function|const|let|var)\s+\w+\s*=?\s*\([^)]*\)\s*{/,
  },
  python: {
    extensions: [".py"],
    patterns: {
      recursion: /def\s+(\w+)\s*\([^)]*\):(?:[^:]*?\b\1\s*\()/g,
      dynamic_memory: /\b(list|dict|set)\s*\(/g,
      complex_flow: /\b(break|continue|return\s+.+)$/gm,
      unbounded_loops: /\b(while\s+[^:]+:|for\s+\w+\s+in\s+[^:]+:)$/gm,
      eval_usage: /\b(exec|eval)\s*\(/g,
      global_vars: /\bglobal\s+\w+/g,
      try_catch: /\btry:/g,
      multiple_returns: /def\s+\w+\s*\([^)]*\):[^:]*return[^:]*return/gm,
      nested_conditionals: /(if\s+[^:]+:[^:]*){2,}/g,
      import_risk: /\bfrom\s+.*\s+import\s+\*/gm,
    },
    function_regex: /^def\s+\w+\s*\([^)]*\):/,
  },
  c: {
    extensions: [".c", ".cpp", ".h"],
    patterns: {
      recursion: /(\w+)\s*\([^)]*\)\s*\{(?:[^}]*?\b\1\s*\()/g,
      dynamic_memory: /\b(malloc|calloc|realloc|free)\s*\(/g,
      complex_flow: /\b(goto|break|continue|return\s+[^;]+;)/g,
      unbounded_loops: /\b(while\s*\([^)]*\)|for\s*\([^;]*;[^\n]*;[^\n]*\))/g,
      eval_usage: /\b(system|exec)\s*\(/g,
      global_vars: /^\w+\s+\w+\s*=/gm,
      try_catch: /\btry\s*{/g,
      multiple_returns: /\w+\s+\w+\s*\([^)]*\)\s*{[^}]*return[^}]*return/g,
      nested_conditionals: /(if\s*\([^)]*\)\s*{[^}]*){2,}/g,
    },
    function_regex: /^\w+\s+\w+\s*\([^)]*\)\s*{/,
  },
};

function countFunctionLines(lines, startIdx, closingChar = "}") {
  let braceCount = 0;
  let endIdx = startIdx;

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i].trim();

    if (closingChar === "}") {
      // Count braces for JS and C
      braceCount +=
        (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
      if (braceCount === 0 && i > startIdx) {
        // Only break if we've passed the start and braces balance
        endIdx = i + 1; // Include the closing brace line
        break;
      }
    } else if (closingChar === "dedent") {
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
      if (!line.startsWith(" ") && i > startIdx + 1) {
        // Dedent after at least one indented line
        endIdx = i;
        break;
      }
      braceCount = line.startsWith(" ") ? 1 : 0; // Track indentation
    }
  }

  // If loop completes without breaking, use the last line
  if (endIdx === startIdx && braceCount > 0) {
    endIdx = lines.length;
  }

  return endIdx - startIdx;
}

// Check unchecked returns
function checkReturnUsage(lines, language) {
  const issues = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (/^\w+\s*\([^)]*\)\s*[;]?$/.test(line) && !/=\s*\w+\s*\(/.test(line)) {
      if (
        !line.includes("print") &&
        !line.includes("console.") &&
        !line.includes("void")
      ) {
        issues.push(`Line ${i + 1}: Unchecked function return - '${line}'`);
      }
    }
  }
  return issues;
}

// Analyze a single file
async function analyzeFile(filePath, language) {
  const content = await fs.readFile(filePath, "utf-8");
  const lines = content.split("\n");
  const issues = [];
  const langConfig = LANGUAGE_PATTERNS[language];
  const closingChar = language === "python" ? "dedent" : "}";
  
  // Check patterns
  for (const [issueType, pattern] of Object.entries(langConfig.patterns)) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const lineNum = content.substring(0, match.index).split("\n").length;
      issues.push(`Line ${lineNum}: ${issueType} detected - '${match[0]}'`);
    }
  }

  // Check function length
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (langConfig.function_regex.test(line)) {
      const funcMatch = line.match(/^(?:def|function|\w+\s+)?(\w+)/);
      const funcName = funcMatch ? funcMatch[1] : "anonymous";
      const length = countFunctionLines(lines, i, closingChar);
      if (length > MAX_FUNCTION_LINES) {
        issues.push(
          `Line ${i + 1}: Function '${funcName}' exceeds ${MAX_FUNCTION_LINES} lines (${length} lines)`,
        );
      }
    }
  }

  // Check return usage
  issues.push(...checkReturnUsage(lines, language));

  return issues;
}

// Scan the codebase
async function scanCodebase(directory) {
  const results = [];
  try {
    const files = await fs.readdir(directory, { recursive: true });
    for (const file of files) {
      const filePath = path.join(directory, file);
      const ext = path.extname(file).toLowerCase();
      let language = null;

      for (const [lang, config] of Object.entries(LANGUAGE_PATTERNS)) {
        if (config.extensions.includes(ext)) {
          language = lang;
          break;
        }
      }

      if (language) {
        const issues = await analyzeFile(filePath, language);
        results.push({ file: filePath, language, issues });
      }
    }
    return results;
  } catch (err) {
    throw new Error(`Failed to scan codebase: ${err.message}`);
  }
}

module.exports = { scanCodebase };
