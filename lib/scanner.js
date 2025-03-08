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
const { createHash } = require('crypto');

const CHECKSUMS_FILE = 'checksums.sha256.txt';

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
 * what triggers the check. Patterns are grouped by language (JavaScript/TypeScript, Python, C/C++,
 * Go, Rust, and Java).
 */
const LANGUAGE_PATTERNS = {
  javascript: require('./lang/javascript').JavaScriptPatterns,
  python: require('./lang/python').PythonPatterns,
  c: require('./lang/c').CPatterns,
  java: require('./lang/java').JavaPatterns,
  go: require('./lang/go').GoPatterns,
  rust: require('./lang/rust').RustPatterns,
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
      //issues.push(`Line ${i + 1}: Unchecked function return - '${line}'`);
      issues.push({
        message: `Unchecked function return - '${line}'`,
        issueType: `unchecked_func_return`,
        lineNum: i + 1,
      });

      // Additional security check: Warn if a critical function's return is ignored
      const isCritical = (criticalFunctions || []).some((func) =>
        line.includes(func)
      );
      if (isCritical) {
        // issues.push(
        //   `Line ${i + 1}: Security risk - Unchecked return from critical function - '${line}'`
        // );
        issues.push({
          message: `Security risk - Unchecked return from critical function - '${line}'`,
          issueType: `unchecked_func_return_crit`,
          lineNum: i + 1,
        });
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
      issues.push({
        message: `${match[0]}`,
        issueType,
        lineNum,
      });
      //issues.push(`Line ${lineNum}: ${issueType} detected - '${match[0]}'`); // Log issue with matched code
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
        // issues.push(
        //   `Line ${i + 1}: Function '${funcName}' exceeds ${MAX_FUNCTION_LINES} lines (${length} lines)`
        // );
        issues.push({
          message: `Function '${funcName}' exceeds ${MAX_FUNCTION_LINES} lines (${length} lines)`,
          issueType: 'exceeds_max_func_lines',
          lineNum: i + 1,
        });
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
 * Analyzes JavaScript/TypeScript, Python, C/C++, Go, Rust, and Java codebases to
 * identify performance, reliability, and security violations (e.g., unbounded loops,
 * exposed secrets) that could jeopardize space systems. Returns a structured result
 * set for reporting, enabling developers to ensure code meets stringent space mission standards.
 *
 * Example:
 * - Directory: `/code` with `main.js` (`while(true) {}`) and `script.py` (`api_key = "xyz123"`)
 *   → Returns `[ { file: "/code/main.js", language: "javascript", issues: ["Line 1: unbounded_loops..."] }, ... ]`.
 *
 * @param {string} directory - Path to the directory to scan.
 * @param {boolean} createSums - Enables creation of check sums for files scanned.
 * @param {string[]} ignorePatterns - Array of string patterns to match on for ignoring
 * @returns {Promise<Object[]>} - Array of objects with file path, language, and detected issues.
 * @throws {Error} - If directory traversal fails (e.g., permissions denied).
 */
async function scanCodebase(
  directory,
  createSums = false,
  ignorePatterns = []
) {
  const results = []; // Accumulate analysis results for each file
  const checksums = [];

  try {
    // Read all files recursively in the directory, leveraging Node >=18 for efficiency
    const files = await fs.readdir(directory, { recursive: true });
    const checkSumIndex = await loadChecksums(directory + '/' + CHECKSUMS_FILE);

    // Process each file to detect space-proofing issues
    for (const file of files) {
      const filePath = path.join(directory, file); // Construct full file path
      const stat = await fs.stat(filePath);
      // only scan files
      if (!stat.isFile()) {
        continue;
      }

      const ext = path.extname(file).toLowerCase(); // Get file extension (e.g., ".js")
      let language = null; // Initialize language as null until identified

      if (filePath.match(CHECKSUMS_FILE)) {
        continue;
      } else if (ignorePatterns?.length) {
        // Check if this path should be ignored
        const isIgnored = ignorePatterns.some((ignore) => {
          if (ignore.includes('*')) {
            const pattern = ignore.replace('*', '.*');
            return new RegExp(`^${pattern}$`).test(path.basename(filePath));
          } else {
            return (
              filePath.match(ignore) ||
              filePath.startsWith(ignore) ||
              path.basename(filePath) === ignore
            );
          }
        });

        if (isIgnored) {
          continue;
        }
      }

      const fileHash = await createHashFromFile(filePath);
      if (createSums) {
        checksums.push(`${fileHash}  ${file}`);
      } else if (
        checkSumIndex &&
        checkSumIndex[file] &&
        checkSumIndex[file] !== fileHash
      ) {
        results.push({
          file: filePath,
          relativePath: file,
          language: '',
          issues: [
            {
              message: `Check sum mismatch for file`,
              issueType: 'checksum_mismatch',
              lineNum: null,
            },
          ],
        });
      }

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
        results.push({ file: filePath, relativePath: file, language, issues }); // Add result with file details
      }
    }

    if (createSums) {
      await fs.writeFile(
        directory + '/' + CHECKSUMS_FILE,
        checksums.join('\n'),
        'utf8'
      );
    }

    return results; // Return all analysis results for reporting
  } catch (err) {
    // Handle errors (e.g., inaccessible directory), ensuring clear failure reporting
    throw new Error(`Failed to scan codebase: ${err.message}`);
  }
}

/**
 * @method createHashFromFile - Create a hash from a file of any size
 *
 * @param filePath
 * @returns {Promise<string>}
 */
async function createHashFromFile(filePath) {
  try {
    // Read the entire file as a Buffer using fs.promises.readFile
    const fileBuffer = await fs.readFile(filePath);

    // Create and update the hash with the raw Buffer
    const fileHash = createHash('sha256');
    fileHash.update(fileBuffer);

    // Return the hex digest
    return fileHash.digest('hex');
  } catch (error) {
    throw new Error(`Failed to create hash for ${filePath}: ${error.message}`);
  }
}

/**
 * @method loadChecksums - Load the checksums file if it exists and return a file path indexed hash table
 *
 * @param checksumFilePath
 * @returns {Object}
 */
async function loadChecksums(checksumFilePath) {
  try {
    // Read the checksum file
    const checksumContent = await fs.readFile(checksumFilePath, 'utf8');
    const checksumLines = checksumContent
      .trim()
      .split('\n')
      .filter((line) => line && !line.startsWith('#')); // Ignore comments and empty lines

    if (!checksumContent || !checksumLines?.length) {
      return null;
    }

    // Initialize an object to store hashes as keys and filenames as values
    const checksumIndex = {};

    // Parse each line and store in the index
    for (const line of checksumLines) {
      // Parse the line: <HASH>  <FILENAME> (two spaces between hash and filename)
      const match = line.match(/^([0-9a-f]{32}|[0-9a-f]{64})\s{2}(.*)$/);
      if (!match) {
        continue;
      }

      const [_, hash, filename] = match;
      checksumIndex[filename] = hash;
      // console.log(`Indexed ${filename} -> ${hash}`);
    }

    console.log(`Check sum file found: ${checksumFilePath}`);
    console.log(
      `Loaded ${Object.keys(checksumIndex).length} checksums into memory.`
    );
    return checksumIndex;
  } catch (error) {
    console.log(
      `Failed to load checksums (try using --create-sums): ${error.message}`
    );
    return null;
  }
}

module.exports = { scanCodebase };
