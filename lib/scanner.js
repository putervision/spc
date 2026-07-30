/**
 * scanner.js - Core logic for @putervision/spc, a space-proofing code analysis tool.
 * Analyzes codebases across 20 programming languages for patterns that compromise performance,
 * reliability, and security in high-stakes environments like space missions. Inspired by NASA's
 * Power of Ten rules, it enforces code quality through checks like bounded loops and small
 * functions, while adding security rules to detect vulnerabilities such as RF-based API
 * injection or exposed secrets. Exports `scanCodebase` to scan directories and report issues,
 * ensuring code is robust, verifiable, and secure for space-ready systems.
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { createHash } = require('crypto');
const { buildIgnorePatterns, isPathIgnored } = require('./ignore');
const { loadConfig } = require('./config');

const CHECKSUMS_FILE = 'checksums.sha256.txt';
const MAX_FUNCTION_LINES = 60;
const BATCH_CONCURRENCY = 20;

/**
 * Language-specific patterns for code quality and security checks.
 */
const LANGUAGE_PATTERNS = {
  javascript: require('./lang/javascript').JavaScriptPatterns,
  python: require('./lang/python').PythonPatterns,
  c: require('./lang/c').CPatterns,
  java: require('./lang/java').JavaPatterns,
  go: require('./lang/go').GoPatterns,
  rust: require('./lang/rust').RustPatterns,
  ada: require('./lang/ada').AdaPatterns,
  csharp: require('./lang/cs').CSharpPatterns,
  fortran: require('./lang/fortran').FortranPatterns,
  ruby: require('./lang/ruby').RubyPatterns,
  swift: require('./lang/swift').SwiftPatterns,
  kotlin: require('./lang/kotlin').KotlinPatterns,
  lua: require('./lang/lua').LuaPatterns,
  php: require('./lang/php').PHPPatterns,
  scala: require('./lang/scala').ScalaPatterns,
  haskell: require('./lang/haskell').HaskellPatterns,
  zig: require('./lang/zig').ZigPatterns,
  julia: require('./lang/julia').JuliaPatterns,
  elixir: require('./lang/elixir').ElixirPatterns,
  bash: require('./lang/bash').BashPatterns,
};

const EXTENSIONS_CACHE = {};

/**
 * Safely resolves real path, falling back if mock/unsupported environment.
 */
async function safeRealPath(p) {
  if (typeof fs.realpath === 'function') {
    try {
      return await fs.realpath(p);
    } catch (e) {
      if (e && e.message === 'Permission denied') throw e;
      return p;
    }
  }
  return p;
}

/**
 * Counts the number of lines in a function.
 */
function countFunctionLines(lines, startIdx, closingChar = '}') {
  let braceCount = 0;
  let endIdx = startIdx;

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i].trim();

    if (closingChar === '}') {
      braceCount +=
        (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
      if (braceCount === 0 && i > startIdx) {
        endIdx = i + 1;
        break;
      }
    } else if (closingChar === 'dedent') {
      if (i === startIdx) continue;
      if (!line) {
        endIdx = i;
        break;
      }
      if (!line.startsWith(' ') && i > startIdx + 1) {
        endIdx = i;
        break;
      }
      braceCount = line.startsWith(' ') ? 1 : 0;
    }
  }

  if (endIdx === startIdx && braceCount > 0) {
    endIdx = lines.length;
  }

  return endIdx - startIdx;
}

/**
 * Checks for function calls with unchecked return values.
 */
function checkReturnUsage(
  lines,
  ignoreList,
  criticalFunctions,
  voidReturnIndicator
) {
  const issues = [];
  const callPattern = /^\w+\s*\([^)]*\)\s*[;]?$/;
  const assignmentPattern = /=\s*\w+\s*\(/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (!line || !callPattern.test(line) || assignmentPattern.test(line)) {
      continue;
    }

    const isIgnored = (ignoreList || []).some((func) => line.includes(func));
    if (isIgnored) continue;

    const hasVoidIndicators = line.includes(voidReturnIndicator);

    if (!hasVoidIndicators) {
      issues.push({
        message: `Unchecked function return - '${line}'`,
        issueType: `unchecked_func_return`,
        lineNum: i + 1,
      });

      const isCritical = (criticalFunctions || []).some((func) =>
        line.includes(func)
      );
      if (isCritical) {
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
 * Parses inline suppression comments like `spc-disable` or `spc-disable-line`.
 */
function isLineSuppressed(lines, lineIdx, issueType) {
  const currentLine = lines[lineIdx] || '';
  const prevLine = lineIdx > 0 ? lines[lineIdx - 1] : '';

  const directiveRegex = /spc-disable(?:-line)?(?:\s+([\w\d_,\s-]+))?/;

  const checkComment = (lineText) => {
    const match = lineText.match(directiveRegex);
    if (!match) return false;
    const disabledRules = match[1];
    if (!disabledRules || disabledRules.trim() === '') return true;
    const rulesList = disabledRules.split(',').map((r) => r.trim());
    return rulesList.includes(issueType) || rulesList.includes('all');
  };

  return checkComment(currentLine) || checkComment(prevLine);
}

/**
 * Analyzes a single file for space-proofing issues.
 */
async function analyzeFile(filePath, language) {
  const content = await fs.readFile(filePath, 'utf-8');
  const lines = content.split('\n');
  const rawIssues = [];
  const langConfig = LANGUAGE_PATTERNS[language];
  const closingChar = language === 'python' ? 'dedent' : '}';

  for (const [issueType, pattern] of Object.entries(langConfig.patterns)) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      rawIssues.push({
        message: `${match[0]}`,
        issueType,
        lineNum,
      });
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (langConfig.function_regex.test(line)) {
      const funcMatch = line.match(/^(?:def|function|\w+\s+)?(\w+)/);
      const funcName = funcMatch ? funcMatch[1] : 'anonymous';
      const length = countFunctionLines(lines, i, closingChar);
      if (length > MAX_FUNCTION_LINES) {
        rawIssues.push({
          message: `Function '${funcName}' exceeds ${MAX_FUNCTION_LINES} lines (${length} lines)`,
          issueType: 'exceeds_max_func_lines',
          lineNum: i + 1,
        });
      }
    }
  }

  rawIssues.push(
    ...checkReturnUsage(
      lines,
      langConfig.ignore_functions,
      langConfig.critical_functions,
      langConfig.void_return_indicator
    )
  );

  // Filter out issues suppressed by inline comments (spc-disable)
  const filteredIssues = rawIssues.filter((issue) => {
    if (!issue.lineNum) return true;
    return !isLineSuppressed(lines, issue.lineNum - 1, issue.issueType);
  });

  return filteredIssues;
}

/**
 * Loads .spcignore file if present.
 */
async function loadSpcIgnore(directory) {
  try {
    const ignorePath = path.join(directory, '.spcignore');
    const content = await fs.readFile(ignorePath, 'utf8');
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
  } catch {
    return [];
  }
}

/**
 * Scans a directory recursively for space-proofing issues across multiple files.
 */
async function scanCodebase(
  directory,
  createSums = false,
  ignorePatterns = []
) {
  const results = [];
  const checksums = [];

  try {
    const resolvedDir = await safeRealPath(directory);
    const config = await loadConfig(resolvedDir);
    const spcIgnoreRules = await loadSpcIgnore(resolvedDir);
    const combinedIgnore = buildIgnorePatterns([
      ...ignorePatterns,
      ...spcIgnoreRules,
      ...(config.ignorePatterns || []),
    ]);

    const files = await fs.readdir(resolvedDir, { recursive: true });
    const checkSumIndex = await loadChecksums(
      path.join(resolvedDir, CHECKSUMS_FILE)
    );

    // Process files in bounded concurrent chunks
    for (let i = 0; i < files.length; i += BATCH_CONCURRENCY) {
      const batch = files.slice(i, i + BATCH_CONCURRENCY);
      await Promise.all(
        batch.map(async (file) => {
          const filePath = path.join(resolvedDir, file);

          try {
            const stat = await fs.stat(filePath);
            if (!stat.isFile()) return;

            // Prevent path traversal escapes for resolved symlinks
            const realPath = await safeRealPath(filePath);
            if (
              realPath !== filePath &&
              typeof realPath === 'string' &&
              typeof resolvedDir === 'string' &&
              !realPath.startsWith(resolvedDir)
            )
              return;

            if (filePath.match(CHECKSUMS_FILE)) return;

            if (
              isPathIgnored(filePath, combinedIgnore) ||
              isPathIgnored(file, combinedIgnore)
            ) {
              return;
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

            const ext = path.extname(file).toLowerCase();
            let language = EXTENSIONS_CACHE[ext] ?? null;

            if (!language) {
              for (const [lang, config] of Object.entries(LANGUAGE_PATTERNS)) {
                if (config.extensions.includes(ext)) {
                  language = lang;
                  EXTENSIONS_CACHE[ext] = lang;
                  break;
                }
              }
            }

            if (language) {
              const issues = await analyzeFile(filePath, language);
              results.push({
                file: filePath,
                relativePath: file,
                language,
                issues,
              });
            }
          } catch (err) {
            // Silently skip inaccessible or unreadable files
          }
        })
      );
    }

    if (createSums) {
      await fs.writeFile(
        path.join(resolvedDir, CHECKSUMS_FILE),
        checksums.join('\n'),
        'utf8'
      );
    }

    return results;
  } catch (err) {
    throw new Error(`Failed to scan codebase: ${err.message}`);
  }
}

/**
 * Create SHA-256 hash using stream-based reading or buffer fallback.
 */
async function createHashFromFile(filePath) {
  try {
    if (typeof fsSync.createReadStream === 'function') {
      const hash = createHash('sha256');
      const stream = fsSync.createReadStream(filePath);
      if (stream && typeof stream.on === 'function') {
        return await new Promise((resolve, reject) => {
          stream.on('data', (chunk) => hash.update(chunk));
          stream.on('end', () => resolve(hash.digest('hex')));
          stream.on('error', (err) => reject(err));
        });
      }
    }
  } catch {
    // Fallback to readFile buffer reading if stream fails or in mocked environment
  }

  try {
    const fileBuffer = await fs.readFile(filePath);
    const fileHash = createHash('sha256');
    fileHash.update(fileBuffer);
    return fileHash.digest('hex');
  } catch (error) {
    throw new Error(`Failed to create hash for ${filePath}: ${error.message}`);
  }
}

/**
 * Load and validate checksums file.
 */
async function loadChecksums(checksumFilePath) {
  try {
    const checksumContent = await fs.readFile(checksumFilePath, 'utf8');
    const checksumLines = checksumContent
      .trim()
      .split('\n')
      .filter((line) => line && !line.startsWith('#'));

    if (!checksumContent || !checksumLines?.length) return null;

    const checksumIndex = {};
    for (const line of checksumLines) {
      const match = line.match(/^([0-9a-f]{32}|[0-9a-f]{64})\s{2}(.*)$/i);
      if (!match) continue;

      const [, hash, filename] = match;
      checksumIndex[filename] = hash;
    }

    console.log(`Checksum file loaded: ${checksumFilePath}`);
    return checksumIndex;
  } catch {
    return null;
  }
}

module.exports = { scanCodebase };
