/**
 * scanner.js - Core logic for @putervision/spc, a space-proofing & AI agent code analysis tool.
 * Analyzes codebases across 20 programming languages + AI agent skills, prompts, MCP server configs,
 * and LLM model deployment files for reliability and security vulnerabilities.
 */

const fs = require('fs').promises;
const path = require('path');
const { buildIgnorePatterns, isPathIgnored } = require('./ignore');
const { loadConfig } = require('./config');
const { loadPlugins } = require('./plugin');
const {
  CHECKSUMS_FILE,
  createHashFromFile,
  loadChecksums,
} = require('./checksum');
const { PATTERN_INFO } = require('./info');

const DEFAULT_MAX_FUNCTION_LINES = 60;
const BATCH_CONCURRENCY = 20;

/**
 * Built-in language-specific patterns and AI/Agent rule modules.
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
  // AI Agent, MCP Server & LLM Model Security Rule Engines
  agent: require('./lang/agent').AgentPatterns,
  mcp: require('./lang/mcp').McpPatterns,
  model: require('./lang/model').ModelPatterns,
};

const EXTENSION_TO_LANGUAGE_MAP = {};
const FILENAME_TO_LANGUAGE_MAP = {};

/**
 * Builds reverse lookup maps for file extensions and exact filenames.
 */
function buildRoutingMaps() {
  for (const [lang, config] of Object.entries(LANGUAGE_PATTERNS)) {
    if (config.extensions) {
      for (const ext of config.extensions) {
        EXTENSION_TO_LANGUAGE_MAP[ext.toLowerCase()] = lang;
      }
    }
    if (config.filenames) {
      for (const name of config.filenames) {
        FILENAME_TO_LANGUAGE_MAP[name.toLowerCase()] = lang;
      }
    }
  }
}
buildRoutingMaps();

/**
 * Safely resolves real path, falling back if mock/unsupported environment.
 * @param {string} p - Path to resolve.
 * @returns {Promise<string>} Resolved real path or original path.
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
 * @param {string[]} lines - Code lines.
 * @param {number} startIdx - Line index of function declaration.
 * @param {string} closingChar - 'dedent' for Python, else '}'.
 * @returns {number} Function line count.
 */
function countFunctionLines(lines, startIdx, closingChar = '}') {
  let braceCount = 0;
  let endIdx = startIdx;

  if (closingChar === 'dedent') {
    const startLine = lines[startIdx];
    const initialIndent = startLine.search(/\S/);
    endIdx = lines.length;

    for (let i = startIdx + 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue; // Skip blank lines in Python
      const currentIndent = line.search(/\S/);
      if (currentIndent !== -1 && currentIndent <= initialIndent) {
        endIdx = i;
        break;
      }
    }
    return Math.max(1, endIdx - startIdx);
  }

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i].trim();
    braceCount +=
      (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
    if (braceCount === 0 && i > startIdx) {
      endIdx = i + 1;
      break;
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
  ignoreList = [],
  criticalFunctions = [],
  voidReturnIndicator = 'void'
) {
  const issues = [];
  const callPattern = /^\w+\s*\([^)]*\)\s*[;]?$/;
  const assignmentPattern = /=\s*\w+\s*\(/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (!line || !callPattern.test(line) || assignmentPattern.test(line)) {
      continue;
    }

    const isIgnored = ignoreList.some((func) => line.includes(func));
    if (isIgnored) continue;

    const hasVoidIndicators =
      voidReturnIndicator !== 'N/A' && line.includes(voidReturnIndicator);

    if (!hasVoidIndicators) {
      issues.push({
        message: `Unchecked function return - '${line}'`,
        issueType: 'unchecked_func_return',
        lineNum: i + 1,
      });

      const isCritical = criticalFunctions.some((func) => line.includes(func));
      if (isCritical) {
        issues.push({
          message: `Security risk - Unchecked return from critical function - '${line}'`,
          issueType: 'unchecked_func_return_crit',
          lineNum: i + 1,
        });
      }
    }
  }

  return issues;
}

/**
 * Parses inline and block-level suppression comments like `spc-disable` or `spc-disable-line`.
 * @param {string[]} lines - Array of file lines.
 * @returns {Function} Function taking (lineIdx, issueType) -> boolean.
 */
function createSuppressionFilter(lines) {
  const lineSuppressed = new Array(lines.length).fill(false);
  const disabledRulesByLine = new Array(lines.length).fill(null);
  let activeBlockDisable = false;
  let activeBlockRules = null;

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i];

    // Single-line directive: spc-disable-line [rule1,rule2]
    const singleLineMatch = lineText.match(
      /spc-disable-line(?:\s+([\w\d_,\s-]+))?/
    );
    if (singleLineMatch) {
      lineSuppressed[i] = true;
      disabledRulesByLine[i] = singleLineMatch[1]
        ? singleLineMatch[1].split(',').map((r) => r.trim())
        : ['all'];
    }

    // Next-line directive on previous line: spc-disable-next-line
    const nextLineMatch = lineText.match(
      /spc-disable-next-line(?:\s+([\w\d_,\s-]+))?/
    );
    if (nextLineMatch && i + 1 < lines.length) {
      lineSuppressed[i + 1] = true;
      disabledRulesByLine[i + 1] = nextLineMatch[1]
        ? nextLineMatch[1].split(',').map((r) => r.trim())
        : ['all'];
    }

    // Block start: spc-disable [rule1,rule2]
    const blockStartMatch = lineText.match(
      /spc-disable(?!\s*-\s*line)(?:\s+([\w\d_,\s-]+))?/
    );
    if (blockStartMatch && !singleLineMatch && !nextLineMatch) {
      activeBlockDisable = true;
      activeBlockRules = blockStartMatch[1]
        ? blockStartMatch[1].split(',').map((r) => r.trim())
        : ['all'];
    }

    // Block end: spc-enable
    if (lineText.includes('spc-enable')) {
      activeBlockDisable = false;
      activeBlockRules = null;
    }

    if (activeBlockDisable) {
      lineSuppressed[i] = true;
      disabledRulesByLine[i] = activeBlockRules;
    }
  }

  return (lineIdx, issueType) => {
    if (lineIdx < 0 || lineIdx >= lines.length) return false;
    if (!lineSuppressed[lineIdx]) return false;
    const rules = disabledRulesByLine[lineIdx];
    if (!rules || rules.includes('all')) return true;
    return rules.includes(issueType);
  };
}

/**
 * Analyzes a single file for space-proofing and AI agent security issues.
 * @param {string} filePath - Absolute file path.
 * @param {string} language - Target language/module identifier.
 * @param {Object} config - Loaded configuration object.
 * @param {Object} options - Scan filter options (category, aiOnly, skipAi).
 * @returns {Promise<Array<Object>>} Detected issues array.
 */
async function analyzeFile(filePath, language, config = {}, options = {}) {
  let content = '';
  try {
    content = await fs.readFile(filePath, 'utf-8');
  } catch (_err) {
    return []; // Return empty array if file cannot be read
  }

  const lines = content.split('\n');
  const rawIssues = [];
  const langConfig = LANGUAGE_PATTERNS[language];
  if (!langConfig) return [];

  const maxFuncLines = config.maxFunctionLines || DEFAULT_MAX_FUNCTION_LINES;
  const configRules = config.rules || {};
  const isSuppressed = createSuppressionFilter(lines);
  const closingChar = language === 'python' ? 'dedent' : '}';

  // 1. Regex Pattern Matching
  if (langConfig.patterns) {
    for (const [issueType, pattern] of Object.entries(langConfig.patterns)) {
      if (!pattern) continue;
      // Skip if rule is disabled in .spc.config.json
      if (configRules[issueType] && configRules[issueType].enabled === false) {
        continue;
      }

      // Filter by category if requested
      if (options.category) {
        const cat = PATTERN_INFO[issueType]?.category ?? langConfig.category;
        if (cat !== options.category) continue;
      }

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
  }

  // 2. Function Length Checks (for code languages with function_regex)
  if (
    langConfig.function_regex &&
    (!configRules.exceeds_max_func_lines ||
      configRules.exceeds_max_func_lines.enabled !== false)
  ) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (langConfig.function_regex.test(line)) {
        const funcMatch = line.match(/^(?:def|function|\w+\s+)?(\w+)/);
        const funcName = funcMatch ? funcMatch[1] : 'anonymous';
        const length = countFunctionLines(lines, i, closingChar);
        if (length > maxFuncLines) {
          rawIssues.push({
            message: `Function '${funcName}' exceeds ${maxFuncLines} lines (${length} lines)`,
            issueType: 'exceeds_max_func_lines',
            lineNum: i + 1,
          });
        }
      }
    }
  }

  // 3. Unchecked Return Checks
  if (langConfig.ignore_functions && langConfig.critical_functions) {
    rawIssues.push(
      ...checkReturnUsage(
        lines,
        langConfig.ignore_functions,
        langConfig.critical_functions,
        langConfig.void_return_indicator
      )
    );
  }

  // Filter out suppressed issues
  const filteredIssues = rawIssues.filter((issue) => {
    if (!issue.lineNum) return true;
    return !isSuppressed(issue.lineNum - 1, issue.issueType);
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
  } catch (_err) {
    return [];
  }
}

/**
 * Scans a directory recursively for space-proofing & AI security issues.
 * @param {string} directory - Directory path to scan.
 * @param {boolean} createSums - Whether to generate checksums manifest.
 * @param {Array<string>} ignorePatterns - Custom ignore patterns.
 * @param {Object} options - Additional scan options (category, aiOnly, skipAi, configPath, pluginsDir).
 * @returns {Promise<Array<Object>>} Scan results array per file.
 */
async function scanCodebase(
  directory,
  createSums = false,
  ignorePatterns = [],
  options = {}
) {
  const results = [];
  const checksums = [];

  try {
    const resolvedDir = await safeRealPath(directory);
    const config = await loadConfig(options.configPath || resolvedDir);
    const spcIgnoreRules = await loadSpcIgnore(resolvedDir);
    const combinedIgnore = buildIgnorePatterns([
      ...ignorePatterns,
      ...spcIgnoreRules,
      ...(config.ignorePatterns || []),
    ]);

    // Load custom plugins if available
    const customPlugins = await loadPlugins(
      options.pluginsDir || path.join(resolvedDir, 'plugins')
    );
    for (const plugin of customPlugins) {
      if (plugin.language && plugin.patterns) {
        LANGUAGE_PATTERNS[plugin.language] = plugin;
        if (plugin.extensions) {
          plugin.extensions.forEach((ext) => {
            EXTENSION_TO_LANGUAGE_MAP[ext.toLowerCase()] = plugin.language;
          });
        }
        if (plugin.filenames) {
          plugin.filenames.forEach((fn) => {
            FILENAME_TO_LANGUAGE_MAP[fn.toLowerCase()] = plugin.language;
          });
        }
      }
    }

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
            ) {
              return;
            }

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
                    message: `Checksum mismatch for file`,
                    issueType: 'checksum_mismatch',
                    lineNum: null,
                  },
                ],
              });
            }

            const baseName = path.basename(file).toLowerCase();
            const ext = path.extname(file).toLowerCase();

            // Match by exact filename first (e.g. SKILL.md, mcp.json), then extension
            let language =
              FILENAME_TO_LANGUAGE_MAP[baseName] ||
              EXTENSION_TO_LANGUAGE_MAP[ext] ||
              null;

            if (language) {
              // Apply --ai-only or --skip-ai filters if specified
              const isAiCategory = ['agent', 'mcp', 'model'].includes(language);
              if (options.aiOnly && !isAiCategory) return;
              if (options.skipAi && isAiCategory) return;

              const issues = await analyzeFile(
                filePath,
                language,
                config,
                options
              );
              results.push({
                file: filePath,
                relativePath: file,
                language,
                issues,
              });
            }
          } catch (_err) {
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

module.exports = {
  scanCodebase,
  analyzeFile,
  LANGUAGE_PATTERNS,
};
