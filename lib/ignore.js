/**
 * ignore.js - Shared ignore pattern utilities for @putervision/spc.
 */

const DEFAULT_IGNORE_PATTERNS = [
  'node_modules[/\\\\]',
  '__pycache__[/\\\\]',
  '\\.git[/\\\\]',
  '\\.svn[/\\\\]',
  'dist[/\\\\]',
  'build[/\\\\]',
  'target[/\\\\]',
  '\\.idea[/\\\\]',
  '*.o',
  '*.obj',
  '*.class',
  '*.pyc',
  '*.pyo',
  '*.so',
  '*.dylib',
  '*.dll',
  '\\.vscode[/\\\\]',
  '\\.DS_Store',
  '*.log',
  'vendor[/\\\\]',
  'obj[/\\\\]',
  'bin[/\\\\]',
  '*.exe',
  '*.mod',
  '*.gem',
  '*.zig-cache[/\\\\]',
  'zig-out[/\\\\]',
  '_build[/\\\\]',
  'checksums\\.sha256\\.txt',
];

const regexCache = new Map();

function getOrCreateRegex(pattern) {
  if (pattern instanceof RegExp) return pattern;
  let cached = regexCache.get(pattern);
  if (!cached) {
    try {
      let regexStr = pattern;
      if (regexStr.startsWith('*.')) {
        regexStr = '\\.' + regexStr.slice(2) + '($|[/\\\\])';
      }
      cached = new RegExp(regexStr, 'i');
    } catch {
      cached = { test: (p) => p.includes(pattern) };
    }
    regexCache.set(pattern, cached);
  }
  return cached;
}

/**
 * Combines default ignore patterns with extra exclude patterns and env variables.
 * @param {string[]} extraExcludes - Additional user-provided exclude patterns.
 * @param {object} options - Options including noDefaultIgnores.
 * @returns {string[]}
 */
function buildIgnorePatterns(extraExcludes = [], options = {}) {
  const { noDefaultIgnores = false } = options;
  const envPatterns = process.env.IGNORE_PATTERNS
    ? process.env.IGNORE_PATTERNS.split(',')
        .map((p) => p.trim())
        .filter(Boolean)
    : [];

  const basePatterns = noDefaultIgnores ? [] : DEFAULT_IGNORE_PATTERNS;
  return [...new Set([...basePatterns, ...envPatterns, ...extraExcludes])];
}

/**
 * Checks if a relative or absolute file path matches any ignore pattern.
 * @param {string} filePath - Path to check.
 * @param {string[]} ignorePatterns - List of regex strings/patterns to check against.
 * @returns {boolean}
 */
function isPathIgnored(filePath, ignorePatterns = []) {
  if (!filePath || !ignorePatterns || ignorePatterns.length === 0) {
    return false;
  }

  const normalizedPath = filePath.replace(/\\/g, '/');
  for (let i = 0; i < ignorePatterns.length; i++) {
    const matcher = getOrCreateRegex(ignorePatterns[i]);
    if (matcher.test(normalizedPath) || matcher.test(filePath)) {
      return true;
    }
  }
  return false;
}

module.exports = {
  DEFAULT_IGNORE_PATTERNS,
  buildIgnorePatterns,
  isPathIgnored,
  getOrCreateRegex,
};
