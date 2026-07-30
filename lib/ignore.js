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

/**
 * Combines default ignore patterns with extra exclude patterns.
 * @param {string[]} extraExcludes - Additional user-provided exclude patterns.
 * @returns {string[]}
 */
function buildIgnorePatterns(extraExcludes = []) {
  const envPatterns = process.env.IGNORE_PATTERNS
    ? process.env.IGNORE_PATTERNS.split(',')
    : DEFAULT_IGNORE_PATTERNS;

  return [...new Set([...envPatterns, ...extraExcludes])];
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

  return ignorePatterns.some((pattern) => {
    try {
      const regex = new RegExp(pattern, 'i');
      return regex.test(filePath);
    } catch {
      return filePath.includes(pattern);
    }
  });
}

module.exports = {
  DEFAULT_IGNORE_PATTERNS,
  buildIgnorePatterns,
  isPathIgnored,
};
