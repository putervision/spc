#!/usr/bin/env node

/**
 * cli.js - Command-line interface for @putervision/spc, the Space Proof Code tool.
 * Executes the codebase scanner and reports space-proofing issues to the user, analyzing
 * directories for performance, reliability, and security violations. Designed to help developers
 * ensure code readiness for space missions by providing clear, actionable feedback.
 *
 * Usage:
 * - `space-proof-code /path/to/code` → Scans /path/to/code and logs issues.
 * - `space-proof-code` → Scans current directory if no path provided.
 * - `space-proof-code --help` → Displays this help menu.
 * - `space-proof-code --version` → Displays the tool version.
 * - `space-proof-code --create-sums` → cs Generates a check sum file in the scanned code path
 *
 * Runs asynchronously to handle large codebases efficiently, with robust error handling to
 * ensure usability in mission-critical preparation workflows.
 */

const fs = require('fs').promises; // Filesystem module for async directory checks
const { scanCodebase } = require('../lib/scanner'); // Import core scanning logic
const { PATTERN_INFO } = require('../lib/info');

const packageJson = require('../package.json'); // Import package.json for version info

// CLI metadata
const CLI_NAME = 'space-proof-code';
const VERSION = packageJson.version;
const IGNORE_PATTERNS_DEFAULT = [
  'node_modules[/\\\\]', // JS/TS: Excludes dependency dir, matches "node_modules/lib" or "node_modules\\lib"
  '__pycache__[/\\\\]', // Python: Excludes bytecode cache, matches "__pycache__/module.pyc" or "__pycache__\\module.pyc"
  '\.git[/\\\\]', // All: Excludes Git metadata, matches ".git/hooks/pre-commit" or ".git\\hooks\\pre-commit"
  '\.svn[/\\\\]', // All: Excludes Subversion metadata, matches ".svn/entries" or ".svn\\entries"
  'dist[/\\\\]', // JS/TS: Excludes build output, matches "dist/main.js" or "dist\\main.js"
  'build[/\\\\]', // Java, C/C++, Rust: Excludes build output, matches "build/main.o" or "build\\main.o"
  'target[/\\\\]', // Rust, Java: Excludes build output, matches "target/debug/main" or "target\\debug\\main"
  '\.idea[/\\\\]', // Java: Excludes IntelliJ metadata, matches ".idea/workspace.xml" or ".idea\\workspace.xml"
  '*.o', // C/C++: Excludes object files, matches "main.o" (basename)
  '*.obj', // C/C++: Excludes Windows object files, matches "main.obj" (basename)
  '*.class', // Java: Excludes compiled class files, matches "MyClass.class" (basename)
  '*.pyc', // Python: Excludes bytecode files, matches "module.pyc" (basename)
  '*.pyo', // Python: Excludes optimized bytecode, matches "module.pyo" (basename)
  '*.so', // C/C++, Rust: Excludes shared objects, matches "lib.so" (basename)
  '*.dylib', // C/C++, Rust: Excludes macOS dynamic libs, matches "lib.dylib" (basename)
  '*.dll', // C/C++: Excludes Windows dynamic libs, matches "app.dll" (basename)
  '\.vscode[/\\\\]', // All: Excludes VS Code metadata, matches ".vscode/settings.json" or ".vscode\\settings.json"
  '\.DS_Store', // All (macOS): Excludes Finder metadata, matches ".DS_Store" (full path or basename)
  '*.log', // All: Excludes log files, matches "app.log" (basename)
  'vendor[/\\\\]', // Go: Excludes dependency dir, matches "vendor/golang.org/x/tool" or "vendor\\golang.org\\x\\tool"
  'Godeps[/\\\\]', // Go: Excludes legacy dependency dir, matches "Godeps/_workspace" or "Godeps\\_workspace"
  '*.ali', // Ada: Excludes library info files, matches "main.ali" (basename)
  'obj[/\\\\]', // Ada, C#: Excludes object dir, matches "obj/Debug/" or "obj\\Debug\\"
  'bin[/\\\\]', // C#, Java: Excludes binary output, matches "bin/Release/" or "bin\\Release\\"
  '*.exe', // C#, Fortran: Excludes executables, matches "program.exe" (basename)
  '*.mod', // Fortran: Excludes module files, matches "module.mod" (basename)
  '*.gem', // Ruby: Excludes gem files, matches "mygem.gem" (basename)
  'vendor/bundle[/\\\\]', // Ruby: Excludes Bundler dependency dir, matches "vendor/bundle/ruby/" or "vendor\\bundle\\ruby\\"
  '*.xcodeproj[/\\\\]', // Swift: Excludes Xcode project dirs, matches "MyApp.xcodeproj/" or "MyApp.xcodeproj\\"
  '*.xcworkspace[/\\\\]', // Swift: Excludes Xcode workspace dirs, matches "MyApp.xcworkspace/" or "MyApp.xcworkspace\\"
  'build.gradle[/\\\\]', // Kotlin: Excludes Gradle build dirs, matches "build.gradle/" or "build.gradle\\"
  '*.luac', // Lua: Excludes compiled Lua bytecode, matches "script.luac" (basename)
  'vendor/cache[/\\\\]', // PHP: Excludes Composer cache, matches "vendor/cache/" or "vendor\\cache\\"
  '*.phar', // PHP: Excludes PHP archives, matches "app.phar" (basename)
  'target/scala[/\\\\]', // Scala: Excludes Scala-specific build output, matches "target/scala-2.13/" or "target\\scala-2.13\\"
  '*.hi', // Haskell: Excludes interface files, matches "Main.hi" (basename)
  '*.o-boot', // Haskell: Excludes GHC bootstrap files, matches "Main.o-boot" (basename)
  'dist-newstyle[/\\\\]', // Haskell: Excludes Cabal build dir, matches "dist-newstyle/build/" or "dist-newstyle\\build\\"
];
const IGNORE_PATTERNS = process.env.IGNORE_PATTERNS || IGNORE_PATTERNS_DEFAULT;

/**
 * Displays the help menu with usage instructions.
 */
function showHelp() {
  console.log(`
${CLI_NAME} v${VERSION} - Space Proof Code Tool

Usage: ${CLI_NAME} [directory] [options]

Env vars:
  IGNORE_PATTERNS - string array defaults to ['node_modules', '__pycache__']
    -ignores files while scanning that match on any pattern provided in the string array

Options:
  --help, -h         Display this help menu
  --version, -v      Display the version number
  --create-sums, -cs  Generates a check sum file in the scanned code path

Examples:
  ${CLI_NAME} /path/to/code    Scan the specified directory
  ${CLI_NAME}                  Scan the current directory
  ${CLI_NAME} --help           Show this help menu
  ${CLI_NAME} --version        Show the version
  ${CLI_NAME} --create-sums    Creates checksum file
  `);
}

/**
 * Main entry point for the CLI, orchestrating argument parsing, directory scanning, and result reporting.
 * Validates the target directory, scans for issues, and outputs findings in a user-friendly format.
 */
async function main() {
  const args = process.argv.slice(2); // Skip node and script path

  // Handle no arguments (no-op case: scan current directory)
  if (args.length === 0) {
    return await scanDirectory(process.cwd());
  }

  // Parse command-line arguments
  const firstArg = args[0];
  switch (firstArg) {
    case '--help':
    case '-h':
      showHelp();
      return;

    case '--version':
    case '-v':
      console.log(`${CLI_NAME} v${VERSION}`);
      return;

    case '--create-sums':
    case '-cs':
      return await scanDirectory(process.cwd(), true);

    default:
      if (args[1]) {
        switch (args[1]) {
          case '--create-sums':
          case '-cs':
            return await scanDirectory(firstArg, true);
        }
      }
      return await scanDirectory(firstArg);
  }
}

/**
 * Scans the specified directory and reports results.
 * @param {string} directory - The directory to scan.
 * @param {boolean} createSums - Enables creation of check sums for files scanned.
 */
async function scanDirectory(directory, createSums = false) {
  const startTime = Date.now();
  // Check if the directory exists asynchronously
  const dirExists = await fs
    .access(directory)
    .then(() => true) // Resolve to true if accessible
    .catch(() => false); // Resolve to false if not found or inaccessible

  // Exit with an error if the directory doesn’t exist, ensuring clear user feedback
  if (!dirExists) {
    console.error(`Error: Directory '${directory}' not found or inaccessible.`);
    throw new Error('process.exit(1)');
  }

  // Notify user of the scanning process start
  console.log(`Scanning ${directory} for space-proofing issues...`);
  console.log(`- Ignore patterns: ${IGNORE_PATTERNS}`);
  console.log(`- Create check sums: ${createSums}`);

  try {
    // Scan the directory for space-proofing issues using the core scanner
    const results = await scanCodebase(directory, createSums, IGNORE_PATTERNS);

    if (results.length === 0) {
      console.log('No files found to analyze.');
      return;
    }

    let totalIssues = 0;
    let totalSeverity = 0;
    const issueCounts = {};
    results.forEach(({ file, language, issues, relativePath }) => {
      console.log(
        `\nAnalyzing ${relativePath} (${language ? language : 'n/a'})`
      ); // Header for each file
      if (issues?.length > 0) {
        totalIssues += issues.length;
        // Report issues if any are found, with details for remediation
        console.log(`Issues found: ${issues.length}`);
        const newIssues = [];
        issues.forEach((issue) => {
          const severity = PATTERN_INFO[issue.issueType]?.severity ?? 0;
          const url = PATTERN_INFO[issue.issueType]?.url ?? 'N/A';

          totalSeverity += severity;
          newIssues.push({
            issue: issue.issueType,
            severity,
            line: issue.lineNum,
            ['path to issue']: issue.lineNum
              ? `${relativePath}:${issue.lineNum}`
              : issue.message.split('\n')[0]?.substring(0, 55),
            //info: url,
          });
          if (!issueCounts[issue.issueType]) {
            issueCounts[issue.issueType] = {
              severity,
              total: 1,
              info: url,
            };
          } else {
            issueCounts[issue.issueType].total++;
          }
        });
        console.table(newIssues);
      } else {
        console.log('  No issues found.');
      }
    });

    console.table(issueCounts);
    const end = Date.now();
    const timeDiff = (end - startTime) / 1000;
    console.log(`${CLI_NAME} v${VERSION}`);
    console.log(`Scanning complete in ${timeDiff} seconds`);
    console.log(
      `Total severity: ${totalSeverity} - Total issues: ${totalIssues} - Risk Level: ${(totalSeverity / totalIssues).toFixed(2)} / 5.00`
    );
  } catch (err) {
    console.error(`Error during scan: ${err.message}`);
  }
}

// Execute the main function and handle top-level errors
main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  throw new Error('process.exit(1)');
});
