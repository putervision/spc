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

const packageJson = require('../package.json'); // Import package.json for version info

// CLI metadata
const CLI_NAME = 'space-proof-code';
const VERSION = packageJson.version;
const IGNORE_PATTERNS_DEFAULT = ['node_modules', '__pycache__', '.git'];
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
  --help, -h     Display this help menu
  --version, -v  Display the version number
  --create-sums -cs Generates a check sum file in the scanned code path

Examples:
  ${CLI_NAME} /path/to/code    Scan the specified directory
  ${CLI_NAME}                  Scan the current directory
  ${CLI_NAME} --help          Show this help menu
  ${CLI_NAME} --version       Show the version
  ${CLI_NAME} --create-sums Creates checksum file
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

    results.forEach(({ file, language, issues }) => {
      console.log(`\nAnalyzing ${file} (${language ? language : 'n/a'})...`); // Header for each file
      if (issues?.length > 0) {
        // Report issues if any are found, with details for remediation
        console.log(`Issues in ${file}:`);
        issues.forEach((issue) => console.log(`  - ${issue.split('\n')[0]}`));
      } else {
        console.log('  No issues found.');
      }
    });
  } catch (err) {
    console.error(`Error during scan: ${err.message}`);
    throw new Error('process.exit(1)');
  }
}

// Execute the main function and handle top-level errors
main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  throw new Error('process.exit(1)');
});
