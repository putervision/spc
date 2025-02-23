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

/**
 * Displays the help menu with usage instructions.
 */
function showHelp() {
  console.log(`
${CLI_NAME} v${VERSION} - Space Proof Code Tool

Usage: ${CLI_NAME} [directory] [options]

Options:
  --help, -h     Display this help menu
  --version, -v  Display the version number

Examples:
  ${CLI_NAME} /path/to/code    Scan the specified directory
  ${CLI_NAME}                  Scan the current directory
  ${CLI_NAME} --help          Show this help menu
  ${CLI_NAME} --version       Show the version
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

    default:
      // Assume it's a directory path if not a flag
      return await scanDirectory(firstArg);
  }
}

/**
 * Scans the specified directory and reports results.
 * @param {string} directory - The directory to scan.
 */
async function scanDirectory(directory) {
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

  try {
    // Scan the directory for space-proofing issues using the core scanner
    const results = await scanCodebase(directory);

    if (results.length === 0) {
      console.log('No files found to analyze.');
      return;
    }

    results.forEach(({ file, language, issues }) => {
      console.log(`\nAnalyzing ${file} (${language})...`); // Header for each file
      if (issues.length > 0) {
        // Report issues if any are found, with details for remediation
        console.log(`Issues in ${file}:`);
        issues.forEach((issue) => console.log(`  - ${issue}`));
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
