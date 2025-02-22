#!/usr/bin/env node

/**
 * cli.js - Command-line interface for @putervision/spc, the Space Proof Code tool.
 * Executes the codebase scanner and reports space-proofing issues to the user, analyzing
 * directories for performance, reliability, and security violations. Designed to help developers
 * ensure code readiness for space missions by providing clear, actionable feedback.
 *
 * Example usage:
 * - `space-proof-code /path/to/code` → Scans /path/to/code and logs issues.
 * - `space-proof-code` → Scans current directory if no path provided.
 *
 * Runs asynchronously to handle large codebases efficiently, with robust error handling to
 * ensure usability in mission-critical preparation workflows.
 */

const fs = require('fs').promises; // Filesystem module for async directory checks
const { scanCodebase } = require('../lib/checker'); // Import core scanning logic

/**
 * Main entry point for the CLI, orchestrating directory scanning and result reporting.
 * Validates the target directory, scans for issues, and outputs findings in a user-friendly format.
 */
async function main() {
  // Default to current working directory if no argument provided (process.argv[2])
  const directory = process.argv[2] || process.cwd();

  // Check if the directory exists asynchronously to avoid blocking
  const dirExists = await fs
    .access(directory)
    .then(() => true) // Resolve to true if accessible
    .catch(() => false); // Resolve to false if not found or inaccessible

  // Exit with an error if the directory doesn’t exist, ensuring clear user feedback
  if (!dirExists) {
    console.error(`Error: Directory '${directory}' not found.`);
    throw new Error('process.exit(1)'); // Trigger process exit with error code
  }

  // Notify user of the scanning process start
  console.log(`Scanning ${directory} for space-proofing issues...`);

  try {
    // Scan the directory for space-proofing issues using the core checker
    const results = await scanCodebase(directory);

    // Iterate over results and display findings for each file
    results.forEach(({ file, language, issues }) => {
      console.log(`\nAnalyzing ${file} (${language})...`); // Header for each file
      if (issues.length > 0) {
        // Report issues if any are found, with details for remediation
        console.log(`Issues in ${file}:`);
        issues.forEach((issue) => console.log(`  - ${issue}`));
      } else {
        // Confirm no issues for user assurance
        console.log('  No issues found.');
      }
    });
  } catch (err) {
    // Handle scanning errors (e.g., file access issues), providing clear feedback
    console.error(err.message);
    //throw new Error("process.exit(1): " + err.message); // Exit with error code on failure
  }
}

// Execute the main function asynchronously, ensuring non-blocking operation
void main();
