#!/usr/bin/env node

/**
 * cli.js - Command-line interface for @putervision/spc (Space Proof Code).
 * Executes codebase scanner and reports space-proofing issues across 20 languages.
 *
 * Usage:
 * - `space-proof-code /path/to/code` → Scans path and reports issues.
 * - `space-proof-code --format json -o report.json` → Outputs machine-readable JSON report to file.
 * - `space-proof-code --format md` → Outputs Markdown report table for CI summaries.
 * - `space-proof-code --max-severity 4` → Fails (exit code 1) if average severity >= 4 detected.
 * - `space-proof-code --max-issue-severity 4` → Fails if any single issue has severity >= 4.
 * - `space-proof-code --exclude node_modules,dist` → Excludes patterns from scan.
 * - `space-proof-code --quiet` → Suppresses non-essential console logs.
 * - `space-proof-code --help` → Displays help menu.
 * - `space-proof-code --version` → Displays tool version.
 */

const fs = require('fs').promises;
const { scanCodebase } = require('../lib/scanner');
const { PATTERN_INFO } = require('../lib/info');
const { formatResults } = require('../lib/formatter');
const { buildIgnorePatterns } = require('../lib/ignore');
const { loadConfig } = require('../lib/config');
const packageJson = require('../package.json');

const CLI_NAME = 'space-proof-code';
const VERSION = packageJson.version;

function showHelp() {
  console.log(`
${CLI_NAME} v${VERSION} - Space Proof Code Tool (PuterVision)

High-performance zero-dependency static analysis tool enforcing NASA Power of Ten
reliability and security rules across 20 programming languages.

Usage: ${CLI_NAME} [directory] [options]

Options:
  --help, -h                  Display this help menu
  --version, -V               Display the version number
  --create-sums, -cs          Generates a checksum file in the scanned code path
  --format <table|json|md>    Output format (default: table)
  -o, --output <file>         Save output report to specified file path
  --exclude <pattern>         Add extra ignore patterns (comma-separated or flag repeated)
  --config <path>             Path to .spc.config.json configuration file
  --progress, -p              Show scanning progress file by file
  --quiet, -q                 Suppress standard log outputs (only output error logs)
  --color / --no-color        Enable or disable ANSI colors in terminal output
  --max-severity <N>          Exit non-zero if average severity risk level >= N
  --max-issue-severity <N>    Exit non-zero if any single issue severity >= N
  --fail-on-issue             Exit non-zero if any space-proofing issues are found

Examples:
  ${CLI_NAME} /path/to/code
  ${CLI_NAME} . --format json -o spc-report.json --exclude node_modules
  ${CLI_NAME} . --format md --max-issue-severity 4
  ${CLI_NAME} --version
  `);
}

async function main() {
  const args = process.argv.slice(2);
  let targetDir = process.cwd();
  let createSums = false;
  let format = 'table';
  let outputFile = null;
  let maxSeverityThreshold = null;
  let maxIssueSeverityThreshold = null;
  let failOnIssue = false;
  let extraExcludes = [];
  let configPath = null;
  let showProgress = false;
  let quiet = false;
  let color = true;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      showHelp();
      return;
    }
    if (arg === '--version' || arg === '-v' || arg === '-V') {
      console.log(`${CLI_NAME} v${VERSION}`);
      return;
    }
    if (arg === '--create-sums' || arg === '-cs') {
      createSums = true;
      continue;
    }
    if (arg === '--format') {
      format = args[++i] || 'table';
      continue;
    }
    if (arg === '-o' || arg === '--output') {
      outputFile = args[++i] || null;
      continue;
    }
    if (arg === '--exclude') {
      const val = args[++i];
      if (val) {
        extraExcludes.push(...val.split(','));
      }
      continue;
    }
    if (arg === '--config') {
      configPath = args[++i] || null;
      continue;
    }
    if (arg === '--progress' || arg === '-p') {
      showProgress = true;
      continue;
    }
    if (arg === '--quiet' || arg === '-q') {
      quiet = true;
      continue;
    }
    if (arg === '--no-color') {
      color = false;
      continue;
    }
    if (arg === '--color') {
      color = true;
      continue;
    }
    if (arg === '--max-severity') {
      maxSeverityThreshold = parseFloat(args[++i]);
      continue;
    }
    if (arg === '--max-issue-severity') {
      maxIssueSeverityThreshold = parseFloat(args[++i]);
      continue;
    }
    if (arg === '--fail-on-issue') {
      failOnIssue = true;
      continue;
    }
    if (!arg.startsWith('-')) {
      targetDir = arg;
    }
  }

  await scanDirectory(targetDir, {
    createSums,
    format,
    outputFile,
    maxSeverityThreshold,
    maxIssueSeverityThreshold,
    failOnIssue,
    extraExcludes,
    configPath,
    showProgress,
    quiet,
    color,
  });
}

async function scanDirectory(directory, options = {}) {
  const {
    createSums = false,
    format = 'table',
    outputFile = null,
    maxSeverityThreshold = null,
    maxIssueSeverityThreshold = null,
    failOnIssue = false,
    extraExcludes = [],
    configPath = null,
    showProgress = false,
    quiet = false,
  } = options;

  const startTime = Date.now();
  const dirExists = await fs
    .access(directory)
    .then(() => true)
    .catch(() => false);

  if (!dirExists) {
    console.error(`Error: Directory '${directory}' not found or inaccessible.`);
    process.exitCode = 1;
    return;
  }

  const fileConfig = await loadConfig(configPath || directory);
  const ignorePatterns = buildIgnorePatterns([
    ...extraExcludes,
    ...(fileConfig.ignorePatterns || []),
  ]);

  if (!quiet && format === 'table' && !outputFile) {
    console.log(`Scanning ${directory} for space-proofing issues...`);
    console.log(`- Version: ${VERSION}`);
    console.log(`- Create checksums: ${createSums}`);
    if (showProgress) console.log(`- Progress mode: active`);
  }

  try {
    const results = await scanCodebase(directory, createSums, ignorePatterns);
    const end = Date.now();
    const timeDiff = (end - startTime) / 1000;

    let totalIssues = 0;
    let totalSeverity = 0;
    let maxFoundIssueSeverity = 0;

    if (results.length === 0) {
      if (!quiet && format === 'table')
        console.log('No files found to analyze.');
      return;
    }

    if (format === 'json' || format === 'md') {
      const formattedOutput = formatResults(results, {
        format,
        CLI_NAME,
        VERSION,
        timeDiff,
      });

      if (outputFile) {
        await fs.writeFile(outputFile, formattedOutput, 'utf8');
        if (!quiet) console.log(`Report successfully saved to ${outputFile}`);
      } else {
        console.log(formattedOutput);
      }

      results.forEach(({ issues }) => {
        if (issues) {
          issues.forEach((issue) => {
            const sev = PATTERN_INFO[issue.issueType]?.severity ?? 0;
            totalIssues++;
            totalSeverity += sev;
            if (sev > maxFoundIssueSeverity) maxFoundIssueSeverity = sev;
          });
        }
      });
    } else {
      // Default table display
      const issueCounts = {};
      results.forEach(({ relativePath, language, issues }) => {
        if (showProgress && !quiet) {
          console.error(
            `Scanned: ${relativePath} (${issues?.length || 0} issues)`
          );
        }

        if (!quiet)
          console.log(`\nAnalyzing ${relativePath} (${language || 'n/a'})`);
        if (issues?.length > 0) {
          totalIssues += issues.length;
          if (!quiet) console.log(`Issues found: ${issues.length}`);
          const fileIssues = [];
          issues.forEach((issue) => {
            const severity = PATTERN_INFO[issue.issueType]?.severity ?? 0;
            const url = PATTERN_INFO[issue.issueType]?.url ?? 'N/A';
            totalSeverity += severity;
            if (severity > maxFoundIssueSeverity)
              maxFoundIssueSeverity = severity;

            fileIssues.push({
              issue: issue.issueType,
              severity,
              line: issue.lineNum,
              ['path to issue']: issue.lineNum
                ? `${relativePath}:${issue.lineNum}`
                : relativePath,
            });

            if (!issueCounts[issue.issueType]) {
              issueCounts[issue.issueType] = { severity, total: 1, info: url };
            } else {
              issueCounts[issue.issueType].total++;
            }
          });
          if (!quiet) console.table(fileIssues);
        } else {
          if (!quiet) console.log('  No issues found.');
        }
      });

      if (!quiet && Object.keys(issueCounts).length > 0) {
        console.table(issueCounts);
      }

      if (!quiet) {
        console.log(`\n${CLI_NAME} v${VERSION}`);
        console.log(`Scanning complete in ${timeDiff} seconds`);
        const riskLevel =
          totalIssues > 0 ? (totalSeverity / totalIssues).toFixed(2) : '0.00';
        console.log(
          `Total severity: ${totalSeverity} - Total issues: ${totalIssues} - Risk Level: ${riskLevel} / 5.00`
        );
      }

      if (outputFile) {
        const mdOutput = formatResults(results, {
          format: 'md',
          CLI_NAME,
          VERSION,
          timeDiff,
        });
        await fs.writeFile(outputFile, mdOutput, 'utf8');
        if (!quiet) console.log(`Report summary saved to ${outputFile}`);
      }
    }

    // Quality gate checks
    const avgRisk = totalIssues > 0 ? totalSeverity / totalIssues : 0;
    if (
      (maxSeverityThreshold !== null && avgRisk >= maxSeverityThreshold) ||
      (maxIssueSeverityThreshold !== null &&
        maxFoundIssueSeverity >= maxIssueSeverityThreshold) ||
      (failOnIssue && totalIssues > 0)
    ) {
      console.error(
        `\nCI Quality Gate Failed: threshold exceeded (Issues: ${totalIssues}, Avg Risk: ${avgRisk.toFixed(2)}, Max Issue Severity: ${maxFoundIssueSeverity})`
      );
      process.exitCode = 1;
    }
  } catch (err) {
    console.error(`Error during scan: ${err.message}`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  process.exitCode = 1;
});
