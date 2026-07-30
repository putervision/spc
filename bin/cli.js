#!/usr/bin/env node

/**
 * cli.js - Command-line interface for @putervision/spc (Space Proof Code).
 * Executes codebase scanner and reports space-proofing issues across 20 languages.
 *
 * Usage:
 * - `space-proof-code /path/to/code` → Scans path and reports issues.
 * - `space-proof-code --format json -o report.json` → Outputs machine-readable JSON report to file.
 * - `space-proof-code --format md` → Outputs Markdown report table for CI summaries.
 * - `space-proof-code --max-severity 4` → Fails (exit code 1) if severity >= 4 detected.
 * - `space-proof-code --help` → Displays help menu.
 * - `space-proof-code --version` → Displays tool version.
 */

const fs = require('fs').promises;
const path = require('path');
const { scanCodebase } = require('../lib/scanner');
const { PATTERN_INFO } = require('../lib/info');
const { formatResults } = require('../lib/formatter');
const packageJson = require('../package.json');

const CLI_NAME = 'space-proof-code';
const VERSION = packageJson.version;

const IGNORE_PATTERNS_DEFAULT = [
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
];

const IGNORE_PATTERNS = process.env.IGNORE_PATTERNS
  ? process.env.IGNORE_PATTERNS.split(',')
  : IGNORE_PATTERNS_DEFAULT;

function showHelp() {
  console.log(`
${CLI_NAME} v${VERSION} - Space Proof Code Tool (PuterVision)

Usage: ${CLI_NAME} [directory] [options]

Options:
  --help, -h            Display this help menu
  --version, -v         Display the version number
  --create-sums, -cs    Generates a checksum file in the scanned code path
  --format <table|json|md> Output format (default: table)
  -o, --output <file>   Save output report to specified file path
  --max-severity <N>    Exit non-zero if total severity average or issue severity reaches N
  --fail-on-issue       Exit non-zero if any space-proofing issues are found

Examples:
  ${CLI_NAME} /path/to/code
  ${CLI_NAME} . --format json -o spc-report.json
  ${CLI_NAME} . --format md
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
  let failOnIssue = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      showHelp();
      return;
    }
    if (arg === '--version' || arg === '-v') {
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
    if (arg === '--max-severity') {
      maxSeverityThreshold = parseFloat(args[++i]);
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
    failOnIssue,
  });
}

async function scanDirectory(directory, options = {}) {
  const {
    createSums = false,
    format = 'table',
    outputFile = null,
    maxSeverityThreshold = null,
    failOnIssue = false,
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

  if (format === 'table' && !outputFile) {
    console.log(`Scanning ${directory} for space-proofing issues...`);
    console.log(`- Version: ${VERSION}`);
    console.log(`- Create checksums: ${createSums}`);
  }

  try {
    const results = await scanCodebase(directory, createSums, IGNORE_PATTERNS);
    const end = Date.now();
    const timeDiff = (end - startTime) / 1000;

    let totalIssues = 0;
    let totalSeverity = 0;

    if (results.length === 0) {
      if (format === 'table') console.log('No files found to analyze.');
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
        console.log(`Report successfully saved to ${outputFile}`);
      } else {
        console.log(formattedOutput);
      }
    } else {
      // Default table display
      const issueCounts = {};
      results.forEach(({ relativePath, language, issues }) => {
        console.log(`\nAnalyzing ${relativePath} (${language || 'n/a'})`);
        if (issues?.length > 0) {
          totalIssues += issues.length;
          console.log(`Issues found: ${issues.length}`);
          const fileIssues = [];
          issues.forEach((issue) => {
            const severity = PATTERN_INFO[issue.issueType]?.severity ?? 0;
            const url = PATTERN_INFO[issue.issueType]?.url ?? 'N/A';
            totalSeverity += severity;

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
          console.table(fileIssues);
        } else {
          console.log('  No issues found.');
        }
      });

      if (Object.keys(issueCounts).length > 0) {
        console.table(issueCounts);
      }

      console.log(`\n${CLI_NAME} v${VERSION}`);
      console.log(`Scanning complete in ${timeDiff} seconds`);
      const riskLevel =
        totalIssues > 0 ? (totalSeverity / totalIssues).toFixed(2) : '0.00';
      console.log(
        `Total severity: ${totalSeverity} - Total issues: ${totalIssues} - Risk Level: ${riskLevel} / 5.00`
      );

      if (outputFile) {
        const mdOutput = formatResults(results, {
          format: 'md',
          CLI_NAME,
          VERSION,
          timeDiff,
        });
        await fs.writeFile(outputFile, mdOutput, 'utf8');
        console.log(`Report summary saved to ${outputFile}`);
      }
    }

    // Quality gate checks
    const avgRisk = totalIssues > 0 ? totalSeverity / totalIssues : 0;
    if (
      (maxSeverityThreshold !== null && avgRisk >= maxSeverityThreshold) ||
      (failOnIssue && totalIssues > 0)
    ) {
      console.error(
        `\nCI Quality Gate Failed: threshold exceeded (Issues: ${totalIssues}, Risk Level: ${avgRisk.toFixed(2)})`
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
