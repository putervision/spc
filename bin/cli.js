#!/usr/bin/env node

/**
 * cli.js - Command-line interface for @putervision/spc (Space Proof Code).
 * Executes codebase scanner across 20 languages + AI Agent Skills, MCP server configs,
 * prompt instructions, and LLM model deployment configurations.
 *
 * Usage:
 * - `spc /path/to/code` → Scans path and reports issues.
 * - `spc --format json -o report.json` → Outputs machine-readable JSON report.
 * - `spc --format sarif -o report.sarif` → Outputs SARIF v2.1.0 for GitHub Code Scanning.
 * - `spc --ai-only` → Scans only AI Agent skills, prompt templates, MCP configs, and model files.
 * - `spc --category security` → Filters rules by category (nasa, security, quality, agent).
 * - `spc --list-rules` → Displays all rules with severities and categories.
 */

const fs = require('fs').promises;
const { scanCodebase } = require('../lib/scanner');
const { PATTERN_INFO, getAgentToolSchema } = require('../lib/info');
const { formatResults } = require('../lib/formatter');
const { buildIgnorePatterns } = require('../lib/ignore');
const { loadConfig } = require('../lib/config');
const packageJson = require('../package.json');

const CLI_NAME = 'space-proof-code';
const VERSION = packageJson.version;

function showHelp() {
  console.log(`
${CLI_NAME} v${VERSION} - Space Proof Code & AI Agent Security Analyzer (PuterVision)

High-performance zero-dependency static analysis tool enforcing NASA Power of Ten
reliability rules across 20 programming languages, plus AI agent skill, MCP config,
prompt template, and LLM model deployment security auditing.

Usage: ${CLI_NAME} [directory] [options]

Options:
  --help, -h                    Display this help menu
  --version, -v, -V             Display the version number
  --format <table|json|md|sarif> Output format (default: table)
  -o, --output <file>           Save output report to specified file path
  --category <name>             Filter checks by category (nasa, security, quality, agent)
  --ai-only                     Scan only AI agent skills, prompts, MCP configs & model files
  --skip-ai                     Skip AI agent checks, scan traditional code languages only
  --list-rules                  Display all supported rules, severities, and categories
  --agent-tools, --schema       Print structured agent tool & operation schema JSON
  --create-sums, -cs            Generates a SHA-256 checksum manifest file in target path
  --exclude <pattern>           Add extra ignore patterns (comma-separated or flag repeated)
  --config <path>               Path to .spc.config.json configuration file
  --progress, -p                Show scanning progress file by file
  --quiet, -q                   Suppress non-essential log outputs
  --color / --no-color          Enable or disable ANSI colors in terminal output
  --max-severity <N>            Exit non-zero if average severity risk level >= N
  --max-issue-severity <N>      Exit non-zero if any single issue severity >= N
  --fail-on-issue               Exit non-zero if any issues are detected

Examples:
  spc /path/to/code
  spc . --format sarif -o spc-report.sarif
  spc . --ai-only --format json -o agent-audit.json
  spc --agent-tools
  spc --list-rules
  spc --version
  `);
}

function listRules() {
  console.log(`\nSpace Proof Code (SPC v${VERSION}) — Rule Registry\n`);
  console.log(
    'Issue Type'.padEnd(32) +
      'Category'.padEnd(12) +
      'Severity'.padEnd(10) +
      'Documentation URI'
  );
  console.log('-'.repeat(85));

  for (const [issueType, info] of Object.entries(PATTERN_INFO)) {
    const cat = info.category || 'quality';
    const sev = `${info.severity}/5`;
    const url = info.url || 'N/A';
    console.log(issueType.padEnd(32) + cat.padEnd(12) + sev.padEnd(10) + url);
  }
  console.log(`\nTotal rules: ${Object.keys(PATTERN_INFO).length}\n`);
}

async function main() {
  const args = process.argv.slice(2);
  const targetDirs = [];
  let createSums = false;
  let format = 'table';
  let outputFile = null;
  let category = null;
  let aiOnly = false;
  let skipAi = false;
  let maxSeverityThreshold = null;
  let maxIssueSeverityThreshold = null;
  let failOnIssue = false;
  let extraExcludes = [];
  let configPath = null;
  let showProgress = false;
  let quiet = false;

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
    if (arg === '--list-rules') {
      listRules();
      return;
    }
    if (arg === '--agent-tools' || arg === '--schema') {
      console.log(JSON.stringify(getAgentToolSchema(), null, 2));
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
    if (arg === '--category') {
      category = (args[++i] || '').toLowerCase();
      continue;
    }
    if (arg === '--ai-only') {
      aiOnly = true;
      continue;
    }
    if (arg === '--skip-ai') {
      skipAi = true;
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
    if (arg === '--color') {
      process.env.FORCE_COLOR = '1';
      delete process.env.NO_COLOR;
      continue;
    }
    if (arg === '--no-color') {
      process.env.NO_COLOR = '1';
      delete process.env.FORCE_COLOR;
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
      targetDirs.push(arg);
    }
  }

  const dirsToScan = targetDirs.length > 0 ? targetDirs : [process.cwd()];

  await scanDirectory(dirsToScan, {
    createSums,
    format,
    outputFile,
    category,
    aiOnly,
    skipAi,
    maxSeverityThreshold,
    maxIssueSeverityThreshold,
    failOnIssue,
    extraExcludes,
    configPath,
    showProgress,
    quiet,
  });
}

async function scanDirectory(directories, options = {}) {
  const {
    createSums = false,
    format = 'table',
    outputFile = null,
    category = null,
    aiOnly = false,
    skipAi = false,
    maxSeverityThreshold = null,
    maxIssueSeverityThreshold = null,
    failOnIssue = false,
    extraExcludes = [],
    configPath = null,
    showProgress = false,
    quiet = false,
  } = options;

  const targetDirs = Array.isArray(directories) ? directories : [directories];
  const startTime = Date.now();

  const validDirs = [];
  for (const dir of targetDirs) {
    const dirExists = await fs
      .access(dir)
      .then(() => true)
      .catch(() => false);
    if (!dirExists) {
      console.error(`Error: Directory '${dir}' not found or inaccessible.`);
      process.exitCode = 1;
      return;
    }
    validDirs.push(dir);
  }

  const fileConfig = await loadConfig(configPath || targetDirs[0]);
  const ignorePatterns = buildIgnorePatterns([
    ...extraExcludes,
    ...(fileConfig.ignorePatterns || []),
  ]);

  if (!quiet && format === 'table' && !outputFile) {
    console.error(
      `Scanning ${targetDirs.join(', ')} for space-proofing & AI security issues...`
    );
    console.error(`- Version: ${VERSION}`);
    console.error(`- Create checksums: ${createSums}`);
    if (category) console.error(`- Category filter: ${category}`);
    if (aiOnly) console.error(`- Scan mode: AI Agent & MCP files only`);
    if (showProgress) console.error(`- Progress mode: active`);
  }

  try {
    let results = [];
    for (const dir of validDirs) {
      const dirResults = await scanCodebase(dir, createSums, ignorePatterns, {
        category,
        aiOnly,
        skipAi,
        configPath,
      });
      results.push(...dirResults);
    }
    const end = Date.now();
    const timeDiff = (end - startTime) / 1000;

    let totalIssues = 0;
    let totalSeverity = 0;
    let maxFoundIssueSeverity = 0;

    if (results.length === 0) {
      if (!quiet && format === 'table') {
        console.error('No matching files found to analyze.');
      }
      return;
    }

    if (format === 'json' || format === 'md' || format === 'sarif') {
      const formattedOutput = formatResults(results, {
        format,
        CLI_NAME,
        VERSION,
        timeDiff,
      });

      if (outputFile) {
        await fs.writeFile(outputFile, formattedOutput, 'utf8');
        if (!quiet) console.error(`Report successfully saved to ${outputFile}`);
      } else {
        process.stdout.write(formattedOutput + '\n');
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
      // Default table display (console table)
      const issueCounts = {};
      results.forEach(({ relativePath, language, issues }) => {
        if (showProgress && !quiet) {
          console.error(
            `Scanned: ${relativePath} (${issues?.length || 0} issues)`
          );
        }

        if (!quiet) {
          console.log(`\nAnalyzing ${relativePath} (${language || 'n/a'})`);
        }
        if (issues?.length > 0) {
          totalIssues += issues.length;
          if (!quiet) console.log(`Issues found: ${issues.length}`);
          const fileIssues = [];
          issues.forEach((issue) => {
            const severity = PATTERN_INFO[issue.issueType]?.severity ?? 0;
            const url = PATTERN_INFO[issue.issueType]?.url ?? 'N/A';
            totalSeverity += severity;
            if (severity > maxFoundIssueSeverity) {
              maxFoundIssueSeverity = severity;
            }

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
        if (!quiet) console.error(`Report summary saved to ${outputFile}`);
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
