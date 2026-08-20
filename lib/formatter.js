/**
 * formatter.js - Output formatting utilities for @putervision/spc.
 * Supports table (console display), json (machine readable), md (Markdown table), and sarif (GitHub Code Scanning).
 */

const { PATTERN_INFO } = require('./info');

/**
 * Maps numeric severity (1-5) to SARIF rule level ('error', 'warning', 'note').
 * @param {number} severity - Severity score from 1 to 5.
 * @returns {string} SARIF level.
 */
function mapSeverityToSarifLevel(severity) {
  if (severity >= 4) return 'error';
  if (severity >= 3) return 'warning';
  return 'note';
}

/**
 * Formats scan results into the requested format (table, json, md, sarif).
 *
 * @param {Array} results - Array of scan results per file.
 * @param {Object} options - Options containing format ('table'|'json'|'md'|'sarif'), CLI_NAME, and VERSION.
 * @returns {string|null} - Output string or null if printed directly.
 */
function formatResults(results, options = {}) {
  const {
    format = 'table',
    CLI_NAME = 'space-proof-code',
    VERSION = '1.5.0',
    timeDiff = 0,
  } = options;

  let totalIssues = 0;
  let totalSeverity = 0;
  const issueCounts = {};
  const processedResults = [];

  results.forEach(({ file: _file, language, issues, relativePath }) => {
    const fileIssues = [];
    if (issues && issues.length > 0) {
      totalIssues += issues.length;
      issues.forEach((issue) => {
        const severity = PATTERN_INFO[issue.issueType]?.severity ?? 0;
        const url = PATTERN_INFO[issue.issueType]?.url ?? 'N/A';
        const category = PATTERN_INFO[issue.issueType]?.category ?? 'quality';

        totalSeverity += severity;
        fileIssues.push({
          issue: issue.issueType,
          severity,
          category,
          line: issue.lineNum,
          path: issue.lineNum
            ? `${relativePath}:${issue.lineNum}`
            : relativePath,
          message: issue.message,
          info: url,
        });

        if (!issueCounts[issue.issueType]) {
          issueCounts[issue.issueType] = {
            severity,
            category,
            total: 1,
            info: url,
          };
        } else {
          issueCounts[issue.issueType].total++;
        }
      });
    }
    processedResults.push({
      file: relativePath,
      language: language || 'n/a',
      issueCount: issues ? issues.length : 0,
      issues: fileIssues,
    });
  });

  const riskLevel =
    totalIssues > 0 ? (totalSeverity / totalIssues).toFixed(2) : '0.00';

  if (format === 'json') {
    const outputData = {
      tool: CLI_NAME,
      version: VERSION,
      scanTimeSeconds: timeDiff,
      summary: {
        totalFilesScanned: results.length,
        totalIssues,
        totalSeverity,
        riskLevel: parseFloat(riskLevel),
        issueCounts,
      },
      files: processedResults,
    };
    return JSON.stringify(outputData, null, 2);
  }

  if (format === 'sarif') {
    const sarifRulesMap = {};
    const sarifResults = [];

    processedResults.forEach((fileRes) => {
      fileRes.issues.forEach((iss) => {
        if (!sarifRulesMap[iss.issue]) {
          sarifRulesMap[iss.issue] = {
            id: iss.issue,
            name: iss.issue,
            shortDescription: {
              text: `SPC Security & Reliability Rule: ${iss.issue}`,
            },
            helpUri: `https://github.com/putervision/spc/tree/main/${iss.info}`,
            properties: {
              severity: iss.severity,
              category: iss.category,
            },
          };
        }

        sarifResults.push({
          ruleId: iss.issue,
          level: mapSeverityToSarifLevel(iss.severity),
          message: { text: iss.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: fileRes.file,
                },
                region: {
                  startLine: iss.line || 1,
                },
              },
            },
          ],
        });
      });
    });

    const sarifData = {
      $schema:
        'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: CLI_NAME,
              version: VERSION,
              informationUri: 'https://github.com/putervision/spc',
              rules: Object.values(sarifRulesMap),
            },
          },
          results: sarifResults,
        },
      ],
    };
    return JSON.stringify(sarifData, null, 2);
  }

  if (format === 'md') {
    let md =
      `# Space Proof Code (` + CLI_NAME + ` v` + VERSION + `) Report\n\n`;
    md += `**Files Scanned**: ${results.length} | **Total Issues**: ${totalIssues} | **Total Severity**: ${totalSeverity} | **Risk Level**: ${riskLevel} / 5.00\n\n`;
    md += `## Issue Summary\n\n`;
    md += `| Issue Type | Category | Severity | Count | Documentation |\n`;
    md += `|---|---|---|---|---|\n`;

    Object.keys(issueCounts).forEach((type) => {
      const item = issueCounts[type];
      md += `| \`${type}\` | \`${item.category}\` | ${item.severity} | ${item.total} | [Docs](${item.info}) |\n`;
    });

    md += `\n## Detailed Findings\n\n`;
    processedResults.forEach((fileRes) => {
      if (fileRes.issueCount > 0) {
        md += `### ${fileRes.file} (${fileRes.language})\n\n`;
        md += `| Line | Issue | Category | Severity | Message |\n`;
        md += `|---|---|---|---|---|\n`;
        fileRes.issues.forEach((iss) => {
          md += `| ${iss.line || 'N/A'} | \`${iss.issue}\` | \`${iss.category}\` | ${iss.severity} | ${iss.message.replace(/\|/g, '\\|')} |\n`;
        });
        md += `\n`;
      }
    });

    return md;
  }

  // Format: table (returns formatted plain-text report)
  let tableOutput = `${CLI_NAME} v${VERSION} — Scan Report\n`;
  tableOutput += `Files Scanned: ${results.length} | Issues: ${totalIssues} | Total Severity: ${totalSeverity} | Risk Level: ${riskLevel} / 5.00\n\n`;

  if (totalIssues > 0) {
    tableOutput += 'Issues Found:\n';
    processedResults.forEach((fileRes) => {
      if (fileRes.issueCount > 0) {
        tableOutput += `\n  ${fileRes.file} (${fileRes.language}):\n`;
        fileRes.issues.forEach((iss) => {
          tableOutput += `    line ${iss.line || 'N/A'}: [${iss.issue}] (severity: ${iss.severity}/5) ${iss.message}\n`;
        });
      }
    });
  } else {
    tableOutput += 'No issues detected.\n';
  }

  return tableOutput;
}

module.exports = { formatResults };
