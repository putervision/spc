/**
 * formatter.js - Output formatting utilities for @putervision/spc.
 * Supports table (console display), json (machine readable), and md (Markdown table).
 */

const { PATTERN_INFO } = require('./info');

/**
 * Formats scan results into the requested format (table, json, md).
 *
 * @param {Array} results - Array of scan results per file.
 * @param {Object} options - Options containing format ('table'|'json'|'md'), CLI_NAME, and VERSION.
 * @returns {string|null} - Output string or null if printed directly.
 */
function formatResults(results, options = {}) {
  const {
    format = 'table',
    CLI_NAME = 'space-proof-code',
    VERSION = '1.2.0',
    timeDiff = 0,
  } = options;

  let totalIssues = 0;
  let totalSeverity = 0;
  const issueCounts = {};
  const processedResults = [];

  results.forEach(({ file, language, issues, relativePath }) => {
    const fileIssues = [];
    if (issues && issues.length > 0) {
      totalIssues += issues.length;
      issues.forEach((issue) => {
        const severity = PATTERN_INFO[issue.issueType]?.severity ?? 0;
        const url = PATTERN_INFO[issue.issueType]?.url ?? 'N/A';

        totalSeverity += severity;
        fileIssues.push({
          issue: issue.issueType,
          severity,
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

  if (format === 'md') {
    let md =
      `# Space Proof Code (` + CLI_NAME + ` v` + VERSION + `) Report\n\n`;
    md += `**Files Scanned**: ${results.length} | **Total Issues**: ${totalIssues} | **Total Severity**: ${totalSeverity} | **Risk Level**: ${riskLevel} / 5.00\n\n`;
    md += `## Issue Summary\n\n`;
    md += `| Issue Type | Severity | Count | Documentation |\n`;
    md += `|---|---|---|---|\n`;

    Object.keys(issueCounts).forEach((type) => {
      const item = issueCounts[type];
      md += `| \`${type}\` | ${item.severity} | ${item.total} | [Docs](${item.info}) |\n`;
    });

    md += `\n## Detailed Findings\n\n`;
    processedResults.forEach((fileRes) => {
      if (fileRes.issueCount > 0) {
        md += `### ${fileRes.file} (${fileRes.language})\n\n`;
        md += `| Line | Issue | Severity | Message |\n`;
        md += `|---|---|---|---|\n`;
        fileRes.issues.forEach((iss) => {
          md += `| ${iss.line || 'N/A'} | \`${iss.issue}\` | ${iss.severity} | ${iss.message.replace(/\|/g, '\\|')} |\n`;
        });
        md += `\n`;
      }
    });

    return md;
  }

  // Default: table output (printed via console in CLI, but returns summary object)
  return null;
}

module.exports = { formatResults };
