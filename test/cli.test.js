const { execSync } = require('child_process');
const path = require('path');

const CLI_PATH = path.join(__dirname, '../bin/cli.js');

describe('CLI Integration', () => {
  it('outputs version string with --version', () => {
    const output = execSync(`node "${CLI_PATH}" --version`, { encoding: 'utf-8' });
    expect(output).toContain('space-proof-code v1.4.0');
  });

  it('outputs help text with --help', () => {
    const output = execSync(`node "${CLI_PATH}" --help`, { encoding: 'utf-8' });
    expect(output).toContain('space-proof-code v1.4.0');
    expect(output).toContain('--exclude');
    expect(output).toContain('--max-issue-severity');
  });

  it('outputs JSON report with --format json', () => {
    const output = execSync(`node "${CLI_PATH}" ./lib --format json`, {
      encoding: 'utf-8',
    });
    expect(() => JSON.parse(output)).not.toThrow();
    const parsed = JSON.parse(output);
    expect(parsed.summary.totalIssues).toBeDefined();
  });
});
