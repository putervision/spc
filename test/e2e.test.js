const { execSync } = require('child_process');
const path = require('path');

describe('SPC End-to-End CLI Integration Suite', () => {
  const cliPath = path.join(__dirname, '..', 'bin', 'cli.js');
  const examplesDir = path.join(__dirname, 'examples');

  test('runs CLI --version cleanly', () => {
    const output = execSync(`node ${cliPath} --version`, { encoding: 'utf8' });
    expect(output).toContain('space-proof-code v1.4.0');
  });

  test('runs CLI --list-rules and outputs rule registry', () => {
    const output = execSync(`node ${cliPath} --list-rules`, { encoding: 'utf8' });
    expect(output).toContain('Rule Registry');
    expect(output).toContain('prompt_injection_hazard');
    expect(output).toContain('recursion');
  });

  test('runs CLI --agent-tools and outputs tool specification schema JSON', () => {
    const output = execSync(`node ${cliPath} --agent-tools`, { encoding: 'utf8' });
    const parsed = JSON.parse(output);
    expect(parsed.name).toBe('space-proof-code');
    expect(parsed.operations.length).toBeGreaterThan(0);
  });

  test('runs CLI scan with --format json', () => {
    const output = execSync(`node ${cliPath} ${examplesDir} --format json`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const parsed = JSON.parse(output);
    expect(parsed.tool).toBe('space-proof-code');
    expect(parsed.version).toBe('1.4.0');
    expect(parsed.summary.totalIssues).toBeGreaterThan(0);
  });

  test('runs CLI scan with --format sarif', () => {
    const output = execSync(`node ${cliPath} ${examplesDir} --format sarif`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].tool.driver.name).toBe('space-proof-code');
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  });

  test('runs CLI scan with --ai-only flag', () => {
    const output = execSync(`node ${cliPath} ${examplesDir} --ai-only --format json`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const parsed = JSON.parse(output);
    expect(parsed.files.length).toBeGreaterThan(0);
    const languages = parsed.files.map((f) => f.language);
    languages.forEach((lang) => {
      expect(['agent', 'mcp', 'model']).toContain(lang);
    });
  });
});
