const { formatResults } = require('../lib/formatter');

describe('formatResults (lib/formatter.js)', () => {
  const sampleResults = [
    {
      file: '/mock/app.js',
      relativePath: 'app.js',
      language: 'javascript',
      issues: [
        {
          message: 'Unbounded loop detected',
          issueType: 'unbounded_loops',
          lineNum: 10,
        },
        {
          message: 'Hardcoded secret | key found',
          issueType: 'exposed_secrets',
          lineNum: 15,
        },
        {
          message: 'Minor conditional issue',
          issueType: 'nested_conditionals',
          lineNum: 20,
        },
        {
          message: 'Custom unlisted issue',
          issueType: 'custom_unknown_issue',
          lineNum: null,
        },
      ],
    },
    {
      file: '/mock/clean.js',
      relativePath: 'clean.js',
      language: 'javascript',
      issues: [],
    },
  ];

  it('formats results as JSON', () => {
    const jsonOutput = formatResults(sampleResults, { format: 'json' });
    expect(jsonOutput).toBeDefined();
    const parsed = JSON.parse(jsonOutput);
    expect(parsed.summary.totalIssues).toBe(4);
    expect(parsed.files).toHaveLength(2);
    expect(parsed.files[0].file).toBe('app.js');
  });

  it('formats results as SARIF v2.1.0 and maps severity levels correctly', () => {
    const sarifOutput = formatResults(sampleResults, { format: 'sarif' });
    expect(sarifOutput).toBeDefined();
    const parsed = JSON.parse(sarifOutput);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].results.length).toBe(4);

    const levels = parsed.runs[0].results.map((r) => r.level);
    expect(levels).toContain('error');
    expect(levels).toContain('note');
  });

  it('formats results as Markdown tables and escapes pipe characters', () => {
    const mdOutput = formatResults(sampleResults, { format: 'md' });
    expect(mdOutput).toContain('# Space Proof Code');
    expect(mdOutput).toContain('app.js');
    expect(mdOutput).toContain('unbounded_loops');
    expect(mdOutput).toContain('exposed_secrets');
    expect(mdOutput).toContain('\\|');
  });

  it('returns null for default table format', () => {
    const tableOutput = formatResults(sampleResults, { format: 'table' });
    expect(tableOutput).toBeNull();
  });

  it('handles empty results array', () => {
    const jsonOutput = formatResults([], { format: 'json' });
    const parsed = JSON.parse(jsonOutput);
    expect(parsed.summary.totalIssues).toBe(0);
    expect(parsed.files).toHaveLength(0);
  });
});
