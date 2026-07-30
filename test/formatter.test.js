const { formatResults } = require('../lib/formatter');

describe('formatResults', () => {
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
          message: 'Hardcoded secret key found',
          issueType: 'exposed_secrets',
          lineNum: 15,
        },
      ],
    },
  ];

  it('formats results as JSON', () => {
    const jsonOutput = formatResults(sampleResults, { format: 'json' });
    expect(jsonOutput).toBeDefined();
    const parsed = JSON.parse(jsonOutput);
    expect(parsed.summary.totalIssues).toBe(2);
    expect(parsed.files).toHaveLength(1);
    expect(parsed.files[0].file).toBe('app.js');
  });

  it('formats results as Markdown', () => {
    const mdOutput = formatResults(sampleResults, { format: 'md' });
    expect(mdOutput).toContain('# Space Proof Code');
    expect(mdOutput).toContain('app.js');
    expect(mdOutput).toContain('unbounded_loops');
    expect(mdOutput).toContain('exposed_secrets');
  });

  it('returns null for table format', () => {
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
