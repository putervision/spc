const path = require('path');
const { analyzeFile } = require('../lib/scanner');

describe('MCP Server Config Rules', () => {
  const badMcpPath = path.join(__dirname, 'examples', 'bad-mcp.json');

  test('detects wildcard grants, unencrypted env secrets, and exposed endpoints in mcp.json', async () => {
    const issues = await analyzeFile(badMcpPath, 'mcp');
    expect(issues.length).toBeGreaterThan(0);

    const types = issues.map((i) => i.issueType);
    expect(types).toContain('overly_permissive_mcp_grant');
    expect(types).toContain('unencrypted_mcp_env_secret');
    expect(types).toContain('exposed_mcp_endpoint');
    expect(types).toContain('missing_mcp_auth');
  });
});
