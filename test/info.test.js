const { getCapabilities, getAgentToolSchema } = require('../lib/info');

describe('Agent Tool & Capabilities Schema (lib/info.js)', () => {
  test('returns tool capabilities summary', () => {
    const caps = getCapabilities();
    expect(caps.tool).toBe('space-proof-code');
    expect(caps.supportedLanguages.length).toBe(20);
    expect(caps.supportedAiDomains).toEqual(['agent', 'mcp', 'model']);
    expect(caps.outputFormats).toEqual(['table', 'json', 'md', 'sarif']);
    expect(caps.totalRules).toBeGreaterThan(50);
  });

  test('returns machine-readable agent tool specification schema', () => {
    const schema = getAgentToolSchema();
    expect(schema.name).toBe('space-proof-code');
    expect(Array.isArray(schema.operations)).toBe(true);
    expect(schema.operations.length).toBe(3);

    const scanOp = schema.operations.find((op) => op.name === 'scanCodebase');
    expect(scanOp).toBeDefined();
    expect(scanOp.parameters.properties.format.enum).toContain('sarif');
    expect(scanOp.parameters.properties.category.enum).toContain('agent');
  });
});
