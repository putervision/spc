const path = require('path');
const { analyzeFile } = require('../lib/scanner');

describe('LLM & Model Config Rules', () => {
  const badModelPath = path.join(__dirname, 'examples', 'bad-model-config.json');

  test('detects unsafe deserialization, HTTP model downloads, and exposed keys in model configs', async () => {
    const issues = await analyzeFile(badModelPath, 'model');
    expect(issues.length).toBeGreaterThan(0);

    const types = issues.map((i) => i.issueType);
    expect(types).toContain('unsafe_model_deserialization');
    expect(types).toContain('insecure_model_endpoint');
    expect(types).toContain('unauthenticated_model_download');
    expect(types).toContain('unsafe_model_temperature');
    expect(types).toContain('exposed_model_api_key');
  });
});
