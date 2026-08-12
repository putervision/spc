const path = require('path');
const fs = require('fs').promises;
const { loadConfig } = require('../lib/config');

describe('Config Handler (loadConfig)', () => {
  const tempConfigDir = path.join(__dirname, 'temp_config_test');

  afterEach(async () => {
    try {
      await fs.rm(tempConfigDir, { recursive: true, force: true });
    } catch (_e) {
      // Ignore
    }
  });

  test('returns default configuration if config file does not exist', async () => {
    const config = await loadConfig(path.join(__dirname, 'nonexistent_dir'));
    expect(config.maxFunctionLines).toBe(60);
    expect(config.rules).toEqual({});
  });

  test('loads custom .spc.config.json settings from directory', async () => {
    await fs.mkdir(tempConfigDir, { recursive: true });
    const configContent = JSON.stringify({
      maxFunctionLines: 40,
      rules: {
        recursion: { enabled: false },
      },
      ignorePatterns: ['temp_dist/**'],
    });

    await fs.writeFile(path.join(tempConfigDir, '.spc.config.json'), configContent, 'utf8');

    const config = await loadConfig(tempConfigDir);
    expect(config.maxFunctionLines).toBe(40);
    expect(config.rules.recursion.enabled).toBe(false);
    expect(config.ignorePatterns).toContain('temp_dist/**');
  });
});
