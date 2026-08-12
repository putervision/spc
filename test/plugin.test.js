const path = require('path');
const fs = require('fs').promises;
const { loadPlugins } = require('../lib/plugin');

describe('Plugin Loader (loadPlugins)', () => {
  const tempPluginDir = path.join(__dirname, 'temp_plugins');

  afterEach(async () => {
    try {
      await fs.rm(tempPluginDir, { recursive: true, force: true });
    } catch (_e) {
      // Ignore
    }
  });

  test('returns empty array if plugins directory does not exist or is empty', async () => {
    const plugins = await loadPlugins(path.join(__dirname, 'nonexistent_plugins'));
    expect(Array.isArray(plugins)).toBe(true);
    expect(plugins.length).toBe(0);
  });

  test('loads valid plugin JS files and ignores non-JS files', async () => {
    await fs.mkdir(tempPluginDir, { recursive: true });

    const validPluginContent = `
      module.exports = {
        name: 'sample_plugin',
        language: 'sample',
        extensions: ['.sample'],
        patterns: {
          sample_rule: /sample_pattern/g
        }
      };
    `;

    await fs.writeFile(path.join(tempPluginDir, 'my_plugin.js'), validPluginContent, 'utf8');
    await fs.writeFile(path.join(tempPluginDir, 'readme.txt'), 'Not a JS file', 'utf8');

    const plugins = await loadPlugins(tempPluginDir);
    expect(plugins.length).toBe(1);
    expect(plugins[0].name).toBe('sample_plugin');
    expect(plugins[0].language).toBe('sample');
    expect(plugins[0].extensions).toEqual(['.sample']);
  });
});
