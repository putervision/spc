/**
 * plugin.js - Plugin architecture handler for @putervision/spc.
 * Supports loading custom rule and pattern plugins from a local plugins directory.
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * Loads custom language rules or pattern plugins from a plugins directory.
 * @param {string} pluginDir - Directory containing JS plugin files.
 * @returns {Promise<Array<Object>>} List of loaded plugin objects.
 */
async function loadPlugins(pluginDir) {
  const plugins = [];
  if (!pluginDir) return plugins;

  try {
    const files = await fs.readdir(pluginDir);
    for (const file of files) {
      if (file.endsWith('.js')) {
        const pluginPath = path.join(pluginDir, file);
        try {
          const plugin = require(pluginPath);
          if (
            plugin &&
            (plugin.extensions || plugin.filenames) &&
            plugin.patterns
          ) {
            plugins.push({
              name: plugin.name || path.basename(file, '.js'),
              language: plugin.language || path.basename(file, '.js'),
              extensions: plugin.extensions || [],
              filenames: plugin.filenames || [],
              patterns: plugin.patterns || {},
              category: plugin.category || 'custom',
            });
          }
        } catch (_err) {
          // Skip invalid plugin modules
        }
      }
    }
  } catch (_err) {
    // Return empty array if pluginDir doesn't exist or is inaccessible
  }

  return plugins;
}

module.exports = {
  loadPlugins,
};
