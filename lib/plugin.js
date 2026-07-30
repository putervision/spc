/**
 * plugin.js - Plugin architecture skeleton for @putervision/spc.
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
  try {
    const files = await fs.readdir(pluginDir);
    for (const file of files) {
      if (file.endsWith('.js')) {
        const pluginPath = path.join(pluginDir, file);
        const plugin = require(pluginPath);
        if (plugin && plugin.extensions && plugin.patterns) {
          plugins.push(plugin);
        }
      }
    }
  } catch {
    // Return empty array if plugins directory doesn't exist or errors out
  }
  return plugins;
}

module.exports = {
  loadPlugins,
};
