/**
 * config.js - Configuration file handler for @putervision/spc.
 * Supports loading .spc.config.json settings.
 */

const fs = require('fs').promises;
const path = require('path');

const DEFAULT_CONFIG = {
  maxFunctionLines: 60,
  rules: {},
  ignorePatterns: [],
};

/**
 * Loads and validates .spc.config.json from directory or custom path.
 * @param {string} directory - Directory or custom config file path.
 * @returns {Promise<Object>} Loaded configuration merged with defaults.
 */
async function loadConfig(directory) {
  let configPath = path.join(directory, '.spc.config.json');

  try {
    const stat = await fs.stat(directory);
    if (stat.isFile()) {
      configPath = directory;
    }
  } catch {
    // Keep directory path
  }

  try {
    const content = await fs.readFile(configPath, 'utf-8');
    const userConfig = JSON.parse(content);
    return {
      ...DEFAULT_CONFIG,
      ...userConfig,
      rules: { ...DEFAULT_CONFIG.rules, ...(userConfig.rules || {}) },
      ignorePatterns: [
        ...DEFAULT_CONFIG.ignorePatterns,
        ...(userConfig.ignorePatterns || []),
      ],
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

module.exports = {
  DEFAULT_CONFIG,
  loadConfig,
};
