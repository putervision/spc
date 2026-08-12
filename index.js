/**
 * index.js - Programmatic entry point for @putervision/spc (Space Proof Code).
 * Exports the codebase scanner engine, output formatters, rule metadata, config handler,
 * and AI agent tool specifications.
 */

const { scanCodebase } = require('./lib/scanner');
const { formatResults } = require('./lib/formatter');
const {
  PATTERN_INFO,
  RULE_CATEGORIES,
  getCapabilities,
  getAgentToolSchema,
} = require('./lib/info');
const { loadConfig } = require('./lib/config');
const { loadPlugins } = require('./lib/plugin');

module.exports = {
  scanCodebase,
  formatResults,
  PATTERN_INFO,
  RULE_CATEGORIES,
  getCapabilities,
  getAgentToolSchema,
  loadConfig,
  loadPlugins,
};
