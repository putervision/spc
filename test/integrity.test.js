const fs = require('fs');
const path = require('path');
const { PATTERN_INFO, RULE_CATEGORIES, getCapabilities } = require('../lib/info');

describe('Rule Registry & Engine Parity Integrity', () => {
  const langDir = path.join(__dirname, '..', 'lib', 'lang');
  const langFiles = fs.readdirSync(langDir).filter((f) => f.endsWith('.js'));

  const implementedRules = new Set([
    'exceeds_max_func_lines',
    'unchecked_func_return',
    'unchecked_func_return_crit',
    'checksum_mismatch',
  ]);

  for (const file of langFiles) {
    const mod = require(path.join(langDir, file));
    const config = Object.values(mod)[0];
    if (config && config.patterns) {
      for (const ruleKey of Object.keys(config.patterns)) {
        implementedRules.add(ruleKey);
      }
    }
  }

  test('all PATTERN_INFO rules have at least one implementation in the engine (zero phantom rules)', () => {
    const phantomRules = [];
    for (const ruleKey of Object.keys(PATTERN_INFO)) {
      if (!implementedRules.has(ruleKey)) {
        phantomRules.push(ruleKey);
      }
    }

    expect(phantomRules).toEqual([]);
  });

  test('all implemented rules in language configs exist in PATTERN_INFO registry', () => {
    for (const file of langFiles) {
      const mod = require(path.join(langDir, file));
      const config = Object.values(mod)[0];
      if (config && config.patterns) {
        for (const ruleKey of Object.keys(config.patterns)) {
          expect(PATTERN_INFO[ruleKey]).toBeDefined();
          expect(PATTERN_INFO[ruleKey].category).toBeDefined();
          expect(typeof PATTERN_INFO[ruleKey].severity).toBe('number');
        }
      }
    }
  });

  test('getCapabilities returns accurate counts and metadata', () => {
    const caps = getCapabilities();
    expect(caps.totalRules).toBe(Object.keys(PATTERN_INFO).length);
    expect(caps.ruleCategories).toEqual(RULE_CATEGORIES);
    expect(Array.isArray(caps.supportedLanguages)).toBe(true);
    expect(Array.isArray(caps.supportedAiDomains)).toBe(true);
  });
});
