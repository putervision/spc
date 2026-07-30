const { PATTERN_INFO } = require('../lib/info');

const LANGUAGES = [
  'ada',
  'bash',
  'c',
  'cs',
  'elixir',
  'fortran',
  'go',
  'haskell',
  'java',
  'javascript',
  'julia',
  'kotlin',
  'lua',
  'php',
  'python',
  'ruby',
  'rust',
  'scala',
  'swift',
  'zig',
];

describe('Language Pattern Integrity', () => {
  LANGUAGES.forEach((lang) => {
    describe(`Language config: ${lang}`, () => {
      const configModule = require(`../lib/lang/${lang}`);
      const exportKey = Object.keys(configModule)[0];
      const config = configModule[exportKey];

      it('exports a valid configuration object', () => {
        expect(config).toBeDefined();
        expect(Array.isArray(config.extensions)).toBe(true);
        expect(config.extensions.length).toBeGreaterThan(0);
        expect(typeof config.patterns).toBe('object');
      });

      it('contains zero null pattern definitions', () => {
        Object.entries(config.patterns).forEach(([_key, val]) => {
          expect(val).not.toBeNull();
        });
      });

      it('compiles all regex patterns without syntax error', () => {
        Object.entries(config.patterns).forEach(([_key, pattern]) => {
          expect(pattern instanceof RegExp).toBe(true);
        });
      });

      it('maps pattern keys to defined PATTERN_INFO metadata', () => {
        Object.keys(config.patterns).forEach((ruleKey) => {
          expect(PATTERN_INFO[ruleKey]).toBeDefined();
          expect(typeof PATTERN_INFO[ruleKey].severity).toBe('number');
        });
      });
    });
  });
});
