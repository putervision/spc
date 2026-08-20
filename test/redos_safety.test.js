const fs = require('fs');
const path = require('path');

describe('Regular Expression Catastrophic Backtracking (ReDoS) Safety', () => {
  const langDir = path.join(__dirname, '..', 'lib', 'lang');
  const langFiles = fs.readdirSync(langDir).filter((f) => f.endsWith('.js'));

  const longInput = 'x'.repeat(2000);
  const maliciousCode =
    'if (a) { return 1; } '.repeat(100) +
    'function test() { return 1; return 2; }\n' +
    'break outer; continue inner;\n' +
    'var a = "' +
    'a'.repeat(1000) +
    '";\n';

  langFiles.forEach((file) => {
    test(`patterns in ${file} execute safely without ReDoS on adversarial inputs`, () => {
      const mod = require(path.join(langDir, file));
      const config = Object.values(mod)[0];
      if (!config || !config.patterns) return;

      for (const pattern of Object.values(config.patterns)) {
        if (!(pattern instanceof RegExp)) continue;

        // Test 1: Long repeating string
        const start1 = Date.now();
        longInput.match(pattern);
        const duration1 = Date.now() - start1;
        expect(duration1).toBeLessThan(50);

        // Test 2: Adversarial code blocks
        const start2 = Date.now();
        maliciousCode.match(pattern);
        const duration2 = Date.now() - start2;
        expect(duration2).toBeLessThan(50);
      }
    });
  });
});
