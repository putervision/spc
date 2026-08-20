/**
 * build.js - Build and verification script for @putervision/spc (Space Proof Code).
 * Validates rule pattern syntax, checks PATTERN_INFO metadata integrity,
 * verifies docs sync, and exports distribution artifacts to dist/.
 */

const fs = require('fs').promises;
const path = require('path');
const {
  PATTERN_INFO,
  RULE_CATEGORIES,
  getCapabilities,
  getAgentToolSchema,
} = require('../lib/info');

const DIST_DIR = path.join(__dirname, '..', 'dist');

async function build() {
  console.log('========================================================');
  echo(
    '🏗️  Building & Auditing @putervision/spc v' +
      require('../package.json').version
  );
  console.log('========================================================');

  // 1. Audit PATTERN_INFO Integrity
  console.log('\n[1/4] Auditing PATTERN_INFO metadata integrity...');
  let totalRules = 0;
  const missingInfo = [];

  for (const [ruleName, info] of Object.entries(PATTERN_INFO)) {
    totalRules++;
    if (!info.severity || info.severity < 1 || info.severity > 5) {
      missingInfo.push(
        `Rule '${ruleName}' has invalid severity level: ${info.severity}`
      );
    }
    if (
      !info.category ||
      !Object.values(RULE_CATEGORIES).includes(info.category)
    ) {
      missingInfo.push(
        `Rule '${ruleName}' has invalid category: ${info.category}`
      );
    }
    if (!info.url) {
      missingInfo.push(`Rule '${ruleName}' is missing documentation URL`);
    }
  }

  if (missingInfo.length > 0) {
    console.error('❌ Metadata audit failed:');
    missingInfo.forEach((err) => console.error('  - ' + err));
    process.exit(1);
  }
  console.log(`✅ Verified ${totalRules} rules in PATTERN_INFO registry.`);

  // 2. Validate Language Pattern Engines and Parity
  console.log(
    '\n[2/4] Validating 23 Language & AI pattern rule engines and checking rule parity...'
  );
  const langDir = path.join(__dirname, '..', 'lib', 'lang');
  const langFiles = await fs.readdir(langDir);
  let totalEnginePatterns = 0;
  const implementedRuleKeys = new Set([
    'exceeds_max_func_lines',
    'unchecked_func_return',
    'unchecked_func_return_crit',
    'checksum_mismatch',
  ]);

  for (const file of langFiles) {
    if (file.endsWith('.js')) {
      const modulePath = path.join(langDir, file);
      const mod = require(modulePath);
      const patternExport = Object.values(mod)[0];

      if (patternExport && patternExport.patterns) {
        for (const [key, pattern] of Object.entries(patternExport.patterns)) {
          totalEnginePatterns++;
          implementedRuleKeys.add(key);
          if (!(pattern instanceof RegExp)) {
            console.error(
              `❌ File ${file} pattern '${key}' is not a valid RegExp`
            );
            process.exit(1);
          }
          if (!PATTERN_INFO[key]) {
            console.warn(
              `⚠️ Warning: Pattern key '${key}' in ${file} is missing from PATTERN_INFO`
            );
          }
        }
      }
    }
  }

  const phantomRules = Object.keys(PATTERN_INFO).filter(
    (k) => !implementedRuleKeys.has(k)
  );
  if (phantomRules.length > 0) {
    console.error(
      '❌ Build integrity guard failed: Found phantom rules with no engine implementation:'
    );
    phantomRules.forEach((r) => console.error('  - ' + r));
    process.exit(1);
  }

  console.log(
    `✅ Validated ${langFiles.length} rule engines containing ${totalEnginePatterns} compiled regex patterns (zero phantom rules).`
  );

  // 3. Create dist/ directory and write distribution artifacts
  console.log('\n[3/4] Exporting distribution artifacts to dist/...');
  await fs.mkdir(DIST_DIR, { recursive: true });

  const capabilities = getCapabilities();
  const agentSchema = getAgentToolSchema();

  await fs.writeFile(
    path.join(DIST_DIR, 'capabilities.json'),
    JSON.stringify(capabilities, null, 2),
    'utf8'
  );

  await fs.writeFile(
    path.join(DIST_DIR, 'schema.json'),
    JSON.stringify(agentSchema, null, 2),
    'utf8'
  );

  await fs.writeFile(
    path.join(DIST_DIR, 'rule-registry.json'),
    JSON.stringify(PATTERN_INFO, null, 2),
    'utf8'
  );

  console.log(
    '✅ Generated dist/capabilities.json, dist/schema.json, and dist/rule-registry.json'
  );

  // 4. Verify docs index sync
  console.log('\n[4/4] Verifying docs/index.html synchronization...');
  const currentVersion = require('../package.json').version;
  const indexHtml = await fs.readFile(
    path.join(__dirname, '..', 'docs', 'index.html'),
    'utf8'
  );
  if (!indexHtml.includes(`RELEASE v${currentVersion}`)) {
    console.error(
      `❌ docs/index.html is missing v${currentVersion} release badge!`
    );
    process.exit(1);
  }
  console.log(
    `✅ docs/index.html version badge verified for v${currentVersion}.`
  );

  console.log('\n========================================================');
  console.log('🎉 BUILD SUCCESSFUL! @putervision/spc is production-ready.');
  console.log('========================================================\n');
}

function echo(msg) {
  console.log(msg);
}

build().catch((err) => {
  console.error('Fatal build error: ' + err.message);
  process.exit(1);
});
