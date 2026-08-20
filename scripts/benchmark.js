#!/usr/bin/env node

/**
 * benchmark.js - Measures throughput and scan performance of @putervision/spc.
 */

const path = require('path');
const { scanCodebase } = require('../lib/scanner');
const { buildIgnorePatterns } = require('../lib/ignore');

async function runBenchmark() {
  console.log('⚡ Space Proof Code (SPC) Performance Benchmark\n');
  const targetDir = path.resolve(__dirname, '..');
  const ignorePatterns = buildIgnorePatterns();

  const iterations = 5;
  const timings = [];
  let totalFiles = 0;
  let totalIssues = 0;

  for (let i = 1; i <= iterations; i++) {
    const start = process.hrtime.bigint();
    const results = await scanCodebase(targetDir, false, ignorePatterns);
    const end = process.hrtime.bigint();
    const durationMs = Number(end - start) / 1e6;
    timings.push(durationMs);

    totalFiles = results.length;
    totalIssues = results.reduce((acc, r) => acc + (r.issues?.length || 0), 0);
    console.log(
      `  Run ${i}: ${durationMs.toFixed(2)} ms (${results.length} files scanned)`
    );
  }

  const avgMs = timings.reduce((a, b) => a + b, 0) / iterations;
  const minMs = Math.min(...timings);
  const maxMs = Math.max(...timings);
  const throughput = (totalFiles / (avgMs / 1000)).toFixed(1);

  console.log('\n📊 Benchmark Summary:');
  console.log(`  - Files scanned: ${totalFiles}`);
  console.log(`  - Issues detected: ${totalIssues}`);
  console.log(`  - Average duration: ${avgMs.toFixed(2)} ms`);
  console.log(
    `  - Min / Max duration: ${minMs.toFixed(2)} ms / ${maxMs.toFixed(2)} ms`
  );
  console.log(`  - Throughput: ${throughput} files/second\n`);
}

runBenchmark().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
