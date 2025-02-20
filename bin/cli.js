#!/usr/bin/env node
const fs = require("fs").promises;
const { scanCodebase } = require("../lib/checker");

async function main() {
  const directory = process.argv[2] || process.cwd();
  const dirExists = await fs
    .access(directory)
    .then(() => true)
    .catch(() => false);

  if (!dirExists) {
    console.error(`Error: Directory '${directory}' not found.`);
    process.exit(1);
  }

  console.log(`Scanning ${directory} for space-proofing issues...`);
  try {
    const results = await scanCodebase(directory);
    results.forEach(({ file, language, issues }) => {
      console.log(`\nAnalyzing ${file} (${language})...`);
      if (issues.length > 0) {
        console.log(`Issues in ${file}:`);
        issues.forEach((issue) => console.log(`  - ${issue}`));
      } else {
        console.log("  No issues found.");
      }
    });
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

void main();
