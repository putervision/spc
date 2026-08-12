/**
 * checksum.js - Modular SHA-256 checksum utility for @putervision/spc.
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const { createHash } = require('crypto');

const CHECKSUMS_FILE = 'checksums.sha256.txt';

/**
 * Creates a SHA-256 hash for a specified file using stream or buffer fallback.
 * @param {string} filePath - Absolute path to target file.
 * @returns {Promise<string>} Hex-encoded SHA-256 digest.
 */
async function createHashFromFile(filePath) {
  try {
    if (typeof fsSync.createReadStream === 'function') {
      const hash = createHash('sha256');
      const stream = fsSync.createReadStream(filePath);
      if (stream && typeof stream.on === 'function') {
        return await new Promise((resolve, reject) => {
          stream.on('data', (chunk) => hash.update(chunk));
          stream.on('end', () => resolve(hash.digest('hex')));
          stream.on('error', (err) => reject(err));
        });
      }
    }
  } catch (_err) {
    // Fallback to readFile buffer reading if stream fails or in mocked env
  }

  try {
    const fileBuffer = await fs.readFile(filePath);
    const fileHash = createHash('sha256');
    fileHash.update(fileBuffer);
    return fileHash.digest('hex');
  } catch (error) {
    throw new Error(`Failed to create hash for ${filePath}: ${error.message}`);
  }
}

/**
 * Loads and parses a checksums manifest file.
 * @param {string} checksumFilePath - Path to checksum manifest file.
 * @returns {Promise<Object|null>} Map of relative filename to expected hash.
 */
async function loadChecksums(checksumFilePath) {
  try {
    const checksumContent = await fs.readFile(checksumFilePath, 'utf8');
    const checksumLines = checksumContent
      .trim()
      .split('\n')
      .filter((line) => line && !line.startsWith('#'));

    if (!checksumContent || !checksumLines?.length) return null;

    const checksumIndex = {};
    for (const line of checksumLines) {
      const match = line.match(/^([0-9a-f]{32}|[0-9a-f]{64})\s{2}(.*)$/i);
      if (!match) continue;

      const [, hash, filename] = match;
      checksumIndex[filename] = hash;
    }

    return checksumIndex;
  } catch (_err) {
    return null;
  }
}

module.exports = {
  CHECKSUMS_FILE,
  createHashFromFile,
  loadChecksums,
};
