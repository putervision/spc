const path = require('path');
const fs = require('fs').promises;
const { createHashFromFile, loadChecksums } = require('../lib/checksum');

describe('Checksum Utility (lib/checksum.js)', () => {
  const exampleFile = path.join(__dirname, 'examples', 'bad-example.sh');
  const tempChecksumFile = path.join(__dirname, 'examples', 'test_checksums.txt');

  afterEach(async () => {
    try {
      await fs.unlink(tempChecksumFile);
    } catch (_e) {
      // Ignore if not present
    }
  });

  test('generates SHA-256 hash from existing file', async () => {
    const hash = await createHashFromFile(exampleFile);
    expect(typeof hash).toBe('string');
    expect(hash.length).toBe(64);
  });

  test('throws error if file for hashing is missing', async () => {
    await expect(
      createHashFromFile(path.join(__dirname, 'nonexistent_file.xyz'))
    ).rejects.toThrow();
  });

  test('loads valid checksum manifest file', async () => {
    const content = `
# Comment line
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  example.js
`;
    await fs.writeFile(tempChecksumFile, content, 'utf8');
    const index = await loadChecksums(tempChecksumFile);
    expect(index).not.toBeNull();
    expect(index['example.js']).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  test('returns null for empty or comments-only manifest', async () => {
    await fs.writeFile(tempChecksumFile, '# Only comments\n\n', 'utf8');
    const index = await loadChecksums(tempChecksumFile);
    expect(index).toBeNull();
  });

  test('returns null if checksum manifest does not exist', async () => {
    const index = await loadChecksums(path.join(__dirname, 'nonexistent_checksums.txt'));
    expect(index).toBeNull();
  });
});
