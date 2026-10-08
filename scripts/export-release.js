import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { PROJECT } from '../src/client-config.js';
import { readRelease } from '../src/release.js';

if (process.argv.length > 3) throw new Error('Usage: node scripts/export-release.js [new-destination]');
const destination = resolve(process.argv[2] || join(PROJECT, 'output', `github-ready-${Date.now()}-${process.pid}`));
if (existsSync(destination)) throw new Error('Export destination already exists; choose a new directory');
// Validate every source before creating any release output.
const files = readRelease(PROJECT);
mkdirSync(destination, { recursive: true });
for (const { path, data } of files) {
  const output = join(destination, path);
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, data, { flag: 'wx' });
}
const manifest = files.map(({ path, data }) => ({ path, sha256: createHash('sha256').update(data).digest('hex') }));
writeFileSync(join(destination, 'RELEASE-MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Exported ${files.length} public files to ${destination}`);
