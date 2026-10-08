import { readFileSync, writeFileSync } from 'node:fs';
import { buildBootstrap } from '../src/bootstrap.js';

const [keyFile, outputFile, mode] = process.argv.slice(2);
if (!keyFile || !outputFile) {
  console.error('用法: node scripts/build-bootstrap.js <public-key> <output-file> [--sudo]');
  process.exit(2);
}
const output = buildBootstrap(readFileSync(new URL('../server-setup.sh', import.meta.url), 'utf8'), readFileSync(keyFile, 'utf8'), { sudo: mode === '--sudo' });
writeFileSync(outputFile, output, { encoding: 'ascii', mode: 0o600 });
