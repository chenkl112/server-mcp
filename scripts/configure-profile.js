import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync, renameSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { configureProfile } from '../src/profile.js';

const [file, mode, option, inventory] = process.argv.slice(2);
if (!file || !['--enable', '--disabled'].includes(mode) || (option && (option !== '--inventory' || !inventory)) || process.argv.length > 6) {
  console.error('用法: node scripts/configure-profile.js <profile.yml> --enable|--disabled [--inventory <servers.json>]');
  process.exit(2);
}
const path = resolve(file);
const source = existsSync(path) ? readFileSync(path, 'utf8') : '[]\n';
const output = configureProfile(source, { enabled: mode === '--enable', inventory });
mkdirSync(dirname(path), { recursive: true });
if (existsSync(path)) copyFileSync(path, `${path}.bak-${Date.now()}`);
const temp = `${path}.tmp-${process.pid}`;
writeFileSync(temp, output, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
renameSync(temp, path);
console.log(`已写入 ${path} (enabled=${mode === '--enable'})`);
