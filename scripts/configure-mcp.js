import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync, renameSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { configureMcp } from '../src/client-config.js';

const [file, option, inventory] = process.argv.slice(2);
if (!file || (option && (option !== '--inventory' || !inventory)) || process.argv.length > 5) {
  console.error('Usage: node scripts/configure-mcp.js <client.json> [--inventory <servers.json>]');
  process.exit(2);
}
const path = resolve(file);
const source = existsSync(path) ? readFileSync(path, 'utf8') : '{}';
const output = configureMcp(source, inventory ? { inventory } : {});
mkdirSync(dirname(path), { recursive: true });
if (existsSync(path)) copyFileSync(path, `${path}.bak-${Date.now()}`);
const temp = `${path}.tmp-${process.pid}`;
writeFileSync(temp, output, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
renameSync(temp, path);
console.log(`MCP configuration written to ${path}`);
