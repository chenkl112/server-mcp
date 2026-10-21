import { readFileSync, writeFileSync } from 'node:fs';
import { buildBootstrap } from '../src/bootstrap.js';

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith('--')));
const positional = args.filter((a) => !a.startsWith('--'));
const [keyFile, outputFile] = positional;

if (!keyFile || !outputFile) {
  console.error('用法: node scripts/build-bootstrap.js <public-key> <output-file> [--sudo] [--full-sudo]');
  console.error('  --sudo       运输层用 sudo -n 执行(借用有 sudo 的管理员账户)');
  console.error('  --full-sudo  目标态:给 ops-us 完整 sudo(见 README「sudo 的两种权限模式」)');
  process.exit(2);
}

const output = buildBootstrap(
  readFileSync(new URL('../server-setup.sh', import.meta.url), 'utf8'),
  readFileSync(keyFile, 'utf8'),
  { sudo: flags.has('--sudo'), fullSudo: flags.has('--full-sudo') },
);
writeFileSync(outputFile, output, { encoding: 'ascii', mode: 0o600 });
