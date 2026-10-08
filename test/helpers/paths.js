// Tests generate disposable credentials and never load production private keys.
import { mkdtempSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
export const CANONICAL_KEY_DIR = mkdtempSync(join(tmpdir(), 'mcp-test-keys-'));
export const KEY_NAME = 'test_ed25519';
export const KEY_PATH = join(CANONICAL_KEY_DIR, KEY_NAME);
export const PUB_PATH = `${KEY_PATH}.pub`;
export const BOOTSTRAP_PATH = join(CANONICAL_KEY_DIR, 'bootstrap.txt');
execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', KEY_PATH, '-N', '', '-C', 'disposable-test-key'], { stdio: 'ignore' });
process.on('exit', () => rmSync(CANONICAL_KEY_DIR, { recursive: true, force: true }));
export function requireCredentials() {
  if (!existsSync(KEY_PATH) || !existsSync(PUB_PATH)) throw new Error('临时测试密钥生成失败');
  return { keyPath: KEY_PATH, pubPath: PUB_PATH, bootstrapPath: BOOTSTRAP_PATH, dir: CANONICAL_KEY_DIR };
}
export { homedir };
