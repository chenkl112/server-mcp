import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { buildBootstrap } from '../src/bootstrap.js';
import { PUB_PATH } from './helpers/paths.js';
const script = readFileSync(new URL('../server-setup.sh', import.meta.url), 'utf8');
const key = readFileSync(PUB_PATH, 'utf8');
test('引导产物携带完整脚本和匹配的公钥,且无固定临时文件', () => {
  const output = buildBootstrap(script, key);
  const b64 = output.match(/printf '%s' '([A-Za-z0-9+/=]+)'/)[1];
  assert.equal(Buffer.from(b64, 'base64').toString(), script);
  assert.ok(output.includes(key.trim().split(/\s+/).slice(0, 2).join(' ')));
  assert.match(output, /base64 -d \| bash -s --/);
  assert.ok(!output.includes('/tmp/'));
  assert.ok(!/[^\x00-\x7f]/.test(output));
});
test('自动初始化使用免交互 sudo,公钥注释不进入 shell', () => {
  const pub = key.trim().split(/\s+/).slice(0, 2).join(' ');
  const output = buildBootstrap(script, `${pub} '$(touch /tmp/bad)'`, { sudo: true });
  assert.match(output, /sudo -n bash -s --/);
  assert.ok(!output.includes('touch'));
  assert.throws(() => buildBootstrap(script, 'not a public key'));
});
