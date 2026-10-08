import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { PROJECT } from '../src/client-config.js';
import { releaseFiles, readRelease } from '../src/release.js';

test('发布允许清单排除私人清单、密钥、历史和生成配置', () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-fixture-'));
  try {
    const canary = randomUUID();
    const publicFiles = readRelease(PROJECT);
    for (const { path, data } of publicFiles) {
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), data);
    }
    for (const path of ['servers.json', 'keys/key', 'output/client.json', 'review-artifacts/history.js', 'src/settings.local.js']) {
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), canary);
    }
    assert.deepEqual(releaseFiles(dir), publicFiles.map(f => f.path));
    assert.equal(readRelease(dir).some(f => f.data.includes(canary)), false);
    // Construct a private key header without embedding real key material in tests.
    writeFileSync(join(dir, 'src', 'leak.js'), ['-----BEGIN ', 'OPENSSH ', 'PRIVATE KEY-----'].join(''));
    assert.throws(() => readRelease(dir), /private key material/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('导出实际文件和哈希清单一致,拒绝覆盖已有目录', () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-export-'));
  try {
    const destination = join(dir, 'public');
    const script = join(PROJECT, 'scripts', 'export-release.js');
    execFileSync(process.execPath, [script, destination]);
    const manifest = JSON.parse(readFileSync(join(destination, 'RELEASE-MANIFEST.json'), 'utf8'));
    assert.deepEqual(manifest.map(f => f.path), releaseFiles(PROJECT));
    for (const { path, sha256 } of manifest) {
      assert.equal(createHash('sha256').update(readFileSync(join(destination, path))).digest('hex'), sha256);
    }
    for (const privateDir of ['servers.json', 'review-artifacts', 'output', 'node_modules', 'keys']) {
      assert.equal(readdirSync(destination).includes(privateDir), false);
    }
    assert.throws(() => execFileSync(process.execPath, [script, destination], { stdio: 'pipe' }));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
