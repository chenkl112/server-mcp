import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, existsSync, mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { join, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { parse } from 'yaml';
import { configureProfile, PROJECT } from '../src/profile.js';
import { createServerConfig, configureMcp } from '../src/client-config.js';
import { loadInventory, resolveServer } from '../src/inventory.js';

// No live profile or private servers.json is read by these tests.
test('DSH 生成配置绑定当前安装位置,默认禁用且使用安全开关', () => {
  const entry = parse(configureProfile())[0];
  assert.equal(entry.enabled, false);
  assert.equal(entry.name, '@deepseek-ai/dsh-mcp-client');
  assert.equal(entry.config.command, process.execPath);
  assert.equal(entry.config.args[0], join(PROJECT, 'src', 'index.js'));
  assert.ok(existsSync(entry.config.args[0]));
  assert.equal(entry.config.env.DSH_VPS_ALLOW_TOFU, '0');
  assert.equal(entry.config.env.DSH_VPS_HOST_FINGERPRINTS, '');
  assert.equal(entry.config.env.DSH_VPS_SSH_KEY, undefined);
});

test('通用配置保留其他服务,不携带旧密钥配置,支持仓库外清单', () => {
  const inventory = join(tmpdir(), 'external inventory', 'servers.json');
  const config = JSON.parse(configureMcp(JSON.stringify({
    other: true,
    mcpServers: { other: { command: 'other' }, vps: { custom: 1, env: { CUSTOM: 'kept', DSH_VPS_SSH_KEY: 'old', DSH_VPS_SSH_KEY_PASSPHRASE: 'old' } } },
  }), { inventory }));
  assert.equal(config.other, true);
  assert.deepEqual(config.mcpServers.other, { command: 'other' });
  assert.equal(config.mcpServers.vps.custom, 1);
  assert.equal(config.mcpServers.vps.command, process.execPath);
  assert.equal(config.mcpServers.vps.env.CUSTOM, 'kept');
  assert.equal(config.mcpServers.vps.env.DSH_VPS_INVENTORY, inventory);
  assert.equal(config.mcpServers.vps.env.DSH_VPS_SSH_KEY, undefined);
  assert.equal(config.mcpServers.vps.env.DSH_VPS_SSH_KEY_PASSPHRASE, undefined);
  assert.ok(isAbsolute(createServerConfig().args[0]));
  for (const invalid of ['[]', 'null', '{"mcpServers":[]}', '{"mcpServers":null}']) assert.throws(() => configureMcp(invalid));
});

test('配置 CLI 可以为尚不存在的清单生成配置,更新时备份原内容', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-config-'));
  try {
    const output = join(dir, 'client.json');
    const inventory = join(dir, 'not-created.json');
    const args = [join(PROJECT, 'scripts', 'configure-mcp.js'), output, '--inventory', inventory];
    execFileSync(process.execPath, args);
    const first = readFileSync(output, 'utf8');
    execFileSync(process.execPath, args);
    const backup = readdirSync(dir).find(name => name.startsWith('client.json.bak-'));
    assert.ok(backup);
    assert.equal(readFileSync(join(dir, backup), 'utf8'), first);
    assert.equal(JSON.parse(first).mcpServers.vps.env.DSH_VPS_INVENTORY, inventory);
    assert.equal(existsSync(inventory), false);
    assert.throws(() => execFileSync(process.execPath, [args[0], output, '--unknown'], { stdio: 'pipe' }));
    const profile = join(dir, 'profile.yml');
    execFileSync(process.execPath, [join(PROJECT, 'scripts', 'configure-profile.js'), profile, '--disabled', '--inventory', inventory]);
    assert.equal(parse(readFileSync(profile, 'utf8'))[0].config.env.DSH_VPS_INVENTORY, inventory);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('公开示例使用占位符和空指纹,不会被误当作认证就绪', () => {
  const path = join(PROJECT, 'servers.example.json');
  const example = JSON.parse(readFileSync(path, 'utf8'));
  const inv = loadInventory({ path, env: {} });
  for (const [name, entry] of Object.entries(example.servers)) {
    assert.match(entry.host, /^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
    assert.match(entry.key, /^\$\{/);
    assert.deepEqual(entry.fingerprints, []);
    assert.ok(resolveServer(inv, name).error);
    assert.ok(resolveServer(inv, name, { probeOnly: true }).record);
  }
  const snippet = parse(readFileSync(join(PROJECT, 'dsh-profile-snippet.yml'), 'utf8'));
  assert.equal(snippet[0].enabled, false);
  assert.equal(snippet[0].config.command, '${NODE_EXECUTABLE}');
});

test('冒烟测试里的期望工具集与服务器实际注册的工具一致', () => {
  // 防止"加了工具忘记更新冒烟测试"这类漂移
  const src = readFileSync(join(PROJECT, 'src', 'index.js'), 'utf8');
  const registered = [...src.matchAll(/server\.registerTool\(\s*'([^']+)'/g)].map((m) => m[1]);
  const smoke = readFileSync(join(PROJECT, 'smoke-client.js'), 'utf8');
  const expectedBlock = smoke.match(/const EXPECTED_TOOLS = \[([\s\S]*?)\];/);
  assert.ok(expectedBlock, '冒烟测试里应有 EXPECTED_TOOLS');
  const expected = [...expectedBlock[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);

  assert.deepEqual([...registered].sort(), [...expected].sort(), '注册的工具与冒烟测试期望必须一致');
  assert.ok(registered.length >= 9, `工具数应 >= 9,实际 ${registered.length}`);
});
