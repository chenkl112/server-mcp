/**
 * 多服务器清单解析与目标解析测试。
 * 用临时目录构造 fixture,不依赖网络,也不需要真实服务器。
 *
 * 运行:node --test test/inventory.test.js
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadInventory, resolveServer, describeServer, expandEnv, detectPlaceholders } from '../src/inventory.js';
import { verifyHostKeyFor, fingerprintSha256 } from '../src/ssh.js';

import { KEY_PATH as REAL_KEY, requireCredentials } from './helpers/paths.js';
requireCredentials();

function fixtureDir() {
  return mkdtempSync(join(tmpdir(), 'vps-inv-'));
}

function writeInventory(dir, obj) {
  const p = join(dir, 'servers.json');
  writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8');
  return p;
}

test('合法清单:两台服务器均可就绪,default 生效', () => {
  const dir = fixtureDir();
  const keyCopy = join(dir, 'key');
  copyFileSync(REAL_KEY, keyCopy);

  const path = writeInventory(dir, {
    default: 'web1',
    servers: {
      web1: { host: '10.0.0.1', user: 'ops-us', key: keyCopy, fingerprints: ['SHA256:AAAA'] },
      db1: { host: '10.0.0.2', user: 'ops-us', key: 'key', fingerprints: ['ssh-ed25519 SHA256:BBBB'] },
    },
  });

  const inv = loadInventory({ path, env: {} });
  assert.equal(inv.problems.length, 0, `清单问题: ${inv.problems.join('; ')}`);
  assert.equal(inv.servers.size, 2);
  assert.equal(inv.defaultName, 'web1');

  const web1 = inv.servers.get('web1');
  assert.equal(web1.problems.length, 0, `web1 问题: ${web1.problems.join('; ')}`);
  assert.equal(web1.port, 22, '端口应默认 22');
  assert.ok(web1.privateKey && web1.privateKey.length > 0, '私钥应已载入');

  // 相对路径应相对清单文件解析
  const db1 = inv.servers.get('db1');
  assert.equal(db1.keyPath, keyCopy, '相对 key 应解析到清单同目录');
  assert.equal(db1.problems.length, 0, `db1 问题: ${db1.problems.join('; ')}`);

  const r = resolveServer(inv, null);
  assert.equal(r.record.name, 'web1');
});

test('未替换的占位符会让该服务器"未就绪",而不是拿错值去连接', () => {
  const dir = fixtureDir();
  copyFileSync(REAL_KEY, join(dir, 'key'));
  const path = writeInventory(dir, {
    servers: {
      bad: { host: 'REPLACE_WITH_SERVER_IP', user: 'ops-us', key: 'key', fingerprints: ['SHA256:AAAA'] },
      envbad: { host: '${NO_SUCH_HOST_VAR}', user: 'ops-us', key: 'key', fingerprints: ['SHA256:AAAA'] },
    },
  });

  const inv = loadInventory({ path, env: {} });
  assert.match(inv.servers.get('bad').problems.join(' '), /占位符/);
  assert.match(inv.servers.get('envbad').problems.join(' '), /占位符/);

  // 未就绪的服务器必须拒绝成为调用目标
  const r = resolveServer(inv, 'bad');
  assert.match(r.error ?? '', /尚未就绪/);
});

test('环境变量展开:${VAR} 会被替换,未设置的保持原样', () => {
  assert.equal(expandEnv('host-${PORT}', { PORT: '2222' }), 'host-2222');
  assert.equal(expandEnv('${MISSING}', {}), '${MISSING}');
  assert.deepEqual(detectPlaceholders('${A} and REPLACE_WITH_X'), ['${A}', 'REPLACE_WITH_X']);
  assert.deepEqual(detectPlaceholders('192.0.2.10'), []);
});

test('缺少指纹的服务器未就绪(fail-closed)', () => {
  const dir = fixtureDir();
  copyFileSync(REAL_KEY, join(dir, 'key'));
  const path = writeInventory(dir, {
    servers: { nopin: { host: '10.0.0.9', user: 'ops-us', key: 'key', fingerprints: [] } },
  });

  const inv = loadInventory({ path, env: {} });
  const rec = inv.servers.get('nopin');
  assert.match(rec.problems.join(' '), /未固定主机指纹/);
  assert.match(resolveServer(inv, 'nopin').error ?? '', /尚未就绪/);
});

test('TOFU 环境变量不能绕过指纹固定', () => {
  const dir = fixtureDir();
  copyFileSync(REAL_KEY, join(dir, 'key'));
  const path = writeInventory(dir, {
    servers: { tofu: { host: '10.0.0.9', user: 'ops-us', key: 'key', fingerprints: [] } },
  });

  const inv = loadInventory({ path, env: { DSH_VPS_ALLOW_TOFU: '1' } });
  assert.match(resolveServer(inv, 'tofu').error, /未固定主机指纹/);
});

test('清单缺失/格式错误/为空都给出可读错误而不是崩溃', () => {
  const dir = fixtureDir();

  const missing = loadInventory({ path: join(dir, 'nope.json'), env: {} });
  assert.match(missing.problems.join(' '), /无法读取清单/);

  const badJson = join(dir, 'bad.json');
  writeFileSync(badJson, '{ not json', 'utf8');
  assert.match(loadInventory({ path: badJson, env: {} }).problems.join(' '), /不是合法 JSON/);

  const noServers = writeInventory(dir, { servers: {} });
  assert.match(loadInventory({ path: noServers, env: {} }).problems.join(' '), /没有任何服务器条目/);

  const arrServers = writeInventory(dir, { servers: [] });
  assert.match(loadInventory({ path: arrServers, env: {} }).problems.join(' '), /缺少顶层 "servers" 对象/);
});

test('非法服务器名被拒绝且不影响其他条目', () => {
  const dir = fixtureDir();
  copyFileSync(REAL_KEY, join(dir, 'key'));
  const path = writeInventory(dir, {
    servers: {
      'bad name!': { host: '10.0.0.1', user: 'ops-us', key: 'key', fingerprints: ['SHA256:A'] },
      good: { host: '10.0.0.2', user: 'ops-us', key: 'key', fingerprints: ['SHA256:A'] },
    },
  });
  const inv = loadInventory({ path, env: {} });
  assert.equal(inv.servers.has('bad name!'), false);
  assert.equal(inv.servers.has('good'), true);
  assert.match(inv.problems.join(' '), /不合法/);
});

test('私钥不存在时该服务器未就绪,错误信息点明路径', () => {
  const dir = fixtureDir();
  const path = writeInventory(dir, {
    servers: { nokey: { host: '10.0.0.1', user: 'ops-us', key: 'missing_key', fingerprints: ['SHA256:A'] } },
  });
  const inv = loadInventory({ path, env: {} });
  const msg = inv.servers.get('nokey').problems.join(' ');
  assert.match(msg, /无法读取私钥/);
  assert.match(msg, /missing_key/);
});

test('per-server 指纹校验:只认自己那一份', () => {
  const dir = fixtureDir();
  copyFileSync(REAL_KEY, join(dir, 'key'));
  const path = writeInventory(dir, {
    servers: {
      web1: { host: '10.0.0.1', user: 'ops-us', key: 'key', fingerprints: ['SHA256:ONLY_WEB1'] },
      db1: { host: '10.0.0.2', user: 'ops-us', key: 'key', fingerprints: ['SHA256:ONLY_DB1'] },
    },
  });
  const inv = loadInventory({ path, env: {} });
  const web1 = inv.servers.get('web1');

  const fakeKey = Buffer.from('some other host key bytes');
  const fp = fingerprintSha256(fakeKey);

  // web1 的指纹表里没有这个指纹 → 拒绝
  const denied = verifyHostKeyFor(web1, fakeKey, null);
  assert.equal(denied.ok, false);
  assert.equal(denied.fingerprint, fp);
  assert.match(denied.reason, /web1/);

  // 把观测到的指纹加进 web1 后 → 通过
  web1.accepted.push({ algo: null, fp: fp.replace(/=+$/, '') });
  assert.equal(verifyHostKeyFor(web1, fakeKey, null).ok, true);

  // db1 的指纹表不受影响,仍然拒绝同一把密钥
  const db1 = inv.servers.get('db1');
  assert.equal(verifyHostKeyFor(db1, fakeKey, null).ok, false);
});

test('安全投影不泄露私钥字节或口令', () => {
  const dir = fixtureDir();
  copyFileSync(REAL_KEY, join(dir, 'key'));
  const path = writeInventory(dir, {
    servers: { s1: { host: '10.0.0.1', user: 'ops-us', key: 'key', passphrase: 'super-secret', fingerprints: ['SHA256:A'] } },
  });
  const inv = loadInventory({ path, env: {} });
  const described = describeServer(inv.servers.get('s1'));
  const json = JSON.stringify(described);
  assert.equal(json.includes('super-secret'), false, '投影中不得出现口令');
  assert.equal(json.includes('PRIVATE KEY'), false, '投影中不得出现私钥内容');
  assert.equal(described.keyPath.endsWith('key'), true, '但应保留密钥路径便于排查');
  assert.deepEqual(described.pinnedFingerprints, ['SHA256:A']);
});
