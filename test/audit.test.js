/**
 * 审计日志测试:写入、读取、汇总,以及"绝不泄露输出内容"这条硬性约束。
 * 用临时路径,不污染真实审计日志。
 *
 * 运行:node --test test/audit.test.js
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// 必须在 import audit.js 之前设置,模块读取时即决定路径
const dir = mkdtempSync(join(tmpdir(), 'vps-audit-'));
const LOG = join(dir, 'nested', 'approved-writes.jsonl');
process.env.DSH_VPS_AUDIT_LOG = LOG;

const { recordApprovedWrite, recordReadCommand, readAudit, summarizeAudit, auditLogPath } = await import('../src/audit.js');

test('只读命令同样留痕(红队指出的反向盲区)', () => {
  const before = readAudit({ limit: 500 }).total;

  const ok = recordReadCommand({
    server: 'web1',
    host: '192.0.2.10',
    user: 'ops-us',
    command: 'docker ps -a',
    result: { code: 0, stdout: 'CONTAINER ID  NAME\n', stderr: '', durationMs: 120, truncated: false, timedOut: false },
  });
  assert.equal(ok.kind, 'read-command');
  assert.equal(ok.outcome, 'executed');
  assert.equal(ok.exitCode, 0);

  // 被拦截的尝试也要留痕,便于发现"反复试探什么"
  const blocked = recordReadCommand({
    server: 'web1',
    command: 'cat /etc/shadow',
    blockedReason: '命中禁止清单:读取系统凭据文件',
  });
  assert.equal(blocked.kind, 'read-command');
  assert.equal(blocked.outcome, 'blocked');
  assert.match(blocked.blockedReason, /凭据/);

  const after = readAudit({ limit: 500 });
  assert.equal(after.total, before + 2, '只读命令应写入审计');

  // kind 过滤:只看写操作时,不该混入只读命令
  const onlyWrites = readAudit({ limit: 500, kind: 'approved-write' });
  assert.ok(onlyWrites.entries.every((e) => e.kind === 'approved-write'));
  const onlyReads = readAudit({ limit: 500, kind: 'read-command' });
  assert.ok(onlyReads.entries.length >= 2);
  assert.ok(onlyReads.entries.every((e) => e.kind === 'read-command'));
});

test('只读命令的审计同样不含输出内容', () => {
  const secret = 'mysql://root:AnotherSecret456@db:3306/halo';
  recordReadCommand({
    server: 'web1',
    host: '192.0.2.10',
    user: 'ops-us',
    command: 'docker inspect db1',
    result: { code: 0, stdout: `env=${secret}`, stderr: '', durationMs: 9, truncated: false, timedOut: false },
  });
  const raw = readFileSync(LOG, 'utf8');
  assert.equal(raw.includes('AnotherSecret456'), false, '只读审计也不得包含输出内容');
  const { entries } = readAudit({ limit: 500, kind: 'read-command' });
  const hit = entries.find((e) => e.command === 'docker inspect db1');
  assert.ok(hit, '应能找到该条');
  assert.equal(hit.stdout, undefined, '不应有 stdout 字段');
  assert.ok(hit.stdoutBytes > 0, '但应记录输出字节数');
});

test('写入成功并创建缺失的目录', () => {
  const entry = recordApprovedWrite({
    server: 'web1',
    host: '192.0.2.10',
    user: 'ops-us',
    command: 'systemctl restart docker',
    reason: '重启 docker 以加载新配置',
    result: { code: 0, stdout: 'ok', stderr: '', durationMs: 1234, truncated: false, timedOut: false },
  });

  assert.equal(entry.outcome, 'executed');
  assert.equal(entry.exitCode, 0);
  assert.equal(entry.server, 'web1');
  assert.equal(entry.loginUser, 'ops-us');
  assert.ok(existsSync(LOG), '应自动创建 audit 目录与日志文件');
  assert.equal(auditLogPath(), LOG);
});

test('审计条目绝不包含 stdout/stderr 内容', () => {
  const secret = 'mysql://root:SuperSecret123@db:3306/halo';
  recordApprovedWrite({
    server: 'db1',
    host: '198.51.100.20',
    user: 'ops-us',
    command: 'docker inspect db1',
    reason: '排查连接串',
    result: { code: 0, stdout: `env=${secret}`, stderr: `warn ${secret}`, durationMs: 10, truncated: false },
  });

  const raw = readFileSync(LOG, 'utf8');
  assert.equal(raw.includes('SuperSecret123'), false, '审计日志不得包含命令输出内容');
  assert.equal(raw.includes('mysql://'), false, '审计日志不得包含连接串');

  const { entries } = readAudit({ limit: 10 });
  const db1 = entries.find((e) => e.server === 'db1');
  assert.ok(db1.stdoutBytes > 0, '但应记录输出字节数,便于判断是否被截断');
  assert.equal(db1.stdout, undefined, '不应有 stdout 字段');
});

test('超长命令被截断,但仍保留完整哈希用于比对', () => {
  const long = `systemctl restart ${'a'.repeat(5000)}`;
  const entry = recordApprovedWrite({
    server: 'web1',
    host: '192.0.2.10',
    user: 'ops-us',
    command: long,
    reason: 'x',
    result: { code: 0, stdout: '', stderr: '', durationMs: 1, truncated: false },
  });
  assert.ok(entry.command.length < long.length);
  assert.match(entry.command, /\[truncated\]$/);
  assert.equal(entry.commandBytes, Buffer.byteLength(long), '原始字节数应保留');
  assert.match(entry.commandSha256, /^[0-9a-f]{64}$/, '应保留完整命令的哈希');
});

test('失败与超时有独立的 outcome', () => {
  recordApprovedWrite({
    server: 'web1',
    host: '192.0.2.10',
    user: 'ops-us',
    command: 'systemctl restart nope',
    reason: 'x',
    result: { code: 5, stdout: '', stderr: 'not found', durationMs: 20, truncated: false, timedOut: false },
  });
  recordApprovedWrite({
    server: 'web1',
    host: '192.0.2.10',
    user: 'ops-us',
    command: 'apt-get upgrade',
    reason: 'x',
    result: { code: null, stdout: 'partial', stderr: '', durationMs: 120000, truncated: true, timedOut: true },
  });
  recordApprovedWrite({
    server: 'web1',
    host: '192.0.2.10',
    user: 'ops-us',
    command: 'whatever',
    reason: 'x',
    result: null,
    error: 'connection lost',
  });

  const { entries } = readAudit({ limit: 10 });
  const outcomes = entries.map((e) => e.outcome);
  assert.ok(outcomes.includes('executed'));
  assert.ok(outcomes.includes('timeout'));
  assert.ok(outcomes.includes('error'));
  const timeoutEntry = entries.find((e) => e.outcome === 'timeout');
  assert.equal(timeoutEntry.outputTruncated, true);
});

test('读取支持按服务器过滤,并按时间倒序', () => {
  const all = readAudit({ limit: 100 });
  assert.ok(all.total >= 6);
  const web1 = readAudit({ limit: 100, server: 'web1' });
  assert.ok(web1.matched >= 4);
  assert.ok(web1.entries.every((e) => e.server === 'web1'));
  const ts = all.entries.map((e) => e.ts);
  const sorted = [...ts].sort().reverse();
  assert.deepEqual(ts, sorted, '条目应按时间倒序(最新在前)');
});

test('汇总不含命令原文', () => {
  const s = summarizeAudit();
  assert.equal(s.exists, true);
  assert.ok(s.total >= 6);
  assert.ok(s.byServer.web1 >= 4);
  assert.ok(Object.keys(s.byOutcome).length >= 3);
  assert.equal(JSON.stringify(s).includes('systemctl'), false, '汇总不应带命令原文');
});

test('日志不存在时返回 exists:false 而不是崩溃', () => {
  const saved = process.env.DSH_VPS_AUDIT_LOG;
  process.env.DSH_VPS_AUDIT_LOG = join(dir, 'does-not-exist.jsonl');
  try {
    const r = readAudit({ limit: 5 });
    assert.equal(r.exists, false);
    assert.equal(r.total, 0);
    assert.deepEqual(r.entries, []);
    assert.equal(summarizeAudit().exists, false);
  } finally {
    process.env.DSH_VPS_AUDIT_LOG = saved;
  }
});
