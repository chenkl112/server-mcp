/**
 * 冒烟测试:以子进程方式启动多服务器 MCP,走完整 stdio JSON-RPC 握手。
 *
 * 覆盖:
 *   * 握手与 8 个工具注册
 *   * list_servers / policy_info(清单与策略读取)
 *   * read_only_command 白名单放行与三层拦截
 *   * ssh_exec_approved 未批准时必须拒绝
 *   * 目标服务器不可达时的结构化错误(不崩溃)
 *
 * 用临时清单指向一个不可达地址,因此不依赖任何真实服务器。
 * 运行:node smoke-client.js
 */
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

// 用集中解析的凭据路径,避免这里硬编码后被删/被搬导致冒烟莫名失败
import { KEY_PATH as SMOKE_KEY, requireCredentials } from './test/helpers/paths.js';
requireCredentials();

const EXPECTED_TOOLS = [
  'list_servers',
  'host_key',
  'test_connection',
  'status_snapshot',
  'read_only_command',
  'read_file',
  'ssh_exec_approved',
  'read_audit_log',
  'policy_info',
];

// 测试清单:一个正常条目(不可达) + 一个残留占位符的条目(应"未就绪")
const dir = mkdtempSync(join(tmpdir(), 'vps-smoke-'));
const auditPath = join(dir, 'audit', 'writes.jsonl');
// 随机 nonce 放进"原因"字段:验证审计记了这次尝试,却没记下命令输出内容
const nonce = randomUUID();
const inventoryPath = join(dir, 'servers.json');
writeFileSync(
  inventoryPath,
  JSON.stringify(
    {
      default: 'unreachable',
      servers: {
        unreachable: {
          host: '127.0.0.1',
          port: 1,
          user: 'ops-us',
          key: SMOKE_KEY,
          fingerprints: ['SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
          connectTimeoutMs: 1500,
          hardTimeoutMs: 5000,
          maxOutputBytes: 65536,
        },
        notready: {
          host: 'REPLACE_WITH_SERVER_IP',
          user: 'ops-us',
          key: SMOKE_KEY,
          fingerprints: ['SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
        },
      },
    },
    null,
    2,
  ),
  'utf8',
);

const failures = [];
function check(label, cond, detail = '') {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    console.log(`  ✗ ${label}${detail ? ` — ${detail}` : ''}`);
    failures.push(label);
  }
}

const serverPath = new URL('./src/index.js', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  env: { ...process.env, DSH_VPS_INVENTORY: inventoryPath, DSH_VPS_AUDIT_LOG: join(dir, 'audit', 'writes.jsonl') },
  stderr: 'pipe',
});
transport.stderr?.on('data', (d) => process.stderr.write(`  [server] ${d}`));

const client = new Client({ name: 'smoke-client', version: '0.2.0' }, { capabilities: {} });

const body = (r) => r.content?.[0]?.text ?? '';

try {
  await client.connect(transport);
  console.log('✓ stdio 握手成功');

  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  console.log(`✓ 工具数量: ${names.length}`);
  for (const t of tools) console.log(`   - ${t.name}${t.annotations?.readOnlyHint ? '  (只读)' : '  (写)'}`);

  const missing = EXPECTED_TOOLS.filter((n) => !names.includes(n));
  check('工具齐全', missing.length === 0, `缺少 ${missing.join(', ')}`);
  check('每个工具都有 inputSchema', tools.every((t) => t.inputSchema && typeof t.inputSchema === 'object'));

  console.log('\n--- list_servers ---');
  const ls = JSON.parse(body(await client.callTool({ name: 'list_servers', arguments: {} })));
  check('读到 2 台服务器', ls.servers?.length === 2, JSON.stringify(ls.servers?.map((s) => s.name)));
  check('default 为 unreachable', ls.defaultServer === 'unreachable');
  check('不可达条目显示已就绪(指纹已配置)', ls.servers.find((s) => s.name === 'unreachable')?.ready === true);
  const notready = ls.servers.find((s) => s.name === 'notready');
  check('占位符条目显示未就绪', notready?.ready === false && /占位符/.test(notready?.problems?.join(' ') ?? ''));
  check('清单/策略中不含私钥材料', !body(await client.callTool({ name: 'list_servers', arguments: {} })).includes('PRIVATE KEY'));

  console.log('\n--- read_only_command 三层校验 ---');
  const allow = await client.callTool({ name: 'read_only_command', arguments: { command: 'id' } });
  const allowText = body(allow);
  check('白名单命令放行(id)', !/blocked/.test(allowText));
  check('放行后给出结构化连接错误(不可达主机)', /error|timed out|ETIMEDOUT|连接/i.test(allowText), allowText.slice(0, 120));

  for (const [cmd, label] of [
    ['cat /etc/shadow', '凭据文件'],
    ['docker ps && rm -rf /tmp', '连接符+破坏'],
    ['sudo docker ps', '提权'],
    ['docker volume rm x', '删数据卷'],
    ['echo x > /root/y', '重定向写入'],
  ]) {
    const r = await client.callTool({ name: 'read_only_command', arguments: { command: cmd } });
    check(`拦截 ${label}`, /blocked|命中禁止|结构不安全|白名单/.test(body(r)), cmd);
  }

  console.log('\n--- 索引到未就绪/未知服务器必须报错 ---');
  const badTarget = await client.callTool({ name: 'status_snapshot', arguments: { server: 'notready' } });
  check('未就绪服务器被拒绝', /尚未就绪/.test(body(badTarget)) && badTarget.isError === true);

  const unknown = await client.callTool({ name: 'list_servers', arguments: {} });
  check('list_servers 可用', unknown.isError !== true);

  console.log('\n--- ssh_exec_approved 未批准 ---');
  const ap = await client.callTool({
    name: 'ssh_exec_approved',
    arguments: { command: 'systemctl restart docker', reason: `冒烟测试 ${nonce}`, approvedByUser: false },
  });
  check('未批准时拒绝执行', /未获用户批准/.test(body(ap)));

  const apDenied = await client.callTool({
    name: 'ssh_exec_approved',
    arguments: { command: 'docker volume rm agents-anywhere_pg', reason: '冒烟测试', approvedByUser: true },
  });
  check('即使批准也拒绝删数据卷', /即使批准也不允许/.test(body(apDenied)));

  console.log('\n--- policy_info ---');
  const pol = JSON.parse(body(await client.callTool({ name: 'policy_info', arguments: {} })));
  check('策略含白名单', Array.isArray(pol.allowlist?.readAllowPrefixes) && pol.allowlist.readAllowPrefixes.length > 20);
  check('策略含 per-server 指纹模式', /per-server/.test(pol.hostKeyPinning?.mode ?? ''));
  check('策略含禁止规则数', Number.isInteger(pol.allowlist?.denyPatternCount));

  console.log('\n--- read_audit_log(审计留痕) ---');
  const audit = JSON.parse(body(await client.callTool({ name: 'read_audit_log', arguments: {} })));
  check('审计日志已生成', audit.exists === true, `path=${auditPath}`);
  check('未批准尝试已留痕', (audit.entries ?? []).some((e) => e.error === 'not-approved-by-user'));
  check('硬性禁止尝试已留痕', (audit.entries ?? []).some((e) => /hard-deny/.test(e.error ?? '')));
  check('命令原文与原因被记录', (audit.entries ?? []).some((e) => e.command === 'systemctl restart docker' && (e.reason ?? '').includes(nonce)));

  // 关键负向验证:审计文件里必须能找到这次尝试,但绝不能出现命令输出内容
  const rawLog = existsSync(auditPath) ? readFileSync(auditPath, 'utf8') : '';
  check('审计文件可读且非空', rawLog.length > 0);
  check('审计文件包含本次尝试(nonce 可检索)', rawLog.includes(nonce));
  check('审计条目不含 stdout/stderr 字段', !/"stdout"\s*:/.test(rawLog) && !/"stderr"\s*:/.test(rawLog));
  check('审计条目含哈希与输出字节数', /"commandSha256":"[0-9a-f]{64}"/.test(rawLog) && /"stdoutBytes":\d+/.test(rawLog));

  const auditSummary = JSON.parse(body(await client.callTool({ name: 'read_audit_log', arguments: { summaryOnly: true } })));
  check('审计汇总可用', typeof auditSummary.total === 'number');
  check('汇总不含命令原文', !JSON.stringify(auditSummary).includes('systemctl'));

  await client.close();
  console.log(
    failures.length ? `\n✗ 冒烟测试失败 ${failures.length} 项:${failures.join(' | ')}\n` : '\n✓ 冒烟测试全部通过\n',
  );
  process.exitCode = failures.length ? 1 : 0;
} catch (err) {
  console.error(`\n✗ 冒烟测试异常: ${err?.stack ?? err}\n`);
  process.exitCode = 1;
  try {
    await client.close();
  } catch {
    /* noop */
  }
}
