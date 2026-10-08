/**
 * 端到端集成测试:真实 SSH 连接(本机 in-process sshd)。
 *
 * 为什么需要它:在此之前所有测试要么只测守卫逻辑,要么只验证"主机不可达时报错"。
 * 真正跑过网络栈、KEX、主机密钥校验、exec 通道、stdout/stderr 分流、退出码、超时与限流
 * 的路径**从未被验证过** —— 而这正是"让 AI 操控服务器"的核心。
 *
 * 做法:用 ssh2 自带的 Server 在本机随机端口起一个最小 sshd,只接受本项目的
 * 运维公钥,并为测试用语提供确定的命令实现。客户端侧(我们的 src/ssh.js)完全真实。
 *
 * 覆盖:
 *   * 主机密钥固定:指纹错误必须拒绝连接
 *   * 命令执行:stdout / stderr / 退出码 分流正确
 *   * 输出限流:超过 maxOutputBytes 必须截断并标记
 *   * 本地超时:硬上限生效,返回 timedOut 而不挂死
 *   * MCP 工具层:read_only_command / status_snapshot / read_file 走真实 socket
 *
 * 运行:node --test test/integration-ssh.test.js
 */
import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import ssh2 from 'ssh2';
import { KEY_PATH, PUB_PATH, requireCredentials } from './helpers/paths.js';

import { runCommand, probeHostKey, verifyHostKeyFor } from '../src/ssh.js';
import { loadInventory, resolveServer } from '../src/inventory.js';

const { Server, utils } = ssh2;

requireCredentials();
const OPS_PUB = PUB_PATH;

/** 测试 sshd 的命令实现:确定、无副作用。 */
const STUB_COMMANDS = new Map([
  ['id', "uid=1001(ops-us) gid=1001(ops-us) groups=1001(ops-us)\n"],
  ['hostname', 'test-vps-1\n'],
  ['uptime', ' 12:00:00 up 10 days,  3:21,  1 user,  load average: 0.10, 0.20, 0.15\n'],
  ['uname -a', 'Linux test-vps-1 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\n'],
  ['cat /etc/os-release', 'NAME="Ubuntu"\nVERSION="24.04.1 LTS (Noble Numbat)"\n'],
  ['free -h', '               total        used        free\nMem:           3.3Gi       1.5Gi       185Mi\n'],
  ['df -h', '/dev/vda2        69G   16G   51G  23% /\n'],
  ['docker ps -q', ''],
  ['sudo -n true', ''],
  ['sudo -n docker ps -q', 'c0ffee123456\n'],
  ['wc -c /var/log/syslog', '  123456 /var/log/syslog\n'],
]);

/** head -c 读取的文件内容(read_file 按 maxBytes 生成不同的字节数,故单独按模式匹配) */
const STUB_FILES = new Map([
  ['/etc/nginx/nginx.conf', 'user www-data;\nworker_processes auto;\ninclude /etc/nginx/modules-enabled/*.conf;\n'],
  ['/etc/docker/daemon.json', '{\n  "log-driver": "json-file"\n}\n'],
]);

let server;
let port;
let hostFingerprint;
let inventoryPath;
let hostKeyDir;
/** 记录服务端收到的命令,用于断言"客户端确实发出去了" */
const received = [];

function fingerprintOf(keyObject) {
  const der = keyObject.export({ type: 'spki', format: 'der' });
  // 与 src/hostkey.js 的算法保持一致:对 ssh2 提供的原始 key blob 求 sha256
  return 'SHA256:' + createHash('sha256').update(der).digest('base64').replace(/=+$/, '');
}

before(async () => {
  // 生成临时主机密钥。注意:必须用 ssh-keygen 生成 OpenSSH 格式 ——
  // Node crypto 导出的 PKCS8 PEM 不被 ssh2 的 Server 接受。
  const keyDir = mkdtempSync(join(tmpdir(), 'vps-hostkey-'));
  hostKeyDir = keyDir;
  const hostKeyPath = join(keyDir, 'ssh_host_ed25519_key');
  const { execFileSync } = await import('node:child_process');
  // -N '' 必须是真的空字符串:execFileSync 不走 shell,传 '""' 会把两个引号当口令
  execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', hostKeyPath, '-N', '', '-C', 'test-host'], {
    stdio: 'ignore',
  });
  const hostKeyPem = readFileSync(hostKeyPath);

  const opsPubText = readFileSync(OPS_PUB, 'utf8').trim();
  const parsed = utils.parseKey(opsPubText);
  assert.ok(!(parsed instanceof Error), `运维公钥应可解析: ${parsed?.message}`);

  server = new Server({ hostKeys: [hostKeyPem] }, (client) => {
    // 客户端在 status_snapshot 里会并发建多条连接,连接被中途关闭时
    // 服务端会抛 KEY_EXCHANGE_FAILED 之类错误 —— 挂上 handler 避免污染测试输出
    client.on('error', () => {});
    client.on('close', () => {});

    client.on('authentication', (ctx) => {
      // 只接受本项目那把运维密钥
      if (ctx.method === 'publickey' && ctx.key.algo === parsed.type && Buffer.compare(ctx.key.data, parsed.getPublicSSH()) === 0) {
        return ctx.accept();
      }
      return ctx.reject(['publickey']);
    });

    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec, rejectExec, info) => {
          const cmd = info.command;
          received.push(cmd);
          const stream = acceptExec();
          if (cmd === 'unicode-output') {
            const bytes = Buffer.from('中文🙂'.repeat(2000));
            stream.write(bytes.subarray(0, 1));
            setTimeout(() => {
              stream.write(bytes.subarray(1));
              stream.stderr.write(bytes);
              stream.exit(0);
              stream.end();
            }, 15);
            return;
          }
          if (cmd === 'sleep 5') {
            // 用于验证本地超时:故意慢
            setTimeout(() => {
              stream.exit(0);
              stream.end();
            }, 5000);
            return;
          }
          if (cmd === 'sh -c echo-out-err-and-exit-3') {
            stream.write('to-stdout\n');
            stream.stderr.write('to-stderr\n');
            stream.exit(3);
            stream.end();
            return;
          }
          if (cmd === 'big-output') {
            // 用于验证限流:写出远超 maxOutputBytes 的内容
            for (let i = 0; i < 40; i += 1) stream.write('x'.repeat(1024));
            stream.exit(0);
            stream.end();
            return;
          }
          const out = STUB_COMMANDS.get(cmd);
          if (out !== undefined) {
            stream.write(out);
            stream.exit(0);
            stream.end();
            return;
          }
          // head -c <N> <path>:read_file 会按 maxBytes 生成不同 N,因此按模式匹配
          const headMatch = cmd.match(/^head -c (\d+) (\/\S+)$/);
          if (headMatch) {
            const file = STUB_FILES.get(headMatch[2]);
            if (file !== undefined) {
              stream.write(file.slice(0, Number(headMatch[1])));
              stream.exit(0);
              stream.end();
              return;
            }
          }
          stream.stderr.write(`bash: ${cmd.split(' ')[0]}: command not found\n`);
          stream.exit(127);
          stream.end();
        });
      });
    });
  });

  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  port = server.address().port;

  // 先用一条"不固定指纹"的记录探测,拿到真实指纹(与用户核对指纹的流程一致)
  const probeRecord = {
    name: 'local',
    host: '127.0.0.1',
    port,
    user: 'ops-us',
    privateKey: readFileSync(KEY_PATH),
    accepted: [],
    limits: { connectTimeoutMs: 5000, hardTimeoutMs: 8000, maxOutputBytes: 8192 },
  };
  const probe = await probeHostKey(probeRecord);
  hostFingerprint = probe.observedFingerprint;
  assert.ok(hostFingerprint, `探测应拿到指纹,实际: ${JSON.stringify(probe)}`);
});

after(() => {
  server?.close();
  try {
    rmSync(hostKeyDir, { recursive: true, force: true });
  } catch {
    /* 临时目录清理失败不影响结论 */
  }
});

function makeRecord(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'vps-int-'));
  const p = join(dir, 'servers.json');
  writeFileSync(
    p,
    JSON.stringify({
      default: 'local',
      servers: {
        local: {
          host: '127.0.0.1',
          port,
          user: 'ops-us',
          key: KEY_PATH,
          fingerprints: [hostFingerprint],
          connectTimeoutMs: 5000,
          hardTimeoutMs: 8000,
          maxOutputBytes: 8192,
          ...overrides,
        },
      },
    }),
    'utf8',
  );
  const inv = loadInventory({ path: p, env: {} });
  const { record, error } = resolveServer(inv, null);
  assert.ok(record, `清单应就绪: ${error}`);
  return record;
}

test('主机密钥固定:指纹匹配时连接成功', async () => {
  const rec = makeRecord();
  const r = await runCommand(rec, 'id');
  assert.equal(r.code, 0);
  assert.match(r.stdout, /uid=1001\(ops-us\)/);
  assert.equal(r.timedOut, false);
  assert.ok(received.includes('id'), '服务端应确实收到 id 命令');
});

test('主机密钥固定:指纹不匹配必须拒绝连接(防中间人)', async () => {
  const rec = makeRecord({ fingerprints: ['SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'] });
  await assert.rejects(
    () => runCommand(rec, 'id'),
    (err) => {
      assert.match(err.message, /主机密钥校验未通过|Host denied|verification/i);
      return true;
    },
    '指纹不符时必须抛错而不是静默连接',
  );
});

test('指纹固定语法:不匹配的指纹不会因为算法前缀被绕过', () => {
  const rec = makeRecord();
  const verdict = verifyHostKeyFor(rec, Buffer.from('not-the-real-key'), null);
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /不匹配/);
});

test('stdout / stderr / 退出码 分流正确', async () => {
  const rec = makeRecord();
  const r = await runCommand(rec, 'sh -c echo-out-err-and-exit-3');
  assert.equal(r.code, 3, '退出码应原样传回');
  assert.match(r.stdout, /to-stdout/);
  assert.match(r.stderr, /to-stderr/);
  // 关键:两者不能串道
  assert.equal(r.stdout.includes('to-stderr'), false);
  assert.equal(r.stderr.includes('to-stdout'), false);
});

test('未知命令返回非零退出码与 stderr,不抛异常', async () => {
  const rec = makeRecord();
  const r = await runCommand(rec, 'definitely-not-a-command');
  assert.equal(r.code, 127);
  assert.match(r.stderr, /command not found/);
});

test('输出限流:超过 maxOutputBytes 必须截断并标记 truncated', async () => {
  const rec = makeRecord({ maxOutputBytes: 4096 });
  const r = await runCommand(rec, 'big-output');
  assert.equal(r.truncated, true, '应标记被截断');
  assert.ok(Buffer.byteLength(r.stdout) <= 4096, `stdout 不应无界增长,实际 ${Buffer.byteLength(r.stdout)}`);
});

test('本地超时:超出上限时返回 timedOut 而不是挂死', async () => {
  const rec = makeRecord({ hardTimeoutMs: 1000 });
  const started = Date.now();
  const r = await runCommand(rec, 'sleep 5', { timeoutMs: 1000 });
  const elapsed = Date.now() - started;
  assert.equal(r.timedOut, true, '应标记超时');
  assert.ok(elapsed < 4500, `应在超时后很快返回,实际耗时 ${elapsed}ms`);
  assert.equal(typeof r.stdout, 'string');
  assert.equal(typeof r.stderr, 'string');
  assert.ok(Buffer.byteLength(r.stderr) <= rec.limits.maxOutputBytes);
});

test('多字节输出按字节限流,跨 chunk 的 UTF-8 保持完整', async () => {
  const rec = makeRecord({ maxOutputBytes: 4096 });
  const r = await runCommand(rec, 'unicode-output');
  assert.equal(r.truncated, true);
  assert.ok(r.stdout.startsWith('中文🙂'));
  for (const output of [r.stdout, r.stderr]) {
    assert.ok(Buffer.byteLength(output) <= 4096);
    assert.ok(!output.includes('\ufffd'));
  }
});

test('探测主机指纹不需要认证(未固定指纹时也能拿到)', async () => {
  // 刻意构造"未固定指纹"的记录:探测的意义就在于指纹还没固定的时候可用,
  // 因此这里不能走 makeRecord(它会断言清单已就绪)。
  const rec = {
    name: 'local',
    host: '127.0.0.1',
    port,
    user: 'ops-us',
    keyPath: KEY_PATH,
    privateKey: readFileSync(KEY_PATH),
    accepted: [],
    limits: { connectTimeoutMs: 5000, hardTimeoutMs: 8000, maxOutputBytes: 8192 },
  };
  const p = await probeHostKey(rec);
  assert.equal(p.ok, false, '探测阶段不应建立认证会话');
  assert.equal(p.observedFingerprint, hostFingerprint, '应回报观测到的真实指纹');
  assert.match(p.verifyReason, /未固定/);
});

/* ------------------------------------------------------------------ *
 * MCP 工具层:走真实 socket + 完整 JSON-RPC
 * ------------------------------------------------------------------ */
test('MCP 层:read_only_command 与 status_snapshot 走真实 SSH 返回结构化数据', async () => {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');

  const dir = mkdtempSync(join(tmpdir(), 'vps-int-mcp-'));
  const invPath = join(dir, 'servers.json');
  writeFileSync(
    invPath,
    JSON.stringify({
      default: 'local',
      servers: {
        unpinned: { host: '127.0.0.1', port, fingerprints: [] },
        local: {
          host: '127.0.0.1',
          port,
          user: 'ops-us',
          key: KEY_PATH,
          fingerprints: [hostFingerprint],
          connectTimeoutMs: 5000,
          hardTimeoutMs: 8000,
          maxOutputBytes: 65536,
        },
      },
    }),
    'utf8',
  );

  const serverPath = new URL('../src/index.js', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath],
    env: { ...process.env, DSH_VPS_INVENTORY: invPath, DSH_VPS_AUDIT_LOG: join(dir, 'audit.jsonl') },
    stderr: 'ignore',
  });
  const client = new Client({ name: 'integration', version: '1.0.0' }, { capabilities: {} });
  await client.connect(transport);

  try {
    const body = (r) => r.content?.[0]?.text ?? '';

    const beforeProbe = received.length;
    const observed = JSON.parse(body(await client.callTool({ name: 'host_key', arguments: { server: 'unpinned' } })));
    assert.equal(observed.observedFingerprint, hostFingerprint);
    assert.equal(observed.alreadyPinned, false);
    const unready = await client.callTool({ name: 'read_only_command', arguments: { server: 'unpinned', command: 'id' } });
    assert.equal(unready.isError, true);
    assert.equal(received.length, beforeProbe, '探测和未就绪记录均不得发送远程命令');

    // 1) 真实执行只读命令
    const one = JSON.parse(body(await client.callTool({ name: 'read_only_command', arguments: { command: 'id' } })));
    assert.equal(one.server, 'local');
    assert.equal(one.exitCode, 0);
    assert.match(one.stdout, /uid=1001\(ops-us\)/);

    // 2) 状态快照(只取 identity 分组,服务端有对应 stub)
    const snap = JSON.parse(
      body(await client.callTool({ name: 'status_snapshot', arguments: { sections: ['identity'] } })),
    );
    assert.equal(snap.server, 'local');
    assert.equal(snap.sections.identity.hostname.stdout, 'test-vps-1');
    assert.match(snap.sections.identity['os-release'].stdout, /24\.04\.1 LTS/);
    assert.match(snap.sections.identity.id.stdout, /ops-us/);

    // 3) test_connection 反映真实连通性
    const tc = JSON.parse(body(await client.callTool({ name: 'test_connection', arguments: {} })));
    assert.equal(tc.connected, true);
    assert.equal(tc.hostname, 'test-vps-1');
    assert.equal(tc.privileges.passwordlessSudoAll, true, 'stub 里 sudo -n true 成功');

    // 4) read_file 走真实通道
    const rfRaw = body(await client.callTool({ name: 'read_file', arguments: { path: '/etc/nginx/nginx.conf' } }));
    const rf = JSON.parse(rfRaw);
    assert.match(rf.content ?? '', /worker_processes auto/, `read_file 应返回文件内容,实际响应: ${rfRaw}`);

    // 5) read_file 对凭据路径仍然拒绝(不因真实通道而放宽)
    const denied = await client.callTool({ name: 'read_file', arguments: { path: '/etc/shadow' } });
    assert.match(body(denied), /凭据类文件/);

    // 6) 只读白名单对真实通道同样生效
    const blocked = await client.callTool({ name: 'read_only_command', arguments: { command: 'rm -rf /tmp/x' } });
    assert.match(body(blocked), /白名单|禁止/);

    // 7) 批准通道:真实执行写命令(测试 sshd 无副作用)并留痕
    const ap = JSON.parse(
      body(
        await client.callTool({
          name: 'ssh_exec_approved',
          arguments: { command: 'wc -c /var/log/syslog', reason: '集成测试:验证写通道与审计留痕', approvedByUser: true },
        }),
      ),
    );
    assert.equal(ap.exitCode, 0);
    assert.match(ap.stdout, /123456/);
    assert.equal(ap.audit.outcome, 'executed');

    const audit = JSON.parse(body(await client.callTool({ name: 'read_audit_log', arguments: {} })));
    const entry = audit.entries.find((e) => e.command === 'wc -c /var/log/syslog');
    assert.ok(entry, '写操作应被审计记录');
    assert.equal(entry.outcome, 'executed');
    assert.equal(entry.exitCode, 0);
    assert.equal(entry.server, 'local');

    const auditPath = join(dir, 'audit.jsonl');
    rmSync(auditPath);
    mkdirSync(auditPath);
    const beforeWrite = received.length;
    const auditBlocked = await client.callTool({
      name: 'ssh_exec_approved',
      arguments: { command: 'wc -c /var/log/syslog', reason: '验证审计失败时禁止执行', approvedByUser: true },
    });
    assert.equal(auditBlocked.isError, true);
    assert.equal(received.length, beforeWrite, '审计不可写时不得发送批准命令');
  } finally {
    await client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
