/**
 * 上线验收脚本(只读,不修改服务器任何状态)。
 *
 * 用途:在你跑完 server-setup.sh 之后,一条命令完成端到端验收:
 *   1. 主机指纹是否与清单固定值一致
 *   2. ops-us 是否可登录、身份与清单是否相符
 *   3. 提权面是否真的被收窄(允许的可用、该拒的必须拒)
 *   4. 只读状态采集是否正常,并回显关键指标
 *
 * 全部命令都走 MCP 的同一套只读白名单;脚本本身不执行任何写操作。
 *
 * 用法:
 *   node scripts/verify-onboarding.js            # 用清单里的 default
 *   node scripts/verify-onboarding.js web1       # 指定服务器名
 */
import { loadInventory, resolveServer, describeServer } from '../src/inventory.js';
import { runCommand, probeHostKey } from '../src/ssh.js';
import { checkReadCommand } from '../src/guard.js';

const target = process.argv[2];

const results = [];
function record(label, ok, detail = '') {
  results.push({ label, ok, detail });
  const icon = ok === true ? '✓' : ok === false ? '✗' : '•';
  const color = ok === true ? '\x1b[32m' : ok === false ? '\x1b[31m' : '\x1b[90m';
  console.log(`  ${color}${icon}\x1b[0m ${label}${detail ? `  ${detail}` : ''}`);
}

/** 只读执行:先过白名单,保证验收脚本自己也不会越权 */
async function readOnly(rec, cmd) {
  const guarded = cmd.startsWith('sudo -n /usr/local/sbin/mcp-readonly docker ') ? cmd.replace('sudo -n /usr/local/sbin/mcp-readonly ', '') : cmd;
  const verdict = checkReadCommand(guarded);
  if (!verdict.ok) throw new Error(`命令未通过只读白名单(${cmd}):${verdict.why}`);
  const r = await runCommand(rec, cmd, { timeoutMs: 30000 });
  if (r.timedOut || r.code !== 0) {
    return { ...r, failed: true };
  }
  return r;
}

console.log(`\n=== 上线验收 ===\n`);

const inv = loadInventory({});
console.log(`清单: ${inv.path}`);
for (const s of inv.list) {
  const d = describeServer(s);
  console.log(`  ${d.ready ? '✓' : '✗'} ${d.name} → ${d.user}@${d.host}:${d.port}${d.ready ? '' : ` (${d.problems.join('; ')})`}`);
}

const { record: rec, error } = resolveServer(inv, target);
if (error) {
  console.error(`\n✗ 无法选择目标服务器:${error}\n`);
  process.exit(2);
}
console.log(`\n目标: ${rec.name} (${rec.user}@${rec.host}:${rec.port})\n`);

/* ---- 1. 主机指纹 ---- */
console.log('[1/5] 主机密钥指纹');
{
  const probe = await probeHostKey(rec);
  const pinned = rec.accepted.map((f) => f.fp);
  const match = pinned.includes(probe.observedFingerprint);
  record(
    '握手观测到的指纹与清单固定值一致',
    match,
    `${probe.observedFingerprint ?? '(无)'}`,
  );
  if (!match) {
    console.log('      请核对:服务器上 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub');
  }
}

/* ---- 2. 身份 ---- */
console.log('\n[2/5] 登录与身份');
{
  let id;
  try {
    id = await readOnly(rec, 'id');
  } catch (err) {
    record('能够通过 SSH 登录', false, err.message);
    console.log('\n✗ 无法登录。请确认已在该服务器上执行 server-setup.sh,且 ops-us 的 authorized_keys 含本机公钥。\n');
    process.exit(1);
  }
  record('能够通过 SSH 登录(密钥认证)', !id.failed);
  const groups = await readOnly(rec, 'id -nG');
  record('不属于特权组', !groups.failed && !/\b(root|sudo|wheel|docker|lxd|incus-admin|disk)\b/.test(groups.stdout));
  record('身份符合预期且非 root', id.stdout.includes(`(${rec.user})`) && !/^uid=0\b/.test(id.stdout), id.stdout.trim());
  const host = await readOnly(rec, 'hostname');
  record('hostname 可读', !host.failed, host.stdout.trim());
}

/* ---- 3. 提权面是否真的收窄 ---- */
console.log('\n[3/5] 提权面核验(关键安全项)');
{
  const okCases = [
    ['sudo -n /usr/local/sbin/mcp-readonly docker ps -q', 'docker 只读提权可用'],
    ['sudo -n /usr/local/sbin/mcp-readonly journalctl -n 1 --no-pager', 'journalctl 只读提权可用'],
  ];
  for (const [cmd, label] of okCases) {
    let r;
    try {
      r = await runCommand(rec, cmd, { timeoutMs: 30000 });
      r.failed = r.timedOut || r.code !== 0;
    } catch (err) {
      record(label, false, err.message);
      continue;
    }
    record(label, !r.failed, r.failed ? `stderr: ${r.stderr.trim().split('\n')[0]}` : '');
  }

  // 这些必须失败。用只读白名单放行的形式去测提权是否被拒:
  //   sudo -n <危险命令> 会被 ssh_exec 交给远端 shell,由 sudoers 决定成败
  const mustDeny = [
    ['sudo -n -l -- systemctl start docker', 'systemctl start 必须被拒'],
    ['sudo -n -l -- systemctl edit docker', 'systemctl edit 必须被拒(可注入 root 单元)'],
    ['sudo -n -l -- docker run --rm alpine true', 'docker run 必须被拒(容器即 root)'],
    ['sudo -n -l -- cat /etc/shadow', '读 shadow 必须被拒'],
    ['sudo -n -l -- useradd hacker', '建账户必须被拒'],
    ['sudo -n -l -- journalctl --rotate', '日志维护必须被拒'],
    ['sudo -n -l -- dmesg -C', '清内核日志必须被拒'],
    ['sudo -n -l -- ss -K', '断开连接必须被拒'],
  ];
  for (const [cmd, label] of mustDeny) {
    // 注意:sudo 命令不走只读白名单,这里直接调用 SSH 层是有意的 ——
    // 目的就是验证"服务器端的 sudoers 是否拒绝",而不是验证本地白名单。
    const r = await runCommand(rec, cmd, { timeoutMs: 20000 });
    const denied = !r.timedOut && r.code === 1;
    record(label, denied, denied ? '' : '⚠ 竟然成功,提权面未收窄!');
  }
}

/* ---- 4. 只读状态采集 ---- */
console.log('\n[4/5] 状态采集');
{
  const checks = [
    ['hostname', '主机名'],
    ['uptime', '运行时长'],
    ['free -h', '内存'],
    ['df -h /', '磁盘'],
    ['sudo -n /usr/local/sbin/mcp-readonly docker ps -a --format "table {{.Names}}\t{{.Status}}"', '容器(需 docker 权限)'],
    ['ss -lntp', '监听端口'],
  ];
  for (const [cmd, label] of checks) {
    let r;
    try {
      r = await readOnly(rec, cmd);
    } catch (err) {
      record(label, false, err.message);
      continue;
    }
    if (r.failed) {
      record(label, false, r.stderr.trim().split('\n')[0]);
      continue;
    }
    const first = r.stdout.trim().split('\n')[0] ?? '';
    record(label, true, first.slice(0, 90));
  }
}

/* ---- 5. 与历史排查对照 ---- */
console.log('\n[5/5] 待办排查项(只读)');
{
  const r1 = await readOnly(rec, 'grep -c "Failed password" /var/log/auth.log');
  if (r1.code === 0) {
    const n = Number.parseInt(r1.stdout.trim(), 10);
    record('SSH 失败登录次数', true, `${n} 次${n > 1000 ? '  ← 建议启用 fail2ban / 仅密钥登录' : ''}`);
  } else {
    record('SSH 失败登录次数(可选)', null, '账户无权读取 auth.log');
  }

  const r2 = await safeRead(rec, 'sudo -n /usr/local/sbin/mcp-readonly docker ps -a --format "{{.Names}} {{.Ports}}"');
  if (r2 && !r2.failed) {
    const exposed = r2.stdout
      .split('\n')
      .filter((l) => l.includes('0.0.0.0:'))
      .map((l) => l.trim());
    record(
      '容器端口绑定到 0.0.0.0 的数量',
      null,
      exposed.length ? `${exposed.length} 个:\n      ${exposed.join('\n      ')}` : '无',
    );
  }
}

async function safeRead(rec, cmd) {
  try {
    return await readOnly(rec, cmd);
  } catch {
    return null;
  }
}

/* ---- 汇总 ---- */
const failed = results.filter((r) => r.ok === false);
console.log(`\n=== 汇总:${results.length - failed.length}/${results.length} 项通过 ===`);
if (failed.length) {
  console.log('未通过项:');
  for (const f of failed) console.log(`  ✗ ${f.label}${f.detail ? `  ${f.detail}` : ''}`);
  process.exitCode = 1;
} else {
  console.log('全部通过 —— 通道可用且提权面已按设计收窄。\n');
}
