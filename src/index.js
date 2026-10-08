#!/usr/bin/env node
/**
 * dsh-vps-ops-mcp —— 自建多服务器运维 MCP(stdio)。
 *
 * 安全模型(自下而上四层,对每一台服务器独立生效):
 *   1. 传输层:SSH 密钥认证(ed25519),私钥放工作区外,连接前用 parseKey 预校验。
 *   2. 身份层:每台服务器各自固定主机指纹(pinning),未固定或指纹不符一律拒绝。
 *   3. 授权层:所有服务器共用同一套命令白名单;写操作必须用户逐次批准,
 *              且仍受"即使批准也不允许"的硬性禁止清单约束。
 *   4. 约束层:远端 shell 执行前做结构校验、逐服务器超时/输出/长度上限、清单热重载。
 *
 * 清单:servers.json(可用 DSH_VPS_INVENTORY 指定),修改后热生效,无需重启 MCP 服务。
 * STDOUT 专用于 MCP 协议,日志一律走 STDERR。
 */
import { readFileSync, statSync } from 'node:fs';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { loadInventory, resolveServer, describeServer, DEFAULT_INVENTORY_PATH } from './inventory.js';
import { runCommand, probeHostKey } from './ssh.js';
import { checkReadCommand, checkApprovedCommand, checkFilePath, allowlistForDisplay } from './guard.js';
import { recordApprovedWrite, recordReadCommand, readAudit, summarizeAudit, auditLogPath } from './audit.js';

const SERVER_NAME = 'dsh-vps-ops';
const SERVER_VERSION = '0.4.0';

const READ_TIMEOUT_MS = 30000;
const APPROVED_TIMEOUT_MS = 120000;

function log(...args) {
  process.stderr.write(`[${SERVER_NAME}] ${args.join(' ')}\n`);
}

function text(payload, isError = false) {
  return {
    content: [{ type: 'text', text: typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

/* ------------------------------------------------------------------ *
 * 清单热重载:按 mtime 判断,改了 servers.json 立即生效
 * ------------------------------------------------------------------ */
let cached = null;
let cachedMtime = null;

function inventoryPath() {
  return process.env.DSH_VPS_INVENTORY || DEFAULT_INVENTORY_PATH;
}

function currentInventory() {
  const path = inventoryPath();
  let mtime = null;
  try {
    mtime = statSync(path).mtimeMs;
  } catch {
    mtime = null;
  }
  if (!cached || cachedMtime !== mtime) {
    cached = loadInventory({ path });
    cachedMtime = mtime;
    log(`清单已加载:${path} → ${cached.servers.size} 台服务器${cached.problems.length ? ` / 问题: ${cached.problems.join('; ')}` : ''}`);
  }
  return cached;
}

const SERVER_ARG = z.string().min(1).max(32).optional().describe('目标服务器名(见 list_servers);缺省用清单的 default');

function target(requested, options) {
  const inv = currentInventory();
  const r = resolveServer(inv, requested, options);
  if (r.error) return { error: text({ error: r.error, servers: [...inv.servers.keys()] }, true) };
  return { record: r.record };
}

async function exec(record, command, timeoutMs) {
  try {
    const r = await runCommand(record, command, { timeoutMs });
    return { ok: true, ...r };
  } catch (err) {
    return { ok: false, error: `${err.message}`, code: null, stdout: '', stderr: '' };
  }
}

/* ------------------------------------------------------------------ *
 * 服务实例
 * ------------------------------------------------------------------ */
const server = new McpServer(
  { name: SERVER_NAME, version: SERVER_VERSION },
  {
    instructions:
      '通过 SSH 读取并受控操作多台 VPS。先用 list_servers 看有哪些机器。' +
      '读状态优先用 status_snapshot(可加 allServers 一次采集全部);' +
      'read_only_command 只能执行白名单内的只读命令;' +
      '任何写操作必须使用 ssh_exec_approved,并在调用前把完整命令原文与影响展示给用户、获得明确同意。',
  },
);

/* --- 工具 0:list_servers ------------------------------------------------ */
server.registerTool(
  'list_servers',
  {
    title: '列出所有受管服务器',
    description: '返回清单中的服务器、各自固定的主机指纹、就绪状态与策略摘要。不建立任何连接。',
    inputSchema: {},
    annotations: { readOnlyHint: true },
  },
  async () => {
    const inv = currentInventory();
    return text({
      inventoryPath: inv.path,
      defaultServer: inv.defaultName,
      connected: false,
      servers: inv.list.map(describeServer),
      inventoryProblems: inv.problems,
      policy: { allowlist: allowlistForDisplay() },
    });
  },
);

/* --- 工具 1:host_key --------------------------------------------------- */
server.registerTool(
  'host_key',
  {
    title: '探测服务器 SSH 主机指纹',
    description:
      '连接(不认证)并返回服务器提供的 SSH 主机密钥指纹,以及当前固定状态。' +
      '把指纹写进 servers.json 对应条目的 fingerprints 后,该服务器才可用。',
    inputSchema: { server: SERVER_ARG },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ server: requested }) => {
    const t = target(requested, { probeOnly: true });
    if (t.error) return t.error;
    const rec = t.record;

    const res = await probeHostKey(rec);
    const alreadyPinned = rec.accepted.some((f) => f.fp === res.observedFingerprint);
    return text({
      server: rec.name,
      host: rec.host,
      port: rec.port,
      user: rec.user,
      observedFingerprint: res.observedFingerprint ?? null,
      handshake: res.ok ? '主机密钥与固定指纹匹配' : res.verifyReason ?? res.error ?? null,
      alreadyPinned,
      pinnedFingerprints: rec.accepted.map((f) => f.fp),
      nextStep: res.observedFingerprint && !alreadyPinned
        ? `在服务器上核对: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub,一致后把 "${res.observedFingerprint}" 写入 servers.json 的 servers.${rec.name}.fingerprints`
        : null,
    });
  },
);

/* --- 工具 2:test_connection -------------------------------------------- */
server.registerTool(
  'test_connection',
  {
    title: '测试连接与身份',
    description: '验证主机指纹固定、密钥认证与目标身份;返回 id/hostname、免密 sudo 与 docker 可用性。',
    inputSchema: { server: SERVER_ARG },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ server: requested }) => {
    const t = target(requested);
    if (t.error) return t.error;
    const rec = t.record;

    const id = await exec(rec, 'id', READ_TIMEOUT_MS);
    if (!id.ok) {
      return text({ server: rec.name, host: rec.host, connected: false, error: id.error }, true);
    }

    const [hostname, sudo, dockerDirect] = await Promise.all([
      exec(rec, 'hostname', READ_TIMEOUT_MS),
      exec(rec, 'sudo -n true', READ_TIMEOUT_MS),
      exec(rec, 'docker ps -q', READ_TIMEOUT_MS),
    ]);
    const dockerOk = dockerDirect.ok && dockerDirect.code === 0;
    const dockerSudo = dockerOk ? null : await exec(rec, 'sudo -n /usr/local/sbin/mcp-readonly docker ps -q', READ_TIMEOUT_MS);

    return text({
      server: rec.name,
      connected: true,
      host: rec.host,
      port: rec.port,
      user: rec.user,
      keyPath: rec.keyPath,
      identity: id.stdout.trim(),
      hostname: hostname.ok ? hostname.stdout.trim() : null,
      pinnedFingerprints: rec.accepted.map((f) => f.fp),
      privileges: {
        passwordlessSudoAll: sudo.ok && sudo.code === 0,
        dockerWithoutSudo: dockerOk,
        dockerViaSudo: dockerSudo ? dockerSudo.ok && dockerSudo.code === 0 : null,
      },
      limits: rec.limits,
    });
  },
);

/* --- 工具 3:status_snapshot -------------------------------------------- */
const SNAPSHOT_SECTIONS = {
  identity: [
    ['id', 'id'],
    ['hostname', 'hostname'],
    ['uptime', 'uptime'],
    ['kernel', 'uname -a'],
    ['os-release', 'cat /etc/os-release'],
  ],
  resources: [
    ['memory', 'free -h'],
    ['disk-usage', 'df -h'],
    ['inodes', 'df -i'],
    ['load', 'cat /proc/loadavg'],
    ['top-cpu', 'ps -eo pid,ppid,user,pcpu,pmem,etime,args --sort=-pcpu | head -15'],
    ['top-mem', 'ps -eo pid,ppid,user,pcpu,pmem,etime,args --sort=-pmem | head -10'],
    ['block-devices', 'lsblk'],
  ],
  docker: [
    ['containers', 'docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}"'],
    ['stats', 'docker stats --no-stream'],
    ['disk', 'docker system df'],
    ['volumes', 'docker volume ls'],
    ['networks', 'docker network ls'],
    ['images', 'docker images'],
  ],
  network: [
    ['listening', 'ss -lntup'],
    ['established', 'ss -tnp state established'],
    ['routes', 'ip route'],
    ['addresses', 'ip -br addr'],
  ],
  security: [
    ['failed-logins', 'grep -c "Failed password" /var/log/auth.log'],
    ['last-logins', 'last -n 10'],
    // 注:此处原用 awk 提取字段,但 awk 能把程序文本当参数(BEGIN{system(...)} 可执行任意命令),
    // 已从只读白名单移除。改用 grep -E 匹配普通用户行,效果等价且无解释能力。
    ['users-uid-ge-1000', 'grep -E "^[^:]+:[^:]*:1[0-9]{3}:" /etc/passwd'],
    ['cron-spool', 'ls -la /var/spool/cron/crontabs'],
    ['enabled-services', 'systemctl list-unit-files --type=service --state=enabled'],
    ['deleted-binaries', 'ls -l /proc/*/exe | grep -i deleted'],
    ['tmp-executables', 'find /tmp /var/tmp /dev/shm -type f -perm -u+x'],
  ],
  logs: [
    ['journal-errors', 'journalctl -p err -n 30 --no-pager'],
    ['oom-events', 'journalctl -k --no-pager | grep -i "out of memory"'],
  ],
};

async function collectSnapshot(record, sections) {
  // docker 权限探测:决定后续命令是否加 sudo -n
  const direct = await exec(record, 'docker ps -q', READ_TIMEOUT_MS);
  const dockerPrefix = direct.ok && direct.code === 0 ? '' : 'sudo -n /usr/local/sbin/mcp-readonly ';

  const out = {};
  const jobs = [];
  for (const section of sections) {
    out[section] = {};
    for (const [label, cmd] of SNAPSHOT_SECTIONS[section]) {
      const full = cmd.startsWith('docker ') ? dockerPrefix + cmd
        : cmd.startsWith('journalctl ') ? 'sudo -n /usr/local/sbin/mcp-readonly ' + cmd : cmd;
      jobs.push(
        () => exec(record, full, READ_TIMEOUT_MS).then((r) => {
          out[section][label] = r.ok
            ? { exitCode: r.code, timedOut: r.timedOut, truncated: r.truncated, stdout: r.stdout.trim(), stderr: r.stderr.trim() || undefined }
            : { error: r.error };
        }),
      );
    }
  }
  let nextJob = 0;
  await Promise.all(Array.from({ length: Math.min(4, jobs.length) }, async () => {
    while (nextJob < jobs.length) await jobs[nextJob++]();
  }));

  return {
    server: record.name,
    host: record.host,
    collectedAt: new Date().toISOString(),
    dockerSudoUsed: dockerPrefix !== '',
    sections: out,
  };
}

server.registerTool(
  'status_snapshot',
  {
    title: '服务器状态快照',
    description:
      '并行采集只读状态:身份、资源、Docker、网络、安全基线、日志错误。使用内置诊断命令,由远端 shell 执行。' +
      '用 server 指定单台,或用 allServers=true 一次采集全部服务器。',
    inputSchema: {
      server: SERVER_ARG,
      allServers: z.boolean().optional().describe('为 true 时采集清单中所有就绪服务器'),
      sections: z.array(z.enum(Object.keys(SNAPSHOT_SECTIONS))).optional().describe('要采集的分组,缺省全部'),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ server: requested, allServers, sections }) => {
    const inv = currentInventory();
    const wanted = sections?.length ? sections : Object.keys(SNAPSHOT_SECTIONS);

    let records;
    if (allServers) {
      records = inv.list.filter((r) => r.problems.length === 0);
      if (!records.length) {
        return text(
          { error: '清单中没有就绪的服务器', servers: inv.list.map(describeServer), inventoryProblems: inv.problems },
          true,
        );
      }
      if (records.length > 5) {
        return text({ error: `一次最多采集 5 台(allServers 收到 ${records.length} 台),请分批或用 server 指定` }, true);
      }
    } else {
      const t = target(requested);
      if (t.error) return t.error;
      records = [t.record];
    }

    const results = [];
    for (const rec of records) results.push(await collectSnapshot(rec, wanted));

    return text(allServers ? { serverCount: results.length, results } : results[0]);
  },
);

/* --- 工具 4:read_only_command ----------------------------------------- */
server.registerTool(
  'read_only_command',
  {
    title: '执行只读命令(白名单)',
    description:
      '在指定服务器执行一条经白名单和结构校验的只读命令。远端由 shell 执行,禁止写重定向、命令替换、后台执行、sudo。' +
      '可用 `;` 或 `&&` 拆分多段(每段单独校验);管道右侧只允许纯过滤器。',
    inputSchema: {
      command: z.string().min(1).max(4096).describe('要执行的只读命令'),
      server: SERVER_ARG,
      timeoutMs: z.number().int().min(1000).max(120000).optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ command, server: requested, timeoutMs }) => {
    const verdict = checkReadCommand(command);
    if (!verdict.ok) {
      // 被拒绝的尝试也留痕:能看出"反复试探什么"
      recordReadCommand({ server: requested ?? '(default)', command, error: 'blocked', blockedReason: verdict.why });
      return text({ blocked: true, reason: verdict.why, command }, true);
    }

    const t = target(requested);
    if (t.error) return t.error;
    const rec = t.record;

    const r = await exec(rec, command, timeoutMs ?? READ_TIMEOUT_MS);

    // 只读命令同样留痕(只记元数据,不记输出)—— 红队指出的反向盲区
    recordReadCommand({
      server: rec.name,
      host: rec.host,
      user: rec.user,
      command,
      result: r.ok ? r : null,
      error: r.ok ? null : r.error,
    });

    if (!r.ok) return text({ server: rec.name, command, error: r.error }, true);

    return text({
      server: rec.name,
      host: rec.host,
      command,
      matchedPrefixes: verdict.matchedPrefixes,
      exitCode: r.code,
      signal: r.signal ?? null,
      durationMs: r.durationMs,
      truncated: r.truncated,
      stdout: r.stdout,
      stderr: r.stderr,
    });
  },
);

/* --- 工具 5:read_file -------------------------------------------------- */
server.registerTool(
  'read_file',
  {
    title: '读取远程文件(受限)',
    description:
      '读取远程文本文件,默认上限 256 KiB。凭据类路径一律拒绝(/etc/shadow、/etc/ssh/*、.ssh/*、' +
      '*.env、*.pem、*.key、.docker/config.json、.my.cnf、.pgpass、.netrc、/proc/*/environ 等)。' +
      '路径必须是确定的字面绝对路径,不接受通配符或变量。',
    inputSchema: {
      path: z.string().min(1).max(1024).describe('远程文件的绝对路径(确定路径,不含通配符)'),
      server: SERVER_ARG,
      maxBytes: z.number().int().min(1024).max(262144).optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ path, server: requested, maxBytes }) => {
    // 路径校验统一走 guard 的 checkFilePath:与命令通道共用同一套"敏感文件形态"判定,
    // 避免两处各维护一份黑名单而逐渐不一致(早期版本正是这样漏掉 .my.cnf / .pgpass / *.pem 的)。
    const pathVerdict = checkFilePath(path);
    if (!pathVerdict.ok) return text({ blocked: true, reason: pathVerdict.why, path }, true);

    const limit = maxBytes ?? 262144;
    const cmd = `head -c ${limit} ${path}`;
    const verdict = checkReadCommand(cmd);
    if (!verdict.ok) return text({ blocked: true, reason: verdict.why }, true);

    const t = target(requested);
    if (t.error) return t.error;
    const rec = t.record;

    const r = await exec(rec, cmd, READ_TIMEOUT_MS);
    if (!r.ok) return text({ server: rec.name, path, error: r.error }, true);
    if (r.code !== 0) return text({ server: rec.name, path, exitCode: r.code, stderr: r.stderr }, true);

    return text({ server: rec.name, path, bytes: Buffer.byteLength(r.stdout), truncatedAt: limit, content: r.stdout });
  },
);

/* --- 工具 6:ssh_exec_approved ----------------------------------------- */
server.registerTool(
  'ssh_exec_approved',
  {
    title: '执行写操作(必须用户批准)',
    description:
      '对指定服务器执行非只读命令的唯一通道。调用前必须把完整命令原文、目的、影响面、回滚方式展示给用户并获得明确同意,' +
      '并由用户显式批准(approvedByUser=true)。即使批准,仍禁止删数据卷、改防火墙、改账户、改计划任务等操作。',
    inputSchema: {
      command: z.string().min(1).max(8192).describe('要执行的命令原文'),
      reason: z.string().min(4).max(500).describe('为什么要执行它(会展示给用户)'),
      approvedByUser: z.boolean().describe('用户是否已在对话中明确批准。未批准时必须为 false,工具会拒绝执行。'),
      server: SERVER_ARG,
      timeoutMs: z.number().int().min(1000).max(600000).optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
  async ({ command, reason, approvedByUser, server: requested, timeoutMs }) => {
    if (approvedByUser !== true) {
      // 未获批准也是一次尝试,留痕有助于发现"反复试探"的行为
      recordApprovedWrite({
        server: requested ?? '(default)',
        host: null,
        user: null,
        command,
        reason,
        result: null,
        error: 'not-approved-by-user',
      });
      return text(
        {
          executed: false,
          reason: '未获用户批准。请先把命令原文与影响说明展示给用户,得到明确同意后再以 approvedByUser=true 重新调用。',
          command,
        },
        true,
      );
    }

    const verdict = checkApprovedCommand(command);
    if (!verdict.ok) {
      recordApprovedWrite({
        server: requested ?? '(default)',
        host: null,
        user: null,
        command,
        reason,
        result: null,
        error: `hard-deny: ${verdict.why}`,
      });
      return text({ executed: false, reason: verdict.why, command }, true);
    }

    const t = target(requested);
    if (t.error) return t.error;
    const rec = t.record;

    const intent = recordApprovedWrite({
      server: rec.name, host: rec.host, user: rec.user,
      command, reason, outcome: 'authorized',
    });
    if (intent.auditWriteFailed) {
      return text({ executed: false, reason: '无法记录批准操作,已拒绝执行', auditError: intent.auditWriteFailed }, true);
    }

    const r = await exec(rec, command, timeoutMs ?? APPROVED_TIMEOUT_MS);

    // 审计:记录命令、目标与结果(刻意不记录 stdout/stderr)
    const audit = recordApprovedWrite({
      server: rec.name,
      host: rec.host,
      user: rec.user,
      command,
      reason,
      result: r.ok ? r : null,
      error: r.ok ? null : r.error,
    });

    if (!r.ok) return text({ server: rec.name, command, error: r.error, audit: { ts: audit.ts } }, true);

    return text({
      server: rec.name,
      host: rec.host,
      command,
      reason,
      approvedByUser: true,
      exitCode: r.code,
      signal: r.signal ?? null,
      durationMs: r.durationMs,
      timedOut: r.timedOut,
      truncated: r.truncated,
      stdout: r.stdout,
      stderr: r.stderr,
      audit: { ts: audit.ts, outcome: audit.outcome, log: auditLogPath(), ...(audit.auditWriteFailed ? { writeFailed: audit.auditWriteFailed } : {}) },
    }, r.timedOut || r.code !== 0 || Boolean(audit.auditWriteFailed));
  },
);

/* --- 工具 8:read_audit_log -------------------------------------------- */
server.registerTool(
  'read_audit_log',
  {
    title: '查看写操作审计日志',
    description:
      '返回本 MCP 记录的所有写操作尝试:时间、目标服务器、命令原文、原因、结果、退出码、耗时。' +
      '包含被拒绝的尝试(未获批准/命中硬性禁止)。用于事后追责与自证清白。',
    inputSchema: {
      limit: z.number().int().min(1).max(500).optional().describe('返回条数,默认 50'),
      server: z.string().min(1).max(32).optional().describe('只看某台服务器'),
      kind: z
        .enum(['approved-write', 'read-command'])
        .optional()
        .describe('只看写操作(approved-write)或只看只读命令(read-command)'),
      summaryOnly: z.boolean().optional().describe('只返回统计汇总,不含命令原文'),
    },
    annotations: { readOnlyHint: true },
  },
  async ({ limit, server: filterServer, kind, summaryOnly }) => {
    if (summaryOnly) return text(summarizeAudit());
    return text(readAudit({ limit: limit ?? 50, server: filterServer, kind }));
  },
);

/* --- 工具 7:policy_info ----------------------------------------------- */
server.registerTool(
  'policy_info',
  {
    title: '查看当前安全策略',
    description: '返回只读白名单、禁止清单、各服务器指纹固定状态与各项限制,用于审计这个 MCP 能做什么。',
    inputSchema: {},
    annotations: { readOnlyHint: true },
  },
  async () => {
    const inv = currentInventory();
    return text({
      server: { name: SERVER_NAME, version: SERVER_VERSION },
      inventory: {
        path: inv.path,
        defaultServer: inv.defaultName,
        count: inv.servers.size,
        problems: inv.problems,
        servers: inv.list.map(describeServer),
      },
      hostKeyPinning: { mode: 'per-server pinned fingerprints', allowTofu: false },
      allowlist: allowlistForDisplay(),
      limits: { readTimeoutMs: READ_TIMEOUT_MS, approvedTimeoutMs: APPROVED_TIMEOUT_MS },
      notes: [
        'SSH 密码认证永不使用,仅密钥;私钥位于工作区外,配置文件中不含密钥材料。',
        '每台服务器必须固定主机指纹,否则拒绝连接。',
        'ssh_exec_approved 只接受支持的命令形态,以目标受限账户运行,受其 sudoers 限制;批准记录写入失败时不执行。',
        'servers.json 修改后热生效,无需重启 MCP 服务。',
      ],
    });
  },
);

/* ------------------------------------------------------------------ *
 * 启动
 * ------------------------------------------------------------------ */
async function main() {
  const inv = currentInventory();
  log(`启动 v${SERVER_VERSION} | 清单 ${inv.path} | ${inv.servers.size} 台服务器 | default=${inv.defaultName ?? '(未设置)'}`);
  for (const rec of inv.list) {
    log(`  ${rec.problems.length ? '✗' : '✓'} ${rec.name} → ${rec.user}@${rec.host}:${rec.port}${rec.problems.length ? ` (${rec.problems.join('; ')})` : ''}`);
  }

  // 启动时验证一次清单可读性,避免只在调用时才暴露低级错误
  try {
    readFileSync(inv.path, 'utf8');
  } catch {
    log('提示:清单当前不可读,可使用 host_key 工具前的 list_servers 查看具体问题');
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  log('stdio 已连接,MCP 就绪');
}

main().catch((err) => {
  log(`致命错误: ${err?.stack ?? err}`);
  process.exit(1);
});
