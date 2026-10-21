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
import {
  checkReadCommand,
  checkApprovedCommand,
  checkSudoCommand,
  checkFilePath,
  checkDeletePath,
  checkDownloadUrl,
  checkDownloadTarget,
  allowlistForDisplay,
} from './guard.js';
import { assessCommand } from './risk.js';
import { approvalGate, approvalSettings } from './approval.js';
import { recordApprovedWrite, recordReadCommand, readAudit, summarizeAudit, auditLogPath } from './audit.js';

const SERVER_NAME = 'dsh-vps-ops';
const SERVER_VERSION = '0.5.0';

const READ_TIMEOUT_MS = 30000;
const APPROVED_TIMEOUT_MS = 120000;
const SUDO_TIMEOUT_MS = 180000;

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
 * 命令拼装、风险摘要与审批结果整理
 * ------------------------------------------------------------------ */

/** POSIX 单引号转义:整体当字面量传给远端 shell,不做任何展开。 */
function singleQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

/**
 * 把一条命令包装成 sudo 调用。
 *
 * * 简单命令(systemctl restart docker)直接 `sudo -n <cmd>`,远端 shell 照常解析参数;
 * * 含 shell 语法的命令(管道、重定向、&& …)必须包进 `bash -c`,
 *   否则 sudo 只会把 `-n` 之后第一个词当命令、其余当参数,语义会悄悄变形;
 * * 一律用 `-n`(非交互):需要密码时立即失败,而不是把会话挂在那里等输入。
 */
function buildSudoCommand(command) {
  const needsShell = /[;|&<>`$(){}\n\\]/.test(command);
  return needsShell ? `sudo -n bash -c ${singleQuote(command)}` : `sudo -n ${command}`;
}

/* ------------------------------------------------------------------ *
 * 服务器侧 sudo 就绪探测
 * ------------------------------------------------------------------ *
 * 为什么需要:服务器侧只要没配好 NOPASSWD,`sudo_exec` 一定在最后一步失败
 * (`sudo: a password is required`),但那时用户已经点过审批页了 —— 白跑一趟,
 * 而且报错看起来像"服务坏了"。这里先探一次,没就绪就直接告诉用户去做什么,
 * 连审批页都不弹。
 */
const SUDO_PROBE_TTL_MS = 300000; // 就绪:5 分钟内不再探
const SUDO_PROBE_FAIL_TTL_MS = 60000; // 未就绪:1 分钟后重探,方便粘完 bootstrap 立刻重试
const sudoProbeCache = new Map(); // serverName → { ok, checkedAt, detail }

async function sudoReadiness(record, { force = false } = {}) {
  const cached = sudoProbeCache.get(record.name);
  if (!force && cached) {
    const ttl = cached.ok ? SUDO_PROBE_TTL_MS : SUDO_PROBE_FAIL_TTL_MS;
    if (Date.now() - cached.checkedAt < ttl) return cached;
  }

  const r = await exec(record, 'sudo -n true', READ_TIMEOUT_MS);
  const ok = r.ok && r.code === 0;
  // 区分"连不上"与"连上了但没有免密 sudo" —— 两者的处理方式完全不同。
  const problem = ok ? null : r.ok ? 'sudo-not-configured' : 'connection';
  const detail = ok
    ? null
    : r.ok
      ? ((r.stderr || '').trim().split('\n').filter(Boolean)[0] ?? `退出码 ${r.code}`)
      : (r.error ?? '连接失败');

  const entry = { ok, problem, checkedAt: Date.now(), detail };
  sudoProbeCache.set(record.name, entry);
  return entry;
}

/** 未就绪时给用户的可执行指引(不弹审批页,直接回退)。 */
function sudoNotReadyPayload(record, readiness) {
  if (readiness.problem === 'connection') {
    return {
      executed: false,
      blocked: true,
      sudo: true,
      server: record.name,
      error: 'server-unreachable',
      detail: readiness.detail,
      reason: '连不上服务器,没法确认提权是否可用;命令没有执行,也没有弹审批页。',
      nextStep: '先确认网络与指纹(可调 test_connection),再重试。',
    };
  }

  return {
    executed: false,
    blocked: true,
    sudo: true,
    server: record.name,
    error: 'server-side-sudo-not-configured',
    detail: readiness.detail,
    reason:
      '服务器侧还没有给 ops-us 配置免密 sudo,所以这条命令即使你批准,也会在服务器上以 ' +
      '`sudo: a password is required` 失败。已提前拦截,没有打扰你审批。',
    nextStep:
      '在服务器上以 root 执行一次 bootstrap.txt(只需一次,之后不再需要动):\n' +
      '  1) 本机: Get-Content <凭据目录>\\bootstrap.txt | Set-Clipboard\n' +
      '  2) 服务器: ssh ubuntu@<ip> 然后 sudo -i,粘贴执行\n' +
      '详见 README「一次性部署」。',
  };
}

/** 只把风险结论回传给模型(不含内部字段),便于它在对话里如实转述。 */
function riskPayload(risk) {
  if (!risk) return null;
  return {
    level: risk.level,
    levelLabel: risk.levelLabel,
    summary: risk.summary,
    categories: risk.categories,
    mandatoryCategories: risk.mandatoryCategories,
    destructive: risk.destructive,
    download: risk.download,
    privileged: risk.privileged,
    findings: risk.findings.map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })),
    rollback: risk.rollback,
    requiresAck: risk.requiresAck,
    requiresTypedPhrase: risk.requiresTypedPhrase,
  };
}

/**
 * 把闸门的结局翻译成 MCP 工具结果。
 *
 * 关键约定:**拒绝、超时、并发冲突、执行失败都不算"成功"**(isError: true),
 * 这样模型不会把"没执行"当成"执行了"继续往下推理。
 */
function respondOutcome(outcome, { server, command, displayCommand, sudo, reason, extra = {}, treatNonZeroAsError = false }) {
  const base = {
    server,
    command,
    displayCommand,
    sudo: sudo === true,
    reason,
    status: outcome.status,
    approvalId: outcome.approvalId ?? null,
    approval: outcome.approval ?? null,
    risk: riskPayload(outcome.risk),
    ...extra,
  };

  if (outcome.status === 'pending') {
    return {
      isError: false,
      payload: {
        ...base,
        executed: false,
        nextStep: '用 approval_resume(approvalId) 继续等待同一个请求;不要重复发起。',
      },
    };
  }

  // 对话模式:等待用户在聊天里回话。这一条既不是错误,也不是"已执行"。
  if (outcome.status === 'awaiting-user') {
    return {
      isError: false,
      payload: {
        ...base,
        executed: false,
        expiresAt: outcome.expiresAt ?? null,
        promptForUser: outcome.promptForUser ?? null,
        nextStep:
          '把 promptForUser 原样发给用户,然后**结束本轮**等他回复。' +
          '用户明确同意后:approval_resume({approvalId, decision:"allow", userReply:"<用户原话>"});' +
          '用户拒绝:approval_resume({approvalId, decision:"deny"})。' +
          '不要替用户决定,也不要编造他的回复。',
      },
    };
  }

  if (outcome.status === 'too-fast' || outcome.status === 'needs-user-reply' || outcome.status === 'bad-decision') {
    return {
      isError: true,
      payload: {
        ...base,
        executed: false,
        blocked: true,
        reason: outcome.reason,
        ...(outcome.elapsedMs != null
          ? { elapsedMs: outcome.elapsedMs, minDelayMs: outcome.minDelayMs, remainingMs: outcome.remainingMs ?? null }
          : {}),
      },
    };
  }

  if (outcome.status === 'executed') {
    const r = outcome.result ?? {};
    if (r.ok === false) {
      return {
        isError: true,
        payload: { ...base, executed: false, error: `命令已获批准,但执行失败:${r.error}` },
      };
    }
    return {
      isError: treatNonZeroAsError && (r.timedOut === true || r.code !== 0),
      payload: {
        ...base,
        executed: true,
        exitCode: r.code,
        signal: r.signal ?? null,
        durationMs: r.durationMs,
        timedOut: r.timedOut === true,
        truncated: r.truncated,
        stdout: r.stdout,
        stderr: r.stderr,
        audit: r.audit ?? null,
      },
    };
  }

  if (outcome.status === 'execution-failed') {
    return { isError: true, payload: { ...base, executed: false, error: outcome.error } };
  }

  if (outcome.status === 'busy' || outcome.status === 'unknown') {
    return {
      isError: true,
      payload: { ...base, executed: false, reason: outcome.reason, ...(outcome.busyWith ? { busyWith: outcome.busyWith } : {}) },
    };
  }

  // denied / timeout / disabled
  return {
    isError: true,
    payload: {
      ...base,
      executed: false,
      denied: true,
      reason: outcome.reason ?? '未执行。',
      hint: '这不是错误,而是审批结果:命令一个字都没有执行。若仍需要,请重新发起审批。',
    },
  };
}

/**
 * 统一执行入口:审批通过后真正下发命令。
 *
 * 审计分两次写,与 0.4.0 原有约定一致:
 *   ① outcome=authorized 的"意图"记录 —— 写失败就**不执行**(fail-closed);
 *   ② 执行结果记录 —— 含退出码、耗时,刻意不含输出内容。
 */
async function executeApproved({ rec, command, displayCommand, reason, risk, tool, sudo, timeoutMs, approval }) {
  const startedAt = Date.now();

  const intent = recordApprovedWrite({
    tool,
    server: rec.name,
    host: rec.host,
    user: rec.user,
    command,
    displayCommand,
    reason,
    sudo: sudo === true,
    risk,
    approval,
    outcome: 'authorized',
  });
  if (intent.auditWriteFailed) {
    return { ok: false, error: `无法记录批准操作,已拒绝执行(${intent.auditWriteFailed})` };
  }

  const r = await exec(rec, displayCommand, timeoutMs);

  const audit = recordApprovedWrite({
    tool,
    server: rec.name,
    host: rec.host,
    user: rec.user,
    command,
    displayCommand,
    reason,
    sudo: sudo === true,
    risk,
    approval,
    result: r.ok ? r : null,
    error: r.ok ? null : r.error,
  });

  return {
    ...r,
    durationMs: r.ok ? r.durationMs : Date.now() - startedAt,
    audit: {
      ts: audit.ts,
      outcome: audit.outcome,
      log: auditLogPath(),
      ...(audit.auditWriteFailed ? { writeFailed: audit.auditWriteFailed } : {}),
    },
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
      'read_only_command 只能执行白名单内的只读命令。' +
      '需要 root 权限时用 sudo_exec,删除用 delete_path,从网上下载用 fetch_url —— ' +
      '这四条(含 ssh_exec_approved)都是**两阶段**的:第一次调用不会执行,只返回 awaiting-user 与一份 promptForUser;' +
      '你要把 promptForUser 原样发给用户,然后**结束本轮**等他回复;' +
      '用户明确同意后,再调用 approval_resume(approvalId, decision:"allow", userReply:"<用户原话>") 才真正执行。' +
      '不要替用户决定、不要编造 userReply、也不要把 awaiting-user 说成已执行。' +
      '不确定某条命令有多危险时,先调 review_command 只做审查不执行。',
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
    title: '执行写操作(必须先拿到用户回复)',
    description:
      '对指定服务器执行非只读命令。**第一次调用不会执行**,只返回 awaiting-user 与 promptForUser;' +
      '把 promptForUser 发给用户并结束本轮,用户同意后用 approval_resume 才真正执行。' +
      'approvedByUser 只是"我已经把这事告诉用户了"的声明,真正生效的是用户那句回复。' +
      '即使批准,仍禁止删数据卷、改防火墙、改账户、改计划任务等操作;需要 root 请改用 sudo_exec。',
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
        tool: 'ssh_exec_approved',
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
        tool: 'ssh_exec_approved',
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

    const risk = assessCommand(command, { sudo: false });
    const outcome = await approvalGate().request({
      tool: 'ssh_exec_approved',
      server: rec.name,
      host: rec.host,
      user: rec.user,
      reason,
      command,
      displayCommand: command,
      sudo: false,
      risk,
      execute: ({ approval } = {}) =>
        executeApproved({
          rec,
          command,
          displayCommand: command,
          reason,
          risk,
          tool: 'ssh_exec_approved',
          sudo: false,
          timeoutMs: timeoutMs ?? APPROVED_TIMEOUT_MS,
          approval,
        }),
    });

    const shaped = respondOutcome(outcome, {
      server: rec.name,
      command,
      displayCommand: command,
      sudo: false,
      reason,
      treatNonZeroAsError: true,
    });
    return text(shaped.payload, shaped.isError);
  },
);

/* --- 工具 7:review_command(只审查,不执行) ---------------------------- */
server.registerTool(
  'review_command',
  {
    title: '审查一条命令的风险(不执行)',
    description:
      '只做静态审查,不连接任何服务器、不执行任何东西。返回风险等级、逐条风险点、回滚建议,' +
      '以及该命令会被哪条规则硬拦。在向用户提出写操作之前先用它自查,避免拿一条注定被拒的命令去打扰用户。',
    inputSchema: {
      command: z.string().min(1).max(8192).describe('准备执行的命令原文(不含 sudo 前缀)'),
      sudo: z.boolean().optional().describe('这条命令是否打算以 sudo 执行,默认 false'),
    },
    annotations: { readOnlyHint: true },
  },
  async ({ command, sudo }) => {
    const asSudo = sudo === true;
    const verdict = asSudo ? checkSudoCommand(command) : checkApprovedCommand(command);
    const risk = assessCommand(command, { sudo: asSudo });
    return text({
      command,
      sudo: asSudo,
      wouldBeBlocked: !verdict.ok,
      blockedReason: verdict.ok ? null : verdict.why,
      risk: riskPayload(risk),
      whichChannel: asSudo ? 'sudo_exec' : 'ssh_exec_approved',
      nextStep: verdict.ok
        ? `若确要执行,调用 ${asSudo ? 'sudo_exec' : 'ssh_exec_approved'} —— 它会返回待确认稿,由用户决定。`
        : '这条命令连审批机会都没有(命中硬性禁止)。请换一个不触碰受保护路径/凭据的方案。',
    });
  },
);

/* --- 工具 9:sudo_exec(以 root 执行,必须人工审批) --------------------- */
server.registerTool(
  'sudo_exec',
  {
    title: '以 root 执行命令(每次都必须人工审批)',
    description:
      '用 `sudo -n` 以 root 身份执行一条命令。**两阶段**:第一次调用只返回 awaiting-user 与一份 promptForUser' +
      '(命令原文 + 风险等级 + 逐条风险点 + 回滚建议);把它原样发给用户并结束本轮,用户回复同意后,再调用 ' +
      'approval_resume(approvalId, decision:"allow", userReply:"<用户原话>") 才真正执行。' +
      '你无法代替用户批准:缺少 userReply、或距发起不到最短等待时间都会被拒绝。' +
      '超时(默认 30 分钟)按拒绝关闭。' +
      '系统授权根文件(/etc/passwd、/etc/sudoers、/etc/shadow)与不可逆破坏动作(磁盘、裸写设备)仍然被硬拦。',
    inputSchema: {
      command: z.string().min(1).max(8192).describe('要执行的命令原文(不含 sudo 前缀,工具会自己加)'),
      reason: z.string().min(4).max(500).describe('为什么要以 root 执行它(会展示给用户)'),
      server: SERVER_ARG,
      timeoutMs: z.number().int().min(1000).max(600000).optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
  async ({ command, reason, server: requested, timeoutMs }) => {
    const verdict = checkSudoCommand(command);
    if (!verdict.ok) {
      recordApprovedWrite({
        tool: 'sudo_exec',
        server: requested ?? '(default)',
        host: null,
        user: null,
        command,
        reason,
        sudo: true,
        result: null,
        error: `hard-deny: ${verdict.why}`,
      });
      return text({ executed: false, sudo: true, blocked: true, reason: verdict.why, command }, true);
    }

    const t = target(requested);
    if (t.error) return t.error;
    const rec = t.record;

    // 先探服务器侧是否配好了免密 sudo:没配好就直说,不弹审批页白跑一趟
    const ready = await sudoReadiness(rec);
    if (!ready.ok) return text(sudoNotReadyPayload(rec, ready), true);

    const displayCommand = buildSudoCommand(command);
    const risk = assessCommand(command, { sudo: true });

    const outcome = await approvalGate().request({
      tool: 'sudo_exec',
      server: rec.name,
      host: rec.host,
      user: rec.user,
      reason,
      command,
      displayCommand,
      sudo: true,
      risk,
      execute: ({ approval } = {}) =>
        executeApproved({
          rec,
          command,
          displayCommand,
          reason,
          risk,
          tool: 'sudo_exec',
          sudo: true,
          timeoutMs: timeoutMs ?? SUDO_TIMEOUT_MS,
          approval,
        }),
    });

    const shaped = respondOutcome(outcome, {
      server: rec.name,
      command,
      displayCommand,
      sudo: true,
      reason,
    });
    return text(shaped.payload, shaped.isError);
  },
);

/* --- 工具 10:delete_path(删除,必须人工审批) -------------------------- */
server.registerTool(
  'delete_path',
  {
    title: '删除文件或目录(必须先拿到用户回复)',
    description:
      '删除服务器上一个**确定的绝对路径**。结构化参数(不是 shell 字符串),因此不会出现引号/通配符注入。' +
      '**两阶段**:第一次调用只返回 awaiting-user 与确认稿(删除目标会单独置顶,并列出不可恢复的原因),' +
      '你把它发给用户、结束本轮;用户回复同意后用 approval_resume 才真正删除。' +
      '根目录、系统顶层目录(/etc、/usr、/root、/var … 本身)、受保护路径(账户/凭据/系统配置/MySQL 数据)一律拒绝。' +
      '需要 root 权限才能删的路径(如 /root 下的目录)请把 sudo 设为 true。',
    inputSchema: {
      path: z.string().min(1).max(1024).describe('要删除的绝对路径(确定路径,不含通配符、变量、~)'),
      recursive: z.boolean().optional().describe('目录是否递归删除(rm -r),默认 false'),
      sudo: z.boolean().optional().describe('是否以 root 删除,默认 false'),
      reason: z.string().min(4).max(500).describe('为什么要删它(会展示给用户)'),
      server: SERVER_ARG,
      timeoutMs: z.number().int().min(1000).max(600000).optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
  async ({ path: targetPath, recursive, sudo, reason, server: requested, timeoutMs }) => {
    const pv = checkDeletePath(targetPath);
    if (!pv.ok) {
      recordApprovedWrite({
        tool: 'delete_path',
        server: requested ?? '(default)',
        host: null,
        user: null,
        command: `rm -- ${targetPath}`,
        reason,
        sudo: sudo === true,
        result: null,
        error: `hard-deny: ${pv.why}`,
      });
      return text({ executed: false, path: targetPath, blocked: true, reason: pv.why }, true);
    }

    const rm = `${recursive ? 'rm -rf' : 'rm -f'} -- ${singleQuote(pv.normalized)}`;
    const gv = sudo === true ? checkSudoCommand(rm) : checkApprovedCommand(rm);
    if (!gv.ok) {
      recordApprovedWrite({
        tool: 'delete_path',
        server: requested ?? '(default)',
        host: null,
        user: null,
        command: rm,
        reason,
        sudo: sudo === true,
        result: null,
        error: `hard-deny: ${gv.why}`,
      });
      return text({ executed: false, path: pv.normalized, blocked: true, reason: gv.why }, true);
    }

    const t = target(requested);
    if (t.error) return t.error;
    const rec = t.record;

    if (sudo === true) {
      const ready = await sudoReadiness(rec);
      if (!ready.ok) return text(sudoNotReadyPayload(rec, ready), true);
    }

    const displayCommand = sudo === true ? buildSudoCommand(rm) : rm;
    const risk = assessCommand(rm, {
      sudo: sudo === true,
      extraFindings: [
        {
          id: 'delete-target',
          category: '删除',
          severity: recursive ? 'high' : 'medium',
          title: `删除目标:${pv.normalized}${recursive ? '(递归)' : ''}`,
          detail:
            '删除操作没有回收站:被删的文件不会出现在任何"最近删除"里,' +
            '递归删除还会把整棵目录树一并带走。请确认该路径下没有你还需要的东西。',
        },
      ],
    });

    const outcome = await approvalGate().request({
      tool: 'delete_path',
      server: rec.name,
      host: rec.host,
      user: rec.user,
      reason,
      command: rm,
      displayCommand,
      sudo: sudo === true,
      risk,
      execute: ({ approval } = {}) =>
        executeApproved({
          rec,
          command: rm,
          displayCommand,
          reason,
          risk,
          tool: 'delete_path',
          sudo: sudo === true,
          timeoutMs: timeoutMs ?? APPROVED_TIMEOUT_MS,
          approval,
        }),
    });

    const shaped = respondOutcome(outcome, {
      server: rec.name,
      command: rm,
      displayCommand,
      sudo: sudo === true,
      reason,
      extra: { path: pv.normalized, recursive: recursive === true },
    });
    return text(shaped.payload, shaped.isError);
  },
);

/* --- 工具 11:fetch_url(下载,必须人工审批) ---------------------------- */
server.registerTool(
  'fetch_url',
  {
    title: '从网络下载文件到服务器(必须先拿到用户回复)',
    description:
      '用 curl 把一个 http(s) URL 下载到服务器上的确定路径。**两阶段**:第一次调用只返回 awaiting-user 与确认稿' +
      '(URL、落盘路径、来源协议、非 https/直连 IP/覆盖已有文件等风险点);你把它发给用户、结束本轮,' +
      '用户同意后用 approval_resume 才真正下载。' +
      '这只下载,**绝不执行**下载下来的内容 —— 要运行它必须另外走 sudo_exec 并重新审批。' +
      '下载完成后会回传 sha256 与文件大小,便于核对来源。' +
      'http:// 明文下载会被标为高风险;URL 内嵌凭据(user:pass@)、ftp/file 协议、shell 元字符一律拒绝。',
    inputSchema: {
      url: z.string().min(8).max(2048).describe('要下载的 http/https URL'),
      destPath: z.string().min(1).max(1024).describe('服务器上的落盘绝对路径(会被覆盖,请自行确认)'),
      reason: z.string().min(4).max(500).describe('为什么要下载它(会展示给用户)'),
      sudo: z.boolean().optional().describe('是否以 root 写盘(例如落盘到 /root 下),默认 false'),
      maxTimeSec: z.number().int().min(5).max(1800).optional().describe('下载超时秒数,默认 300'),
      server: SERVER_ARG,
      timeoutMs: z.number().int().min(1000).max(600000).optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
  async ({ url, destPath, reason, sudo, maxTimeSec, server: requested, timeoutMs }) => {
    const uv = checkDownloadUrl(url);
    if (!uv.ok) return text({ executed: false, url, blocked: true, reason: uv.why }, true);

    const dv = checkDownloadTarget(destPath);
    if (!dv.ok) return text({ executed: false, destPath, blocked: true, reason: dv.why }, true);

    const seconds = maxTimeSec ?? 300;
    const curl =
      `curl -fsSL --proto '=https,http' --proto-redir '=https,http'` +
      ` --connect-timeout 20 --max-time ${seconds}` +
      ` -o ${singleQuote(dv.normalized)} ${singleQuote(uv.url)}`;

    const gv = sudo === true ? checkSudoCommand(curl) : checkApprovedCommand(curl);
    if (!gv.ok) {
      return text({ executed: false, url, destPath: dv.normalized, blocked: true, reason: gv.why }, true);
    }

    const t = target(requested);
    if (t.error) return t.error;
    const rec = t.record;

    if (sudo === true) {
      const ready = await sudoReadiness(rec);
      if (!ready.ok) return text(sudoNotReadyPayload(rec, ready), true);
    }

    const displayCommand = sudo === true ? buildSudoCommand(curl) : curl;

    const extraFindings = [
      {
        id: 'download-source',
        category: '下载',
        severity: uv.insecure ? 'high' : 'medium',
        title: `下载来源:${uv.host}${uv.isIp ? '(直连 IP)' : ''}${uv.insecure ? ' 明文 http' : ' https'}`,
        detail: uv.insecure
          ? '明文 http 下载的内容可在链路上被任何人替换 —— 你在服务器上落地的可能不是原作者的文件。'
          : '内容来自外部域名。域名、CDN、发布者账户任何一个环节被攻破,落地内容就不是你以为的那一份。',
      },
      {
        id: 'download-dest',
        category: '下载',
        severity: 'high',
        title: `落盘路径:${dv.normalized}`,
        detail: '若该文件已存在会被直接覆盖且不留备份;请确认覆盖是你要的,或先把原文件改名备份。',
      },
    ];
    if (uv.isIp) {
      extraFindings.push({
        id: 'download-raw-ip',
        category: '下载',
        severity: 'high',
        title: '直连 IP 下载(没有域名证书校验)',
        detail: '直连 IP 时无法通过域名证书确认对方身份,https 也只能证明"对方持有某张证书",不能证明"对方是那家发布者"。',
      });
    }

    const risk = assessCommand(curl, { sudo: sudo === true, extraFindings });

    const outcome = await approvalGate().request({
      tool: 'fetch_url',
      server: rec.name,
      host: rec.host,
      user: rec.user,
      reason,
      command: curl,
      displayCommand,
      sudo: sudo === true,
      risk,
      execute: ({ approval } = {}) =>
        executeApproved({
          rec,
          command: curl,
          displayCommand,
          reason,
          risk,
          tool: 'fetch_url',
          sudo: sudo === true,
          timeoutMs: timeoutMs ?? Math.max(APPROVED_TIMEOUT_MS, (seconds + 60) * 1000),
          approval,
        }),
    });

    const shaped = respondOutcome(outcome, {
      server: rec.name,
      command: curl,
      displayCommand,
      sudo: sudo === true,
      reason,
      extra: { url: uv.url, destPath: dv.normalized },
    });

    // 只有真的下成功才去核对落地结果
    if (outcome.status === 'executed' && outcome.result?.ok && outcome.result.code === 0) {
      const verify = await exec(
        rec,
        `sha256sum -- ${singleQuote(dv.normalized)}; stat -c 'size=%s owner=%U group=%G mode=%a' ${singleQuote(dv.normalized)}`,
        READ_TIMEOUT_MS,
      );
      shaped.payload.verification = verify.ok
        ? { exitCode: verify.code, output: `${verify.stdout}${verify.stderr}`.trim() }
        : { error: verify.error };
      shaped.payload.nextStep =
        '下载完成,内容**尚未执行**。若要运行它,必须另外调用 sudo_exec(或 ssh_exec_approved),' +
        '那会重新弹出审批页面;在那之前请先用 sha256 核对来源。';
    }

    return text(shaped.payload, shaped.isError);
  },
);

/* --- 工具 12:approval_resume ------------------------------------------ */
server.registerTool(
  'approval_resume',
  {
    title: '把用户的回复落实为审批结果',
    description:
      '**对话审批模式(默认)**下:某个工具返回 status="awaiting-user" 后,你应当把 promptForUser 原样发给用户、' +
      '结束本轮等他回复。用户明确同意后,用 decision="allow" 并把 userReply 填成**用户的原话**(逐字,不得编造);' +
      '用户拒绝时 decision="deny"。缺少 userReply、或距发起不到最短等待时间,都会被拒绝 —— ' +
      '因为那说明请求根本没被展示给用户。' +
      '**浏览器审批模式**下:该工具只用于继续等待页面结果,不需要 decision。',
    inputSchema: {
      approvalId: z.string().min(4).max(64).describe('awaiting-user / pending 结果里的 approvalId'),
      decision: z
        .enum(['allow', 'deny'])
        .optional()
        .describe('对话模式:用户同意传 allow,拒绝传 deny。浏览器模式不需要'),
      userReply: z
        .string()
        .min(1)
        .max(2000)
        .optional()
        .describe('用户在对话里同意时的**原话**(逐字)。绝不可编造;缺了会以 needs-user-reply 拒绝'),
      waitMs: z.number().int().min(1000).max(55000).optional().describe('浏览器模式下最多等待毫秒数'),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
  async ({ approvalId, decision, userReply, waitMs }) => {
    const outcome = await approvalGate().resume(approvalId, { decision, userReply, waitMs });
    const shaped = respondOutcome(outcome, {
      server: outcome.server ?? '(unknown)',
      command: outcome.command ?? '',
      displayCommand: outcome.displayCommand ?? '',
      sudo: outcome.sudo === true,
      reason: null,
    });
    return text(shaped.payload, shaped.isError);
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
      limits: {
        readTimeoutMs: READ_TIMEOUT_MS,
        approvedTimeoutMs: APPROVED_TIMEOUT_MS,
        sudoTimeoutMs: SUDO_TIMEOUT_MS,
      },
      approval: {
        ...approvalGate().stats(),
        channels: {
          chat: '对话确认(默认):工具返回确认稿 → 模型告知用户 → 等用户回复 → approval_resume 执行',
          prompt: '浏览器一次性审批页面(人点"允许"才执行)',
          deny: '全部拒绝(无人值守用)',
          allow: '跳过审批(仅供测试,启动时会告警)',
        },
      },
      writeChannels: [
        { tool: 'ssh_exec_approved', requiresApproval: true, sudo: false, note: 'approvedByUser 只是声明,真正生效的是用户回复' },
        { tool: 'sudo_exec', requiresApproval: true, sudo: true, note: '以 root 执行;approvalMode=deny 时必拒' },
        { tool: 'delete_path', requiresApproval: true, sudo: 'optional', note: '结构化删除,不可恢复' },
        { tool: 'fetch_url', requiresApproval: true, sudo: 'optional', note: '只下载不执行;下载后可核对 sha256' },
      ],
      notes: [
        'SSH 密码认证永不使用,仅密钥;私钥位于工作区外,配置文件中不含密钥材料。',
        '每台服务器必须固定主机指纹,否则拒绝连接。',
        '写操作是两阶段的:第一次调用只返回确认稿,用户回复并 approval_resume 后才执行。',
        '对话审批依赖模型如实转述与等待,属于流程约束而非密码学强制;需要更强保证请设 DSH_VPS_APPROVAL_MODE=prompt(浏览器页面)。',
        '批准记录写入失败时不执行(fail-closed)。',
        'SSH 会话以 ops-us 身份建立;sudo_exec 通过 sudo -n 提权,实际能否提权仍由服务器侧 sudoers 决定。',
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
  const settings = approvalSettings();
  log(`启动 v${SERVER_VERSION} | 清单 ${inv.path} | ${inv.servers.size} 台服务器 | default=${inv.defaultName ?? '(未设置)'}`);
  log(`审批模式 ${settings.mode}:请求有效期 ${settings.ttlMs}ms${settings.mode === 'chat' ? `,最短等待 ${settings.minDelayMs}ms` : `,单次等待 ${settings.waitMs}ms`}`);
  if (settings.mode === 'chat') {
    log('对话确认模式:写操作会先返回确认稿,由模型告知你并等你回复;浏览器页面不再打开。');
  } else if (settings.mode === 'prompt') {
    log('浏览器审批模式:写操作会在本机弹出一次性审批页面。');
  } else if (settings.mode === 'allow') {
    log('⚠⚠⚠ 警告:DSH_VPS_APPROVAL_MODE=allow —— 所有写操作都会跳过人工审批直接执行。仅限自动化测试使用。');
  } else if (settings.mode === 'deny') {
    log('审批模式为 deny:所有需要审批的操作都会被拒绝。');
  }
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
