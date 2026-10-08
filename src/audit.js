/**
 * 写操作审计日志。
 *
 * 为什么需要:批准通道是唯一能改变服务器状态的入口。没有留痕的"批准"等于没有追责依据。
 *
 * 设计取舍:
 *   * 记录**命令原文、目标、结果、退出码、耗时** —— 也就是"做了什么、成没成"。
 *   * **刻意不记录 stdout/stderr** —— 输出里可能带令牌、连接串等敏感内容,审计日志不该变成泄密源。
 *   * 追加写 JSON Lines,一行一条,便于 grep 与程序化统计。
 *   * 单条命令原文超长时截断(默认 2000 字符),避免日志被单条命令撑爆。
 *
 * 日志位置:server-mcp/audit/approved-writes.jsonl(可用 DSH_VPS_AUDIT_LOG 覆盖)
 */
import { appendFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_LOG = resolve(HERE, '..', 'audit', 'approved-writes.jsonl');
const COMMAND_CAP = 2000;

export function auditLogPath() {
  return process.env.DSH_VPS_AUDIT_LOG || DEFAULT_LOG;
}

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

/**
 * 记录一次写操作。返回写入的条目;失败不抛错(审计失败不该让运维动作本身失败),
 * 但会把失败原因一并放进文件与返回值,便于事后发现。
 */
export function recordApprovedWrite({ server, host, user, command, reason, result, error, outcome }) {
  const cmd = String(command ?? '');
  const entry = {
    ts: new Date().toISOString(),
    kind: 'approved-write',
    server,
    host,
    loginUser: user,
    command: cmd.length > COMMAND_CAP ? `${cmd.slice(0, COMMAND_CAP)}…[truncated]` : cmd,
    commandSha256: sha256(cmd),
    commandBytes: Buffer.byteLength(cmd),
    reason,
    outcome: outcome ?? (error ? 'error' : result?.timedOut ? 'timeout' : 'executed'),
    exitCode: result?.code ?? null,
    signal: result?.signal ?? null,
    durationMs: result?.durationMs ?? null,
    stdoutBytes: result?.stdout ? Buffer.byteLength(result.stdout) : 0,
    stderrBytes: result?.stderr ? Buffer.byteLength(result.stderr) : 0,
    outputTruncated: result?.truncated ?? null,
    error: error ? String(error).slice(0, 500) : null,
  };

  const path = auditLogPath();
  try {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    entry.auditWriteFailed = String(err.message);
  }
  return entry;
}

/**
 * 记录一次只读命令。
 *
 * 为什么只读也要留痕:红队审查指出"只读通道不进审计"是反向盲区 ——
 * 该通道允许读 /etc/**、docker inspect、各类日志,是凭据最容易流出的地方,
 * 也是事后排查"AI 到底看过什么"的唯一依据。这里只记元数据,不记输出内容
 * (与写操作同一条纪律:输出可能含令牌、连接串)。
 */
export function recordReadCommand({ server, host, user, command, result, error, blockedReason }) {
  const cmd = String(command ?? '');
  const entry = {
    ts: new Date().toISOString(),
    kind: 'read-command',
    server,
    host,
    loginUser: user,
    command: cmd.length > COMMAND_CAP ? `${cmd.slice(0, COMMAND_CAP)}…[truncated]` : cmd,
    commandSha256: sha256(cmd),
    outcome: blockedReason ? 'blocked' : error ? 'error' : result?.timedOut ? 'timeout' : 'executed',
    blockedReason: blockedReason ? String(blockedReason).slice(0, 300) : null,
    exitCode: result?.code ?? null,
    durationMs: result?.durationMs ?? null,
    stdoutBytes: result?.stdout ? Buffer.byteLength(result.stdout) : 0,
    stderrBytes: result?.stderr ? Buffer.byteLength(result.stderr) : 0,
    outputTruncated: result?.truncated ?? null,
    error: error ? String(error).slice(0, 300) : null,
  };

  const path = auditLogPath();
  try {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    entry.auditWriteFailed = String(err.message);
  }
  return entry;
}

/** 读取最近 n 条(倒序返回,最新在前)。 */
export function readAudit({ limit = 50, server, kind } = {}) {
  const path = auditLogPath();
  if (!existsSync(path)) {
    return { path, exists: false, total: 0, matched: 0, entries: [] };
  }
  const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
  const parsed = [];
  let malformed = 0;
  for (const line of lines) {
    try {
      parsed.push(JSON.parse(line));
    } catch {
      malformed += 1;
    }
  }
  const filtered = parsed.filter((e) => {
    if (server && e.server !== server) return false;
    if (kind && e.kind !== kind) return false;
    return true;
  });
  const capped = Math.min(Math.max(Number(limit) || 50, 1), 500);
  return {
    path,
    exists: true,
    total: parsed.length,
    malformedLines: malformed || undefined,
    matched: filtered.length,
    entries: filtered.slice(-capped).reverse(),
  };
}

/** 汇总:谁在什么时候对哪台机器做了什么(不含命令原文)。 */
export function summarizeAudit() {
  const { path, exists, total, entries } = readAudit({ limit: 500 });
  if (!exists) return { path, exists: false, total: 0 };
  const byServer = {};
  const byOutcome = {};
  for (const e of entries) {
    byServer[e.server] = (byServer[e.server] ?? 0) + 1;
    byOutcome[e.outcome] = (byOutcome[e.outcome] ?? 0) + 1;
  }
  return {
    path,
    exists: true,
    total,
    scanned: entries.length,
    byServer,
    byOutcome,
    latest: entries[0]?.ts ?? null,
  };
}
