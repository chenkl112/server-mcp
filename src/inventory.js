/**
 * 多服务器清单(inventory)。
 *
 * 设计:
 *   * 清单是**数据**,不是代码 —— 加一台服务器只改 JSON,无需改 MCP 源码。
 *   * 每台服务器有自己的固定主机指纹、密钥、账户与超时。
 *   * 清单里可以写 ${ENV_VAR},便于把敏感值留在环境里而非文件里。
 *   * 任何未解析的 ${...} 占位符都会让该服务器标为"未就绪",而不是静默用错值连接。
 *
 * 默认路径:项目根目录的 servers.json(可用 DSH_VPS_INVENTORY 覆盖)
 */
import { readFileSync } from 'node:fs';
import { loadPrivateKey } from './ssh.js';
import { resolve, dirname, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_INVENTORY_PATH = resolve(HERE, '..', 'servers.json');

const DEFAULT_LIMITS = {
  connectTimeoutMs: 15000,
  hardTimeoutMs: 120000,
  maxOutputBytes: 262144,
};

function clampInt(raw, def, min, max) {
  const n = Number.parseInt(raw ?? '', 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(n, min), max);
}

/** 展开 ${VAR};未设置的环境变量会原样保留,以便被 detectPlaceholders 抓到。 */
export function expandEnv(value, env = process.env) {
  if (typeof value !== 'string') return value;
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (whole, name) => {
    const v = env[name];
    return v === undefined || v === '' ? whole : v;
  });
}

/** 找出仍未展开的占位符(含用户忘了改的 REPLACE_WITH_*)。 */
export function detectPlaceholders(value) {
  if (typeof value !== 'string') return [];
  const out = [];
  const re = /\$\{[A-Za-z_][A-Za-z0-9_]*\}|REPLACE_WITH_[A-Z_]+/g;
  let m;
  while ((m = re.exec(value)) !== null) out.push(m[0]);
  return out;
}

function fingerprintList(raw) {
  const list = [];
  for (const item of Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(/[,\n]/) : []) {
    const line = String(item).trim();
    if (!line) continue;
    const m = line.match(/^(?:(\S+)\s+)?(SHA256:[A-Za-z0-9+/=_-]+)$/);
    if (m) list.push({ algo: m[1] ?? null, fp: m[2].replace(/=+$/, '') });
  }
  return list;
}

function normalizeEntry(name, raw, { inventoryDir, globalFingerprints, env }) {
  const problems = [];
  const s = raw && typeof raw === 'object' ? raw : {};

  const host = expandEnv(String(s.host ?? '').trim(), env);
  const user = expandEnv(String(s.user ?? 'ops-us').trim(), env);
  const keyRaw = expandEnv(String(s.key ?? '').trim(), env);
  const passRaw = expandEnv(String(s.passphrase ?? ''), env);
  const portRaw = expandEnv(String(s.port ?? '22'), env);
  const port = Number(portRaw);
  const probeProblems = [];
  if (!host || /[\s\x00-\x1f\x7f]/.test(host) || detectPlaceholders(host).length) probeProblems.push('host 无效或含占位符');
  if (!/^\d+$/.test(portRaw) || !Number.isInteger(port) || port < 1 || port > 65535) probeProblems.push('port 必须是 1–65535 的整数');
  problems.push(...probeProblems);
  if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(user)) problems.push('user 无效');

  if (!host) problems.push('缺少 host');
  for (const [field, value] of [['host', host], ['user', user], ['key', keyRaw], ['passphrase', passRaw]]) {
    const ph = detectPlaceholders(value);
    if (ph.length) problems.push(`${field} 仍含未替换的占位符 ${ph.join(', ')}`);
  }

  const keyPath = keyRaw ? (isAbsolute(keyRaw) ? keyRaw : resolve(inventoryDir, keyRaw)) : '';
  if (!keyPath) problems.push('缺少 key(私钥文件路径)');

  let privateKey;
  if (keyPath && problems.length === 0) {
    const loaded = loadPrivateKey(keyPath, passRaw || undefined);
    if (loaded.problem) problems.push(loaded.problem);
    else privateKey = loaded.privateKey;
  }

  const fingerprints = fingerprintList(s.fingerprints);
  const accepted = fingerprints.length ? fingerprints : globalFingerprints;

  if (!accepted.length) {
    problems.push('未固定主机指纹:先用 host_key 工具探测,再把 SHA256:... 填进该服务器的 fingerprints');
  }

  return {
    name,
    host,
    port,
    user,
    keyPath,
    privateKey,
    passphrase: passRaw || undefined,
    accepted,
    note: typeof s.note === 'string' ? s.note : null,
    limits: {
      connectTimeoutMs: clampInt(s.connectTimeoutMs, DEFAULT_LIMITS.connectTimeoutMs, 1000, 60000),
      hardTimeoutMs: clampInt(s.hardTimeoutMs, DEFAULT_LIMITS.hardTimeoutMs, 1000, 600000),
      maxOutputBytes: clampInt(s.maxOutputBytes, DEFAULT_LIMITS.maxOutputBytes, 4096, 4 * 1024 * 1024),
    },
    problems,
    probeProblems,
  };
}

/**
 * 载入清单。返回:
 *   { path, servers: Map<name, record>, list: record[], problems: string[] }
 * record.problems 非空表示这台服务器"未就绪",调用时会返回结构化错误。
 */
export function loadInventory({ path = process.env.DSH_VPS_INVENTORY || DEFAULT_INVENTORY_PATH, env = process.env } = {}) {
  const result = { path, servers: new Map(), list: [], problems: [] };

  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    result.problems.push(`无法读取清单(${path}): ${err.message}`);
    return result;
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    result.problems.push(`清单不是合法 JSON(${path}): ${err.message}`);
    return result;
  }

  const entries = parsed?.servers;
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
    result.problems.push('清单缺少顶层 "servers" 对象');
    return result;
  }

  const globalFingerprints = fingerprintList(env.DSH_VPS_HOST_FINGERPRINTS);
  const inventoryDir = dirname(path);

  for (const [name, raw] of Object.entries(entries)) {
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) {
      result.problems.push(`服务器名 "${name}" 不合法(只允许字母数字下划线连字符,≤32 字符)`);
      continue;
    }
    const record = normalizeEntry(name, raw, { inventoryDir, globalFingerprints, env });
    result.servers.set(name, record);
    result.list.push(record);
  }

  if (!result.servers.size) result.problems.push('清单里没有任何服务器条目');
  if (parsed?.default && !result.servers.has(parsed.default)) {
    result.problems.push(`default 指向不存在的服务器 "${parsed.default}"`);
  }

  result.defaultName =
    (parsed?.default && result.servers.has(parsed.default) ? parsed.default : null) ??
    (result.servers.size === 1 ? result.list[0].name : null);

  return result;
}

/** 供工具层调用:解析目标服务器,或给出可读的失败原因。 */
export function resolveServer(inventory, requested, { probeOnly = false } = {}) {
  const name = requested || inventory.defaultName;
  if (!name) {
    const names = [...inventory.servers.keys()];
    return {
      error:
        names.length > 0
          ? `未指定 server,且清单未设置 default。可选:${names.join(', ')}`
          : `清单里没有可用服务器(${inventory.problems.join(' / ')})`,
    };
  }
  const record = inventory.servers.get(name);
  if (!record) {
    return { error: `未知服务器 "${name}"。可选:${[...inventory.servers.keys()].join(', ') || '(空)'}` };
  }
  const problems = probeOnly ? record.probeProblems : record.problems;
  if (problems.length) {
    return { error: `服务器 "${name}" 尚未就绪:${problems.join(' / ')}` };
  }
  return { record };
}

/** 给工具输出用的安全投影:绝不含私钥字节或口令。 */
export function describeServer(record) {
  return {
    name: record.name,
    host: record.host,
    port: record.port,
    user: record.user,
    keyPath: record.keyPath,
    note: record.note,
    pinnedFingerprints: record.accepted.map((f) => (f.algo ? `${f.algo} ${f.fp}` : f.fp)),
    ready: record.problems.length === 0,
    problems: record.problems,
  };
}
