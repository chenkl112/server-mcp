/**
 * Codex CLI 的 MCP 配置合并(纯函数,无依赖,可单测)。
 *
 * 为什么单独写:Codex 用 TOML(`~/.codex/config.toml`),而项目原有的
 * `configure-mcp.js` 只生成通用 stdio JSON。手写 TOML 时最容易出的问题是
 * `[mcp_servers.vps.env]` 与 `[mcp_servers.vps]` 的先后顺序,以及 Windows 路径里的
 * 反斜杠没转义 —— 两种都会表现为"配了但连不上"。
 *
 * 设计取舍:
 *   * **不改用户的其他配置**:只动 `mcp_servers.<name>` 和 `mcp_servers.<name>.env` 两张表,
 *     表里我们不认识的键原样保留(用户可能有自己的扩展键)。
 *   * **看不懂就拒绝**:如果目标表里出现跨行数组、内联表等无法安全重写的形态,
 *     直接报错让用户手工改,而不是猜测后写坏主配置文件。
 *   * 输出可重复:同样的输入跑两次,第二次 changed=false。
 */

/** 由本工具托管的键;其余键原样保留。 */
const MANAGED_KEYS = ['command', 'args', 'enabled', 'startup_timeout_sec', 'tool_timeout_sec'];
const MANAGED_ENV = ['DSH_VPS_INVENTORY', 'DSH_VPS_ALLOW_TOFU'];

const HEADER = /^\s*\[([^\[\]]+)\]\s*(?:#.*)?$/;
const KEY_LINE = /^\s*([A-Za-z0-9_"'.-]+)\s*=\s*(.+)$/;

function detectEol(text) {
  return text.includes('\r\n') ? '\r\n' : '\n';
}

/** TOML 基本字符串:Windows 路径必须把反斜杠写成 `\\`。 */
function tomlString(value) {
  return JSON.stringify(String(value));
}

function tomlStringArray(values) {
  return `[${values.map(tomlString).join(', ')}]`;
}

/**
 * 判断一行是否是"自包含"的键值行。
 *
 * 跨行数组(`args = [` 后跟多行)会让"逐行重写"变成猜测,所以这里检查
 * 引号、方括号、花括号在行内是否配平;不配平就由调用方拒绝重写。
 */
function isSelfContainedValue(rawValue) {
  const value = rawValue.replace(/#.*$/, '').trim();
  let quote = null;
  let depth = 0;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (quote) {
      if (ch === '\\' && quote === '"') { i += 1; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '[' || ch === '{') depth += 1;
    else if (ch === ']' || ch === '}') depth -= 1;
  }
  return quote === null && depth === 0;
}

/** 把文本切成"段落":每段是一个表头 + 它的正文。 */
function splitSections(lines) {
  const sections = [];
  let current = { name: null, start: 0, lines: [] };
  lines.forEach((line, index) => {
    const m = HEADER.exec(line);
    if (m) {
      sections.push({ ...current, end: index });
      current = { name: m[1].trim(), start: index, lines: [line] };
    } else {
      current.lines.push(line);
    }
  });
  sections.push({ ...current, end: lines.length });
  return sections;
}

/** 从段落正文里收集 `key = value` 行(按 key 去重,后出现的覆盖先出现的)。 */
function collectKeys(sectionLines) {
  const out = new Map();
  for (const line of sectionLines.slice(1)) {
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const m = KEY_LINE.exec(line);
    if (!m) throw new Error(`无法安全重写的行: ${line.trim()}`);
    if (!isSelfContainedValue(m[2])) throw new Error(`存在跨行值,拒绝重写: ${line.trim()}`);
    out.set(m[1].replace(/^["']|["']$/g, ''), m[2].trim());
  }
  return out;
}

/**
 * 生成/更新 Codex 配置文本。
 *
 * @param {string} source 现有 config.toml 内容(可为空字符串)
 * @param {object} options
 * @param {string} [options.name] 服务器名,默认 `vps`
 * @param {string} options.command node 可执行文件绝对路径
 * @param {string[]} options.args
 * @param {Record<string,string>} [options.env]
 * @param {number} [options.toolTimeoutSec] 必须大于审批等待时长(默认 45 秒)
 * @param {number} [options.startupTimeoutSec]
 * @returns {{ text: string, changed: boolean, notes: string[] }}
 */
export function upsertCodexMcp(source, options) {
  const {
    name = 'vps',
    command,
    args,
    env = {},
    toolTimeoutSec = 620,
    startupTimeoutSec = 20,
  } = options;

  if (!command) throw new Error('缺少 command');
  if (!Array.isArray(args) || args.length === 0) throw new Error('缺少 args');

  const eol = detectEol(source);
  const lines = source.length ? source.split(/\r?\n/) : [];

  // 内联表写法 `mcp_servers.vps = { ... }` 无法安全合并
  if (lines.some((l) => new RegExp(`^\\s*mcp_servers\\s*\\.\\s*${name}\\s*=`).test(l))) {
    throw new Error(`配置里用了内联表 mcp_servers.${name} = {...},无法安全合并,请手工改成 [mcp_servers.${name}] 形式`);
  }

  const sections = splitSections(lines);
  const mainName = `mcp_servers.${name}`;
  const envName = `mcp_servers.${name}.env`;

  const mainSection = sections.find((s) => s.name === mainName);
  const envSection = sections.find((s) => s.name === envName);

  const existingMain = mainSection ? collectKeys(mainSection.lines) : new Map();
  const existingEnv = envSection ? collectKeys(envSection.lines) : new Map();

  const notes = [];

  // 目标值
  const wantedMain = new Map([
    ['command', tomlString(command)],
    ['args', tomlStringArray(args)],
    ['enabled', 'true'],
    ['startup_timeout_sec', String(startupTimeoutSec)],
    ['tool_timeout_sec', String(toolTimeoutSec)],
  ]);
  const wantedEnv = new Map([
    ['DSH_VPS_INVENTORY', tomlString(env.DSH_VPS_INVENTORY ?? '')],
    ['DSH_VPS_ALLOW_TOFU', tomlString(env.DSH_VPS_ALLOW_TOFU ?? '0')],
  ]);

  const changedKeys = [];
  for (const [k, v] of wantedMain) {
    if (existingMain.get(k) !== v) changedKeys.push(`${mainName}.${k}`);
  }
  for (const [k, v] of wantedEnv) {
    if (existingEnv.get(k) !== v) changedKeys.push(`${envName}.${k}`);
  }

  function render(sectionName, existing, wanted) {
    const body = [`[${sectionName}]`];
    // 托管键按固定顺序放前面,便于人工核对
    for (const [k, v] of wanted) body.push(`${k} = ${v}`);
    for (const [k, v] of existing) {
      if (wanted.has(k)) continue;
      body.push(`${k} = ${v}`);
    }
    return body;
  }

  const mainBlock = render(mainName, existingMain, wantedMain);
  const envBlock = render(envName, existingEnv, wantedEnv);

  // 重建:按原顺序替换命中的段,其余原样保留
  const out = [];
  const placed = new Set();
  for (const section of sections) {
    const isTarget = section.name === mainName || section.name === envName;
    if (!isTarget) {
      out.push(...(section.name === null ? section.lines : section.lines));
      continue;
    }
    const block = section.name === mainName ? mainBlock : envBlock;
    if (placed.has(section.name)) {
      notes.push(`重复的 [${section.name}] 已合并为一份`);
      continue;
    }
    placed.add(section.name);
    out.push(...block);
  }

  // 缺失的表追加到末尾(TOML 表顺序不影响语义)
  const append = [];
  if (!placed.has(mainName)) { placed.add(mainName); append.push(...mainBlock); }
  if (!placed.has(envName)) { placed.add(envName); append.push(...envBlock); }
  if (append.length) {
    while (out.length && out[out.length - 1].trim() === '') out.pop();
    out.push(...append);
    notes.push(`已追加 [${mainName}] / [${envName}]`);
  }

  let text = out.join(eol);
  if (!text.endsWith(eol)) text += eol;

  return { text, changed: text !== source, changedKeys, notes };
}

/** 生成给用户看的 TOML 片段(不落盘时用)。 */
export function renderCodexSnippet(options) {
  const { name = 'vps', command, args, env = {}, toolTimeoutSec = 620, startupTimeoutSec = 20 } = options;
  return [
    `[mcp_servers.${name}]`,
    `command = ${tomlString(command)}`,
    `args = ${tomlStringArray(args)}`,
    'enabled = true',
    `startup_timeout_sec = ${startupTimeoutSec}`,
    `# 必须大于审批等待时长(默认 45 秒),否则人工点"允许"的过程中会被客户端掐断`,
    `tool_timeout_sec = ${toolTimeoutSec}`,
    '',
    `[mcp_servers.${name}.env]`,
    `DSH_VPS_INVENTORY = ${tomlString(env.DSH_VPS_INVENTORY ?? '')}`,
    `DSH_VPS_ALLOW_TOFU = ${tomlString(env.DSH_VPS_ALLOW_TOFU ?? '0')}`,
    `# 不要设 DSH_VPS_APPROVAL_MODE:默认 prompt 才是"每次必问"`,
    '',
  ].join('\n');
}

export const CODEX_MANAGED_KEYS = { MANAGED_KEYS, MANAGED_ENV };
