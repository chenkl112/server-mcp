#!/usr/bin/env node
/**
 * 把 VPS 运维 MCP 写进 Codex CLI 的配置(`~/.codex/config.toml`)。
 *
 * 为什么需要:Codex 用 TOML,而 `configure-mcp.js` 只生成通用 stdio JSON。
 * 手写 TOML 有两个常见坑:Windows 路径的反斜杠必须写成 `\\`,
 * 以及 `[mcp_servers.vps.env]` 必须单独成表。任一处写错都表现为"配了但连不上"。
 *
 * 用法:
 *   node scripts/configure-codex.js                  # 只检查并打印片段,不落盘
 *   node scripts/configure-codex.js --write          # 合并写回(自动备份)
 *   node scripts/configure-codex.js --write --force  # 已存在且不一致时也覆盖
 *   node scripts/configure-codex.js --config <path>  # 指定配置文件
 *   node scripts/configure-codex.js --tools-approval-mode <auto|prompt|writes|approve>
 *   node scripts/configure-codex.js --approval-mode <chat|prompt|deny>
 *
 * 关于 default_tools_approval_mode:必须让 Codex 放行本服务器的工具(默认 approve),
 * 否则 Codex 会按 destructiveHint 先拦掉写工具,请求根本到不了本服务端。
 * 合法值由 Codex 自己的 serde 校验给出。
 *
 * 关于 --approval-mode:不传就不写 `DSH_VPS_APPROVAL_MODE`,即用服务端默认(chat 对话确认)。
 * 传 prompt 则改用浏览器一次性页面 —— 令牌模型无法伪造,是更强的保证。
 *
 * 退出码: 0 已一致或写入成功; 2 需要人工处理(存在冲突)
 */
import { readFileSync, writeFileSync, existsSync, copyFileSync, mkdirSync, renameSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { upsertCodexMcp, renderCodexSnippet } from '../src/codex-config.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT = resolve(HERE, '..');

const args = process.argv.slice(2);
const has = (flag) => args.includes(flag);
function value(flag, fallback) {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

const NAME = value('--name', 'vps');
const CONFIG = resolve(
  value('--config', join(process.env.CODEX_HOME || join(homedir(), '.codex'), 'config.toml')),
);
const INVENTORY = resolve(value('--inventory', process.env.DSH_VPS_INVENTORY || join(PROJECT, 'servers.json')));

const options = {
  name: NAME,
  command: process.execPath,
  args: [join(PROJECT, 'src', 'index.js')],
  env: { DSH_VPS_INVENTORY: INVENTORY, DSH_VPS_ALLOW_TOFU: '0' },
  toolTimeoutSec: Number(value('--tool-timeout-sec', 620)),
  startupTimeoutSec: 20,
  toolsApprovalMode: value('--tools-approval-mode', 'approve'),
  // 只有显式给出 --approval-mode 才写进配置;不传则保持服务端默认(chat)
  approvalMode: value('--approval-mode', null),
};

console.log('=== Codex MCP 配置 ===\n');
console.log(`配置文件: ${CONFIG}${existsSync(CONFIG) ? '' : ' (不存在,将新建)'}`);
console.log(`服务器名: ${NAME}`);
console.log(`入口:     ${options.args[0]}`);
console.log(`清单:     ${INVENTORY}`);
console.log('');

if (!existsSync(INVENTORY)) {
  console.error(`✗ 找不到清单 ${INVENTORY}`);
  console.error('  先运行部署脚本生成 servers.json,或用 --inventory 指定。');
  process.exit(2);
}

const source = existsSync(CONFIG) ? readFileSync(CONFIG, 'utf8') : '';

let result;
try {
  result = upsertCodexMcp(source, options);
} catch (err) {
  console.error(`✗ 无法安全合并: ${err.message}`);
  process.exit(2);
}

if (!result.changed) {
  console.log('✓ 配置已经是目标状态,无需修改。');
  console.log('');
  console.log('提示:若 Codex 里看不到这个服务器,检查是否被 [mcp_servers] 之外的设置覆盖。');
  process.exit(0);
}

console.log('目标片段:');
console.log('');
process.stdout.write(renderCodexSnippet(options));
console.log('');

if (result.changedKeys?.length) {
  console.log('将变更的字段:');
  for (const k of result.changedKeys) console.log(`  - ${k}`);
  console.log('');
}

if (!has('--write')) {
  console.log('（未写入。确认无误后加 --write 落盘,会自动备份原文件。）');
  process.exit(0);
}

if (existsSync(CONFIG)) {
  const backup = `${CONFIG}.bak-vps-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  copyFileSync(CONFIG, backup);
  console.log(`已备份: ${backup}`);
} else {
  mkdirSync(dirname(CONFIG), { recursive: true });
}

const temp = `${CONFIG}.tmp-${process.pid}`;
writeFileSync(temp, result.text, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
renameSync(temp, CONFIG);

console.log(`✓ 已写入 ${CONFIG}`);
console.log('');
console.log('接着做:');
console.log(`  codex mcp list            # 应能看到 ${NAME} 且 status=enabled`);
console.log('  node scripts/verify-approval-page.js   # 确认审批弹窗在这台机器上能打开');
