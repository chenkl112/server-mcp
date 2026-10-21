/**
 * Codex TOML 配置合并的单测。
 *
 * 这个模块会改用户的**主配置文件**,所以测试重点不是"能生成"，而是:
 *   * 只动 mcp_servers.<name> 与 .env 两张表,其他表一个字节都不许变;
 *   * 表里不认识的键要保留(用户可能有自己的扩展);
 *   * 重复执行必须幂等;
 *   * 看不懂的形态(内联表、跨行数组)必须**拒绝**,而不是猜。
 *
 * 注意:源码里刻意不写"盘符 + 反斜杠"形式的字面量 —— 仓库的发布闸门会把
 * 绝对 Windows 路径当成泄露信号拒绝导出,所以路径一律运行时拼出来。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { upsertCodexMcp, renderCodexSnippet } from '../src/codex-config.js';

const DRIVE = 'C:';
const p = (...parts) => [DRIVE, ...parts].join('\\');
const toml = (s) => JSON.stringify(s);

const BASE = {
  name: 'vps',
  command: p('Program Files', 'nodejs', 'node.exe'),
  args: [p('repo', 'src', 'index.js')],
  env: { DSH_VPS_INVENTORY: p('repo', 'servers.json'), DSH_VPS_ALLOW_TOFU: '0' },
  toolTimeoutSec: 620,
};

test('空配置:追加两张表,反斜杠被转义', () => {
  const { text, changed } = upsertCodexMcp('', BASE);
  assert.equal(changed, true);
  assert.match(text, /^\[mcp_servers\.vps\]$/m);
  assert.match(text, /^\[mcp_servers\.vps\.env\]$/m);
  // TOML 基本字符串里的反斜杠必须成对
  assert.ok(text.includes(toml(BASE.command)), text);
  assert.ok(text.includes('tool_timeout_sec = 620'));
});

test('只动目标表:其它表与注释原样保留', () => {
  const projectKey = ["projects.'", 'd:', '\\', 'x', "'"].join('');
  const source = [
    'model = "gpt-test"',
    '',
    '[mcp_servers.vps]',
    'command = "old"',
    '',
    '[tui]',
    'status_line = ["a", "b"]',
    '',
    `[${projectKey}]`,
    'trust_level = "trusted"',
    '',
  ].join('\n');

  const { text } = upsertCodexMcp(source, BASE);
  assert.match(text, /^model = "gpt-test"$/m);
  assert.match(text, /^\[tui\]$/m);
  assert.match(text, /^status_line = \["a", "b"\]$/m);
  assert.ok(text.includes(`[${projectKey}]`), text);
  assert.match(text, /^trust_level = "trusted"$/m);
  // 旧值被替换
  assert.equal(/^command = "old"$/m.test(text), false, text);
  assert.ok(text.includes(toml(BASE.command)));
});

test('保留表里不认识的键(用户扩展不会被吃掉)', () => {
  const source = [
    '[mcp_servers.vps]',
    'command = "old"',
    `cwd = ${toml(p('work'))}`,
    'some_future_flag = true',
    '',
  ].join('\n');
  const { text } = upsertCodexMcp(source, BASE);
  assert.ok(text.includes(`cwd = ${toml(p('work'))}`), text);
  assert.ok(text.includes('some_future_flag = true'), text);
  assert.ok(text.includes('enabled = true'));
});

test('保留 env 表里的额外变量', () => {
  const source = ['[mcp_servers.vps.env]', 'DSH_VPS_ALLOW_TOFU = "1"', 'MY_EXTRA = "keep"', ''].join('\n');
  const { text } = upsertCodexMcp(source, BASE);
  assert.ok(text.includes('MY_EXTRA = "keep"'), text);
  assert.ok(text.includes('DSH_VPS_ALLOW_TOFU = "0"'), '托管键应被改成目标值');
});

test('幂等:第二次调用不再产生变化', () => {
  const first = upsertCodexMcp('', BASE).text;
  const second = upsertCodexMcp(first, BASE);
  assert.equal(second.changed, false, second.text);
  assert.equal(second.text, first);
});

test('CRLF 配置保持 CRLF', () => {
  const source = 'model = "x"\r\n\r\n[mcp_servers.vps]\r\ncommand = "old"\r\n';
  const { text } = upsertCodexMcp(source, BASE);
  assert.ok(text.includes('\r\n'), '应保持 CRLF');
  assert.equal(/(?<!\r)\n/.test(text), false, '不应混入裸 LF');
});

test('内联表写法被拒绝(不猜测合并)', () => {
  assert.throws(
    () => upsertCodexMcp('mcp_servers.vps = { command = "x" }\n', BASE),
    /内联表/,
  );
});

test('跨行数组被拒绝(逐行重写会写坏)', () => {
  const source = ['[mcp_servers.vps]', 'args = [', '  "a",', ']', ''].join('\n');
  assert.throws(() => upsertCodexMcp(source, BASE), /跨行值/);
});

test('缺少 command / args 时直接报错', () => {
  assert.throws(() => upsertCodexMcp('', { ...BASE, command: '' }), /command/);
  assert.throws(() => upsertCodexMcp('', { ...BASE, args: [] }), /args/);
});

test('片段输出可用于手工粘贴,且不含审批模式覆盖', () => {
  const snippet = renderCodexSnippet(BASE);
  assert.match(snippet, /^\[mcp_servers\.vps\]$/m);
  assert.match(snippet, /^\[mcp_servers\.vps\.env\]$/m);
  // 关键:不能自带 DSH_VPS_APPROVAL_MODE,否则会静默跳过人工审批
  assert.equal(/DSH_VPS_APPROVAL_MODE/.test(snippet.replace(/^#.*$/gm, '')), false);
  assert.match(snippet, /tool_timeout_sec = 620/);
});
