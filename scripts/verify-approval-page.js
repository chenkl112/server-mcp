#!/usr/bin/env node
/**
 * 验证"审批页在你机器上真的能弹出来"(**浏览器审批模式专用**)。
 *
 * 默认模式已改为对话确认(chat),它不需要浏览器。本脚本用于在改用
 * `DSH_VPS_APPROVAL_MODE=prompt` 之前,确认这台机器的弹窗链路可用。
 *
 * 为什么要单独验证:审批闸门的所有其它环节都被单测覆盖了(拒绝、超时、伪造令牌、
 * 一次性、并发),唯独"用默认浏览器打开页面"这一步只能在真实桌面上验证 ——
 * 它依赖 Windows 的 `rundll32 url.dll,FileProtocolHandler`,而这个调用可能被
 * 组策略、默认程序关联或安全软件拦住。一旦它失败,闸门会按 fail-closed 拒绝
 * 所有写操作,表现就是"工具永远返回 denied",很难自己看出原因。
 *
 * 用法:
 *   node scripts/verify-approval-page.js                 # 弹窗,等你点(最多 120 秒)
 *   node scripts/verify-approval-page.js --auto-deny 15  # 弹窗后 15 秒自动拒绝(无人值守自检)
 *
 * 判定:
 *   页面被打开过 → PASS(说明浏览器链路通)
 *   页面从未被请求 → FAIL(说明默认浏览器调用没生效,按提示排查)
 *
 * 注意:这个脚本**没有**写操作能力,它只在本地起一个页面并立即拒绝,不连接任何服务器。
 */
import { createApprovalGate } from '../src/approval.js';
import { assessCommand } from '../src/risk.js';

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? Number(process.argv[i + 1]) : fallback;
}

const autoDenySec = arg('--auto-deny', 0);
const humanTimeoutSec = arg('--timeout', 120);

const gate = createApprovalGate({
  mode: 'prompt',
  ttlMs: Math.max(autoDenySec || humanTimeoutSec, 30) * 1000 + 5000,
  waitMs: 60000,
});

const command = 'systemctl restart demo-service';
const risk = assessCommand(command, { sudo: true });

console.log('=== 审批页自检 ===\n');
console.log('即将打开一个一次性的审批页面(只在本机 127.0.0.1,内容是一条演示命令)。');
console.log(autoDenySec
  ? `页面打开后 ${autoDenySec} 秒会自动拒绝,便于无人值守验证。\n`
  : `请在页面上点"允许"或"拒绝"(最多等 ${humanTimeoutSec} 秒)。\n`);

let started = false;
const job = {
  tool: 'verify_page',
  server: 'local-selftest',
  host: '127.0.0.1',
  user: 'nobody',
  reason: '自检:验证审批页能否在你机器上弹出(不会执行任何东西)',
  command,
  displayCommand: `sudo -n ${command}`,
  sudo: true,
  risk,
  execute: async () => {
    started = true;
    return { ok: true, code: 0, stdout: 'selftest-would-run', stderr: '', durationMs: 0, truncated: false };
  },
};

if (autoDenySec > 0) {
  // 用定时器在 autoDenySec 后自己去 POST 一次拒绝,模拟用户点"拒绝"
  setTimeout(async () => {
    const stats = gate.stats();
    if (!stats.port) return;
    // 页面 token 只在闸门内部;这里通过 resume 之外的公开路径拿不到,
    // 所以改用"关闭闸门"来收尾 —— 语义同样是拒绝,并且能拿到页面加载统计。
    gate.close();
  }, autoDenySec * 1000).unref?.();
}

const outcome = await gate.request(job);
const stats = gate.stats();

const pageOpened = (stats.pageLoads ?? 0) > 0;

console.log(`审批结果: ${outcome.status}`);
console.log(`页面加载次数: ${stats.pageLoads}`);
console.log(`演示命令是否被执行: ${started ? '是(说明有人点了"允许执行")' : '否'}`);
console.log('');

if (pageOpened) {
  console.log('✅ PASS —— 审批页确实被打开过,浏览器链路可用。');
  if (started) {
    console.log('   而且这次走完了"点允许 + 勾选风险确认 → 执行"的完整链路。');
  } else {
    console.log('   页面打开了但没人点(或点了拒绝),命令没有执行 —— 正是预期。');
  }
  process.exit(0);
}

console.log('❌ FAIL —— 审批页从未被请求,说明默认浏览器没能打开它。');
console.log('');
console.log('排查顺序:');
console.log('  1) 直接看终端上方是否打印了 "请在浏览器中手动打开: http://127.0.0.1:..."');
console.log('  2) 检查 .html 是否被关联到某个程序:  控制面板 → 默认应用 → 按文件类型');
console.log('  3) 组策略/安全软件是否拦截了 rundll32 url.dll,FileProtocolHandler');
console.log('  4) 临时用 DSH_VPS_APPROVAL_MODE=deny 关闭写通道,避免它在无法弹窗时反复拒绝');
process.exit(1);
