/**
 * 审批闸门的端到端测试(真跑 HTTP,不打桩协议层)。
 *
 * 这是整套机制里最该被测试的部分:它是否真的"没有人的点击就不执行"。
 * 因此这里不测"函数返回了什么",而是真的起服务、真的发 GET/POST,
 * 再从**结果**验证:执行了 / 没执行。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { createApprovalGate } from '../src/approval.js';
import { assessCommand } from '../src/risk.js';

function makeJob(command, { sudo = true, tool = 'sudo_exec' } = {}) {
  let calls = 0;
  const job = {
    tool,
    server: 'test-vps',
    host: '198.51.100.7',
    user: 'ops-us',
    reason: '单测:验证审批闸门',
    command,
    displayCommand: sudo ? `sudo -n ${command}` : command,
    sudo,
    risk: assessCommand(command, { sudo }),
    execute: async () => {
      calls += 1;
      return { ok: true, code: 0, signal: null, stdout: 'executed-for-real', stderr: '', durationMs: 3, truncated: false };
    },
  };
  return { job, calls: () => calls };
}

function newGate(overrides = {}) {
  const box = { url: null };
  const gate = createApprovalGate({
    mode: 'prompt',
    ttlMs: 15000,
    waitMs: 8000,
    openBrowser: (u) => {
      box.url = u;
    },
    ...overrides,
  });
  return { gate, box };
}

async function waitFor(predicate, timeoutMs = 3000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const v = predicate();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('等待条件超时');
}

async function decide(url, fields) {
  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  });
}

test('用户点"拒绝"时,命令一个字都不会执行', async () => {
  const { gate, box } = newGate();
  const { job, calls } = makeJob('systemctl restart docker');
  const pending = gate.request(job);

  const url = await waitFor(() => box.url);
  const page = await fetch(url);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes('运维命令审批'), '审批页应能打开');
  assert.ok(html.includes('systemctl restart docker'), '审批页必须显示命令原文');
  assert.ok(html.includes('sudo'), '审批页应标明这是 sudo 执行');

  const res = await decide(url, { decision: 'deny' });
  assert.equal(res.status, 200);

  const outcome = await pending;
  assert.equal(outcome.status, 'denied');
  assert.equal(calls(), 0, '拒绝后绝不能执行');
  assert.equal(outcome.approval.source, 'local-ui');
  assert.equal(outcome.approval.pageLoaded, true, '这次 GET 过页面,应记为已加载');

  gate.close();
});

test('没打开过页面就直接 POST 批准:能执行,但审计里留下 pageLoaded=false', async () => {
  // 这不是"正常用户"的路径 —— 真实用户必须先看到页面才有点的按钮。
  // 闸门无法从 POST 本身区分"人点的"与"脚本 POST 的",所以不阻断,
  // 但把"页面从未被加载"记进审批记录,让审计能看出这种形态。
  const { gate, box } = newGate();
  const { job, calls } = makeJob('systemctl restart docker');
  const pending = gate.request(job);

  const url = await waitFor(() => box.url);
  const res = await decide(url, { decision: 'allow', ack: 'on' }); // 注意:全程没有 GET
  assert.equal(res.status, 200);

  const outcome = await pending;
  assert.equal(outcome.status, 'executed');
  assert.equal(calls(), 1);
  assert.equal(outcome.approval.pageLoaded, false, '没有加载页面就必须在记录里体现');
  assert.equal(gate.stats().pageLoads, 0);

  gate.close();
});

test('用户点"允许"后才执行,且只执行一次', async () => {
  const { gate, box } = newGate();
  const { job, calls } = makeJob('journalctl --vacuum-time=3d');
  const pending = gate.request(job);

  const url = await waitFor(() => box.url);

  // ⚠ 该命令含 journalctl --vacuum → 高危,需要勾选确认
  const risk = job.risk;
  assert.equal(risk.requiresAck, true, '该用例本身应要求勾选');

  const res = await decide(url, { decision: 'allow', ack: 'on' });
  assert.equal(res.status, 200);

  const outcome = await pending;
  assert.equal(outcome.status, 'executed');
  assert.equal(outcome.result.stdout, 'executed-for-real');
  assert.equal(calls(), 1);

  // 再 resume 一次:拿到的还是同一个结果,不会二次执行
  const again = await gate.resume(outcome.approvalId, { waitMs: 1000 });
  assert.equal(again.status, 'executed');
  assert.equal(again.result.stdout, 'executed-for-real');
  assert.equal(calls(), 1, 'resume 不能导致重复执行');

  gate.close();
});

test('高危命令:不勾选风险确认,服务端拒绝批准', async () => {
  const { gate, box } = newGate();
  const { job, calls } = makeJob('rm -rf -- /opt/old-app');
  const pending = gate.request(job);

  const url = await waitFor(() => box.url);
  assert.equal(job.risk.level, 'high');
  assert.equal(job.risk.requiresAck, true);

  const bad = await decide(url, { decision: 'allow', ack: 'off' });
  assert.equal(bad.status, 400, '缺勾选必须在服务端被拒(不能只靠浏览器 required)');
  const badHtml = await bad.text();
  assert.ok(badHtml.includes('勾选'), '应提示需要勾选');

  // 仍未落定,补上勾选后可以批准
  const ok = await decide(url, { decision: 'allow', ack: 'on' });
  assert.equal(ok.status, 200);

  const outcome = await pending;
  assert.equal(outcome.status, 'executed');
  assert.equal(calls(), 1);

  gate.close();
});

test('致命命令:必须手输确认短语,输错不执行', async () => {
  const { gate, box } = newGate();
  const { job, calls } = makeJob('reboot');
  const pending = gate.request(job);

  const url = await waitFor(() => box.url);
  assert.equal(job.risk.level, 'critical');
  assert.equal(job.risk.requiresTypedPhrase, '确认执行');

  const wrong = await decide(url, { decision: 'allow', ack: 'on', phrase: '随便写的' });
  assert.equal(wrong.status, 400);

  const ok = await decide(url, { decision: 'allow', ack: 'on', phrase: '确认执行' });
  assert.equal(ok.status, 200);

  const outcome = await pending;
  assert.equal(outcome.status, 'executed');
  assert.equal(calls(), 1);

  gate.close();
});

test('页面里的旧链接提交后立即失效(一次性令牌)', async () => {
  const { gate, box } = newGate();
  const { job } = makeJob('systemctl restart nginx');
  const pending = gate.request(job);

  const url = await waitFor(() => box.url);
  const first = await decide(url, { decision: 'deny' });
  assert.equal(first.status, 200);
  await pending;

  // 同一个 URL 再交一次:令牌已作废,必须拿不到第二次机会
  const second = await decide(url, { decision: 'allow' });
  assert.equal(second.status, 404);

  gate.close();
});

test('伪造/过期令牌拿到 404,不能凭空批准', async () => {
  const { gate, box } = newGate();
  const { job, calls } = makeJob('systemctl restart nginx');
  const pending = gate.request(job);
  const url = await waitFor(() => box.url);

  const forged = url.replace(/\/a\/[^/]+$/, `/a/${'A'.repeat(43)}`);
  const res = await fetch(forged);
  assert.equal(res.status, 404);

  // 收尾:真的拒一次
  await decide(url, { decision: 'deny' });
  const outcome = await pending;
  assert.equal(outcome.status, 'denied');
  assert.equal(calls(), 0);

  gate.close();
});

test('超时未处理按拒绝关闭(fail-closed)', async () => {
  const { gate } = newGate({ ttlMs: 250, waitMs: 4000 });
  const { job, calls } = makeJob('systemctl restart docker');

  const outcome = await gate.request(job);
  assert.equal(outcome.status, 'timeout');
  assert.equal(calls(), 0, '超时绝不能执行');

  gate.close();
});

test('同一时刻只允许一个待审批请求(避免用弹窗淹没用户)', async () => {
  const { gate, box } = newGate();
  const a = makeJob('systemctl restart docker');
  const pendingA = gate.request(a.job);
  const url = await waitFor(() => box.url);

  const b = makeJob('systemctl restart nginx');
  const outcomeB = await gate.request(b.job);
  assert.equal(outcomeB.status, 'busy');
  assert.equal(b.calls(), 0);

  await decide(url, { decision: 'deny' });
  const outcomeA = await pendingA;
  assert.equal(outcomeA.status, 'denied');

  gate.close();
});

test('deny 模式:未弹窗即拒绝(无人值守的默认安全姿态)', async () => {
  let opened = 0;
  const gate = createApprovalGate({ mode: 'deny', openBrowser: () => { opened += 1; } });
  const { job, calls } = makeJob('systemctl restart docker');

  const outcome = await gate.request(job);
  assert.equal(outcome.status, 'denied');
  assert.equal(calls(), 0);
  assert.equal(opened, 0, 'deny 模式不应打开任何页面');

  gate.close();
});

test('关闭闸门时,待审批请求一律按拒绝结算', async () => {
  const { gate, box } = newGate();
  const { job, calls } = makeJob('systemctl restart docker');
  const pending = gate.request(job);
  await waitFor(() => box.url);

  gate.close();
  const outcome = await pending;
  assert.equal(outcome.status, 'denied');
  assert.equal(calls(), 0);
});
