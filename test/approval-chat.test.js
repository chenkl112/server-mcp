/**
 * 对话审批模式(chat)的测试。
 *
 * 这个模式比浏览器模式弱:服务端无法验证"用户真的回复过",只能验证
 * "模型带来了用户原话"且"没有在同一轮里立刻批准"。所以测试要守住的是
 * 那几条**能挡住自动批准**的规则,而不是"流程看起来对":
 *   * 第一次调用绝不执行;
 *   * 不带 decision 的 resume 不改变状态;
 *   * 不带 userReply 的 allow 被拒;
 *   * 距发起过短的 allow 被拒(模型没等用户);
 *   * 用户拒绝后一定不执行;
 *   * 超时按拒绝关闭。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { createApprovalGate, buildChatPrompt } from '../src/approval.js';
import { assessCommand } from '../src/risk.js';

function makeJob(command, { sudo = false, tool = 'sudo_exec' } = {}) {
  let calls = 0;
  const job = {
    tool,
    server: 'test-vps',
    host: '198.51.100.7',
    user: 'ops-us',
    reason: '单测:对话确认',
    command,
    displayCommand: sudo ? `sudo -n ${command}` : command,
    sudo,
    risk: assessCommand(command, { sudo }),
    execute: async () => {
      calls += 1;
      return { ok: true, code: 0, signal: null, stdout: 'ran', stderr: '', durationMs: 1, truncated: false };
    },
  };
  return { job, calls: () => calls };
}

function chatGate(overrides = {}) {
  return createApprovalGate({
    mode: 'chat',
    ttlMs: 15000,
    waitMs: 2000,
    minDelayMs: 0,
    ...overrides,
  });
}

test('第一次调用只返回确认稿,绝不执行', async () => {
  const gate = chatGate();
  const { job, calls } = makeJob('systemctl restart docker', { sudo: true });

  const outcome = await gate.request(job);
  assert.equal(outcome.status, 'awaiting-user');
  assert.ok(outcome.approvalId, '必须给出 approvalId');
  assert.equal(calls(), 0, '第一次调用不能执行');
  assert.equal(outcome.executed, undefined);

  // 确认稿要包含命令原文与风险信息,否则模型无从转述
  assert.match(outcome.promptForUser, /systemctl restart docker/);
  assert.match(outcome.promptForUser, /风险等级/);
  assert.match(outcome.promptForUser, /回滚/);
  assert.ok(outcome.risk.findings.length > 0);

  gate.close();
});

test('不带 decision 的 resume 只回报状态,不做决定', async () => {
  const gate = chatGate();
  const { job, calls } = makeJob('systemctl restart docker');
  const first = await gate.request(job);

  const again = await gate.resume(first.approvalId, {});
  assert.equal(again.status, 'awaiting-user');
  assert.equal(calls(), 0);

  gate.close();
});

test('缺 userReply 的 allow 被拒绝(避免"模型自己决定")', async () => {
  const gate = chatGate();
  const { job, calls } = makeJob('systemctl restart docker');
  const first = await gate.request(job);

  const res = await gate.resume(first.approvalId, { decision: 'allow' });
  assert.equal(res.status, 'needs-user-reply');
  assert.equal(calls(), 0, '没有用户原话就不能执行');

  gate.close();
});

test('距发起过短的 allow 被拒绝(模型没等用户)', async () => {
  const gate = chatGate({ minDelayMs: 60000 });
  const { job, calls } = makeJob('systemctl restart docker');
  const first = await gate.request(job);

  const res = await gate.resume(first.approvalId, { decision: 'allow', userReply: '允许执行' });
  assert.equal(res.status, 'too-fast');
  assert.equal(calls(), 0);
  assert.ok(res.minDelayMs >= 60000);

  gate.close();
});

test('用户回复后允许:执行一次,并记下原话', async () => {
  const gate = chatGate({ minDelayMs: 0 });
  const { job, calls } = makeJob('systemctl restart docker', { sudo: true });
  const first = await gate.request(job);

  const res = await gate.resume(first.approvalId, { decision: 'allow', userReply: '允许执行,记得先看日志' });
  assert.equal(res.status, 'executed');
  assert.equal(calls(), 1);
  assert.equal(res.approval.source, 'chat');
  assert.equal(res.approval.userReply, '允许执行,记得先看日志');
  assert.equal(res.result.stdout, 'ran');

  // 再次 resume 不会重复执行
  const again = await gate.resume(first.approvalId, { decision: 'allow', userReply: '允许执行' });
  assert.equal(again.status, 'executed');
  assert.equal(calls(), 1, 'resume 不能导致重复执行');

  gate.close();
});

test('用户拒绝:一个字都不执行', async () => {
  const gate = chatGate();
  const { job, calls } = makeJob('rm -rf /opt/old');
  const first = await gate.request(job);

  const res = await gate.resume(first.approvalId, { decision: 'deny' });
  assert.equal(res.status, 'denied');
  assert.equal(calls(), 0);

  gate.close();
});

test('非法 decision 被拒绝', async () => {
  const gate = chatGate();
  const { job, calls } = makeJob('systemctl restart docker');
  const first = await gate.request(job);

  const res = await gate.resume(first.approvalId, { decision: 'maybe' });
  assert.equal(res.status, 'bad-decision');
  assert.equal(calls(), 0);

  gate.close();
});

test('超时未回复按拒绝关闭', async () => {
  const gate = chatGate({ ttlMs: 120, minDelayMs: 0 });
  const { job, calls } = makeJob('systemctl restart docker');
  const first = await gate.request(job);
  assert.equal(first.status, 'awaiting-user');

  await new Promise((r) => setTimeout(r, 250));

  const res = await gate.resume(first.approvalId, { decision: 'allow', userReply: '允许执行' });
  assert.equal(res.status, 'timeout');
  assert.equal(calls(), 0, '超时后不能再被批准');

  gate.close();
});

test('同一时刻只允许一个待确认请求', async () => {
  const gate = chatGate();
  const a = makeJob('systemctl restart docker');
  const first = await gate.request(a.job);
  assert.equal(first.status, 'awaiting-user');

  const b = makeJob('systemctl restart nginx');
  const second = await gate.request(b.job);
  assert.equal(second.status, 'busy');
  assert.equal(b.calls(), 0);

  gate.close();
});

test('未知 approvalId 给出明确答复,不执行', async () => {
  const gate = chatGate();
  const res = await gate.resume('deadbeef', { decision: 'allow', userReply: '允许' });
  assert.equal(res.status, 'unknown');
  gate.close();
});

test('确认稿包含目标、账户、sudo 标记与每条风险点', () => {
  const { job } = makeJob('rm -rf /root/old-app', { sudo: true, tool: 'delete_path' });
  const record = {
    id: 'abc123',
    job,
    expiresAt: new Date(Date.now() + 60000),
  };
  const text = buildChatPrompt(record);

  assert.match(text, /需要你确认:delete_path/);
  assert.match(text, /`test-vps`/);
  assert.match(text, /sudo \/ root/);
  assert.match(text, /```bash/);
  assert.match(text, /sudo -n rm -rf \/root\/old-app/);
  assert.match(text, /请求编号 `abc123`/);
  // 高危命令要能看出"需要明确同意"的氛围:至少列出回滚建议
  assert.match(text, /回滚/);
});

test('对话模式不启动本地 HTTP 服务', async () => {
  const gate = chatGate();
  const { job } = makeJob('systemctl restart docker');
  await gate.request(job);
  assert.equal(gate.stats().port, null, 'chat 模式不应监听端口');
  gate.close();
});
