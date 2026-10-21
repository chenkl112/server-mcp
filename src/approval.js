/**
 * 审批闸门:让"允许执行"这件事必须由**人在浏览器里点一下**,而不是由模型填一个布尔字段。
 *
 * 背景(为什么必须这么做):
 *   README 6.0 节写得很直白 —— 旧写通道的 `approvedByUser: true` 是模型自己填的参数,
 *   被提示注入的 agent 只要把它写成 true 就能执行。那不是技术边界,只是礼貌。
 *   DSH 的 MCP 客户端 `new Client(..., { capabilities: {} })` 不声明 elicitation,
 *   也没有注册任何客户端请求处理器,所以**服务端无法通过 MCP 协议弹窗问用户**。
 *
 * 因此本模块把审批做成带外(out-of-band)的一次性闸门:
 *
 *   1. 工具调用进入这里后**阻塞等待**,同时在 127.0.0.1 上起一次性页面并用默认浏览器打开;
 *   2. 页面展示命令原文、风险等级、逐条风险点与回滚建议;
 *   3. 只有页面提交 `decision=allow` 才执行,提交 `deny`/超时/关窗都按拒绝关闭;
 *   4. 决定与命令**哈希绑定**:页面换成另一条命令不成立(令牌指向具体请求记录);
 *   5. 审批只对那一条命令原文有效,一次性,过期即作废。
 *
 * 失败关闭(fail-closed)是本模块的第一原则:
 *   没有通道、页面打不开、请求超时、令牌不对、并发请求冲突 —— 一律**拒绝**,绝不放行。
 *
 * 诚实的边界(README 会同步写):
 *   能在这台机器上执行任意命令的 agent,理论上可以自己去 POST 这个本地端口。
 *   令牌只出现在浏览器地址栏与进程内存里,不进入模型上下文;端口随机、令牌 256 位、
 *   一次性、5 分钟过期、非法令牌累计 10 次即整体关闭 —— 这抬高了门槛,
 *   但**不是密码学意义上的强制**。真正的硬边界在服务器侧 sudoers。
 */
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { spawn } from 'node:child_process';

import { renderPage, renderDonePage, renderGonePage } from './approval-page.js';

const DEFAULT_TTL_MS = 300000; // 请求最长存活 5 分钟
const DEFAULT_WAIT_MS = 45000; // 单次工具调用最多阻塞 45 秒(DSH 的 MCP 工具调用超时是 60 秒)
const MAX_INVALID_HITS = 10;
const MAX_BODY_BYTES = 64 * 1024;

function log(...args) {
  process.stderr.write(`[dsh-vps-ops] ${args.join(' ')}\n`);
}

function clampInt(raw, def, min, max) {
  const n = Number.parseInt(raw ?? '', 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(n, min), max);
}

/**
 * 当前审批模式。
 *   prompt(默认):浏览器一次性页面,人点"允许"才执行
 *   deny         :完全关闭审批(所有需要审批的操作一律拒绝),适合无人值守
 *   allow        :**仅供自动化测试**,不弹窗直接放行 —— 启动时会大声告警
 */
export function approvalMode(env = process.env) {
  const raw = String(env.DSH_VPS_APPROVAL_MODE ?? 'prompt').trim().toLowerCase();
  if (['deny', 'never', 'off', 'none'].includes(raw)) return 'deny';
  if (['allow', 'auto', 'yolo'].includes(raw)) return 'allow';
  return 'prompt';
}

export function approvalSettings(env = process.env) {
  return {
    mode: approvalMode(env),
    ttlMs: clampInt(env.DSH_VPS_APPROVAL_TTL_MS, DEFAULT_TTL_MS, 5000, 3600000),
    waitMs: clampInt(env.DSH_VPS_APPROVAL_WAIT_MS, DEFAULT_WAIT_MS, 1000, 55000),
  };
}

/** 用默认浏览器打开 URL;失败不抛错(改为只把链接打到 stderr)。 */
function openInBrowser(url) {
  const [cmd, args] =
    process.platform === 'win32'
      ? ['rundll32', ['url.dll,FileProtocolHandler', url]]
      : process.platform === 'darwin'
        ? ['open', [url]]
        : ['xdg-open', [url]];

  try {
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', (err) => {
      log(`⚠ 无法自动打开浏览器(${err.message})。请在浏览器中手动打开: ${url}`);
    });
    child.unref();
    return true;
  } catch (err) {
    log(`⚠ 无法自动打开浏览器(${err.message})。请在浏览器中手动打开: ${url}`);
    return false;
  }
}

function delay(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/**
 * 创建一个审批闸门。
 *
 * @param {object} [opts]
 * @param {'prompt'|'deny'|'allow'} [opts.mode]
 * @param {number} [opts.ttlMs]   请求存活时长
 * @param {number} [opts.waitMs]  单次等待时长
 * @param {(url:string)=>void} [opts.openBrowser] 测试可注入
 */
export function createApprovalGate(opts = {}) {
  const settings = { ...approvalSettings(), ...opts };

  /** @type {Map<string, any>} approvalId → record */
  const records = new Map();
  let httpServer = null;
  let port = null;
  let listenPromise = null;
  let invalidHits = 0;
  let closed = false;
  const counters = { requested: 0, allowed: 0, denied: 0, timedOut: 0, autoAllowed: 0 };

  function pendingRecord() {
    for (const r of records.values()) if (r.status === 'pending') return r;
    return null;
  }

  /* ---------------- HTTP 服务 ---------------- */

  async function ensureServer() {
    if (httpServer) return port;
    if (listenPromise) {
      await listenPromise;
      return port;
    }
    listenPromise = new Promise((resolve, reject) => {
      httpServer = createServer(handleRequest);
      httpServer.on('clientError', (_err, socket) => {
        try { socket.destroy(); } catch { /* noop */ }
      });
      httpServer.once('error', (err) => {
        listenPromise = null;
        reject(err);
      });
      httpServer.listen(0, '127.0.0.1', () => {
        port = httpServer.address().port;
        log(`审批页面服务已就绪: http://127.0.0.1:${port}/ (仅本机可访问)`);
        resolve();
      });
    });
    await listenPromise;
    return port;
  }

  function send(res, status, html) {
    const body = Buffer.from(html, 'utf8');
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store, no-cache, must-revalidate',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    });
    res.end(body);
  }

  function byToken(token) {
    for (const r of records.values()) {
      if (r.status !== 'pending') continue;
      if (r.token && safeEqual(r.token, token)) return r;
    }
    return null;
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          reject(new Error('请求体过大'));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  async function handleRequest(req, res) {
    let url;
    try {
      url = new URL(req.url, 'http://127.0.0.1');
    } catch {
      return send(res, 400, renderGonePage('请求地址不合法。'));
    }

    const m = /^\/a\/([A-Za-z0-9_-]{16,})/.exec(url.pathname);
    if (!m) return send(res, 404, renderGonePage('该审批请求不存在或已被处理。'));

    const token = m[1];
    const record = byToken(token);

    if (!record) {
      invalidHits += 1;
      if (invalidHits >= MAX_INVALID_HITS) {
        log(`⚠ 审批页面连续 ${invalidHits} 次收到无效令牌,已按失败关闭处理并停止审批服务`);
        for (const r of records.values()) {
          if (r.status === 'pending') settle(r, 'deny', { reason: 'invalid-token-flood' });
        }
        closeServer();
      }
      return send(res, 404, renderGonePage('该审批请求不存在、已过期或已被处理。'));
    }

    const action = `/a/${token}`;

    if (req.method === 'GET' || req.method === 'HEAD') {
      return send(
        res,
        200,
        renderPage({
          request: {
            id: record.id,
            tool: record.job.tool,
            server: record.job.server,
            host: record.job.host,
            user: record.job.user,
            reason: record.job.reason,
            command: record.job.command,
            displayCommand: record.job.displayCommand ?? record.job.command,
            sudo: record.job.sudo === true,
            risk: record.job.risk,
            expiresAt: record.expiresAt,
            action,
          },
        }),
      );
    }

    if (req.method !== 'POST') {
      res.setHeader('allow', 'GET, HEAD, POST');
      return send(res, 405, renderGonePage('不支持的请求方法。'));
    }

    let body;
    try {
      body = await readBody(req);
    } catch (err) {
      return send(res, 413, renderGonePage(String(err.message)));
    }

    const form = new URLSearchParams(body);
    const decision = form.get('decision');
    if (decision !== 'allow' && decision !== 'deny') {
      return send(res, 400, renderGonePage('提交内容不合法。'));
    }

    // 服务端二次校验:浏览器端的 required 可以被绕过,这里才是真正的判定
    if (decision === 'allow') {
      const risk = record.job.risk;
      if (risk.requiresAck && form.get('ack') !== 'on') {
        return send(
          res,
          400,
          renderPage({
            request: {
              id: record.id,
              tool: record.job.tool,
              server: record.job.server,
              host: record.job.host,
              user: record.job.user,
              reason: record.job.reason,
              command: record.job.command,
              displayCommand: record.job.displayCommand ?? record.job.command,
              sudo: record.job.sudo === true,
              risk,
              expiresAt: record.expiresAt,
              action,
            },
            validationError: '必须先勾选"我已阅读风险与回滚建议"才能批准。',
          }),
        );
      }
      if (risk.requiresTypedPhrase && String(form.get('phrase') ?? '').trim() !== risk.requiresTypedPhrase) {
        return send(
          res,
          400,
          renderPage({
            request: {
              id: record.id,
              tool: record.job.tool,
              server: record.job.server,
              host: record.job.host,
              user: record.job.user,
              reason: record.job.reason,
              command: record.job.command,
              displayCommand: record.job.displayCommand ?? record.job.command,
              sudo: record.job.sudo === true,
              risk,
              expiresAt: record.expiresAt,
              action,
            },
            validationError: `确认短语不正确,请输入「${risk.requiresTypedPhrase}」。`,
          }),
        );
      }
    }

    settle(record, decision, { source: 'local-ui' });
    return send(res, 200, renderDonePage({
      decision,
      command: record.job.displayCommand ?? record.job.command,
      riskLevel: record.job.risk.level,
    }));
  }

  function closeServer() {
    if (!httpServer) return;
    try { httpServer.close(); } catch { /* noop */ }
    httpServer = null;
    port = null;
    listenPromise = null;
  }

  /* ---------------- 判定与执行 ---------------- */

  /**
   * 落定一次请求:clearTimeout → 记账 → 若批准则执行(且只执行一次)→ resolve。
   * 之后的任何调用只会等待同一个 settled promise。
   */
  function settle(record, status, meta = {}) {
    if (record.status !== 'pending') return;
    record.status = status;
    record.decidedAt = new Date();
    record.source = meta.source ?? 'local-ui';
    if (meta.reason) record.reason = meta.reason;
    clearTimeout(record.timer);
    // 令牌立即失效:页面一旦提交,原链接就不再可用(防止重复提交与回放)
    record.token = null;

    if (status !== 'allow') {
      counters.denied += 1;
      if (status === 'timeout') counters.timedOut += 1;
      record.resolve({ status });
      scheduleCleanup(record);
      return;
    }

    counters.allowed += 1;
    record.executing = true;
    Promise.resolve()
      .then(() =>
        record.job.execute({
          approval: {
            id: record.id,
            source: record.source ?? 'local-ui',
            decidedAt: record.decidedAt ? record.decidedAt.toISOString() : null,
            waitedMs: record.decidedAt ? record.decidedAt - record.createdAt : null,
          },
        }),
      )
      .then((result) => {
        record.executed = true;
        record.result = result;
        record.resolve({ status: 'allow', executed: true, result });
      })
      .catch((err) => {
        record.executed = true;
        record.error = String(err?.message ?? err);
        log(`审批通过但执行失败: ${record.error}`);
        record.resolve({ status: 'allow', executed: false, error: record.error });
      })
      .finally(() => {
        record.executing = false;
        scheduleCleanup(record);
      });
  }

  function scheduleCleanup(record) {
    const t = setTimeout(() => records.delete(record.id), 600000);
    if (typeof t.unref === 'function') t.unref();
  }

  function outcomeOf(record) {
    return {
      approvalId: record.id,
      server: record.job.server,
      host: record.job.host,
      user: record.job.user,
      command: record.job.command,
      sudo: record.job.sudo === true,
      approval: {
        id: record.id,
        tool: record.job.tool,
        source: record.source ?? null,
        requestedAt: record.createdAt.toISOString(),
        decidedAt: record.decidedAt ? record.decidedAt.toISOString() : null,
        waitedMs: record.decidedAt ? record.decidedAt - record.createdAt : null,
      },
      risk: record.job.risk,
      displayCommand: record.job.displayCommand ?? record.job.command,
    };
  }

  /** 等到决定(或执行完成),最多 waitMs。 */
  async function awaitOutcome(record, waitMs) {
    const raced = await Promise.race([
      record.settled.then((v) => ({ settled: true, value: v })),
      delay(Math.max(1, waitMs)).then(() => ({ settled: false })),
    ]);

    if (raced.settled) {
      const value = raced.value;
      if (value.status === 'allow') {
        if (value.executed) {
          return { ...outcomeOf(record), status: 'executed', result: value.result };
        }
        return { ...outcomeOf(record), status: 'execution-failed', error: value.error };
      }
      if (value.status === 'timeout') {
        return {
          ...outcomeOf(record),
          status: 'timeout',
          reason: '审批页面在有效期内没有被处理,按拒绝关闭(fail-closed)。',
        };
      }
      return {
        ...outcomeOf(record),
        status: 'denied',
        reason: record.reason === 'invalid-token-flood'
          ? '审批通道因异常请求被关闭(fail-closed)。'
          : '用户拒绝了这条命令。',
      };
    }

    // 还没等到结果
    if (record.status === 'allow') {
      return {
        ...outcomeOf(record),
        status: 'pending',
        phase: 'executing',
        message: '用户已批准,命令正在执行,请用 approval_resume 获取结果。',
      };
    }
    return {
      ...outcomeOf(record),
      status: 'pending',
      phase: 'awaiting-user',
      expiresAt: record.expiresAt.toISOString(),
      message:
        '审批页面已打开,但用户还没点"允许"。请用 approval_resume(approvalId) 继续等待;' +
        '不要重复发起同一请求。',
    };
  }

  /* ---------------- 对外接口 ---------------- */

  /**
   * 发起一次审批。
   *
   * @param {object} job
   * @param {string} job.tool 工具名(展示用)
   * @param {string} job.server
   * @param {string} [job.host]
   * @param {string} [job.user]
   * @param {string} [job.reason]
   * @param {string} job.command 命令原文(不含 sudo 前缀)
   * @param {string} [job.displayCommand] 真正下发的完整命令(含 sudo 前缀等)
   * @param {boolean} [job.sudo]
   * @param {object} job.risk assessCommand() 的结果
   * @param {() => Promise<any>} job.execute 批准后执行的函数;只会在批准时被调用一次
   */
  async function request(job) {
    if (closed) return { status: 'disabled', reason: '审批闸门已关闭。' };

    if (settings.mode === 'deny') {
      return {
        status: 'denied',
        reason:
          '审批已被禁用(DSH_VPS_APPROVAL_MODE=deny)。该操作默认拒绝;' +
          '如果确实需要执行,请把审批模式改为 prompt 后重启 MCP。',
        risk: job.risk,
      };
    }

    if (settings.mode === 'allow') {
      counters.requested += 1;
      counters.autoAllowed += 1;
      log(`⚠ DSH_VPS_APPROVAL_MODE=allow:跳过人工审批直接执行「${job.displayCommand ?? job.command}」`);
      try {
        const result = await job.execute();
        return {
          approvalId: null,
          status: 'executed',
          result,
          risk: job.risk,
          displayCommand: job.displayCommand ?? job.command,
          approval: { id: null, tool: job.tool, source: 'env-auto-allow', decidedAt: new Date().toISOString(), waitedMs: 0 },
        };
      } catch (err) {
        return { status: 'execution-failed', error: String(err?.message ?? err), risk: job.risk };
      }
    }

    const busy = pendingRecord();
    if (busy) {
      return {
        status: 'busy',
        busyWith: busy.id,
        reason:
          '已有一个审批请求在等待用户处理。为避免用多个弹窗淹没用户,同一时刻只允许一个待审批请求;' +
          '请先用 approval_resume(approvalId) 处理先前那条。',
      };
    }

    counters.requested += 1;
    const id = randomBytes(6).toString('hex');
    const token = randomBytes(32).toString('base64url');

    let settleResolved;
    const settled = new Promise((resolve) => { settleResolved = resolve; });

    const record = {
      id,
      token,
      job,
      createdAt: new Date(),
      decidedAt: null,
      expiresAt: new Date(Date.now() + settings.ttlMs),
      status: 'pending',
      result: null,
      executed: false,
      executing: false,
      resolve: settleResolved,
      settled,
    };
    records.set(id, record);

    record.timer = setTimeout(() => settle(record, 'timeout', { source: 'timeout' }), settings.ttlMs);
    if (typeof record.timer.unref === 'function') record.timer.unref();

    try {
      await ensureServer();
      const url = `http://127.0.0.1:${port}/a/${token}`;
      log(
        `审批请求 ${id} 已发起:${job.tool} → ${job.server}` +
          ` ｜ ${job.risk.levelLabel}风险 ｜ ${job.risk.findings.length} 条风险点`,
      );
      (opts.openBrowser ?? openInBrowser)(url);
    } catch (err) {
      // 起不了页面就是不安全,按拒绝关闭
      log(`✗ 审批页面无法启动(${err.message}),按拒绝关闭`);
      settle(record, 'deny', { source: 'no-channel', reason: 'no-channel' });
    }

    return awaitOutcome(record, settings.waitMs);
  }

  /** 继续等待一条已发起的请求(结果已定时立即返回)。 */
  async function resume(approvalId, { waitMs } = {}) {
    const record = records.get(String(approvalId ?? ''));
    if (!record) {
      return {
        status: 'unknown',
        approvalId: String(approvalId ?? ''),
        reason: '没有这条审批请求,或它早已结束并被清理。请不要重复发起,直接重新走审批。',
      };
    }
    return awaitOutcome(record, waitMs ?? settings.waitMs);
  }

  function stats() {
    return {
      mode: settings.mode,
      ttlMs: settings.ttlMs,
      waitMs: settings.waitMs,
      port,
      pending: [...records.values()].filter((r) => r.status === 'pending').length,
      counters: { ...counters },
    };
  }

  function close() {
    closed = true;
    for (const r of records.values()) {
      if (r.status === 'pending') settle(r, 'deny', { reason: 'gate-closed' });
    }
    closeServer();
  }

  return { request, resume, stats, close, settings };
}

/** 进程级单例:所有工具共用同一个闸门(因此"同时只有一个待审批请求") */
let singleton = null;
export function approvalGate(opts) {
  if (!singleton) singleton = createApprovalGate(opts);
  return singleton;
}
