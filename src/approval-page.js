/**
 * 审批页面渲染(纯字符串拼接,无模板引擎、无前端依赖、无 JavaScript)。
 *
 * 为什么不用 JS:表单的"必须勾选 / 必须输入短语"用 HTML5 的 required 就能实现,
 * 提交到服务端后**服务端还会再校验一遍**(浏览器可被绕过,服务端是唯一可信的一侧)。
 * 没有脚本也让 CSP 能收到最紧:`default-src 'none'; style-src 'unsafe-inline'`。
 */

const LEVEL_COLOR = {
  low: '#15803d',
  medium: '#a16207',
  high: '#c2410c',
  critical: '#b91c1c',
};

const LEVEL_BG = {
  low: '#f0fdf4',
  medium: '#fefce8',
  high: '#fff7ed',
  critical: '#fef2f2',
};

const SEVERITY_LABEL = { low: '低', medium: '中', high: '高', critical: '致命' };

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function hhmmss(date) {
  const d = date instanceof Date ? date : new Date(date);
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function layout(title, body) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Cache-Control" content="no-store">
<title>${esc(title)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px 16px 48px;
    font: 14px/1.65 -apple-system, "Segoe UI", "Microsoft YaHei", Roboto, sans-serif;
    background: #f8fafc; color: #0f172a;
  }
  .wrap { max-width: 820px; margin: 0 auto; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 22px 24px; box-shadow: 0 1px 2px rgba(15,23,42,.04); }
  h1 { font-size: 19px; margin: 0 0 4px; letter-spacing: .2px; }
  .sub { color: #64748b; font-size: 12.5px; margin-bottom: 18px; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12.5px; font-weight: 700; margin-left: 8px; vertical-align: 2px; }
  .kv { display: grid; grid-template-columns: 92px 1fr; gap: 6px 12px; font-size: 13.5px; margin-bottom: 16px; }
  .kv dt { color: #64748b; }
  .kv dd { margin: 0; word-break: break-all; }
  pre {
    margin: 0; padding: 14px 16px; background: #0f172a; color: #e2e8f0; border-radius: 10px;
    font: 13px/1.6 ui-monospace, "Cascadia Mono", Consolas, monospace;
    white-space: pre-wrap; word-break: break-all; border: 1px solid #1e293b;
  }
  .cmdwrap { margin: 0 0 18px; }
  .cmdlabel { font-size: 12.5px; color: #64748b; margin-bottom: 6px; }
  .sect { margin: 0 0 18px; }
  .sect > h2 { font-size: 13px; text-transform: none; color: #334155; margin: 0 0 10px; letter-spacing: .3px; }
  ul { margin: 0; padding-left: 20px; }
  li { margin: 0 0 8px; }
  li b { font-weight: 650; }
  .why { color: #475569; font-size: 13px; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
  .chip { font-size: 12px; padding: 2px 9px; border-radius: 999px; background: #eef2ff; color: #3730a3; font-weight: 600; }
  .chip.must { background: #fee2e2; color: #991b1b; }
  .riskbox { border-radius: 10px; padding: 14px 16px; margin-bottom: 18px; border: 1px solid; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 7px; vertical-align: 1px; }
  form { border-top: 1px dashed #e2e8f0; padding-top: 18px; }
  .gate { background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px; padding: 12px 14px; margin-bottom: 14px; font-size: 13px; }
  .gate label { display: flex; gap: 9px; align-items: flex-start; cursor: pointer; }
  .gate input[type=checkbox] { margin-top: 3px; width: 16px; height: 16px; flex: none; }
  .gate input[type=text] {
    margin-top: 8px; width: 100%; padding: 9px 11px; border: 1px solid #cbd5e1; border-radius: 8px;
    font: 13px ui-monospace, Consolas, monospace;
  }
  .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 6px; }
  button {
    font: inherit; font-weight: 650; padding: 11px 22px; border-radius: 9px; cursor: pointer; border: 1px solid transparent;
  }
  .deny { background: #fff; border-color: #cbd5e1; color: #334155; }
  .deny:hover { background: #f1f5f9; }
  .allow { background: #b91c1c; color: #fff; }
  .allow:hover { background: #991b1b; }
  .allow.low { background: #15803d; }
  .allow.low:hover { background: #166534; }
  .foot { margin-top: 18px; color: #94a3b8; font-size: 12px; }
  .done { text-align: center; padding: 30px 10px; }
  .done .big { font-size: 44px; line-height: 1; margin-bottom: 12px; }
  code { background: #f1f5f9; padding: 1px 5px; border-radius: 4px; font-size: 12.5px; }
</style>
</head>
<body><div class="wrap"><div class="card">${body}</div></div></body>
</html>`;
}

/** 已结束(已批准/已拒绝/已过期)的落地页 */
export function renderDonePage({ decision, command, riskLevel }) {
  const map = {
    allow: { icon: '✅', title: '已批准', text: '该命令正在执行,结果会返回给发起方。' },
    deny: { icon: '⛔', title: '已拒绝', text: '该命令不会被执行的任何一部分。' },
    timeout: { icon: '⌛', title: '已过期', text: '超过有效期未处理,按"拒绝"关闭(fail-closed)。' },
  }[decision] ?? { icon: '•', title: '已处理', text: '' };

  return layout(
    `审批${map.title}`,
    `<div class="done">
      <div class="big">${map.icon}</div>
      <h1>${esc(map.title)}</h1>
      <p class="sub">${esc(map.text)}</p>
      <pre style="text-align:left;margin-top:18px">${esc(command)}</pre>
      <p class="foot">风险等级:${esc(SEVERITY_LABEL[riskLevel] ?? riskLevel ?? '—')} ｜ 本页面已失效,可直接关闭。</p>
    </div>`,
  );
}

/** 校验失败(缺勾选/短语不对)时重新渲染原页面并给出提示 */
export function renderPage({ request, validationError }) {
  const { risk } = request;
  const color = LEVEL_COLOR[risk.level] ?? '#334155';
  const bg = LEVEL_BG[risk.level] ?? '#f8fafc';

  const findings = risk.findings
    .map((f) => {
      const c = LEVEL_COLOR[f.severity] ?? '#64748b';
      return `<li><span class="dot" style="background:${c}"></span><b>${esc(f.title)}</b> ` +
        `<span style="color:${c};font-weight:600;font-size:12px">[${esc(SEVERITY_LABEL[f.severity] ?? f.severity)}]</span>` +
        `<div class="why">${esc(f.detail)}</div></li>`;
    })
    .join('');

  const rollback = risk.rollback.map((r) => `<li>${esc(r)}</li>`).join('');

  const chips = risk.categories
    .map((c) => `<span class="chip${risk.mandatoryCategories.includes(c) ? ' must' : ''}">${esc(c)}</span>`)
    .join('');

  const mandatoryNote = risk.mandatoryCategories.length
    ? `<div style="margin:-4px 0 12px;color:#991b1b;font-size:12.5px;font-weight:650">
         本命令属于强制审查类别:${esc(risk.mandatoryCategories.join('、'))}
       </div>`
    : '';

  const ackBlock = risk.requiresAck
    ? `<label><input type="checkbox" name="ack" value="on" required>
        <span>我已阅读上面的风险与回滚建议,理解这一步可能<strong>不可撤销</strong>。</span></label>`
    : '';

  const phraseBlock = risk.requiresTypedPhrase
    ? `<div style="margin-top:12px">
         <div style="margin-bottom:6px">请输入 <code>${esc(risk.requiresTypedPhrase)}</code> 以确认这是你本人的决定:</div>
         <input type="text" name="phrase" required autocomplete="off" spellcheck="false"
                placeholder="${esc(risk.requiresTypedPhrase)}">
       </div>`
    : '';

  const gate = (ackBlock || phraseBlock)
    ? `<div class="gate">
         ${ackBlock}
         ${phraseBlock}
       </div>`
    : '';

  const error = validationError
    ? `<div style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:9px;padding:10px 14px;margin-bottom:14px;font-size:13px">
         ${esc(validationError)}
       </div>`
    : '';

  const allowClass = risk.level === 'low' || risk.level === 'medium' ? 'allow low' : 'allow';

  const body = `
    <h1>运维命令审批
      <span class="badge" style="background:${bg};color:${color};border:1px solid ${color}33">
        ${esc(risk.levelLabel)}风险
      </span>
    </h1>
    <div class="sub">
      来自 <b>${esc(request.tool)}</b> 的请求 · 请求编号 <code>${esc(request.id)}</code> ·
      有效期至 <b>${esc(hhmmss(request.expiresAt))}</b>
    </div>

    ${error}

    <dl class="kv">
      <dt>目标服务器</dt><dd><b>${esc(request.server)}</b>${request.host ? ` &nbsp;<span style="color:#64748b">${esc(request.host)}</span>` : ''}</dd>
      <dt>登录账户</dt><dd>${esc(request.user || '(未知)')}${request.sudo ? ' &nbsp;→&nbsp; <b style="color:#b91c1c">sudo / root</b>' : ''}</dd>
      ${request.reason ? `<dt>发起原因</dt><dd>${esc(request.reason)}</dd>` : ''}
    </dl>

    <div class="cmdwrap">
      <div class="cmdlabel">将在服务器上执行的命令(原文,未改写)</div>
      <pre>${esc(request.displayCommand ?? request.command)}</pre>
    </div>

    <div class="riskbox" style="background:${bg};border-color:${color}44">
      <div class="chips">${chips}</div>
      ${mandatoryNote}
      <ol style="margin:0;padding-left:20px">${findings}</ol>
    </div>

    <div class="sect">
      <h2>回滚 / 减损建议</h2>
      <ul>${rollback}</ul>
    </div>

    <form method="POST" action="${esc(request.action)}">
      ${gate}
      <div class="actions">
        <button type="submit" class="deny" name="decision" value="deny" formnovalidate>拒绝</button>
        <button type="submit" class="${allowClass}" name="decision" value="allow">允许执行</button>
      </div>
      <div class="foot">
        这是一次性页面,提交后立即失效,批准只对"上面这一条命令原文"有效。
        若你没有发起这次请求,请点"拒绝"并检查 DSH 会话与 MCP 服务器日志。
      </div>
    </form>`;

  return layout('运维命令审批', body);
}

/** 令牌无效 / 请求已被处理 / 服务已关闭 */
export function renderGonePage(reason) {
  return layout(
    '审批链接已失效',
    `<div class="done">
      <div class="big">🔒</div>
      <h1>链接已失效</h1>
      <p class="sub">${esc(reason || '该审批请求不存在、已过期或已被处理。')}</p>
      <p class="foot">如果这是你刚刚打开的页面,请回到 DSH 重新发起请求。</p>
    </div>`,
  );
}
