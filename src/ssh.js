/**
 * SSH 连接层:密钥认证、逐服务器主机指纹固定校验、输出限流、超时上限。
 *
 * 凭据取自 inventory 记录(其字节来自工作区外的密钥文件),绝不写入 DSH 配置。
 * 连接前用 ssh2 的 parseKey 预校验私钥,避免"连上去才报密钥错误"的模糊失败。
 */
import ssh2 from 'ssh2';
import { StringDecoder } from 'node:string_decoder';
import { readFileSync, statSync } from 'node:fs';
import { fingerprintSha256 } from './hostkey.js';

// ssh2 是 CommonJS 包,ESM 下只有 default 导出可用,具名导出不存在
const { Client, utils } = ssh2;

const ABSOLUTE_LIMITS = {
  hardTimeoutMs: 600000,
  connectTimeoutMs: 60000,
  maxOutputBytes: 4 * 1024 * 1024,
};

export { fingerprintSha256 };

function clampInt(raw, def, min, max) {
  const n = Number.parseInt(raw ?? '', 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(n, min), max);
}

/** 读取并校验一台服务器的私钥,返回 { privateKey } 或 { problem }。 */
export function loadPrivateKey(keyPath, passphrase) {
  let buf;
  try {
    const st = statSync(keyPath);
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
      return { problem: `私钥权限过宽(${(st.mode & 0o777).toString(8)}),请执行 chmod 600 ${keyPath}` };
    }
    if (st.size > 64 * 1024) return { problem: '私钥文件异常大,已拒绝加载' };
    buf = readFileSync(keyPath);
  } catch (err) {
    return { problem: `无法读取私钥(${keyPath}): ${err.message}` };
  }

  try {
    const parsed = utils.parseKey(buf, passphrase);
    if (parsed instanceof Error) {
      const needsPass = /passphrase|encrypted/i.test(parsed.message);
      return {
        problem: needsPass
          ? `私钥已加密但口令缺失或错误(在清单里设置 passphrase,或用带口令的 key)`
          : `私钥无法解析:${parsed.message}`,
      };
    }
    return { privateKey: buf, keyType: parsed.type, keyComment: parsed.comment };
  } catch (err) {
    return { problem: `私钥解析异常:${err.message}` };
  }
}

/** 单台服务器的主机密钥校验:只认它自己固定的指纹。 */
export function verifyHostKeyFor(record, keyBytes, algoHint) {
  const fingerprint = fingerprintSha256(keyBytes);
  for (const pin of record.accepted) {
    if (pin.algo && algoHint && pin.algo !== algoHint) continue;
    if (pin.fp === fingerprint) return { ok: true, fingerprint, reason: 'matched-pinned-fingerprint' };
  }
  return {
    ok: false,
    fingerprint,
    reason: record.accepted.length
      ? `主机密钥与 [${record.name}] 固定的指纹不匹配,可能遭到中间人攻击,已拒绝连接`
      : `[${record.name}] 未固定主机指纹,已拒绝连接(请先用 host_key 工具探测并填入清单)`,
  };
}

/**
 * 探测主机指纹(不做认证)。返回观测到的指纹,便于用户核对后写入清单。
 * 无论校验是否通过,都在 payload 里带上 observedFingerprint。
 */
export function probeHostKey(record, { timeoutMs } = {}) {
  const timeout = clampInt(timeoutMs ?? record.limits?.connectTimeoutMs, 15000, 1000, ABSOLUTE_LIMITS.connectTimeoutMs);
  return new Promise((resolve) => {
    const conn = new Client();
    let observed = null;
    let verifyReason = null;
    let observedPublicKey = null;
    let settled = false;

    const finish = (payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { conn.end(); } catch { /* noop */ }
      resolve({ ...payload, observedPublicKey });
    };

    const timer = setTimeout(
      () => finish({ ok: false, observedFingerprint: observed, verifyReason, error: 'connection-timeout', timeoutMs: timeout }),
      timeout + 500,
    );

    conn.on('ready', () => finish({ ok: true, observedFingerprint: observed, verifyReason }));
    conn.on('error', (err) =>
      finish({ ok: false, observedFingerprint: observed, verifyReason, error: err.message, level: err.level }),
    );

    try {
      conn.connect({
        host: record.host,
        port: record.port,
        username: 'probe-only',
        readyTimeout: timeout,
        hostVerifier: (keyBytes) => {
          observed = fingerprintSha256(keyBytes);
          const len = keyBytes.readUInt32BE(0);
          const algo = keyBytes.subarray(4, 4 + len).toString('ascii');
          observedPublicKey = `${algo} ${keyBytes.toString('base64')}`;
          const verdict = verifyHostKeyFor(record, keyBytes, null);
          verifyReason = verdict.reason;
          return false; // 探测阶段绝不建立认证
        },
      });
    } catch (err) {
      finish({ ok: false, error: err.message });
    }
  });
}

/**
 * 在指定服务器上执行一条命令。
 * 返回 { code, signal, stdout, stderr, truncated, durationMs, timedOut }。
 */
export function runCommand(record, command, { timeoutMs = 30000 } = {}) {
  const hard = record.limits?.hardTimeoutMs ?? 120000;
  const maxBytes = record.limits?.maxOutputBytes ?? 262144;
  const connectTimeout = record.limits?.connectTimeoutMs ?? 15000;
  const effectiveTimeout = Math.min(clampInt(timeoutMs, 30000, 1000, hard), hard);

  return new Promise((resolve, reject) => {
    const conn = new Client();
    const started = Date.now();
    const stdout = boundedOutput(maxBytes);
    const stderr = boundedOutput(maxBytes);
    let truncated = false;
    let settled = false;

    const done = (fn, payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { conn.end(); } catch { /* noop */ }
      fn(payload);
    };

    const finishResult = (extra = {}) =>
      done(resolve, {
        code: null,
        signal: null,
        stdout: stdout.text(),
        stderr: stderr.text(),
        truncated,
        durationMs: Date.now() - started,
        timedOut: false,
        ...extra,
      });

    const timer = setTimeout(() => {
      done(resolve, {
        code: null,
        signal: null,
        stdout: stdout.text(),
        stderr: stderr.text(),
        truncated,
        durationMs: Date.now() - started,
        timedOut: true,
      });
    }, effectiveTimeout);

    conn.on('ready', () => {
      conn.exec(command, { env: { LC_ALL: 'C' } }, (err, stream) => {
        if (err) return done(reject, err);
        stream.on('data', (chunk) => { truncated = stdout.add(chunk) || truncated; });
        stream.stderr.on('data', (chunk) => { truncated = stderr.add(chunk) || truncated; });
        stream.on('error', (err) => done(reject, err));
        stream.on('close', (code, signal) =>
          finishResult({ code: signal ? null : code, signal: signal ?? null }),
        );
      });
    });

    conn.on('error', (err) => {
      const friendly = /Host denied|Cannot continue|verification failed/i.test(err.message)
        ? new Error(`[${record.name}] 主机密钥校验未通过,已中止连接(可能遭到中间人攻击)`)
        : err;
      done(reject, friendly);
    });
    conn.on('close', () => {
      if (!settled) done(reject, new Error('SSH connection closed before command completion'));
    });

    try {
      conn.connect({
        host: record.host,
        port: record.port,
        username: record.user,
        privateKey: record.privateKey,
        passphrase: record.passphrase,
        readyTimeout: connectTimeout,
        keepaliveInterval: 10000,
        hostVerifier: (keyBytes) => verifyHostKeyFor(record, keyBytes, null).ok,
      });
    } catch (err) {
      done(reject, err);
    }
  });
}

// 保留字节再解码,兼容 UTF-8 chunk 边界,舍弃截断处的不完整字符。
function boundedOutput(max) {
  const chunks = [];
  let size = 0;
  return {
    add(chunk) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const count = Math.min(bytes.length, max - size);
      if (count) chunks.push(Buffer.from(bytes.subarray(0, count)));
      size += count;
      return count < bytes.length;
    },
    text() {
      const decoder = new StringDecoder('utf8');
      const decoded = decoder.write(Buffer.concat(chunks, size));
      // 非法 UTF-8 的替换字符也纳入输出字节预算。
      return new StringDecoder('utf8').write(Buffer.from(decoded).subarray(0, max));
    },
  };
}
