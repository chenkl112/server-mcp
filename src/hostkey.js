/**
 * 主机指纹计算。
 *
 * 这个模块刻意保持极小 —— 只负责"算出指纹"这一件事。
 *
 * 背景(一次红队审查的产物):早期版本这里还有一整套 `verifyHostKey` /
 * `initHostKeys` / `accepted` 状态 + TOFU 逻辑,但**没有任何调用方** ——
 * 真正生效的逐服务器固定校验在 `ssh.js` 的 `verifyHostKeyFor()` 里。
 * 结果是一份"看起来有防御、实际恒返回 false"的死代码;将来有人接上它,
 * 反而会以为 TOFU 生效。已全部删除,避免这种维护陷阱。
 *
 * 指纹算法:对 ssh2 提供的原始主机密钥字节求 SHA-256,输出 OpenSSH 风格的
 * `SHA256:<base64 去填充>`,与 `ssh-keygen -lf` 的输出一致,便于人工核对。
 */
import crypto from 'node:crypto';

export function fingerprintSha256(keyBytes) {
  return 'SHA256:' + crypto.createHash('sha256').update(keyBytes).digest('base64').replace(/=+$/, '');
}
