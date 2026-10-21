import ssh2 from 'ssh2';

/**
 * 生成"整段粘贴到服务器 root 会话"的引导命令。
 *
 * @param {string} script    server-setup.sh 的内容(会逐字节 base64 内嵌)
 * @param {string} publicKey 运维公钥;只取 algorithm + base64 两段,注释不参与
 * @param {object} [opts]
 * @param {boolean} [opts.sudo]      运输层:用 sudo -n 执行(借用有 sudo 的管理员账户)
 * @param {boolean} [opts.fullSudo]  目标态:给 ops-us 完整 sudo(透传给 server-setup.sh)
 */
export function buildBootstrap(script, publicKey, { sudo = false, fullSudo = false } = {}) {
  const fields = String(publicKey).trim().split(/\s+/);
  const key = `${fields[0]} ${fields[1]}`;
  if (ssh2.utils.parseKey(key) instanceof Error) throw new Error('公钥无法解析');
  const b64 = Buffer.from(script.replace(/\r\n/g, '\n').replace(/^\uFEFF/, '')).toString('base64');
  // 只有经过校验的算法名、base64 块和固定字面量进入 shell 命令。
  const fullSudoArg = fullSudo ? ' --full-sudo' : '';
  return `set -euo pipefail\nprintf '%s' '${b64}' | base64 -d | ${sudo ? 'sudo -n ' : ''}bash -s -- '${key} dsh-vps-ops'${fullSudoArg}\n`;
}
