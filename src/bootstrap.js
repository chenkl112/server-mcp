import ssh2 from 'ssh2';

export function buildBootstrap(script, publicKey, { sudo = false } = {}) {
  const fields = String(publicKey).trim().split(/\s+/);
  const key = `${fields[0]} ${fields[1]}`;
  if (ssh2.utils.parseKey(key) instanceof Error) throw new Error('公钥无法解析');
  const b64 = Buffer.from(script.replace(/\r\n/g, '\n').replace(/^\uFEFF/, '')).toString('base64');
  // Only a validated algorithm and base64 blob enter the shell command.
  return `set -euo pipefail\nprintf '%s' '${b64}' | base64 -d | ${sudo ? 'sudo -n ' : ''}bash -s -- '${key} dsh-vps-ops'\n`;
}
