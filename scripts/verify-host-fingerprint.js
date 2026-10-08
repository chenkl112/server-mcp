/** SSH 握手探测,不加载私钥、不进行认证。 */
import { probeHostKey } from '../src/ssh.js';
const [host, rawPort = '22', format] = process.argv.slice(2);
const port = Number(rawPort);
if (!host || /[\s\x00-\x1f]/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
  console.error('用法: node scripts/verify-host-fingerprint.js <host> [port] [--json]');
  process.exit(2);
}
const result = await probeHostKey({ host, port, accepted: [], limits: {} });
if (format === '--json') console.log(JSON.stringify(result));
else console.log(result.observedFingerprint ? `观测指纹: ${result.observedFingerprint}\n公钥: ${result.observedPublicKey}` : `探测失败: ${result.error}`);
process.exitCode = result.observedFingerprint ? 0 : 1;
