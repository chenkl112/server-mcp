import { parseDocument, isSeq } from 'yaml';
import { createServerConfig, PROJECT } from './client-config.js';

export { PROJECT };
export function configureProfile(source = '[]\n', { enabled = false, inventory } = {}) {
  const doc = parseDocument(source);
  if (doc.errors.length || !isSeq(doc.contents)) throw new Error('DSH profile 必须是合法的 YAML 顶层数组');
  const matches = doc.contents.items.filter(item => item?.get?.('id') === 'mcp-vps-ops');
  if (matches.length > 1) throw new Error('mcp-vps-ops 重复,请先合并重复条目');
  let item = matches[0];
  if (!item) {
    item = doc.createNode({ id: 'mcp-vps-ops', name: '@deepseek-ai/dsh-mcp-client', enabled });
    doc.contents.add(item);
  }
  item.set('name', '@deepseek-ai/dsh-mcp-client');
  item.set('enabled', enabled);
  const previous = item.get('config')?.toJSON?.() ?? {};
  const server = createServerConfig({ inventory });
  const env = { ...previous.env, ...server.env };
  delete env.DSH_VPS_SSH_KEY;
  delete env.DSH_VPS_SSH_KEY_PASSPHRASE;
  item.set('config', doc.createNode({ ...previous, ...server, serverName: 'vps', transport: 'stdio', env, toolCallTimeoutMs: 620000, failOnStartupError: false, reconnect: { enabled: true, maxAttempts: 3 } }));
  return doc.toString();
}
