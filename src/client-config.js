import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Generate paths for the installed clone; do not ship one machine's configuration.
export function createServerConfig({ inventory = process.env.DSH_VPS_INVENTORY || join(PROJECT, 'servers.json') } = {}) {
  return {
    command: process.execPath,
    args: [join(PROJECT, 'src', 'index.js')],
    env: {
      DSH_VPS_INVENTORY: resolve(inventory),
      DSH_VPS_HOST_FINGERPRINTS: '',
      DSH_VPS_ALLOW_TOFU: '0',
    },
  };
}

export function configureMcp(source = '{}', options = {}) {
  const config = JSON.parse(source);
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('MCP config must be a JSON object');
  if (config.mcpServers !== undefined && (!config.mcpServers || typeof config.mcpServers !== 'object' || Array.isArray(config.mcpServers))) {
    throw new Error('mcpServers must be an object');
  }
  const previous = config.mcpServers?.vps ?? {};
  config.mcpServers = {
    ...config.mcpServers,
    vps: { ...previous, ...createServerConfig(options), env: { ...previous.env, ...createServerConfig(options).env } },
  };
  // Credentials belong to the private inventory or externally supplied environment.
  delete config.mcpServers.vps.env.DSH_VPS_SSH_KEY;
  delete config.mcpServers.vps.env.DSH_VPS_SSH_KEY_PASSPHRASE;
  return JSON.stringify(config, null, 2) + '\n';
}
