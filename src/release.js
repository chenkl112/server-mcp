import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT_FILES = [
  '.gitignore', '.gitattributes', 'README.md', 'SECURITY-REVIEW.md',
  'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
  'deploy.ps1', 'setup-local.ps1', 'server-setup.sh', 'smoke-client.js',
  'servers.example.json', 'dsh-profile-snippet.yml',
];
const SOURCE_DIRS = { src: /\.js$/, scripts: /\.js$/, test: /\.js$/, '.github/workflows': /\.ya?ml$/ };

// An allowlist makes exports independent of local inventories, keys and history.
export function releaseFiles(root) {
  const files = [...ROOT_FILES];
  function visit(relative, extension) {
    if (!lstatSync(join(root, relative)).isDirectory()) throw new Error(`Not a regular release directory: ${relative}`);
    for (const entry of readdirSync(join(root, relative), { withFileTypes: true })) {
      const path = `${relative}/${entry.name}`;
      if (entry.isSymbolicLink()) throw new Error(`Release refuses symbolic links: ${path}`);
      if (entry.isDirectory()) visit(path, extension);
      else if (entry.isFile() && extension.test(entry.name) && !entry.name.includes('.local.')) files.push(path);
    }
  }
  for (const [dir, extension] of Object.entries(SOURCE_DIRS)) visit(dir, extension);
  return files.sort();
}

export function readRelease(root) {
  return releaseFiles(root).map(path => {
    if (!lstatSync(join(root, path)).isFile()) throw new Error(`Not a regular release file: ${path}`);
    const data = readFileSync(join(root, path));
    const content = data.toString('utf8');
    const checks = [
      [/\b[A-Za-z]:[\\/]/, 'absolute Windows path'],
      [/-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/, 'private key material'],
      [/https?:\/\/[^\s/]+:[^\s/]+@/, 'URL credentials'],
      [/\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
    ];
    for (const [pattern, label] of checks) {
      if (pattern.test(content)) throw new Error(`Release rejected ${path}: ${label}`);
    }
    return { path, data };
  });
}
