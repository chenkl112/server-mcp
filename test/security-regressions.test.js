import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { checkReadCommand, checkApprovedCommand, checkFilePath } from '../src/guard.js';
import { loadInventory, resolveServer } from '../src/inventory.js';
import { loadPrivateKey } from '../src/ssh.js';

test('shell 展开、转义、选项组合与读工具写入不再绕过守卫', () => {
  for (const command of [
    'cat ${FILE}', 'cat /etc/shad*', 'cat /etc/{passwd,shadow}', 'cat /etc/../etc/shadow', 'cat /etc/./shadow',
    'cat /etc/hosts\u0000; id', 'ls ${X:-;touch /tmp/x}', 'ls \\; touch /tmp/x',
    'cat "/etc/hosts" \\$(id)', 'ls "unterminated',
    "ss '-tK'", "dmesg '-TC'", 'ss --kill', 'ss -D /tmp/dump',
    'journalctl --update-catalog', 'journalctl --sync', 'journalctl --relinquish-var',
    "sort '-o/tmp/output' /etc/hosts", 'sort --compress-program=/bin/sh /etc/hosts',
    'uniq /etc/hosts /tmp/output', 'hostname attacker', 'ifconfig eth0 down',
    'nvidia-smi -pm 1', 'docker compose config --output /tmp/output',
    'cat /etc/hosts | gzip /tmp/file', 'cat /etc/hosts | less -o/tmp/output',
    'ip -b/tmp/commands addr',
    'apt-cache gencaches', 'ulimit -n 65536',
  ]) assert.equal(checkReadCommand(command).ok, false, command);
  for (const command of [
    "bash -c 'rm -rf /etc'", "sh -c 'echo hi'", '/bin/rm -rf /etc',
    "docker exec x /bin/bash -c 'rm -rf /etc'", 'docker --config /tmp/x volume rm x',
    'docker compose down -v', 'docker container rm -v x',
    'tar -cf /tmp/out --checkpoint-action=exec=/bin/sh /tmp/file',
    "sed -i 's/x/y/e' /tmp/file", 'eval rm -rf /etc',
    'rm -rf /tmp/a; rm -rf /etc', 'rm -rf /tmp/a; mv /usr /tmp/b',
    'chmod 777 --reference=/tmp/mode /bin/bash',
    'cp /etc/{passwd,shadow} /tmp', 'cd /etc && rm -rf ssh',
    'chmod 777 /root/.ssh', 'chmod -R 777 /etc/systemd', 'chown ops-us /root/.ssh',
  ]) assert.equal(checkApprovedCommand(command).ok, false, command);
  for (const path of ['/tmp/a\u0000', "/tmp/'x'", '/tmp/\\x', '/etc/../etc/shadow', '/tmp/../../etc/shadow']) {
    assert.equal(checkFilePath(path).ok, false, path);
  }
});

test('加密私钥口令保留首尾空格,错误口令与未展开值均未就绪', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-encrypted-'));
  try {
    const passphrase = ' with spaces ';
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem', cipher: 'aes-256-cbc', passphrase }, publicKeyEncoding: { type: 'pkcs1', format: 'pem' } });
    const key = join(dir, 'key');
    writeFileSync(key, pair.privateKey, { mode: 0o600 });
    assert.ok(loadPrivateKey(key, passphrase).privateKey);
    assert.ok(loadPrivateKey(key, passphrase.trim()).problem);
    const path = join(dir, 'servers.json');
    const entry = { host: 'localhost', key, passphrase, fingerprints: ['SHA256:A'] };
    writeFileSync(path, JSON.stringify({ servers: { test: entry } }));
    let inventory = loadInventory({ path, env: {} });
    assert.equal(inventory.servers.get('test').passphrase, passphrase);
    assert.ok(resolveServer(inventory, 'test').record);
    entry.passphrase = '${UNSET_TEST_PASSPHRASE}';
    writeFileSync(path, JSON.stringify({ servers: { test: entry } }));
    inventory = loadInventory({ path, env: {} });
    assert.match(resolveServer(inventory, 'test').error, /passphrase/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('未准备好认证材料仍可探测,非法端口无法走探测入口', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-probe-target-'));
  try {
    const path = join(dir, 'servers.json');
    for (const port of [22, '22oops', '${UNSET_PORT}', 0, 65536]) {
      writeFileSync(path, JSON.stringify({ servers: { test: { host: 'localhost', port } } }));
      const inventory = loadInventory({ path, env: {} });
      assert.ok(resolveServer(inventory, 'test').error);
      assert.equal(Boolean(resolveServer(inventory, 'test', { probeOnly: true }).record), port === 22);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('root 包装程序实际拒绝危险 argv,安全参数保持原样并强制禁止 pager', () => {
  const bash = process.platform === 'win32'
    ? resolve(execFileSync('git', ['--exec-path'], { encoding: 'utf8' }).trim(), '../../..', 'bin/bash.exe')
    : 'bash';
  const dir = mkdtempSync(join(tmpdir(), 'mcp-wrapper-'));
  const posix = path => process.platform === 'win32' ? execFileSync(bash, ['-c', 'cygpath -u "$1"', 'test', path], { encoding: 'utf8' }).trim() : path;
  try {
    const stub = join(dir, 'stub');
    writeFileSync(stub, '#!/usr/bin/env bash\nprintf "executed\\n"\nprintf "%s\\n" "$@"\n', { mode: 0o755 });
    const raw = readFileSync(new URL('../server-setup.sh', import.meta.url), 'utf8');
    let wrapper = raw.match(/<<'WRAPPER_EOF'\n([\s\S]*?)\nWRAPPER_EOF/)[1];
    assert.ok(wrapper.startsWith('#!/bin/bash\n'), 'sudo 包装程序解释器不能由用户 PATH 选择');
    wrapper = wrapper.replace(/MCP_(?:DOCKER|JOURNALCTL|DMESG|SS)_PATH/g, `'${posix(stub)}'`);
    const file = join(dir, 'wrapper');
    writeFileSync(file, wrapper);
    for (const args of [
      ['ss', '-tK'], ['ss', '--kill'], ['ss', '-D', '/tmp/file'],
      ['dmesg', '-c'], ['dmesg', '-TC'], ['dmesg', '--clear'],
      ['journalctl', '--rotate'], ['journalctl', '--vacuum-time=1s'], ['journalctl', '--update-catalog'],
      ['journalctl', '-n', 'not-a-number'], ['journalctl', '-u', 'x;id'],
      ['docker', 'run', 'alpine'], ['docker', 'volume', 'rm', 'x'], ['docker', '--host', 'evil', 'ps'],
      ['docker', 'ps', '--config', '/tmp/config'], ['docker', 'logs', 'x', '--follow'],
    ]) {
      const r = spawnSync(bash, [posix(file), ...args], { encoding: 'utf8' });
      assert.equal(r.status, 64, `${args.join(' ')}: ${r.stderr}`);
      assert.equal(r.stdout, '');
    }
    for (const args of [['docker', 'ps', '-a', '--format', '{{.Names}}'], ['journalctl', '-n', '1', '--no-pager'], ['dmesg', '-H'], ['ss', '-lntup']]) {
      const r = spawnSync(bash, [posix(file), ...args], { encoding: 'utf8' });
      assert.equal(r.status, 0, `${args.join(' ')}: ${r.stderr}`);
      assert.match(r.stdout, /executed/);
      if (args[0] === 'dmesg') assert.match(r.stdout, /--nopager/);
    }
    const syntax = spawnSync(bash, ['-n', posix(new URL('../server-setup.sh', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))], { encoding: 'utf8' });
    assert.equal(syntax.status, 0, syntax.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
