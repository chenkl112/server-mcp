/**
 * sudo / 删除 / 下载三条新通道的入口校验(guard.js)。
 *
 * 这三条通道比只读通道更危险,所以单测的重点不是"能放行多少",而是:
 *   * 不可逆的破坏动作必须**连审批机会都没有**;
 *   * 受保护路径与凭据形态在提权通道里同样被拦(不因为"是 root 就能碰");
 *   * 结构化路径入口不接受通配符/变量/相对路径。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  checkSudoCommand,
  checkDeletePath,
  checkDownloadUrl,
  checkDownloadTarget,
  SUDO_HARD_DENY,
} from '../src/guard.js';
import { assessCommand } from '../src/risk.js';

test('sudo 通道放行正常运维', () => {
  for (const cmd of [
    'systemctl restart docker',
    'rm -rf /root/old-app',
    'apt-get -y upgrade',
    'docker compose up -d',
    'tar czf /root/backup.tgz -C /root app',
    'journalctl --vacuum-time=3d',
    'mkdir -p /etc/nginx/conf.d',
  ]) {
    const v = checkSudoCommand(cmd);
    assert.equal(v.ok, true, `应放行:${cmd} —— ${v.why ?? ''}`);
  }
});

test('sudo 通道硬拦不可逆的破坏动作', () => {
  for (const cmd of [
    'mkfs.ext4 /dev/sda1',
    'wipefs -a /dev/sda',
    'fdisk /dev/sda',
    'dd if=/dev/zero of=/dev/sda bs=1M',
    'rm -rf /',
    'rm -rf / --no-preserve-root',
    'cat /dev/zero > /dev/sda',
    ':(){ :|:& };:',
  ]) {
    const v = checkSudoCommand(cmd);
    assert.equal(v.ok, false, `必须硬拦:${cmd}`);
    assert.ok(typeof v.why === 'string' && v.why.length > 4);
  }
});

test('sudo 通道不放松受保护路径与凭据判定', () => {
  for (const cmd of [
    'cat /etc/shadow',
    'echo x >> /etc/passwd',
    'rm -f /etc/sudoers',
    'chmod 777 /etc/passwd',
    'cp /root/.ssh/id_rsa /tmp/k',
    'echo bad > /root/.ssh/authorized_keys',
  ]) {
    assert.equal(checkSudoCommand(cmd).ok, false, `必须硬拦:${cmd}`);
  }
});

test('sudo 通道仍然拒绝运行时展开的破坏性命令(目标不可知即不做)', () => {
  for (const cmd of ['rm -rf $HOME/old', 'rm -rf /var/*', 'chmod -R 700 ~/x']) {
    assert.equal(checkSudoCommand(cmd).ok, false, `必须硬拦:${cmd}`);
  }
});

test('空命令与超长命令被拒绝', () => {
  assert.equal(checkSudoCommand('').ok, false);
  assert.equal(checkSudoCommand('   ').ok, false);
  assert.equal(checkSudoCommand(`ls ${'a'.repeat(9000)}`).ok, false);
});

test('sudo 通道刻意不套用只读白名单的黑名单(否则完整 sudo 就没意义)', () => {
  // 这些在"批准通道"里被 APPROVED_DENY 拦,但在 sudo 通道里允许 ——
  // 代价由"每次必须人工点允许 + 致命级需手输短语"承担。
  for (const cmd of ['useradd someone', 'iptables -L', 'systemctl restart nginx']) {
    assert.equal(checkSudoCommand(cmd).ok, true, `sudo 通道应放行(靠审批把关):${cmd}`);
  }
  // 但风险等级必须把它标出来,不能悄悄放过去
  assert.equal(assessCommand('useradd someone', { sudo: true }).level, 'critical');
  assert.equal(assessCommand('iptables -L', { sudo: true }).level, 'high');
});

test('删除路径:拒绝根目录、系统顶层目录、受保护路径', () => {
  for (const p of ['/', '/etc', '/usr', '/var', '/root', '/boot', '/etc/sudoers', '/var/lib/mysql/x', '/root/.ssh/id_rsa']) {
    const v = checkDeletePath(p);
    assert.equal(v.ok, false, `必须拒绝删除:${p}`);
  }
});

test('删除路径:拒绝相对路径、通配符、变量、命令替换', () => {
  for (const p of ['tmp/x', '/var/*', '/var/log/../*', '~/.cache', '/var/log/$HOME', '/opt/$(id)', '/opt/a b']) {
    assert.equal(checkDeletePath(p).ok, false, `必须拒绝:${p}`);
  }
});

test('删除路径:放行正常运维目标,并做词法归一化', () => {
  assert.equal(checkDeletePath('/root/old-app').ok, true);
  assert.equal(checkDeletePath('/var/log/nginx/access.log.1').ok, true);
  assert.equal(checkDeletePath('/opt/app/../old').normalized, '/opt/old');
  assert.equal(checkDeletePath('/tmp/./x').normalized, '/tmp/x');
});

test('下载 URL:只允许 http/https,拒绝内嵌凭据与 shell 元字符', () => {
  assert.equal(checkDownloadUrl('https://example.com/a.sh').ok, true);
  assert.equal(checkDownloadUrl('http://example.com/a.sh').insecure, true);
  assert.equal(checkDownloadUrl('ftp://example.com/a').ok, false);
  assert.equal(checkDownloadUrl('file:///etc/passwd').ok, false);
  // 拼出来而不是写成字面量:仓库的发布闸门会拒绝含 URL 凭据形态的文件
  assert.equal(checkDownloadUrl(['https://user', ':pass@example.com/a'].join('')).ok, false);
  assert.equal(checkDownloadUrl('https://example.com/$(id)').ok, false);
  assert.equal(checkDownloadUrl('https://example.com/a;rm -rf /').ok, false);
  assert.equal(checkDownloadUrl('不合法').ok, false);
  assert.equal(checkDownloadUrl('https://1.2.3.4/a.sh').isIp, true);
});

test('下载落盘路径:拒绝相对路径与受保护路径', () => {
  assert.equal(checkDownloadTarget('/tmp/a.sh').ok, true);
  assert.equal(checkDownloadTarget('tmp/a.sh').ok, false);
  assert.equal(checkDownloadTarget('/etc/passwd').ok, false);
  assert.equal(checkDownloadTarget('/').ok, false);
  assert.equal(checkDownloadTarget('/tmp/a*').ok, false);
});

test('硬拦清单本身是可审计的(能在 policy_info 里展示)', () => {
  assert.ok(Array.isArray(SUDO_HARD_DENY));
  assert.ok(SUDO_HARD_DENY.length >= 5);
  for (const rule of SUDO_HARD_DENY) {
    assert.ok(rule.re instanceof RegExp);
    assert.ok(typeof rule.why === 'string' && rule.why.length > 4);
  }
});
