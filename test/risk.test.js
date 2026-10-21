/**
 * 风险审查引擎的单测。
 *
 * 守两件事:
 *   1. **该报的必须报**:删除、下载、提权、服务、磁盘、凭据六大类都要能被识别;
 *   2. **等级不能虚低**:等级直接决定审批页要不要勾选/输入短语,把致命误判成"中"
 *      等于把一个不可逆操作变成一次点击。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { assessCommand, LEVEL_LABEL, MANDATORY_CATEGORIES } from '../src/risk.js';

const levelOf = (cmd, opts) => assessCommand(cmd, opts).level;
const ids = (cmd, opts) => assessCommand(cmd, opts).findings.map((f) => f.id);

test('只读命令判为低风险,但仍然提示"没命中不等于安全"', () => {
  const r = assessCommand('ls -la /var/log');
  assert.equal(r.level, 'low');
  assert.equal(r.destructive, false);
  assert.equal(r.download, false);
  assert.ok(r.findings.some((f) => f.id === 'no-signal'));
  assert.ok(r.rollback.length >= 1);
});

test('删除类:递归删除按高风险,shred/truncate 直接致命', () => {
  assert.equal(levelOf('rm -rf /var/lib/docker/overlay2'), 'high');
  assert.equal(levelOf('rm /tmp/a.txt'), 'medium');
  assert.equal(levelOf('truncate -s 0 /var/log/syslog'), 'critical');
  assert.equal(levelOf('shred -u /root/a.sql'), 'critical');
  assert.equal(levelOf('find /tmp -name "*.log" -delete'), 'high');
  assert.equal(levelOf('docker volume rm data'), 'critical');
  assert.equal(levelOf('docker system prune -af'), 'critical');
  assert.ok(ids('rm -rf /opt/x').includes('rm'));
});

test('删除目标是系统根/顶层目录时独立判为致命(即使引号包裹也能识破)', () => {
  assert.equal(levelOf('rm -rf /'), 'critical');
  assert.equal(levelOf('rm -rf /*'), 'critical');
  assert.equal(levelOf('rm -rf /etc'), 'critical');
  assert.equal(levelOf('rm -rf /root/../etc'), 'critical');
  // rm 被引号包住(典型形态是 bash -c "..." 里):去引号后仍要命中
  assert.equal(levelOf('bash -c "rm -rf /"'), 'critical');
  assert.ok(ids('bash -c "rm -rf /"').includes('rm-system-target'));
});

test('删除类会指出目标文件被覆盖也算删除', () => {
  const r = assessCommand('cat /dev/null > /root/app/config.yml');
  assert.equal(r.destructive, true);
  assert.ok(r.findings.some((f) => f.id === 'overwrite'));
});

test('下载类:普通下载为中,下载后直接执行一律致命', () => {
  assert.equal(levelOf('curl -fsSL -o /tmp/a.sh https://example.com/a.sh'), 'high');
  assert.equal(levelOf('curl -fsSL https://example.com/x.sh | sh'), 'critical');
  assert.equal(levelOf('bash <(curl -fsSL https://example.com/x.sh)'), 'critical');
  assert.equal(levelOf('git clone https://github.com/a/b'), 'high');
  assert.equal(levelOf('apt-get install -y nginx'), 'high');
  assert.equal(levelOf('pip3 install requests'), 'high');
  assert.equal(levelOf('docker pull nginx:latest'), 'medium');
});

test('删除 + 下载同时出现会被组合放大', () => {
  const r = assessCommand('curl -fsSL https://example.com/v2.tar.gz -o /root/v2.tar.gz && rm -rf /root/v1');
  assert.ok(r.findings.some((f) => f.id === 'combo-download-delete'));
  // 单看每一段都是"中/高",合起来至少是"高"(必须勾选风险确认才放行)
  assert.equal(r.level, 'high');
  assert.equal(r.requiresAck, true);
});

test('提权类:sudo 本身即高危,setuid 与账户变更是致命', () => {
  assert.ok(assessCommand('systemctl restart docker', { sudo: true }).privileged);
  assert.equal(levelOf('chmod +s /usr/bin/bash'), 'critical');
  assert.equal(levelOf('chmod 4755 /tmp/x'), 'critical');
  assert.equal(levelOf('chmod 755 /var/www'), 'high');
  assert.equal(levelOf('chown -R www-data:www-data /var/www'), 'high');
  assert.equal(levelOf('visudo'), 'critical');
  assert.equal(levelOf('useradd hacker'), 'critical');
});

test('服务与系统:重启主机致命,重启服务与改防火墙为高', () => {
  assert.equal(levelOf('reboot'), 'critical');
  assert.equal(levelOf('shutdown -h now'), 'critical');
  assert.equal(levelOf('systemctl stop docker'), 'high');
  assert.equal(levelOf('systemctl restart nginx'), 'medium');
  assert.equal(levelOf('iptables -F'), 'high');
  assert.equal(levelOf('dd if=/dev/zero of=/dev/sda bs=1M'), 'critical');
});

test('解释器与动态执行按"不可静态评估"处理(不容侥幸)', () => {
  // shell -c 里的内容仍然可见,所以按"高"(需勾选)而不是"致命";
  // 真正的解释器与 eval 才是静态完全看不见,一律致命。
  assert.equal(levelOf('bash -c "rm -rf /opt/x"'), 'high');
  assert.ok(ids('bash -c "rm -rf /opt/x"').includes('shell-c'));
  assert.ok(ids('bash -c "rm -rf /opt/x"').includes('rm'));
  assert.equal(levelOf('python3 -c "import shutil; shutil.rmtree(\'/opt\')"'), 'critical');
  assert.equal(levelOf('eval "$X"'), 'critical');
  assert.equal(levelOf('perl -e "1"'), 'critical');
});

test('凭据类一律致命', () => {
  assert.equal(levelOf('cat /etc/shadow'), 'critical');
  assert.equal(levelOf('echo x >> /root/.ssh/authorized_keys'), 'critical');
  assert.equal(levelOf('cp /root/.ssh/id_rsa /tmp/k'), 'critical');
});

test('等级驱动确认强度:高需勾选,致命需手输短语', () => {
  const low = assessCommand('ls');
  assert.equal(low.requiresAck, false);
  assert.equal(low.requiresTypedPhrase, null);

  const high = assessCommand('rm -rf /opt/old');
  assert.equal(high.requiresAck, true);
  assert.equal(high.requiresTypedPhrase, null);

  const critical = assessCommand('reboot');
  assert.equal(critical.requiresAck, true);
  assert.equal(critical.requiresTypedPhrase, '确认执行');
});

test('删除与下载是强制审查类别,且会被单独标出', () => {
  assert.deepEqual(MANDATORY_CATEGORIES, ['删除', '下载']);
  const r = assessCommand('rm -rf /opt/old');
  assert.deepEqual(r.mandatoryCategories, ['删除']);
  assert.ok(r.summary.includes('强制审查'));
});

test('每条风险点都带可读的中文说明与回滚建议', () => {
  const r = assessCommand('systemctl restart docker', { sudo: true });
  for (const f of r.findings) {
    assert.ok(f.title && f.title.length > 2, `风险点应有一句话标题:${JSON.stringify(f)}`);
    assert.ok(f.detail && f.detail.length > 10, `风险点应有说明:${JSON.stringify(f)}`);
  }
  assert.ok(r.rollback.length >= 1);
  assert.equal(LEVEL_LABEL[r.level], r.levelLabel);
});

test('额外的结构化风险点会被合并进结论', () => {
  const r = assessCommand('rm -f -- /opt/a', {
    extraFindings: [
      {
        id: 'custom',
        category: '删除',
        severity: 'critical',
        title: '自定义风险',
        detail: '这是由工具补充的风险点,用来验证合并逻辑。',
      },
    ],
  });
  assert.ok(r.findings.some((f) => f.id === 'custom'));
  assert.equal(r.level, 'critical');
  // 排序:致命在最前
  assert.equal(r.findings[0].severity, 'critical');
});

test('同一风险点不会重复堆积', () => {
  const r = assessCommand('rm -rf /a');
  const rmCount = r.findings.filter((f) => f.id === 'rm').length;
  assert.equal(rmCount, 1);
});
