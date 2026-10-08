/**
 * 批准通道的真实运维命令验证。
 *
 * 为什么单独测:只读白名单拦得住"读得太多",但用户真正依赖的是批准通道
 * 能不能干成正事。如果它把日常运维命令也拒了,用户就会绕过这套机制,
 * 安全设计反而失效。所以这里逐条验证"该放行的放行、该拦的拦住"。
 *
 * 运行:node --test test/operations.test.js
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { checkApprovedCommand, checkReadCommand } from '../src/guard.js';

/** 这些是本次会话真实做过、且以后还会做的运维动作,必须能通过批准通道 */
const REAL_OPERATIONS = [
  // —— 之前下线 aa 服务时逐条用过的 ——
  'cd /root/Agents-Anywhere/docker && docker compose -f docker-compose.postgres.yml -f docker-compose.4c4g.yml down --rmi local',
  'docker compose -f docker-compose.postgres.yml down',
  'docker stop agents-anywhere-server-next-1',
  'docker rm agents-anywhere-migrate-next-1',
  'docker rmi agents-anywhere-server:postgres',
  // 数据库备份与搬运
  'docker exec agents-anywhere-postgres-next-1 pg_dumpall -U agents_anywhere -c -f /tmp/dump.sql',
  'docker cp agents-anywhere-postgres-next-1:/tmp/dump.sql /root/aa-pg-backup.sql',
  'tar czf /root/aa-project.tar.gz -C /root Agents-Anywhere',
  'mkdir -p /root/backups',
  'chmod 600 /root/aa-pg-backup.sql',
  'cp /root/aa-pg-backup.sql /home/ubuntu/',
  'chown ubuntu:ubuntu /home/ubuntu/aa-pg-backup.sql',
  'rm -f /tmp/scratch.log',
  'rm -f /root/aa-pg-backup-2026-10-07.sql',
  'mv /root/old.sql /root/backup/',
  // 服务管理
  'systemctl restart docker',
  'systemctl reload ssh',
  'systemctl daemon-reload',
  'systemctl enable docker',
  'journalctl --rotate',
  // 包管理
  'apt-get update',
  'apt-get install -y jq',
  'apt-get -y upgrade',
  'apt-get remove -y telnet',
  'snap refresh',
  // Docker 镜像维护
  'docker pull postgres:17-alpine',
  'docker compose up -d',
  'docker compose pull',
  'docker compose config',
  // 文件系统维护
  'chmod 700 /root/.ssh',
  'chown -R ubuntu:ubuntu /home/ubuntu/app',
  'mkdir -p /etc/ssh/sshd_config.d',
  'sed -i s/PermitRootLogin yes/PermitRootLogin no/ /etc/ssh/sshd_config',
  'tee /etc/docker/daemon.json',
  'docker tag app:latest app:backup',
];

/** 即使批准也绝不允许 —— 这些是"一键抹掉服务器"级别的动作 */
const NEVER_ALLOWED = [
  ['rm -rf /', '删根'],
  ['rm -rf /etc', '删 /etc'],
  ['rm -rf /var', '删 /var'],
  ['rm -rf /root', '删 /root'],
  ['rm -rf /home', '删 /home'],
  ['rm -fr /usr', '删 /usr(-fr 变体)'],
  ['rm -r -f /boot', '删 /boot(拆分参数)'],
  ['docker volume rm agents-anywhere_agents-anywhere-pg-next', '删数据卷'],
  ['docker volume rm $(docker volume ls -q)', '批量删卷'],
  ['docker system prune -a --volumes', '批量清理含卷'],
  ['docker system prune --all --force', '批量清理'],
  ['mkfs.ext4 /dev/vda1', '格式化'],
  ['dd if=/dev/zero of=/dev/vda bs=1M', '覆写磁盘'],
  ['shutdown -h now', '关机'],
  ['reboot', '重启'],
  ['poweroff', '断电'],
  ['iptables -F', '清防火墙规则'],
  ['ufw disable', '关防火墙'],
  ['cat /etc/shadow', '读 shadow'],
  ['echo x >> /root/.ssh/authorized_keys', '塞后门公钥'],
  ['sed -i s/x/y/ /etc/sudoers', '改 sudoers'],
  ['crontab -r', '清空计划任务'],
  ['userdel -r ubuntu', '删登录账户'],
  ['useradd -o -u 0 -g 0 hacker', '建一个 uid=0 的后门账户'],
  ['usermod -aG sudo nobody', '把普通账户提为 sudo'],
  ['chmod 777 /', '给根目录 777'],
  ['chmod -R 777 /etc', '放开 /etc 权限'],
  ['chmod u+s /bin/bash', '给 bash 加 setuid'],
  // ===== 安全 review 发现的路径变形绕过,全部纳入回归 =====
  ['rm -rf /etc/', '尾部斜杠变形'],
  ['rm -rf /./etc', '点段变形'],
  ['rm -rf //etc', '重复斜杠变形'],
  ['rm -rf /tmp/..', '/tmp/.. 归一化为根目录'],
  ['rm -rf /etc/../etc', '相对段绕回 /etc'],
  ['rm -rf /*', '通配符删除根下全部'],
  ['rm -rf /var/*', '通配符删除 /var 下全部'],
  ['rm -rf $HOME', '变量展开指向家目录'],
  ['rm -rf ${HOME}', '花括号变量展开'],
  ['rm -rf ~', '波浪号展开'],
  ['cd / && rm -rf *', '先切到根再通配删除'],
  ['mv /etc /tmp/x', '用 mv 挪走 /etc'],
  ['chown -R x /usr', '递归改 /usr 属主'],
  ['truncate -s 0 /var/log/syslog', '用 truncate 清空日志'],
];

test('真实运维操作:批准通道必须放行', () => {
  const blocked = [];
  for (const cmd of REAL_OPERATIONS) {
    const r = checkApprovedCommand(cmd);
    if (!r.ok) blocked.push(`  ${cmd}\n     → ${r.why}`);
  }
  assert.deepEqual(blocked, [], `以下真实运维命令被误拦:\n${blocked.join('\n')}`);
  console.log(`  ✓ 放行 ${REAL_OPERATIONS.length} 条真实运维命令`);
});

test('灾难级命令:即使批准也必须拒绝', () => {
  const passed = [];
  for (const [cmd, label] of NEVER_ALLOWED) {
    const r = checkApprovedCommand(cmd);
    if (r.ok) passed.push(`  [${label}] ${cmd}`);
  }
  assert.deepEqual(passed, [], `以下命令被误放行:\n${passed.join('\n')}`);
  console.log(`  ✓ 拦截 ${NEVER_ALLOWED.length} 条灾难级命令`);
});

test('两条通道的分工清晰:只读命令走白名单,写命令走批准', () => {
  // 只读通道应拒绝所有有副作用的命令
  for (const cmd of ['systemctl restart docker', 'apt-get install -y jq', 'docker stop x', 'rm -f /tmp/x']) {
    assert.equal(checkReadCommand(cmd).ok, false, `只读通道不应放行:${cmd}`);
  }
  // 只读命令在批准通道里当然也合法(它不是"危险",只是不需要批准)
  for (const cmd of ['docker ps -a', 'free -h', 'df -h', 'ss -lntp']) {
    assert.equal(checkApprovedCommand(cmd).ok, true, `批准通道不应拒绝只读命令:${cmd}`);
  }
});

test('危险命令的常见变体都拦得住', () => {
  // 参数顺序、长短选项、加引号等变形不应绕过
  const variants = [
    'rm -r -f /',
    'rm --recursive --force /etc',
    'rm -rf "/etc"',
    'dd if=/dev/urandom of=/dev/sda',
    'docker volume rm "agents-anywhere_pg"',
    'docker volume  rm   agents-anywhere_pg',
  ];
  for (const cmd of variants) {
    const r = checkApprovedCommand(cmd);
    assert.equal(r.ok, false, `变体未被拦住:${cmd}${r.why ? ` (${r.why})` : ''}`);
  }

  // 反面对照:删除**具体数据子目录**属于正常运维,不应被误伤
  for (const cmd of ['rm -rf /var/lib/docker', 'rm -rf /root/old-app', 'rm -f /tmp/scratch.log']) {
    const r = checkApprovedCommand(cmd);
    assert.equal(r.ok, true, `具体子目录的删除被误拦:${cmd} → ${r.why}`);
  }
});
