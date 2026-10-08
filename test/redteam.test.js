/**
 * 红队回归测试。
 *
 * 来源:一次独立的对抗性安全审查(第三方红队)。报告列出的每一条绕过都实测复现过,
 * 修复后固化为本文件,防止回归。
 *
 * 关键教训(写在最前面,因为它改变了实现思路):
 *   纯黑名单 + 字面量匹配**无法收敛** —— 审查者逐个找到的绕过
 *   (`unlink`、`setcap`、`cp -a`、`>> /etc/passwd`、`chmod +s`、解释器一句话、
 *   折叠式 glob `/etc/shado[w]`)全属"枚举不全"。
 *   因此本项目的批准通道改为**受保护路径前缀 + 所有写入意图**的判定,
 *   而不是继续往动词黑名单里加词。
 *
 * 运行:node --test test/redteam.test.js
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { checkReadCommand, checkApprovedCommand } from '../src/guard.js';

/** 每一行:命令 + 为什么危险 */
const MUST_BLOCK = [
  // ===== 严重 1:折叠式 glob 绕过字面量黑名单 =====
  // shell 先做 glob 展开,所以 /etc/shado[w] 会变成 /etc/shadow,而字面量看不到
  ['cat /etc/shado[w]', 'glob 折叠绕过 shadow 黑名单'],
  ['head -c 1024 /etc/shad[o]w', 'glob 折叠(单字符类)'],
  ['head -c 1024 /etc/sudoer[s]', 'glob 折叠绕过 sudoers'],
  ['head -c 1024 /root/.ssh/id[r]sa', 'glob 折叠绕过 SSH 私钥'],
  ['head -c 1024 /root/.ssh/authorized_key[s]', 'glob 折叠绕过 authorized_keys'],
  ['head -c 1024 /root/.do[c]ker/config.json', 'glob 折叠绕过 docker 凭据'],
  ['head -c 1024 /opt/app/.en[v]', 'glob 折叠绕过 .env'],
  ['head -c 1024 /etc/ssh/ssh_host_ed25519_ke[y]', 'glob 折叠绕过主机私钥'],

  // ===== 严重 2:批准通道写系统关键文件(与动词无关) =====
  ['echo root2::0:0::/root:/bin/bash >> /etc/passwd', '往 /etc/passwd 追加 UID=0 账户'],
  ['echo x >> /etc/ld.so.preload', '写 ld.so.preload(root 代码执行后门)'],
  ['echo x > /etc/cron.d/backdoor', '写 root 计划任务'],
  ['echo x > /etc/systemd/system/x.service', '写 root systemd 单元'],
  ['echo x > /etc/pam.d/sshd', '改 PAM 认证'],
  ['echo x > /etc/sudoers.d/x', '写 sudoers 片段'],
  ['unlink /etc/passwd', 'unlink 与 rm 同级破坏力'],
  ['mv /etc/passwd /tmp/', '挪走 /etc/passwd'],
  ['mv /etc /tmp/x', '挪走 /etc'],
  ['shred -u /var/lib/mysql/ibdata1', '粉碎 MySQL 数据文件'],
  ['tee /etc/passwd', 'tee 写 /etc/passwd'],
  ['cp /etc/shadow /tmp/x', '复制 shadow 出来'],
  ['tar czf /tmp/m.tgz /var/lib/mysql', '打包 MySQL 数据目录'],
  ['chmod 777 /etc/shadow', '放开 shadow 权限'],
  ['chown ops-us /etc/passwd', '改 /etc/passwd 属主'],
  ['> /etc/passwd', '裸重定向覆盖 passwd'],

  // ===== 严重 4:setuid 的各种写法 =====
  ['chmod +s /bin/bash', 'chmod +s(最常见的 setuid 写法)'],
  ['chmod +sx /bin/bash', 'chmod +sx'],
  ['chmod =s /bin/bash', 'chmod =s'],
  ['chmod u+s /bin/bash', 'chmod u+s'],
  ['chmod 4755 /bin/bash', '八进制 setuid'],
  ['chmod 2755 /x', '八进制 setgid'],
  ['chmod 6755 /x', '八进制 setuid+setgid'],
  ['chmod g+s /usr/bin/x', 'chmod g+s'],
  ['setcap cap_setuid+ep /usr/bin/python3', 'setcap 赋予 capabilities'],

  // ===== 解释器:一行代码即可绕过所有路径规则 =====
  ['python3 -c "import shutil; shutil.rmtree(\'/etc\')"', 'python 一行删目录'],
  ['perl -e "unlink \'/etc/passwd\'"', 'perl 一行删文件'],
  ['node -e "require(\'fs\').rmSync(\'/etc\',{recursive:true})"', 'node 一行删目录'],
  ['ruby -e "File.delete(\'/etc/passwd\')"', 'ruby 一行删文件'],

  // ===== 高危 a:ip 命令缩写与未列出的子命令 =====
  ['ip l s eth0 down', 'ip 缩写形式关网卡'],
  ['ip a d 192.0.2.10/32 dev eth0', 'ip 缩写删地址'],
  ['ip r a default via 192.0.2.10', 'ip 缩写加路由'],
  ['ip a f dev eth0', 'ip 缩写 flush 地址'],
  ['ip n d 1.1.1.1 dev eth0', 'ip 缩写删邻居'],
  ['ip -batch /tmp/x', 'ip -batch 读脚本执行'],
  ['ip netns exec ns1 id', 'ip netns exec 执行命令'],
  ['ip rule add from all lookup 100', 'ip rule 改路由策略'],
  ['ip tunnel add t0 mode gre remote 1.1.1.1', 'ip tunnel 建隧道'],
  ['ip maddr add 01:00:5e:00:00:01 dev eth0', 'ip maddr 改组播'],
  ['ip token set ::1 dev eth0', 'ip token 改标识'],
  ['ip link set eth0 down', 'ip link set 关网卡'],

  // ===== 高危 b:工具自带的写文件/改状态选项 =====
  ['cat /etc/hosts | sort -o /tmp/out', 'sort -o 写文件'],
  ['find /tmp -type f -fprintf /tmp/o %p', 'find -fprintf 写文件'],
  ['find /tmp -type f -fprint /tmp/o', 'find -fprint 写文件'],
  ['find /tmp -type f -fls /tmp/o', 'find -fls 写文件'],
  ['sar -o /tmp/sa 1 1', 'sar -o 写数据文件'],

  // ===== 高危 c:只读通道里的特权参数 =====
  ['date -s @0', 'date -s 改系统时钟'],
  ['date --set=2000-01-01', 'date --set 改时钟'],
  ['ss -K dst 127.0.0.1', 'ss -K 强制断开连接'],
  ['dmesg -C', 'dmesg -C 清内核缓冲'],
  ['dmesg -c', 'dmesg -c 清空并读'],

  // ===== 中危:凭据文件黑名单空洞 =====
  ['head -c 1024 /root/.my.cnf', 'MySQL 客户端凭据'],
  ['head -c 1024 /root/.pgpass', 'PostgreSQL 凭据'],
  ['head -c 1024 /root/.netrc', 'netrc 凭据'],
  ['head -c 1024 /root/.bash_history', '命令历史(常含密码)'],
  ['head -c 1024 /proc/self/environ', '自身环境变量'],
  ['head -c 1024 /proc/1/environ', '进程环境变量'],
  ['head -c 1024 /proc/1/mem', '进程内存'],
  ['cat /etc/letsencrypt/live/x/privkey.pem', 'TLS 私钥'],

  // ===== 低危:杀进程 =====
  ['kill -9 -1', '杀全部进程'],
  ['pkill -9 -u ubuntu', '按用户杀进程'],
  ['killall nginx', '按名字杀进程'],
];

/** 这些必须仍然可用,否则安全就变成了不可用 */
const MUST_ALLOW_READ = [
  'ip route',
  'ip -br addr',
  'ip -s link',
  'ip addr',
  'ip link',
  'ip neigh',
  'ip -6 addr',
  'date',
  'date -u',
  'date +%Y-%m-%d',
  'ss -lntup',
  'ss -tnp state established',
  'dmesg',
  'dmesg -T',
  'ls -l /proc/*/exe',
  'du -sh /var/lib/docker/*',
  'find /tmp -type f -perm -u+x',
  'cat /etc/os-release',
  'systemctl status docker',
  'docker logs x --tail 100',
  'docker inspect x -f "{{.State.Status}}"',
  'docker ps -a --format "table {{.Names}}\t{{.Status}}"',
  'grep -c "Failed password" /var/log/auth.log',
  'ls -la /var/spool/cron/crontabs',
];

const MUST_ALLOW_APPROVED = [
  'rm -rf /var/lib/docker',
  'rm -rf /root/old-app',
  'rm -f /tmp/scratch.log',
  'tar czf /root/backup.tgz -C /root Agents-Anywhere',
  'chmod 700 /root/.ssh',
  'chmod 600 /root/backup.sql',
  'mkdir -p /etc/ssh/sshd_config.d',
  'sed -i s/PermitRootLogin yes/PermitRootLogin no/ /etc/ssh/sshd_config',
  'systemctl restart docker',
  'docker compose -f docker-compose.postgres.yml down --rmi local',
  'apt-get update && apt-get -y upgrade',
  'mv /root/old.sql /root/backup/',
];

test('红队发现:必须拦截', () => {
  const leaked = [];
  for (const [cmd, why] of MUST_BLOCK) {
    const read = checkReadCommand(cmd);
    const approved = checkApprovedCommand(cmd);
    // 两条通道都必须拒绝 —— 只读通道拒了但批准通道放行,等于没防
    if (read.ok) leaked.push(`  [只读通道放行] ${cmd}   (${why})`);
    if (approved.ok) leaked.push(`  [批准通道放行] ${cmd}   (${why})`);
  }
  assert.deepEqual(leaked, [], `红队绕过未被拦住:\n${leaked.join('\n')}`);
  console.log(`  ✓ 拦截 ${MUST_BLOCK.length} 条红队反例(两条通道都拦)`);
});

test('红队修复未误伤正常运维', () => {
  const blocked = [];
  for (const cmd of MUST_ALLOW_READ) {
    const r = checkReadCommand(cmd);
    if (!r.ok) blocked.push(`  [只读] ${cmd}\n        → ${r.why}`);
  }
  for (const cmd of MUST_ALLOW_APPROVED) {
    const r = checkApprovedCommand(cmd);
    if (!r.ok) blocked.push(`  [批准] ${cmd}\n        → ${r.why}`);
  }
  assert.deepEqual(blocked, [], `安全收紧误伤了正常运维:\n${blocked.join('\n')}`);
  console.log(`  ✓ 正常运维未被误伤(只读 ${MUST_ALLOW_READ.length} + 批准 ${MUST_ALLOW_APPROVED.length} 条)`);
});

test('受保护路径的判定与动词无关', () => {
  // 同一目标换不同动词,都必须拒绝 —— 这是"黑名单枚举不全"的根治点
  const targets = ['/etc/passwd', '/etc/ld.so.preload', '/etc/sudoers.d/x', '/var/lib/mysql/ibdata1'];
  const verbs = ['rm -f', 'unlink', 'mv', 'cp', 'cat', 'tee', 'shred -u', 'chmod 777', 'chown nobody'];
  const missed = [];
  for (const t of targets) {
    for (const v of verbs) {
      const cmd = `${v} ${t}`;
      if (checkApprovedCommand(cmd).ok) missed.push(`  ${cmd}`);
    }
  }
  assert.deepEqual(missed, [], `以下组合未被拦截(说明判定仍与动词绑定):\n${missed.join('\n')}`);
});

test('glob 折叠的通用形态都被拦(不限于已知文件名)', () => {
  // 抽查若干"去掉方括号后命中敏感模式"的写法
  for (const cmd of [
    'cat /etc/shad[ow]',
    'cat /etc/sha[d]ow',
    'cat /root/.ssh/authorized_key[s]',
    'cat /root/.ssh/id_r[s]a',
    'cat /etc/ssh/ssh_host_rsa_ke[y]',
  ]) {
    assert.equal(checkReadCommand(cmd).ok, false, `glob 变形未被拦住:${cmd}`);
  }
});
