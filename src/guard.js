import { parseShell, checkToolArguments } from './shell-policy.js';

/**
 * 命令守卫:只读白名单 + 结构校验 + 绝对禁止清单。
 *
 * 设计原则(经安全 review 修正):
 *   远程命令由 **shell** 执行,所以必须按 shell 的语义判断命令的**实际效果**,
 *   而不是按字符串字面量。三类坑:
 *     1. 解释器自带"执行/写文件"能力 —— awk 的 system()、sed 的 w 命令。
 *        仅校验命令名不够,因此这类工具一律不进白名单。
 *     2. 路径变形 —— `/etc/`、`//etc`、`/./etc`、`/tmp/..`、`/etc/../etc`
 *        都解析到受保护路径,必须先做词法归一化再比对。
 *     3. 运行时展开 —— `$HOME`、`${HOME}`、`~`、`*`、`?`、`[]` 在静态检查时看不见真实目标,
 *        与破坏性动词同现时无法证明安全,一律拒绝(fail-closed)。
 *
 * 三层防线:
 *   1. DENY_PATTERNS / APPROVED_DENY —— 绝对禁止
 *   2. 结构校验 —— 拒绝命令替换、写重定向、后台执行
 *   3. 白名单 —— 以 ; / \n / && 拆段、以 | 拆管道,逐段匹配
 *
 * 重要:这些检查只作用于"用于判定的字符串",实际执行的始终是未经修改的原命令。
 */

/* ================================================================== *
 * 通用工具
 * ================================================================== */

/**
 * 路径词法归一化:去掉 . 段、消解 ..、折叠重复斜杠、去掉尾部斜杠。
 * 纯词法、不访问文件系统 —— 因此**无法**解析软链接,这一点在设计上承认:
 * 能防住的是书写变形,防不住的是"先构造一个指向 /etc 的软链接再删它"这类需要落地文件的手法。
 */
export function normalizePathForCheck(path) {
  const abs = path.startsWith('/');
  const out = [];
  for (const seg of path.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      out.pop(); // 已在根时继续 .. 仍停在根,与 POSIX 一致
      continue;
    }
    out.push(seg);
  }
  const joined = out.join('/');
  return abs ? `/${joined}` : joined; // 结果为 "/" 即根目录
}

/** 受保护的系统目录(删除/改权限时不允许作用于这些目录本身) */
const PROTECTED_TOP = /^\/(?:etc|var|usr|boot|root|home|bin|sbin|lib|lib32|lib64|opt|srv|sys|proc|dev)$/;

/**
 * 受保护路径前缀:命中即在**任何**写/删/移/改权限动作里拒绝,与动词无关。
 *
 * 为什么用前缀而不是"动词黑名单":黑名单靠枚举,永远会漏
 * (`unlink`、`setcap`、`cp -a`、`>> /etc/passwd`、解释器一句话……)。
 * 前缀白名单式的判定才收敛。这不是"更严一点",而是换了一种不会持续漏的机制。
 */
export const PROTECTED_PATH_PREFIXES = [
  // 账户与认证:改这些等于造后门
  '/etc/passwd', '/etc/shadow', '/etc/gshadow', '/etc/group', '/etc/subuid', '/etc/subgid',
  '/etc/sudoers', '/etc/sudoers.d/',
  // 动态链接与内核模块(ld.so.preload 是经典的 root 代码执行后门)
  '/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/ld.so.conf.d/',
  '/etc/modules', '/etc/modprobe.d/', '/etc/modules-load.d/',
  // PAM / NSS
  '/etc/pam.d/', '/etc/nsswitch.conf', '/etc/security/',
  // 数据库账户与密码类文件(尽量宽:漏一个就是凭据泄露)
  '/etc/mysql/', '/etc/my.cnf', '/root/.my.cnf', '/root/.pgpass', '/root/.netrc',
  // 计划任务与 systemd(纯文本写入即可获得 root 执行)
  '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/', '/etc/cron.weekly/', '/etc/cron.monthly/',
  '/etc/crontab', '/var/spool/cron/',
  '/etc/systemd/', '/lib/systemd/', '/usr/lib/systemd/',
  '/etc/init.d/', '/etc/rc.local',
  // SSH:保护密钥材料;sshd_config 与 authorized_keys 的**策略文件**本身是正常运维对象,
  // 但主机私钥绝不允许触碰。注意不把 /home/ 整体列入保护 —— 备份文件搬运是常规操作。
  '/etc/ssh/ssh_host_', '/root/.ssh/',
  // 引导与内核参数
  '/boot/', '/etc/default/grub', '/etc/fstab', '/etc/sysctl.conf', '/etc/sysctl.d/',
  // 网络身份
  '/etc/hosts', '/etc/resolv.conf', '/etc/netplan/', '/etc/network/',
  // 业务数据。只保护真正不可重建的:MySQL 数据目录。
  // 刻意**不**保护 /var/lib/docker/ —— 它主要是容器可重建层,而"删容器/清空容器存储"
  // 是正常运维动作;真正不可逆的数据卷由 APPROVED_DENY 的 `docker volume rm` 单独守着。
  '/var/lib/mysql/',
  // 提权与能力
  '/etc/capability.conf', '/usr/bin/sudo', '/usr/bin/su',
];

/**
 * 以写为目的的命令与选项 —— 有了它们,后面的路径就是"写入目标"。
 * 与 PROTECTED_PATH_PREFIXES 配合,能一次性覆盖 rm/unlink/mv/cp/tee/truncate/sed -i 等所有变体。
 */
export const WRITE_VERBS = [
  'rm', 'rmdir', 'unlink', 'shred', 'mv', 'cp', 'install', 'tee', 'truncate',
  'chmod', 'chown', 'chgrp', 'setcap', 'setfacl', 'dd', 'mkfs', 'mkswap', 'wipefs',
];

/**
 * 会把**目标路径本身**破坏/改属性/移走的动词。
 *
 * 与 WRITE_VERBS 的区别:WRITE_VERBS 用于"有写入意图"的判定(含 cp/tar 这类
 * 只是读源、写别处的命令);而这一组用于"目标是系统目录本身就必须拒绝"的判定。
 * 例如 `tar czf /root/x.tgz -C /root A` 里 /root 只是工作目录,应放行;
 * 而 `mv /etc /tmp/x`、`chmod -R 777 /etc` 的目标就是 /etc 本身,必须拒绝。
 */
export const TARGET_DESTROYING_VERBS = [
  'rm', 'rmdir', 'unlink', 'shred', 'chmod', 'chown', 'chgrp',
  'mv', 'truncate', 'setfacl', 'mkfs', 'wipefs', 'mkswap',
];
export const TOOL_WRITE_OPTIONS = [
  { re: /(?:^|\s)sort\b[^\n]*\s-{1,2}(?:o|output)\b/, why: 'sort -o 会写文件' },
  { re: /(?:^|\s)find\b(?=[^\n]*-f(?:printf|print0?|ls)\b)/, why: 'find -fprint/-fprintf/-fls 会写文件' },
  { re: /(?:^|\s)sar\b[^\n]*\s-o\b/, why: 'sar -o 会写二进制数据文件' },
  { re: /(?:^|\s)ss\b[^\n]*\s-(?:K|kill)\b/, why: 'ss -K 会强制断开 TCP 连接' },
  { re: /(?:^|\s)date\b[^\n]*\s(?:-s|--set)\b/, why: 'date -s/--set 会修改系统时钟' },
  { re: /(?:^|\s)script\b/, why: 'script 会执行命令并写类型记录文件' },
  { re: /(?:^|\s)dmesg\b[^\n]*\s-[Cc]\b/, why: 'dmesg -C/-c 会清空内核环形缓冲(销毁取证痕迹)' },
  { re: /(?:^|\s)(?:kill|pkill|killall)\b[^\n]*\s-1(?:\s|$)/, why: '可能杀死全部进程' },
  { re: /(?:^|\s)(?:pkill|killall)\b/, why: 'pkill/killall 按名称杀进程,范围不可控,请指定 PID' },
];

/**
 * 找出真正的"写重定向"。
 *
 * 三个必须同时满足的细节:
 *   * 带文件描述符号的写法 `1>` `2>>` 也要拦住 —— 早期版本用负向后顾 (?<![0-9<>]),
 *     恰好把 `1>` 放过了。
 *   * 不能误伤 `->`(docker --format 里的箭头、命令文本中的箭头),所以先剥掉 `->`。
 *   * `2>/dev/null` 与 `1>/dev/null` 是丢弃输出、不写任何文件,属于无害用法,应放行。
 */
function findWriteRedirect(cmd) {
  const withoutArrows = cmd.replace(/->/g, '');

  // ① 裸的 > 或 >>
  if (/(?<![0-9<>])>>|(?<![0-9<>])>(?!&)/.test(withoutArrows)) return true;

  // ② 带 fd 的写重定向;目标是 /dev/null 时视为无害丢弃
  for (const m of withoutArrows.matchAll(/(\d)(>>?)\s*(\S*)/g)) {
    const target = m[3] ?? '';
    if (target === '' || target === '/dev/null') continue;
    return true;
  }
  return false;
}

/* ================================================================== *
 * 路径与 token 分析
 * ================================================================== */

/** 运行时展开符号:静态检查看不见真实目标 */
const RUNTIME_EXPANSION = /[$~*?[\]]/;

/**
 * 把命令拆成 token(区分引号,但引号会被剥掉),去掉重定向符号本身。
 * 供"逐 token 做路径检查"使用。
 */
function tokenize(cmd) {
  const tokens = [];
  let buf = '';
  let quote = null;
  const push = () => {
    if (buf) tokens.push(buf);
    buf = '';
  };
  for (let i = 0; i < cmd.length; i += 1) {
    const ch = cmd[i];
    if (quote) {
      if (ch === quote) quote = null;
      else buf += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '\\' && i + 1 < cmd.length) {
      buf += cmd[i + 1];
      i += 1;
      continue;
    }
    if (/\s/.test(ch)) {
      push();
      continue;
    }
    if (ch === '>' || ch === '<' || ch === '|' || ch === '&' || ch === ';') {
      push();
      continue;
    }
    buf += ch;
  }
  push();
  return tokens;
}

/** 从 token 里取出它的路径部分(剥掉 env=VAL 前缀与颜色展开前缀) */
function pathPartOf(token) {
  let t = token;
  const eq = t.match(/^[A-Za-z_][A-Za-z0-9_]*=(.*)$/s);
  if (eq) t = eq[1];
  if (t.startsWith('$')) return t; // 交给展开检查处理
  return t;
}

function isProtectedPath(p) {
  return PROTECTED_PATH_PREFIXES.some((prefix) => {
    if (prefix.endsWith('/')) {
      // 目录前缀:既匹配目录本身(/root/.ssh),也匹配其内部(/root/.ssh/id_rsa)
      return p === prefix.slice(0, -1) || p.startsWith(prefix);
    }
    // 文件前缀:精确匹配,或它作为更长的文件名的前缀(/etc/passwd- 是 passwd 的备份)
    return p === prefix || p.startsWith(prefix);
  });
}

/**
 * "批准后仍不允许"的深度校验。返回 { ok } 或 { ok:false, why }。
 *
 * 覆盖四类:
 *   ① 写重定向的目标(> /etc/passwd)
 *   ② 写/删动词后面的路径(rm/mv/cp/tee/unlink/setcap/chmod ...)
 *   ③ 受保护目录**内部任意文件**(不再只管目录本身)
 *   ④ 破坏性动作里的运行时展开($HOME、*、~ —— 目标不可知,fail-closed)
 */
export function checkDestructiveSafety(normalized, originalForRedirect) {
  const raw = originalForRedirect ?? normalized;
  const tokens = tokenize(normalized);
  const paths = tokens.map(pathPartOf).filter((t) => t.startsWith('/'));

  // mkdir 只创建目录,不覆盖已有文件,因此允许它触碰受保护目录(例如建 /etc/ssh/sshd_config.d)。
  // 其余动词照旧。"创建目录"本身不构成提权。
  const onlyMkdir = /(?:^|[\s;|&])mkdir(?:\s|$)/.test(normalized) &&
    !new RegExp(`(?:^|\\s)(${WRITE_VERBS.join('|')})(?:\\s|$)`).test(normalized);
  const protectPaths = !onlyMkdir;

  // ① 写重定向:逐一检查目标
  for (const m of raw.matchAll(/(?:^|\s)(?:\d)?>>?\s*(\S+)/g)) {
    const target = m[1];
    if (target === '/dev/null') continue;
    if (RUNTIME_EXPANSION.test(target)) {
      return { ok: false, why: `写重定向目标含运行时展开 "${target}",无法确定实际写入位置` };
    }
    const norm = normalizePathForCheck(target);
    if (isProtectedPath(norm)) {
      return { ok: false, why: `写重定向目标命中受保护路径(${target} → ${norm})` };
    }
  }

  // ②+③ 受保护路径:任何动作都不允许触碰其内部文件。
  //
  // 注意区分两类规则:
  //   * PROTECTED_PATH_PREFIXES(如 /etc/passwd、/var/lib/mysql/)—— 对**所有**动词生效,
  //     因为改一个文件就能提权或毁数据,不存在"合法的写入目标"。
  //   * PROTECTED_TOP(如 /root、/etc 目录**本身**)—— 只对 TARGET_DESTROYING_VERBS 生效。
  //     否则 `tar czf /root/backup.tgz -C /root X`(把 /root 当工作目录)会被误拦,
  //     而它只是把归档写到 /root 下,并没有动 /root;`mv /etc ...` 则必须拒。
  const destroyVerbPath = new RegExp(
    `(?:^|\\s)(?:${TARGET_DESTROYING_VERBS.join('|')})\\b([^|;&\\n]*)`,
  ).exec(normalized);

  // 仅允许 chmod 700 /root/.ssh 的精确加固形态,禁止放开权限或转移属主。
  const isPermVerb = /^\s*(?:sudo\s+)?(chmod|chown|chgrp)\b/.test(normalized);
  const isProtectedDirItself = (norm) =>
    PROTECTED_PATH_PREFIXES.some((prefix) => prefix.endsWith('/') && norm === prefix.slice(0, -1));

  for (const p of paths) {
    if (RUNTIME_EXPANSION.test(p)) continue; // 交给 ④
    const norm = normalizePathForCheck(p);
    if (norm === '/') return { ok: false, why: `目标归一化为根目录(${p})` };

    if (destroyVerbPath && destroyVerbPath[1].includes(p)) {
      if (PROTECTED_TOP.test(norm)) {
        return { ok: false, why: `目标是系统关键目录(${p} → ${norm}),破坏或移走它等于毁掉系统` };
      }
    }

    if (protectPaths && isProtectedPath(norm)) {
      if (isPermVerb && isProtectedDirItself(norm) && norm === '/root/.ssh' &&
          /^\s*(?:sudo\s+(?:-n\s+)?(?:--\s+)?)?chmod\s+0?700\s+\/root\/\.ssh\s*$/.test(normalized)) continue;
      return {
        ok: false,
        why: `目标命中受保护路径(${p} → ${norm}):这类文件被写入/删除即等于提权或数据丢失`,
      };
    }
  }

  // ④ 破坏性动作 + 运行时展开 → 目标不可知,拒绝
  const hasDestructive = new RegExp(`(?:^|\\s|/)(?:${WRITE_VERBS.join('|')})(?:\\s|$)`).test(normalized);
  if (hasDestructive) {
    const m = normalized.match(RUNTIME_EXPANSION);
    if (m) {
      const token = tokens.find((t) => RUNTIME_EXPANSION.test(t)) ?? m[0];
      return {
        ok: false,
        why:
          `破坏性命令含运行时展开符号 "${token}"(变量/通配符/波浪号),静态检查无法确定实际目标。` +
          `请改用不含展开的字面路径 —— 若确需通配删除,请由你本人在服务器上手工执行`,
      };
    }
  }

  // ⑤ 杀进程:无论动词表怎么列,按 uid/全部进程杀的形态都不可控,直接拒绝
  const killDanger = [
    /(?:^|\s)(?:kill|pkill|killall)\b[^\n]*\s-(?:1|9)\b[^\n]*\s-1(?:\s|$)/,
    /(?:^|\s)(?:kill|pkill|killall)\b[^\n]*\s-1(?:\s|$)/,
    /(?:^|\s)(?:kill|pkill|killall)\b[^\n]*\s-(?:u|U|-uid)\b/,
  ].find((re) => re.test(normalized));
  if (killDanger) {
    return { ok: false, why: '按用户或全部进程杀进程(可能打断业务与本次会话),请指定具体 PID' };
  }

  return { ok: true };
}

/* ================================================================== *
 * 绝对禁止:命中即拒绝
 * ================================================================== */
export const DENY_PATTERNS = [
  // 凭据与密钥外泄
  { re: /\b(authorized_keys|id_rsa|id_ed25519|id_ecdsa)\b/i, why: '触碰 SSH 密钥材料' },
  { re: /\/etc\/(shadow|gshadow|sudoers)/i, why: '读取系统凭据文件' },
  // 常见凭据文件。注意用 (\S*\/)? 前缀容忍 head -c N /path 这类形式
  {
    re: /(?:\S*\/)?\.(?:my\.cnf|pgpass|netrc|npmrc|bash_history|mylogin\.cnf|git-credentials)\b/,
    why: '读取凭据类文件',
  },
  { re: /\/etc\/ssh\/|ssh_host_\w+_key/, why: '读取 SSH 主机密钥或服务端配置' },
  { re: /\/\.(?:aws|docker|kube|config\/rclone)\//, why: '读取云/容器凭据目录' },
  { re: /\.(?:pem|key|p12|pfx|jks|keystore)\b/, why: '读取私钥或证书文件' },
  { re: /(?:^|\/)[^\/]*\.env(?:\.|$|\s)/i, why: '读取环境变量文件(常含密钥)' },
  { re: /\/proc\/(?:self|thread-self|\d+)\/(?:environ|mem|maps|cmdline)/, why: '读取进程环境或内存' },
  { re: /\/proc\/kcore\b/, why: '读取内核内存' },
  { re: /^\s*printenv\b/i, why: '可能导出全部环境变量(含凭据)' },
  { re: /^\s*env\b/i, why: '可能导出全部环境变量(含凭据)' },
  // 反向 shell / 远程载荷
  { re: /\b(nc|ncat|netcat|socat|telnet)\b/i, why: '可能建立反向 shell' },
  { re: /\/dev\/tcp\//i, why: 'bash 反向 shell 特征' },
  { re: /\b(curl|wget)\b[^|]*\|\s*(ba|z|k)?sh/i, why: '远程脚本管道执行' },
  { re: /\bbase64\b[^|]*\|\s*(ba|z|k)?sh/i, why: '解码后管道执行' },
  { re: /\bbase64\s+(-d|--decode)\b\s*$/i, why: '裸解码载荷(未指定待解码文件)' },
  { re: /\bbase64\s+(-d|--decode)\b\s*[^-\s][^\s|;&]*\s*$/i, why: '解码文件后直接进入可执行路径' },
  { re: /\bmkfifo\b/i, why: '命名管道常用于提权' },
  // 块设备与无界字符设备:读取它们等于读磁盘或制造无界输出
  {
    re: /(^|\s)\/dev\/(zero|random|urandom|full|mem|kmem|port|sd[a-z]|nvme\d|vd[a-z]|hd[a-z]|loop\d|mapper\/)/,
    why: '访问块设备或无界字符设备',
  },
  // 持久化与账户
  { re: /(^|[;|]\s*|\bsudo\s+)\s*(crontab|at|batch)\b/i, why: '修改计划任务' },
  { re: /(^|[;|]\s*|\bsudo\s+)\s*(useradd|adduser|usermod|userdel|groupadd|groupmod|passwd|chpasswd)\b/i, why: '修改账户' },
  { re: /\bvisudo\b/i, why: '修改 sudo 配置' },
  { re: /\b(ssh-keygen|ssh-copy-id)\b/i, why: '生成或分发密钥' },
  // 网络与安全设施
  { re: /\b(iptables|ip6tables|nft|ufw|firewall-cmd)\b/i, why: '修改防火墙' },
  { re: /\bsystemctl\b.*\b(mask|unmask|disable)\b/i, why: '屏蔽或禁用系统服务' },
  // 日志破坏(会破坏取证痕迹)
  { re: /\bjournalctl\b.*--(vacuum|rotate|flush)\b/i, why: '清理或轮转系统日志' },
  // 破坏性操作
  { re: /\b(mkfs|fdisk|parted|mkswap)\b/i, why: '磁盘级破坏' },
  { re: /\bdd\b\s+.*of=/i, why: '裸写块设备' },
  { re: /\brm\b\s+(-[a-zA-Z-]+\s+)*\/(\s|$)/i, why: '删除根目录' },
  { re: /\brm\b\s+(-[a-zA-Z-]+\s+)*(\/etc|\/var|\/usr|\/boot|\/root|\/home)(\s|\/|$)/i, why: '删除系统关键目录' },
  { re: /\b(shutdown|reboot|halt|poweroff)\b/i, why: '改变主机电源状态' },
  { re: /\bkill\b\s+(-9\s+)?-1\b/i, why: '杀死所有进程' },
  { re: /\b(chmod|chown)\b.*\s-R\b.*\s\/(\s|$)/i, why: '递归修改根目录权限' },
  { re: /\bfind\b.*\s-(delete|exec|execdir|ok|fprint|fls)\b/i, why: 'find 的破坏性或写入动作' },
  { re: /\bdocker\b.*\b(container|image|network|builder|buildx)?\s*prune\b/i, why: 'Docker 批量清理' },
  { re: /\bdocker\b.*\b(volume\s+rm|system\s+prune|image\s+prune)/i, why: '破坏性 Docker 操作' },
  { re: /\bdocker\b.*\brm\s+(-f\s+)?\$\(/i, why: '批量删除容器' },
  { re: /\bgit\b.*\b(push|remote\s+add)\b/i, why: '代码外联与推送' },
];

/**
 * 只读命令白名单(字符串=前缀,正则=精确形态)。
 *
 * 刻意**不含**能把"程序文本"当参数的工具,原因是它们能在只读命令里执行代码或写文件:
 *   awk    —— BEGIN{system("...")} 执行任意命令;print > "file" 写文件
 *   sed    —— s///w file 写文件
 *   perl/python/node/sh —— 显然
 * 需要提取字段时,改用 cut/grep/head 等无解释能力的工具;确实需要时走批准通道。
 */
export const ALLOW_PREFIXES = [
  // 身份与时间。date 收窄为纯展示形态:排除 -s/--set(改系统时钟)
  'id', 'whoami', 'hostname', 'uname', 'uptime',
  /^date(\s+-u|\s+-R|\s+--rfc-3339=\S+|\s+\+[%a-zA-Z0-9:\/ _-]+)*\s*$/,
  // 资源(去掉 sar:它的 -o 会写二进制数据文件)
  'free', 'df', 'du', 'lsblk', 'lscpu', 'nproc', 'top', 'ps', 'vmstat', 'iostat', 'pidstat', 'tload',
  // 网络状态。ss 排除 -K(强制断开连接);ip 只允许穷举的只读形态
  /^ss\b(?!.*\s-(?:K|kill)\b)/,
  'netstat', 'ifconfig', 'dig', 'nslookup', 'getent', 'ping',
  /^ip\s+(?:-\S+\s+)*(?:addr|a|link|l|route|r|neigh|n|rule|netns)\s+(?:show|list|ls|s|sh)?\s*$/,
  /^ip\s+-br\s+(?:addr|a|link|l)\s*$/,
  /^ip\s+-s\s+(?:link|l)\s*$/,
  'last', 'lastlog', 'w', 'who',
  'ls', 'cat', 'head', 'tail', 'wc', 'stat', 'file',
  /^find\s+[^|;]*(?!-delete)(?!-exec)(?!-fprint)(?!-fprintf)(?!-fls)/,
  'grep', 'egrep', 'sort', 'uniq', 'cut', 'tr', 'od', 'strings', 'md5sum', 'sha256sum',
  // systemd 与日志
  'systemctl status', 'systemctl is-active', 'systemctl is-enabled', 'systemctl is-failed',
  'systemctl list-units', 'systemctl list-unit-files', 'systemctl show', 'systemctl cat',
  /^journalctl\b(?!.*--(vacuum|rotate|flush|setup-keys))/,
  /^dmesg(\s+-(?![Cc])[a-zA-Z]+)*\s*$/, // 排除 -C/-c(清空内核环形缓冲)
  // ip 的只读形态:子命令必须来自穷举列表,且动作(若有)只能是 show/list/ls/s/sh。
  // 这样 `ip l s eth0 down`(缩写 set)、`ip rule add`、`ip netns exec` 全部落空。
  // 选项允许任意 `-x`(覆盖 -br/-s/-4/-6/-o 等展示型开关)。
  /^ip\s+(?:-\S+\s+)*(?:route|r|addr|a|link|l|neigh|n)\s*$/,
  /^ip\s+(?:-\S+\s+)*(?:route|r|addr|a|link|l|neigh|n|rule|netns)\s+(?:show|list|ls|s|sh)\s*$/,
  // 包管理(只读)
  'dpkg -l', 'dpkg -s', 'dpkg -V', 'apt list', 'apt-cache', 'snap list',
  /^sysctl(\s+-n|\s+--values|\s+-a|\s+[a-z0-9_.\/-]+)*\s*$/i,
  // Docker(只读)
  'docker ps', 'docker images', 'docker stats', 'docker logs', 'docker inspect', 'docker version',
  'docker system df', 'docker volume ls', 'docker network ls', 'docker info', 'docker top',
  'docker port', 'docker compose ps', 'docker compose logs', 'docker compose config',
  // 运行时
  'lsof', 'ulimit', 'nvidia-smi',
];

/** 允许出现在管道右侧的纯过滤器(同样排除有解释能力的工具)。 */
export const ALLOW_PIPE_FILTERS = [
  'grep', 'egrep', 'head', 'tail', 'wc', 'sort', 'uniq', 'cut', 'tr',
  'cat', 'od', 'strings', 'zcat', 'column', 'nl', 'fold',
];

/**
 * 结构安全校验。
 *
 * 注意 `&` 的检查**不能**简单用正则打整条命令:
 * `awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd` 里的 && 在单引号内,
 * 那是 awk 的语法而不是 shell 的连接符。因此对 & 走引号感知扫描(见 hasUnquotedAmpersand)。
 */
export const STRUCTURE_DENY = [
  { re: /`/, why: '包含命令替换(反引号)' },
  { re: /\$\(/, why: '包含命令替换 $()' },
  { re: /\bsudo\b/i, why: '沙箱内不允许提权,请改用 ssh_exec_approved' },
];

/**
 * 引号感知地找出未加引号的 &(含 2>&1 与后台执行)。 */
function hasUnquotedAmpersand(cmd) {
  let quote = null;
  for (let i = 0; i < cmd.length; i += 1) {
    const ch = cmd[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '\\') {
      i += 1;
      continue;
    }
    if (ch === '&') return true;
  }
  return false;
}

/**
 * 经用户批准的执行:仍然禁止这些,避免"批准一次就被绕开"。
 * 路径规则只做粗筛;真正的变形绕过由 checkDestructiveSafety() 兜住。
 */
export const APPROVED_DENY = [
  { re: /\b(mkfs|fdisk|parted|mkswap|wipefs)\b/, why: '磁盘级破坏' },
  { re: /\bdd\b\s+[^\n]*of=\/dev\//, why: '裸写块设备' },
  // truncate 的唯一作用就是把文件清零/裁剪,不存在"安全的 truncate",且不可逆
  { re: /\btruncate\b/, why: 'truncate 会不可逆地销毁文件内容' },
  { re: /\bdocker\s+volume\s+rm\b/, why: '删除 Docker 数据卷(不可逆)' },
  { re: /\bdocker\s+system\s+prune\b/, why: '批量清理(可能删掉未使用镜像/卷)' },
  { re: /\bdocker\s+(?:container|image|network|builder|buildx)\s+prune\b/, why: 'Docker 批量清理' },
  { re: /\b(shutdown|reboot|halt|poweroff)\b/, why: '改变主机电源状态' },
  { re: /\/etc\/(shadow|gshadow|sudoers)/, why: '触碰系统凭据文件' },
  { re: /\b(authorized_keys|id_rsa|id_ed25519)\b/, why: '触碰 SSH 密钥材料' },
  { re: /\b(iptables|ip6tables|nft|ufw|firewall-cmd)\b/, why: '修改防火墙' },
  { re: /\b(crontab|chpasswd)\b/, why: '修改计划任务' },
  // setuid/setgid:经典提权后门(给 bash 或任意二进制加 s 位即可拿 root)
  //
  // 这里**不枚举符号写法**:早期版本用 [ugoa]*\+[a-z]*s 之类的正则,结果
  // `chmod +s`、`chmod =s`、`chmod +sx` 全部漏掉 —— 而 `chmod +s` 正是最常见的写法。
  // 改为:批准通道里只要 chmod 出现 `+` 或 `=` 就拒绝。代价是无法批准 `chmod +x`,
  // 但运维几乎不需要 AI 来加执行位,而漏掉 setuid 的代价是整机失守。
  { re: /\bchmod\b[^\n]*[+=]/, why: 'chmod 的符号模式(+ / =)可能设置 setuid/setgid,一律拒绝' },
  { re: /\bchmod\b\s+(?:-[a-zA-Z-]+\s+)*[0-7]*[246][0-7]{3}\b/, why: 'setuid/setgid 位(八进制模式含高阶位)' },
  { re: /\bsetcap\b/, why: 'setcap 赋予文件 capabilities,等价提权' },
  // 解释器:一行代码就能删目录、装后门、读凭据。运维完全不需要 AI 跑解释器语句,
  // 而黑名单永远枚举不完 "python3 -c ..." 里的可能性,所以整类拒绝。
  {
    re: /(?:^|[\s;|&])(?:python3?|perl|ruby|node|nodejs|php|lua|tclsh|irb|deno|bun)\b/,
    why: '解释器可执行任意代码,不接受批准',
  },
  // 账户变更一律不放行:创建账户 = 提权通道,而受管账户由 server-setup.sh 建立
  {
    re: /\b(useradd|adduser|usermod|userdel|groupadd|groupmod|groupdel)\b/,
    why: '修改账户(由 server-setup.sh 负责,不走批准通道)',
  },
];

/**
 * 敏感文件形态(去引号/去 glob 括号后匹配)。
 * 供两条通道共用:只读通道拦 glob 折叠,批准通道也拦 —— 否则
 * `cat /etc/shado[w]` 会从批准通道绕过去。
 */
const CREDENTIAL_SHAPES = [
  /\/etc\/(shadow|gshadow|sudoers|ssh\/ssh_host_)/,
  /(?:\S*\/)?\.(?:my\.cnf|pgpass|netrc|npmrc|bash_history|mylogin\.cnf|git-credentials)\b/,
  /\.(?:pem|key|p12|pfx|jks|keystore)\b/,
  /\/\.(?:aws|docker|kube|config\/rclone)\//,
  /(?:^|\/)[^\/]*\.env(?:\.|$|\s)/i,
  /\/proc\/(?:self|thread-self|\d+)\/(?:environ|mem|maps|cmdline)/,
  /\/proc\/kcore\b/,
  // SSH 私钥与授权列表:允许 id_rsa 与 idrsa 两种形态(后者来自 id[r]sa 这类折叠写法)
  /\/(?:id_?rsa|id_?ed25519|id_?ecdsa|id_?dsa)\b/,
  /\/authorized_keys\b/,
];

/** 路径是否命中敏感文件形态(会先去掉 glob 括号,因此折叠写法也能命中) */
export function isCredentialShapedPath(path) {
  const unfolded = normalizePathForCheck(String(path).replace(/[[\]{}*?]/g, ''));
  return CREDENTIAL_SHAPES.some((re) => re.test(unfolded));
}

/** read_file 这类"直接给路径"的入口用:路径本身是否可信 */
export function checkFilePath(path) {
  const p = String(path ?? '');
  if (!p) return { ok: false, why: '路径为空' };
  if (!p.startsWith('/')) return { ok: false, why: '必须是绝对路径' };
  // 通配符/变量/重定向/命令替换/空白:路径里出现任何一种都说明这不是一个确定路径
  if (/[\s;|&`$<>"'\\()\x00-\x1f\x7f]/.test(p)) return { ok: false, why: '路径包含非法字符(空白、引号、转义、重定向、命令替换等)' };
  if (/[[\]{}*?~]/.test(p)) {
    return { ok: false, why: '路径含通配符或波浪号:展开后的真实目标不可知,请用确定的字面路径' };
  }
  if (isCredentialShapedPath(p)) return { ok: false, why: '该路径属于凭据类文件,禁止读取' };
  return { ok: true, normalized: normalizePathForCheck(p) };
}

/**
 * 敏感文件与 glob 折叠检查。两条通道都要跑。
 * 返回 { ok } 或 { ok:false, why }。
 */
export function checkSensitivePaths(cmd) {
  for (const token of tokenize(cmd)) {
    if (!token.includes('/') && !isCredentialShapedPath(token)) continue;
    const hasGlob = /[[\]{}*?]/.test(token);
    if (hasGlob && isCredentialShapedPath(token)) {
      return {
        ok: false,
        why: `路径 "${token}" 用通配符指向敏感文件(展开后为 ${token.replace(/[[\]{}*?]/g, '')}),拒绝访问`,
      };
    }
    if (isCredentialShapedPath(token)) {
      return { ok: false, why: `路径 "${token}" 属于凭据类文件,拒绝访问` };
    }
  }
  return { ok: true };
}

/**
 * 只读通道里不允许的"改状态"子命令形态。
 *
 * `ip` 支持命令缩写(`l`=link、`s`=set、`a`=addr、`d`=del、`r`=route、`f`=flush),
 * 靠枚举动词必然漏,所以做**结构分析**:取 ip 后面的"对象"与"动作"两个词,
 * 动作命中写操作集合就拒绝。这样 `ip l s eth0 down`、`ip a d ...`、`ip r a ...` 都能识破。
 */
const IP_WRITE_ACTIONS = new Set([
  'add', 'a', 'del', 'delete', 'd', 'set', 's', 'flush', 'f', 'change', 'chg',
  'replace', 'repl', 'up', 'down', 'exec', 'batch', 'promote', 'nomaster',
]);

/** 迭代命令中的 ip 调用形态,命中写动作时返回原因 */
function ipWriteAction(cmd) {
  const tokens = tokenize(cmd);
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i] !== 'ip') continue;
    // 跳过 ip 自己的选项,找到对象词与动作词
    const rest = tokens.slice(i + 1).filter((t) => !t.startsWith('-'));
    const action = rest[1]; // rest[0] 是对象(addr/link/route...),rest[1] 是动作
    if (action && IP_WRITE_ACTIONS.has(action)) {
      return `ip 的写子命令(ip ${rest[0] ?? ''} ${action} …)`;
    }
    // ip -batch FILE 没有对象/动作结构,单独拦
    if (tokens.slice(i + 1).some((t) => t === '-batch' || t === '-force')) {
      return 'ip -batch 会读取并执行脚本文件';
    }
  }
  return null;
}

/** 工具自带的写文件选项(与 DENY_PATTERNS 中的 find 规则等价,供只读通道统一调用) */
function toolWritesFile(cmd) {
  return TOOL_WRITE_OPTIONS.find((o) => o.re.test(cmd))?.why ?? null;
}

/* ================================================================== *
 * 匹配与切分
 * ================================================================== */

function headOf(part) {
  return part.trim().split(/\s+/)[0] ?? '';
}

function matchesPrefix(part, prefix) {
  const p = part.trim();
  if (prefix instanceof RegExp) return prefix.test(p);
  if (p === prefix) return true;
  if (p.startsWith(prefix + ' ')) return true;
  return false;
}

function firstPrefixMatch(part, list) {
  return list.find((prefix) => matchesPrefix(part, prefix)) ?? null;
}

function prefixLabel(prefix) {
  return prefix instanceof RegExp ? prefix.source : prefix;
}

/**
 * 引号感知的切分器:分隔符只有在引号之外才算分隔符。因此
 *   awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd   —— && 在单引号内,不分段
 *   grep -rIlE "/tmp/|base64 -d" /etc/systemd/system        —— | 在双引号内,不算管道
 *   docker ps && rm -rf /tmp                                —— && 在引号外,确实分段并被拦
 */
function splitTopLevel(input, isSeparator) {
  const out = [];
  let buf = '';
  let quote = null;
  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (quote) {
      buf += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      buf += ch;
      continue;
    }
    if (ch === '\\' && i + 1 < input.length) {
      buf += ch + input[i + 1];
      i += 1;
      continue;
    }
    if (isSeparator(input, i)) {
      out.push(buf);
      buf = '';
      continue;
    }
    buf += ch;
  }
  out.push(buf);
  return out.map((s) => s.trim());
}

function splitSegments(cmd) {
  return splitTopLevel(cmd, (s, i) => s[i] === ';' || s[i] === '\n' || (s[i] === '&' && s[i + 1] === '&'));
}

function splitStages(part) {
  return splitTopLevel(part, (s, i) => s[i] === '|' && s[i + 1] !== '|');
}

/* ================================================================== *
 * 对外接口
 * ================================================================== */

export function checkReadCommand(command) {
  const cmd = String(command ?? '').trim();
  if (!cmd) return { ok: false, why: '命令为空' };
  if (cmd.length > 4096) return { ok: false, why: '命令过长(上限 4096 字符)' };

  const shell = parseShell(cmd);
  if (!shell.ok) return shell;
  for (const words of shell.stages) {
    const args = checkToolArguments(words);
    if (!args.ok) return args;
    if (!['ls', 'du', 'find'].includes(words[0]) && words.some(w => /[[\]*?]/.test(w) && (w.startsWith('/') || w.startsWith('.')))) {
      return { ok: false, why: '读取文件内容不接受路径通配符' };
    }
    const canonical = words.join(' ');
    if (TOOL_WRITE_OPTIONS.some(d => d.re.test(canonical))) return { ok: false, why: '命中规范化后的写入选项清单' };
    const sensitive = checkSensitivePaths(canonical);
    if (!sensitive.ok) return sensitive;
  }

  for (const d of DENY_PATTERNS) {
    if (d.re.test(cmd)) return { ok: false, why: `命中禁止清单:${d.why}` };
  }
  for (const s of STRUCTURE_DENY) {
    if (s.re.test(cmd)) return { ok: false, why: `结构不安全:${s.why}` };
  }
  // 未加引号的 & —— 含 2>&1 与后台执行。stdout/stderr 本就分开回传,合并只会丢信息。
  if (hasUnquotedAmpersand(cmd)) {
    return { ok: false, why: '结构不安全:包含未加引号的 &(重定向合并或后台执行)' };
  }
  if (findWriteRedirect(cmd)) {
    return { ok: false, why: '结构不安全:包含输出重定向(写入文件)' };
  }

  // 工具自带的写文件/改状态选项 —— 这些不是 shell 重定向,symbol 检查看不到
  for (const opt of TOOL_WRITE_OPTIONS) {
    if (opt.re.test(cmd)) return { ok: false, why: `命中禁止清单:${opt.why}` };
  }

  // 路径里的通配符与凭据文件:两条通道共用同一套判定
  const sensitive = checkSensitivePaths(cmd);
  if (!sensitive.ok) return sensitive;

  // 只读通道不接受改状态的形态(ip 的写子命令等)
  const ipWrite = ipWriteAction(cmd);
  if (ipWrite) return { ok: false, why: `命中禁止清单:${ipWrite}` };
  const toolWrite = toolWritesFile(cmd);
  if (toolWrite) return { ok: false, why: `命中禁止清单:${toolWrite}` };

  const parts = splitSegments(cmd).filter(Boolean);
  if (parts.length > 8) return { ok: false, why: '命令片段过多(上限 8 段)' };

  const matchedPrefixes = [];
  for (const part of parts) {
    const stages = splitStages(part).filter(Boolean);

    for (let i = 0; i < stages.length; i += 1) {
      const stage = stages[i];
      const list = i === 0 ? ALLOW_PREFIXES : ALLOW_PIPE_FILTERS;
      const hit = firstPrefixMatch(stage, list);
      if (!hit) {
        return {
          ok: false,
          why:
            i === 0
              ? `命令 "${headOf(stage)}" 不在只读白名单内。若确有需要,请走 ssh_exec_approved(需用户批准)。`
              : `管道右侧 "${headOf(stage)}" 不在允许的过滤器列表内`,
        };
      }
      matchedPrefixes.push(prefixLabel(hit));
    }
  }

  return { ok: true, matchedPrefixes, partCount: parts.length };
}

export function checkApprovedCommand(command) {
  const cmd = String(command ?? '').trim();
  if (!cmd) return { ok: false, why: '命令为空' };
  if (cmd.length > 8192) return { ok: false, why: '命令过长(上限 8192 字符)' };

  const shell = parseShell(cmd, { approved: true });
  if (!shell.ok) return shell;
  for (const words of shell.stages) {
    const args = checkToolArguments(words, { approved: true });
    if (!args.ok) return { ok: false, why: `即使批准也不允许:${args.why}` };
    const stageSafety = checkDestructiveSafety(words.join(' '));
    if (!stageSafety.ok) return { ok: false, why: `即使批准也不允许:${stageSafety.why}` };
  }

  // 先剥离引号,防止 rm -rf "/etc" 这类引号变形绕过边界断言
  const normalized = shell.stages.map(words => words.join(' ')).join('; ');

  for (const d of APPROVED_DENY) {
    if (d.re.test(normalized)) return { ok: false, why: `即使批准也不允许:${d.why}` };
  }

  const safety = checkDestructiveSafety(normalized, cmd);
  if (!safety.ok) return { ok: false, why: `即使批准也不允许:${safety.why}` };

  // 审批通道同样不允许访问凭据文件:否则 `cat /etc/shado[w]` 会从这里绕过去。
  // (读凭据本身不是写入动作,但它是明确不该由 AI 做的事。)
  const sensitive = checkSensitivePaths(normalized);
  if (!sensitive.ok) return { ok: false, why: `即使批准也不允许:${sensitive.why}` };

  // ip 的写子命令与工具的写文件选项,在批准通道同样拦(它们不属于"批准的运维动作")
  const ipWrite = ipWriteAction(normalized);
  if (ipWrite) return { ok: false, why: `即使批准也不允许:${ipWrite}` };
  const toolWrite = toolWritesFile(normalized);
  if (toolWrite) return { ok: false, why: `即使批准也不允许:${toolWrite}` };

  return { ok: true };
}

export function allowlistForDisplay() {
  return {
    readAllowPrefixes: ALLOW_PREFIXES.map(prefixLabel),
    allowedPipeFilters: ALLOW_PIPE_FILTERS,
    denyPatternCount: DENY_PATTERNS.length,
    approvedDenyRules: APPROVED_DENY.map((d) => d.why),
    notes: [
      'awk / sed / perl / python 等能把程序文本当参数的工具不在白名单内:它们能在"只读"命令里执行代码或写文件。',
      '破坏性命令(rm/chmod/chown/dd/mv 等)的路径会先做词法归一化:/etc/、//etc、/./etc、/tmp/..、/etc/../etc 都能被识破。',
      '破坏性命令含变量、通配符或波浪号($HOME、${HOME}、~、*)时一律拒绝:静态检查无法确定实际目标,选择 fail-closed。',
      '只读通道不接受 &(含 2>&1):stdout 与 stderr 本就分开回传,合并只会丢信息。',
    ],
  };
}
