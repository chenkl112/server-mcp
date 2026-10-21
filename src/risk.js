/**
 * 命令风险审查引擎(无依赖,可单测)。
 *
 * 为什么需要它:
 *   guard.js 回答的是"能不能执行"(布尔),而人做决定需要的是"会发生什么"。
 *   一次 `rm -rf /var/lib/docker` 和一次 `rm -rf /var/lib/docker/old` 在 guard 眼里
 *   可能都是"允许",但对人的意义完全不同。审查引擎把命令翻译成:
 *     等级 + 类别 + 逐条风险点 + 回滚难度 + 需要哪种确认动作。
 *
 * 设计立场:
 *   * **宁可误报,不可漏报**。这是给人看的第二意见,不是自动放行器:
 *     等级只影响"需要多重的确认动作",从不单独决定是否执行。
 *   * 不做沙箱推演,只做**可解释**的静态判定:每条风险点都要能说清"为什么要提醒"。
 *   * 删除与下载是两条**独立强制审查**的类别(用户明确要求),即使等级只有"中",
 *     也会在审批页单独置顶展示。
 *   * 看不懂的形态(解释器、eval、xargs)一律按"致命"处理 —— 静态看不见的东西,
 *     不能靠猜。
 *
 * 依赖:只依赖同样无外部依赖的 guard.js,复用"路径归一化 + 系统顶层目录"这套口径,
 * 避免两处各维护一份目录名单而逐渐不一致。
 */
import { normalizePathForCheck, PROTECTED_TOP } from './guard.js';

/** 等级由高到低。取所有风险点里的最高级。 */
export const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
export const LEVEL_LABEL = { low: '低', medium: '中', high: '高', critical: '致命' };

/** 强制审查类别:这两类即使在"低风险"列表中也要置顶单独提示。 */
export const MANDATORY_CATEGORIES = ['删除', '下载'];

function rank(severity) {
  return SEVERITY_RANK[severity] ?? 0;
}

function pushFindings(list, finding) {
  if (list.some((f) => f.id === finding.id)) return;
  list.push({
    severity: 'medium',
    ...finding,
  });
}

/* ================================================================== *
 * 各类扫描
 * ================================================================== */

/** 删除类:用户明确要求单独盯住。 */
function scanDelete(cmd, add) {
  if (/(?:^|[\s;|&(`])(?:rm)\b/.test(cmd)) {
    // 注意 `-rf` 这种连写:不能写成 `-[a-zA-Z]*[rR]\b`,
    // 因为 r 后面跟着 f 时 `\b` 不成立,`rm -rf` 会被漏判成"普通删除"。
    const recursive = /\brm\b[^\n]*\s-[a-zA-Z]*[rR][a-zA-Z]*\b|\brm\b[^\n]*\s--recursive\b/.test(cmd);
    const force = /\brm\b[^\n]*\s-[a-zA-Z]*f[a-zA-Z]*\b|\brm\b[^\n]*\s--force\b/.test(cmd);
    add({
      id: 'rm',
      category: '删除',
      severity: recursive ? 'high' : 'medium',
      title: recursive ? '递归删除文件或目录' : '删除文件',
      detail:
        `rm${recursive ? ' -r' : ''}${force ? ' -f' : ''} 删除的文件不进回收站,` +
        '也不会出现在"撤销"里;目录被递归删除后无法按原结构恢复。' +
        '若是数据目录(数据库、容器卷、日志),删除等于数据丢失。',
    });
  }

  // 删除目标是系统根 / 系统顶层目录 / 根下的通配:删完就得重装系统,直接致命。
  // (guard 会硬拦这类命令,但风险引擎仍要能独立说明"为什么这条命令根本不该提出来")
  for (const m of cmd.matchAll(/\brm\b([^\n]*)/g)) {
    for (const tok of m[1].split(/[\s;|&]+/)) {
      if (!tok.startsWith('/')) continue;
      const bare = tok.replace(/["']/g, '');
      const norm = normalizePathForCheck(bare);
      const systemTarget = norm === '/' || PROTECTED_TOP.test(norm) || /^\/\*/.test(bare);
      if (systemTarget) {
        add({
          id: 'rm-system-target',
          category: '删除',
          severity: 'critical',
          title: `删除系统级路径 ${bare}`,
          detail:
            '目标归一化后是根目录、系统顶层目录或根下的通配删除 —— 执行完机器基本就废了,' +
            '只能靠云厂商快照/重装恢复。守卫会直接拒绝这类命令,不会走到审批。',
        });
      }
    }
  }

  if (/(?:^|[\s;|&(`])(?:rmdir|unlink)\b/.test(cmd)) {    add({
      id: 'rmdir-unlink',
      category: '删除',
      severity: 'medium',
      title: '删除目录项/文件',
      detail: 'rmdir/unlink 直接作用于文件系统,不可撤销。',
    });
  }

  if (/(?:^|[\s;|&(`])shred\b/.test(cmd)) {
    add({
      id: 'shred',
      category: '删除',
      severity: 'critical',
      title: '覆写销毁文件内容',
      detail: 'shred 先覆写再删除,数据无法通过任何手段恢复,连取证都做不到。',
    });
  }

  if (/(?:^|[\s;|&(`])truncate\b/.test(cmd)) {
    add({
      id: 'truncate',
      category: '删除',
      severity: 'critical',
      title: 'truncate 清零/裁剪文件',
      detail: 'truncate 的唯一作用就是销毁文件内容,且不可逆;数据库与日志被清零后无法恢复。',
    });
  }

  if (/\bfind\b[^\n]*\s-delete\b/.test(cmd)) {
    add({
      id: 'find-delete',
      category: '删除',
      severity: 'high',
      title: 'find -delete 批量删除',
      detail: 'find 的匹配范围可能比你预期大得多(特别是漏了 -maxdepth),会一次删掉整片目录树。',
    });
  }

  if (/\bgit\s+clean\b[^\n]*\s-[a-zA-Z]*[fd]/.test(cmd)) {
    add({
      id: 'git-clean',
      category: '删除',
      severity: 'high',
      title: 'git clean 删除未跟踪文件',
      detail: 'git clean 删除的是**未被跟踪**的文件:git 里没有记录,删掉就找不回来。',
    });
  }

  if (/\bdocker\s+(?:rm|rmi|container\s+rm|image\s+rm|volume\s+rm|network\s+rm|builder\s+rm)\b/.test(cmd)) {
    const volume = /\bdocker\s+volume\s+rm\b|\bdocker\s+rmi?\b[^\n]*-v\b/.test(cmd);
    add({
      id: 'docker-rm',
      category: '删除',
      severity: volume ? 'critical' : 'high',
      title: volume ? '删除 Docker 数据卷' : '删除容器或镜像',
      detail: volume
        ? '数据卷是容器里唯一不随容器重建而消失的东西,删掉等于业务数据永久丢失。'
        : '容器可以重建,但容器内未挂载到卷的写入数据会一起消失;镜像被删则需重新拉取。',
    });
  }

  if (/\bdocker\s+(?:system\s+prune|container\s+prune|image\s+prune|volume\s+prune|network\s+prune|builder\s+prune)\b/.test(cmd)) {
    add({
      id: 'docker-prune',
      category: '删除',
      severity: 'critical',
      title: 'Docker 批量清理',
      detail:
        'prune 删除的是"当前未被使用"的对象。看起来闲置的容器/卷可能正是备份、迁移或排障要用的,' +
        '而且 volume prune 会把未挂载的数据卷一并删掉。',
    });
  }

  if (/\b(?:apt|apt-get|dpkg)\b[^\n]*\s(?:remove|purge|--purge)\b/.test(cmd)) {
    add({
      id: 'apt-remove',
      category: '删除',
      severity: 'high',
      title: '卸载系统软件包',
      detail:
        'apt remove/purge 会连带删除依赖它的包,可能把正在跑的服务一起拆掉;' +
        'purge 还会删配置文件。',
    });
  }

  if (/\b(?:pip3?|npm|yarn|pnpm|gem)\b[^\n]*\s(?:uninstall|remove)\b/.test(cmd)) {
    add({
      id: 'pkg-uninstall',
      category: '删除',
      severity: 'medium',
      title: '卸载语言级依赖',
      detail: '卸载后依赖它的进程下次重启可能直接起不来。',
    });
  }

  // 覆盖写:目标文件原有内容被丢弃,本质与删除等价
  const redirects = [...cmd.matchAll(/(?:^|\s)(?:\d)?>>?\s*(\S+)/g)].map((m) => m[1]);
  const overwrite = redirects.filter((t) => t !== '/dev/null' && !/^&/.test(t));
  if (overwrite.length) {
    add({
      id: 'overwrite',
      category: '删除',
      severity: 'high',
      title: '重定向覆盖写入',
      detail: `目标 ${overwrite.slice(0, 3).join('、')} 的原有内容会被直接丢弃,且不会留下备份。`,
    });
  }
}

/** 下载类:用户明确要求单独盯住。 */
function scanDownload(cmd, add) {
  const curlLike = /(?:^|[\s;|&(`])(?:curl|wget|fetch)\b/.test(cmd);

  if (curlLike) {
    add({
      id: 'download-http',
      category: '下载',
      severity: 'medium',
      title: '从网络下载内容',
      detail:
        '下载的内容来自外部,服务器上原本没有;在内容被检查前,它就是一段来历不明的字节。' +
        '如果是覆盖已有文件,原文件同时丢失。',
    });

    // 下载后直接执行:供应链攻击最经典的一步
    if (/(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b/.test(cmd)) {
      add({
        id: 'download-pipe-shell',
        category: '下载',
        severity: 'critical',
        title: '下载内容直接交给 shell 执行',
        detail:
          '`curl … | sh` 等于把远程服务器的任意内容当场以你的权限执行,' +
          '没有哈希校验、没有审阅窗口。安装脚本被投毒时,你执行的就是后门。',
      });
    } else if (/\b(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b/.test(cmd)) {
      add({
        id: 'download-procsubst-shell',
        category: '下载',
        severity: 'critical',
        title: '下载内容经进程替换执行',
        detail: '`bash <(curl …)` 与管道执行等价:远程内容未经审阅即被执行。',
      });
    }

    // 注意:`\b-o\b` 是无效的 —— 空格与 `-` 都是非单词字符,中间没有词边界。
    // 选项必须用"前面是空白或开头"来锚定。
    if (/(?:^|\s)(?:curl|wget)\b[^\n]*(?:^|\s)(?:-O|-o|--output|-P|--directory-prefix)(?:\s|$)/.test(cmd)) {
      add({
        id: 'download-to-file',
        category: '下载',
        severity: 'high',
        title: '下载并写入磁盘',
        detail: '写入目标若已存在会被覆盖;写入受保护目录则可能直接影响系统行为。',
      });
    }
  }

  if (/\bgit\s+clone\b/.test(cmd)) {
    add({
      id: 'git-clone',
      category: '下载',
      severity: 'high',
      title: '克隆外部仓库',
      detail: '仓库内容(含 postinstall/hook)会在后续构建或安装时被执行,来源可信度等同于代码执行权限。',
    });
  }

  if (/\b(?:apt|apt-get|dpkg\s+-i)\b[^\n]*\s(?:install|--install)\b/.test(cmd)) {
    add({
      id: 'apt-install',
      category: '下载',
      severity: 'high',
      title: '安装系统软件包(含依赖下载)',
      detail:
        'apt 会从配置的源下载包并执行 maintainer 脚本以 root 运行;' +
        '额外装包会扩大攻击面,也可能替换掉正在使用的库版本。',
    });
  }

  if (/\bapt(?:-get)?\b[^\n]*\s(?:update|upgrade|dist-upgrade|full-upgrade)\b/.test(cmd)) {
    add({
      id: 'apt-upgrade',
      category: '下载',
      severity: 'high',
      title: '升级系统软件包',
      detail:
        '升级会替换正在运行的库与服务,可能中途重启服务或要求重启系统;' +
        '出了问题通常只能靠快照回滚。',
    });
  }

  if (/\b(?:pip3?|gem|cargo|go)\b[^\n]*\s(?:install)\b/.test(cmd)) {
    add({
      id: 'lang-install',
      category: '下载',
      severity: 'high',
      title: '安装语言级依赖',
      detail: '包可能带安装期脚本,并可能与现有版本冲突(依赖地狱)。',
    });
  }

  if (/\b(?:npm|pnpm|yarn|bun)\b[^\n]*\s(?:install|i|add|ci)\b/.test(cmd)) {
    add({
      id: 'node-install',
      category: '下载',
      severity: 'high',
      title: '安装 Node 依赖',
      detail: 'npm 生态的 install 脚本会以当前用户权限执行任意代码,且依赖树深不可测。',
    });
  }

  if (/\bsnap\s+install\b/.test(cmd)) {
    add({
      id: 'snap-install',
      category: '下载',
      severity: 'high',
      title: '安装 snap 包',
      detail: 'snap 包由第三方发布者维护,更新通道不受你控制。',
    });
  }

  if (/\bdocker\s+pull\b/.test(cmd)) {
    add({
      id: 'docker-pull',
      category: '下载',
      severity: 'medium',
      title: '拉取外部镜像',
      detail: '镜像 tag 可被重新推送覆盖;`latest` 尤其如此,拉到的可能不是上次那一份。',
    });
  }

  if (/\b(?:scp|rsync|sftp|ftp)\b/.test(cmd)) {
    add({
      id: 'transfer',
      category: '下载',
      severity: 'medium',
      title: '跨主机传输文件',
      detail: '传输可能覆盖目标端同名文件;来源主机与网络路径的可信度需要你自己确认。',
    });
  }
}

/** 提权与权限变更 */
function scanPrivilege(cmd, add, { sudo }) {
  if (sudo) {
    add({
      id: 'sudo',
      category: '提权',
      severity: 'high',
      title: '以 root 身份执行',
      detail:
        'sudo 之后命令不再受 ops-us 账户权限约束:误删、误改的作用范围是整台机器,' +
        '而且 root 动作通常会绕过运维账户自己的保护。',
    });
  }

  if (/\bchmod\b/.test(cmd)) {
    const setuid = /\bchmod\b[^\n]*[+=]|\bchmod\b[^\n]*\b[246][0-7]{3}\b/.test(cmd);
    add({
      id: 'chmod',
      category: '权限',
      severity: setuid ? 'critical' : 'high',
      title: setuid ? '修改权限(可能是 setuid/setgid)' : '修改文件权限',
      detail: setuid
        ? '给任意二进制加 setuid 位 = 给普通用户一整条提权通道,是经典后门手法。'
        : '权限改错会让服务读不到配置(改小)或让任意用户可写(改大);递归修改影响整棵目录树。',
    });
  }

  if (/\b(?:chown|chgrp|setfacl)\b/.test(cmd)) {
    add({
      id: 'chown',
      category: '权限',
      severity: 'high',
      title: '修改属主/ACL',
      detail: '属主改错会让守护进程无权访问自己的数据;递归修改会连带影响系统目录。',
    });
  }

  if (/\bsetcap\b/.test(cmd)) {
    add({
      id: 'setcap',
      category: '提权',
      severity: 'critical',
      title: 'setcap 赋予文件 capabilities',
      detail: 'capabilities 可以让普通可执行文件获得接近 root 的能力,等价提权后门。',
    });
  }

  if (/\b(?:useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd|chpasswd|visudo)\b|\/etc\/sudoers/.test(cmd)) {
    add({
      id: 'account',
      category: '提权',
      severity: 'critical',
      title: '修改账户或 sudo 配置',
      detail:
        '账户与 sudoers 是机器的授权根:改这里等于重新定义"谁能做什么"。' +
        '这一类变更通常无法通过重启回滚,且很容易留下无人知晓的后门账户。',
    });
  }

  if (/\bcrontab\b|\/etc\/cron|\bat\s+\S/.test(cmd)) {
    add({
      id: 'cron',
      category: '提权',
      severity: 'high',
      title: '修改计划任务',
      detail: '计划任务会以预定义身份周期性执行内容,是持久化与后门的常见载体,且不易被发现。',
    });
  }
}

/** 系统状态与服务 */
function scanSystem(cmd, add) {
  if (/\bsystemctl\b[^\n]*\s(?:restart|stop|start|reload|disable|mask|kill)\b/.test(cmd)) {
    const stopish = /\bsystemctl\b[^\n]*\s(?:stop|disable|mask|kill)\b/.test(cmd);
    add({
      id: 'systemctl-write',
      category: '服务',
      severity: stopish ? 'high' : 'medium',
      title: stopish ? '停止/禁用系统服务' : '重启或重载系统服务',
      detail: stopish
        ? '停止或禁用服务会直接中断业务;disable 之后重启机器服务也不会自动起来。'
        : '重启服务会短暂中断业务;若新配置有问题,服务可能起不来,只能回滚配置再重启。',
    });
  }

  if (/\b(?:reboot|shutdown|poweroff|halt|init\s+[06])\b/.test(cmd)) {
    add({
      id: 'power',
      category: '服务',
      severity: 'critical',
      title: '重启或关闭主机',
      detail:
        '重启会中断全部服务。真正危险的是"起不来":若开机自启项依赖了刚改过的配置,' +
        '机器会停在需要 VNC 控制台救场的状态。',
    });
  }

  if (/(?:^|[\s;|&(`])(?:kill|pkill|killall)\b/.test(cmd)) {
    const pid1 = /\bkill\b[^\n]*\s-?(?:9\s+)?1(?:\s|$)/.test(cmd);
    add({
      id: 'kill',
      category: '服务',
      severity: pid1 ? 'critical' : 'medium',
      title: pid1 ? '杀掉 PID 1(init)' : '向进程发信号',
      detail: pid1
        ? 'PID 1 是 init/systemd,杀掉它等于让整机进入不可预期的停摆状态。'
        : '进程被杀会丢失未落盘的数据;按名称杀(pkill/killall)范围往往超出预期。',
    });
  }

  if (/(?:^|[\s;|&(`])(?:dd)\b/.test(cmd)) {
    const rawDev = /\bdd\b[^\n]*\bof=\/dev\//.test(cmd);
    add({
      id: 'dd',
      category: '磁盘',
      severity: 'critical',
      title: rawDev ? '裸写块设备' : 'dd 低级写入',
      detail: 'dd 不做任何确认,写错 of= 就会覆盖分区表或整块盘;这类破坏通常只能重装系统。',
    });
  }

  if (/\b(?:iptables|ip6tables|nft|ufw|firewall-cmd)\b/.test(cmd)) {
    add({
      id: 'firewall',
      category: '网络',
      severity: 'high',
      title: '修改防火墙规则',
      detail:
        '规则改错会当场切断 SSH —— 包括你自己正在用的这条连接。' +
        '云厂商安全组之外,这是最容易把机器锁死的一类变更。',
    });
  }

  if (/\b(?:mount|umount|swapoff|mkswap|swapon)\b/.test(cmd)) {
    add({
      id: 'mount',
      category: '磁盘',
      severity: 'high',
      title: '挂载/卸载/交换区变更',
      detail: '卸载正在使用的挂载点会中断依赖它的进程;fstab 改动出错会导致下次开机失败。',
    });
  }
}

/** 静态看不见内容的一类:解释器与动态构造 */
function scanOpaque(cmd, add) {
  if (/\b(?:bash|sh|zsh|ksh|dash)\s+-[a-zA-Z]*c\b/.test(cmd)) {
    add({
      id: 'shell-c',
      category: '不可静态评估',
      severity: 'high',
      title: '用 shell -c 包裹命令',
      detail: '外层只是一个 shell 字符串,风险审查只能看到包装层;真正的动作在引号里。',
    });
  }

  if (/\b(?:python3?|perl|ruby|node|nodejs|php|lua|deno|bun)\b/.test(cmd)) {
    add({
      id: 'interpreter',
      category: '不可静态评估',
      severity: 'critical',
      title: '执行解释器',
      detail:
        '解释器能读写任意文件、发起任意网络请求、启动任意子进程。' +
        '静态审查无法判断它到底会做什么 —— 只能由你自己读懂这段脚本。',
    });
  }

  if (/\beval\b|\bsource\b|(?:^|[\s;|&(`])\.\s/.test(cmd)) {
    add({
      id: 'eval',
      category: '不可静态评估',
      severity: 'critical',
      title: 'eval/source 动态执行',
      detail: '这正是绕过静态审查的标准手法:命令文本在运行时才拼出来,审查器看不到。',
    });
  }

  if (/\bxargs\b/.test(cmd)) {
    add({
      id: 'xargs',
      category: '不可静态评估',
      severity: 'high',
      title: 'xargs 批量转参',
      detail: 'xargs 会把大量路径一次性喂给后面的命令,实际作用范围在审查时不可知。',
    });
  }
}

/** 凭据与密钥 */
function scanCredentials(cmd, add) {
  if (/\/etc\/(?:shadow|gshadow|sudoers)/.test(cmd)) {
    add({
      id: 'cred-shadow',
      category: '凭据',
      severity: 'critical',
      title: '触碰系统凭据文件',
      detail: '/etc/shadow、/etc/sudoers 直接决定认证与提权,读写它们都不该由 AI 代劳。',
    });
  }

  if (/\bauthorized_keys\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bprivate\s+key\b/i.test(cmd)) {
    add({
      id: 'cred-ssh',
      category: '凭据',
      severity: 'critical',
      title: '触碰 SSH 密钥材料',
      detail: '私钥泄露等于把服务器交给别人;往 authorized_keys 里加一行就是一条永久后门。',
    });
  }
}

/* ================================================================== *
 * 回滚建议
 * ================================================================== */

const ROLLBACK_BY_ID = {
  rm: '删除不可恢复:先确认云厂商快照/备份存在,并对要删的路径再做一次 ls 确认范围。',
  'rm-system-target': '这条命令的守卫会直接拒绝(不会进审批);真要做请在云控制台先做整机快照,并用 VNC 控台兜底。',
  'rmdir-unlink': '删除不可恢复:删除前对整个父目录做一次快照或打包备份。',
  shred: 'shred 明确用于"不可恢复":没有任何回滚手段,只能靠此前的外部备份。',
  truncate: 'truncate 清零不可恢复:需要保留内容就先 cp 一份到别处。',
  'find-delete': '先去掉 -delete 跑一遍,把匹配结果打印出来核对范围,再真正删除。',
  'git-clean': 'git clean 删的是未跟踪文件,git 里没有副本:必须先 git stash -u 或手工备份。',
  'docker-rm': '容器可重建;数据卷删除不可恢复 —— 删卷前先 docker volume inspect 确认内容。',
  'docker-prune': '先不加 -a 或用 --dry-run 观察将被清理的对象;数据卷清理前务必确认无引用。',
  'apt-remove': '被卸载的包可以用 apt-get install 重新装回,但被 purge 的配置需要手工重建。',
  'pkg-uninstall': '记下卸载前后的版本(pip freeze / npm ls -g),出问题按原版本装回。',
  overwrite: '覆盖写会丢弃原内容:先 cp 一份到 <file>.bak-<日期> 再覆盖。',
  'download-http': '下载物先落到临时目录,校验来源与哈希后再移动到正式位置。',
  'download-pipe-shell': '改用"先下载到文件 → 人工阅读 → 再执行"三步,不要管道直执。',
  'download-procsubst-shell': '改用"先下载到文件 → 人工阅读 → 再执行"三步,不要进程替换直执。',
  'download-to-file': '写入前备份同名文件;先下载到 /tmp 再 mv 到目标位置。',
  'git-clone': '克隆到 /tmp 先审阅内容,再决定是否放到正式目录。',
  'apt-install': '安装前记下相关包版本(apt list --installed);必要时用快照回滚。',
  'apt-upgrade': '升级前给系统盘创建快照 —— 升级失败通常只能靠快照恢复。',
  'lang-install': '用虚拟环境/隔离目录安装,避免污染系统 Python/Node。',
  'node-install': '优先 npm ci 保持锁文件一致;安装脚本可疑时用 --ignore-scripts。',
  'snap-install': '记下版本(snap list),用 snap revert <name> 可回退到上一版本。',
  'docker-pull': '固定 digest 而不是 tag,可回退到原来那一份镜像。',
  transfer: '传输前对目标端同名文件做备份;先传到临时目录再替换。',
  sudo: 'root 动作一旦执行就没有权限边界兜底:先在快照上做,或先跑 --dry-run 变体。',
  chmod: '记录原权限(stat -c "%a %U:%G" <path>)再改,便于逐路径恢复。',
  chown: '记录原属主(stat -c "%U:%G %a" <path>)再改;递归操作前先确认目录树范围。',
  setcap: 'capabilities 可用 setcap -r <file> 移除,但前提是你还记得改过哪个文件。',
  account: '账户/sudoers 变更请手工执行并留档 —— 这类变更最容易留下无人知晓的后门。',
  cron: '记下修改前的 crontab(crontab -l > /tmp/cron.bak),出问题可直接装回。',
  'systemctl-write': '改前备份 unit/配置(systemctl cat <svc>),异常时恢复配置再重启。',
  power: '重启前确认:开机自启项有效、无长任务、有云控制台/VNC 可用。',
  kill: '确认 PID 对应的进程(ps -fp <pid>)与是否有未落盘数据。',
  dd: 'dd 破坏通常不可逆:确认 of= 目标盘符与 if= 来源,并用 fast 云盘快照兜底。',
  firewall: '改规则前先开一个独立的 SSH 会话保活,或准备云控制台 VNC;规则可先用 --dry-run。',
  mount: '卸载前确认无进程占用(lsof +D <mnt>);fstab 改动用 mount -a 先验证。',
  'shell-c': '把 shell -c 里的内容拆成可读的独立命令再执行,否则无法审查。',
  interpreter: '改写成一个可读的脚本文件,先给人看再执行;不要用一句话解释器。',
  eval: '避免 eval/source 动态拼接:命令应当字面可见。',
  xargs: '先用 find … -print 打印候选清单,确认数量与范围后再交给 xargs。',
  'cred-shadow': '凭据文件不支持代操作:请你自己在服务器上执行,并注意不要留下明文。',
  'cred-ssh': '密钥操作请手工完成;任何情况下都不要把私钥内容回传到对话里。',
};

/* ================================================================== *
 * 主入口
 * ================================================================== */

/**
 * 审查一条命令。
 *
 * @param {string} command 将要执行的命令原文(不含 sudo 前缀)
 * @param {object} [opts]
 * @param {boolean} [opts.sudo] 该命令会以 sudo 执行
 * @param {Array}   [opts.extraFindings] 由结构化工具补充的风险点(例如删除工具的目标路径)
 * @returns {{
 *   level: 'low'|'medium'|'high'|'critical',
 *   levelLabel: string,
 *   categories: string[],
 *   mandatoryCategories: string[],
 *   findings: Array,
 *   rollback: string[],
 *   requiresAck: boolean,
 *   requiresTypedPhrase: string|null,
 *   summary: string,
 *   destructive: boolean,
 *   download: boolean,
 *   privileged: boolean,
 * }}
 */
export function assessCommand(command, { sudo = false, extraFindings = [] } = {}) {
  const cmd = String(command ?? '');
  const findings = [];
  const add = (f) => pushFindings(findings, f);

  // 扫两遍:原文 + 去掉引号后的形态。
  // 为什么要第二遍 —— `bash -c "rm -rf /opt"` 里的 rm 前面是引号而不是空白,
  // 只扫原文就会漏掉"删除"这个类别。去引号后 `rm` 前面变成空白,规则就能命中。
  // findings 按 id 去重,所以重复扫描不会重复堆积。
  const variants = [cmd, cmd.replace(/["']/g, ' ')];
  for (const text of variants) {
    scanDelete(text, add);
    scanDownload(text, add);
    scanPrivilege(text, add, { sudo });
    scanSystem(text, add);
    scanOpaque(text, add);
    scanCredentials(text, add);
  }

  for (const extra of extraFindings) add(extra);

  // 组合放大:既删除又下载,说明这是一条"拉取 → 落地/替换"的动作,
  // 单看每一段都只是"中",合起来是"高":新内容直接顶掉旧内容。
  const hasDelete = findings.some((f) => f.category === '删除');
  const hasDownload = findings.some((f) => f.category === '下载');
  if (hasDelete && hasDownload) {
    pushFindings(findings, {
      id: 'combo-download-delete',
      category: '组合',
      severity: 'high',
      title: '下载与删除/覆盖同时出现',
      detail:
        '这条命令同时涉及"取来新内容"和"丢弃旧内容"。两者叠加意味着本地版本会被外部版本直接顶掉,' +
        '而旧版本的唯一副本可能就此消失。',
    });
  }

  if (!findings.length) {
    pushFindings(findings, {
      id: 'no-signal',
      category: '其他',
      severity: 'low',
      title: '未识别到已知风险形态',
      detail:
        '审查器只认已知形态,没命中不等于安全 —— 尤其是脚本文件、解释器参数、别名与函数。' +
        '请自己读懂这条命令。',
    });
  }

  const level = findings.reduce((acc, f) => (rank(f.severity) > rank(acc) ? f.severity : acc), 'low');
  const categories = [...new Set(findings.map((f) => f.category))];
  const mandatoryCategories = categories.filter((c) => MANDATORY_CATEGORIES.includes(c));

  // 回滚建议:去重、按风险点出现顺序取
  const rollback = [];
  for (const f of findings) {
    const hint = ROLLBACK_BY_ID[f.id];
    if (hint && !rollback.includes(hint)) rollback.push(hint);
  }
  if (!rollback.length) {
    rollback.push('该动作没有自动回滚路径:执行前请确认已有快照或备份。');
  }

  // 确认动作强度:低/中 → 一次点击;高 → 需勾选"已阅读风险";致命 → 需手工输入短语
  const requiresAck = rank(level) >= rank('high');
  const requiresTypedPhrase = level === 'critical' ? '确认执行' : null;

  // 排序:致命在前,便于审批页置顶
  findings.sort((a, b) => rank(b.severity) - rank(a.severity));

  const destructive = hasDelete || findings.some((f) => f.id === 'shred' || f.id === 'truncate');
  const download = hasDownload;
  const privileged = sudo || findings.some((f) => f.category === '提权');

  const summary =
    `风险等级:${LEVEL_LABEL[level]}` +
    ` ｜ 类别:${categories.join('、') || '无'}` +
    ` ｜ 风险点:${findings.length} 条` +
    (mandatoryCategories.length ? ` ｜ 强制审查:${mandatoryCategories.join('、')}` : '') +
    (privileged ? ' ｜ 以 root 执行' : '');

  return {
    level,
    levelLabel: LEVEL_LABEL[level],
    categories,
    mandatoryCategories,
    findings,
    rollback,
    requiresAck,
    requiresTypedPhrase,
    summary,
    destructive,
    download,
    privileged,
  };
}

/** 供 policy_info / 审批页使用的一句话说明 */
export function describeRisk(assessment) {
  return `${assessment.summary}。${assessment.findings[0]?.title ?? ''}`;
}
