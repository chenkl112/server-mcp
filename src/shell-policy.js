// Recognize a small POSIX shell subset before applying command policies.
// The remote SSH server runs a shell: unsupported expansions must fail closed.
export function parseShell(command, { approved = false } = {}) {
  const stages = [];
  let words = [], word = '', started = false, quote = null;
  const push = () => { if (started) words.push(word); word = ''; started = false; };
  const stage = () => { push(); if (!words.length) throw new Error('空命令或管道'); stages.push(words); words = []; };
  try {
    for (let i = 0; i < command.length; i++) {
      const c = command[i];
      if (/\x00|[\x01-\x08\x0b-\x1f\x7f]/.test(c)) throw new Error('控制字符');
      if (quote === "'") { if (c === "'") quote = null; else word += c; continue; }
      if (quote === '"') {
        if (c === '"') { quote = null; continue; }
        if (c === '$' || c === '`') throw new Error('动态展开或命令替换');
        if (c === '\\' && ['"', '\\', '$', '`', '\n'].includes(command[i + 1])) {
          const next = command[++i];
          if (next === '\n') throw new Error('续行');
          word += next; continue;
        }
        word += c; continue;
      }
      if (c === '"' || c === "'") { quote = c; started = true; continue; }
      if (c === '\\' || c === '$' || c === '`' || c === '~' || c === '#' || c === '(' || c === ')' || c === '{' || c === '}' || c === '<') throw new Error('不支持的 shell 语法');
      if (c === '>') {
        if (!approved) {
          const rest = command.slice(i);
          const discard = rest.match(/^>\s*\/dev\/null(?=\s|[;|]|$)/);
          if (!discard || !/^[12]$/.test(word)) throw new Error('写重定向');
          word = ''; started = false; i += discard[0].length - 1; continue;
        }
        push(); while (command[i + 1] === '>') i++; continue;
      }
      if (c === '&') {
        if (!approved || command[i + 1] !== '&') throw new Error('后台执行或连接符');
        stage(); i++; continue;
      }
      if (c === '|' || c === ';' || c === '\n') {
        if (c === '|' && command[i + 1] === '|') throw new Error('不支持 ||');
        stage(); continue;
      }
      if (/\s/.test(c)) { push(); continue; }
      word += c; started = true;
    }
    if (quote) throw new Error('引号未闭合');
    push(); if (words.length) stages.push(words);
    if (!stages.length) throw new Error('命令为空');
    return { ok: true, stages };
  } catch (error) { return { ok: false, why: `结构不安全:${error.message}` }; }
}

export function checkToolArguments(words, { approved = false } = {}) {
  let [tool, ...args] = words;
  if (tool === 'sudo' && approved) {
    if (args[0] === '-n') args.shift();
    if (args[0] === '--') args.shift();
    [tool, ...args] = args;
  }
  if (!/^[a-z][a-z0-9-]*$/.test(tool ?? '')) return { ok: false, why: '命令名必须是白名单中的字面名称' };
  const denied = (why) => ({ ok: false, why });
  if (approved) {
    const heads = new Set(('id whoami hostname uname uptime date free df du lsblk lscpu nproc top ps vmstat iostat pidstat ss netstat ip dig nslookup getent ping last lastlog w who ls cat head tail wc stat file find grep egrep sort uniq cut tr od strings md5sum sha256sum systemctl journalctl dmesg dpkg apt apt-cache snap sysctl docker lsof ulimit nvidia-smi cd rm rmdir unlink mv cp install tee chmod chown chgrp mkdir touch echo printf tar gzip zcat sed kill apt-get').split(' '));
    if (!heads.has(tool)) return denied('批准通道不接受解释器、包装器或未知命令');
    if (words.some(w => /(?:^|\/)(?:ba|da|z|k)?sh$|(?:^|\/)(?:python[0-9.]*|perl|ruby|node|php|lua|busybox|env|xargs)$/.test(w))) return denied('不接受解释器或二次执行包装器');
    if (args.some(a => /checkpoint-action|use-compress-program|to-command|--exec|Pre-Invoke|Post-Invoke|--reference|--files-from|--exclude-from/.test(a))) return denied('选项可执行外部程序或间接指定目标');
    if (tool === 'sed' && args.some(a => /^s(.).*\1.*\1.*[ew]/.test(a) || /^[-]?f$|^--file/.test(a))) return denied('sed 执行/写文件脚本或间接脚本');
    if (tool === 'sed' && args.some(a => /^(?:[0-9,$ ]*|\/[^/]*\/)[erw]\b|[;\n]\s*[erw]\b/.test(a))) return denied('sed 执行或间接读写脚本');
    if (['rm', 'rmdir', 'unlink', 'shred', 'mv', 'cp', 'install', 'tee', 'chmod', 'chown', 'chgrp'].includes(tool)) {
      const operands = args.filter(a => !a.startsWith('-'));
      if (['chmod', 'chown', 'chgrp'].includes(tool)) operands.shift();
      if (operands.some(a => !a.startsWith('/'))) return denied('文件写操作必须使用确定的绝对路径');
    }
    if (tool === 'docker') {
      if (!args.length || args[0].startsWith('-')) return denied('Docker 必须直接指定子命令');
      if (args.some(a => /^(?:prune|--volumes)$/.test(a)) || (args.includes('-v') && args.some(a => ['rm', 'down'].includes(a)))) return denied('禁止批量清理或删除数据卷');
      if (args[0] === 'volume' && ['rm', 'remove'].includes(args[1])) return denied('禁止删除数据卷');
    }
    return { ok: true };
  }
  const canonical = words.join(' ');
  if (tool === 'hostname' && args.some(a => !['-f', '--fqdn', '-s', '--short', '-I', '--all-ip-addresses', '-i', '--ip-address', '-d', '--domain', '-A', '--all-fqdns'].includes(a))) return denied('hostname 只允许展示选项');
  if (tool === 'ifconfig' && (args.length > 1 || args.some(a => !/^(?:-a|-s|[a-zA-Z0-9_.:-]+)$/.test(a)) || args.some(a => ['up', 'down'].includes(a)))) return denied('ifconfig 只允许读取接口');
  if (tool === 'ss' && args.some(a => /^--(?:kill|diag|bpf|dump)|^-[^-]*[KDF]/.test(a))) return denied('ss 写文件或断开连接选项');
  if (tool === 'dmesg' && args.some(a => !['-T', '-x', '-H', '--ctime', '--decode', '--human', '--color=never', '--nopager'].includes(a))) return denied('dmesg 只允许展示选项');
  if (tool === 'ip' && args.filter(a => a.startsWith('-')).some(a => !['-br', '-brief', '-s', '-stats', '-4', '-6', '-o', '-oneline', '-j', '-json', '-p', '-pretty', '-d', '-details'].includes(a))) return denied('ip 选项不在只读列表');
  if (tool === 'journalctl' && args.filter(a => a.startsWith('-')).some(a => !/^(?:-n|-u|-p|-k|-b|-r|--no-pager|--since|--until|--unit|--lines|--priority|--boot|--dmesg|--utc|--reverse)(?:=.*)?$/.test(a))) return denied('journalctl 选项不在只读列表');
  if (tool === 'sort' && args.some(a => /^--(?:output|compress-program|files0-from)|^-[^-]*o/.test(a))) return denied('sort 写文件或执行外部程序');
  if (tool === 'uniq' && args.filter(a => !a.startsWith('-')).length > 1) return denied('uniq 的第二个文件参数是输出文件');
  if (tool === 'find' && args.some(a => /^-(?:delete|exec|ok|fprint|fprintf|fls)/.test(a))) return denied('find 写入或执行动作');
  if (tool === 'nvidia-smi' && args.some(a => !/^(?:-q|--query|-L|--list-gpus|--query-gpu=[A-Za-z0-9_.,]+|--format=csv(?:,noheader)?(?:,nounits)?)$/.test(a))) return denied('nvidia-smi 只允许查询');
  if (tool === 'apt-cache' && !['show', 'showpkg', 'search', 'policy', 'stats', 'depends', 'rdepends', 'madison', 'pkgnames'].includes(args[0])) return denied('apt-cache 只允许查询子命令');
  if (tool === 'ulimit' && args.some(a => !/^-[a-zA-Z]+$/.test(a))) return denied('ulimit 只允许查询当前限制');
  if (['gzip', 'less', 'jq'].includes(tool)) return denied('该过滤器可写文件、启动程序或间接读取文件');
  if (tool === 'docker' && /\bcompose\s+config\b/.test(canonical) && args.some(a => /^--output|^-o/.test(a))) return denied('compose config 可写文件');
  return { ok: true };
}
