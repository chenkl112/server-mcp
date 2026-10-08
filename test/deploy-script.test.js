/**
 * 一键部署脚本的静态校验。
 *
 * 为什么需要:deploy.ps1 是用户实际会跑的入口。它出错的表现通常是
 * "跑一半崩了"或"静默做错事",比守卫逻辑的 bug 更难发现。
 * 本机有 PowerShell 解析器,可以直接做语法检查;其余做结构与不变式检查。
 *
 * 运行:node --test test/deploy-script.test.js
 */
import assert from 'node:assert/strict';
import test, { before } from 'node:test';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { powershellEnv } from './helpers/powershell.js';

const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(PROJECT, 'deploy.ps1');

let raw = '';
before(() => {
  raw = readFileSync(SCRIPT, 'utf8');
});

test('脚本存在且带 UTF-8 BOM(否则中文会被 Windows PowerShell 当 ANSI 解析)', () => {
  assert.ok(existsSync(SCRIPT), `找不到 ${SCRIPT}`);
  const bytes = readFileSync(SCRIPT);
  assert.deepEqual([...bytes.subarray(0, 3)], [0xef, 0xbb, 0xbf], 'deploy.ps1 必须以 UTF-8 BOM 开头');
});

test('PowerShell 语法可解析(用真实解析器,不是正则猜)', { skip: process.platform !== 'win32' }, () => {
  // 借 PowerShell 自己的 parser,能抓到中文引号导致的语法错误
  const checker = `
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile('${SCRIPT.replace(/'/g, "''")}', [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count) { $errs | ForEach-Object { $_.Message }; exit 1 } else { exit 0 }
  `;
  try {
    execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', checker], { stdio: 'pipe', env: powershellEnv() });
  } catch (err) {
    assert.fail(`deploy.ps1 语法错误:\n${err.stdout?.toString() ?? err.message}`);
  }
});

test('不使用 $Host 作为参数名($Host 是 PowerShell 只读自动变量)', () => {
  // 曾经踩过:参数名用 $Host 会与只读自动变量冲突。
  // 注意 $Host_ 是**合法且正确**的写法(带下划线,与自动变量无关),因此断言要精确匹配
  // "作为变量名结束"的形态:后面不能跟 [A-Za-z0-9_]。
  const bareHostRefs = raw
    .split('\n')
    .map((line, i) => ({ line: line.trim(), no: i + 1 }))
    .filter(({ line }) => !line.startsWith('#')) // 注释里提到 $Host 是说明,不是用法
    .filter(({ line }) => /\$Host(?![A-Za-z0-9_])/.test(line));

  assert.deepEqual(
    bareHostRefs.map((r) => `行 ${r.no}: ${r.line}`),
    [],
    '不应引用裸 $Host 变量(自动变量,只读)',
  );

  // 参数名是 $TargetHost,同时提供 -Host 别名以便用户直观调用
  assert.match(raw, /\[string\]\$TargetHost/, '参数名应为 $TargetHost');
  assert.match(raw, /\[Alias\('Host'\)\]/, '应提供 -Host 别名');
});

test('原生命令失败不会中断脚本(ssh 会往 stderr 写字)', () => {
  // 关键不变式:必须有包装函数在调用 ssh 时临时放宽 ErrorActionPreference
  assert.match(raw, /function Invoke-Ssh/, '应有 Invoke-Ssh 包装');
  assert.match(raw, /\$ErrorActionPreference = 'Continue'/, 'Invoke-Ssh 内应临时放宽错误偏好');

  // 包装函数**内部**允许直接调用 ssh;函数之外不允许有裸调用。
  // 用大括号计数切出函数体范围,再检查剩余部分。
  const start = raw.indexOf('function Invoke-Ssh');
  assert.ok(start > 0, '应能定位 Invoke-Ssh 定义');
  let depth = 0;
  let end = start;
  for (let i = raw.indexOf('{', start); i < raw.length; i += 1) {
    if (raw[i] === '{') depth += 1;
    else if (raw[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  const outside = raw.slice(0, start) + raw.slice(end + 1);
  const bareSsh = outside
    .split('\n')
    .filter((l) => /&\s*ssh\s/.test(l) && !/ssh-keygen/.test(l));
  assert.deepEqual(bareSsh, [], `Invoke-Ssh 之外存在未经包装的 ssh 调用:\n${bareSsh.join('\n')}`);
});

test('指纹不一致时必须中止(不能静默覆盖)', () => {
  assert.match(raw, /指纹不一致/, '应有指纹不一致的显式处理');
  assert.match(raw, /核对后加 -Force 覆盖/, '应提示如何强制覆盖');
  // 不一致路径必须走 Die(退出),而不是继续
  const block = raw.match(/if \(\$existing\.fingerprints[\s\S]*?\n\}/);
  assert.ok(block, '应能定位指纹校验分支');
  assert.match(block[0], /Die /, '指纹不一致分支必须 Die');
});

test('-BootstrapOnly 时不改 DSH 配置', () => {
  const idx = raw.indexOf('$BootstrapOnly');
  assert.ok(idx > 0, '应有 -BootstrapOnly 开关');
  // BootstrapOnly 分支必须出现在"启用 MCP"之前并 exit
  const bootstrapExit = raw.indexOf('if ($BootstrapOnly)');
  const enableStep = raw.indexOf("Step '6/6 配置 MCP 客户端'");
  assert.ok(bootstrapExit > 0 && enableStep > 0);
  assert.ok(bootstrapExit < enableStep, '-BootstrapOnly 分支必须先于启用步骤并提前退出');
  assert.match(raw.slice(bootstrapExit, enableStep), /exit 0/, '该分支应 exit 0');
});

test('验收清单覆盖"该拒的必须拒"', () => {
  const expectDeny = (raw.match(/expect = 'deny'/g) ?? []).length;
  assert.ok(expectDeny >= 6, `验收里"必须被拒绝"的项应 ≥6,实际 ${expectDeny}`);
  for (const must of ['systemctl start', 'systemctl edit', 'docker run', 'docker volume rm', 'cat /etc/shadow', 'useradd']) {
    const re = new RegExp(`cmd = '[^']*${must.replace(/[/.]/g, '.')}`);
    assert.ok(re.test(raw), `验收应显式检查 "${must}" 被拒绝`);
  }
});

test('密钥默认复用,不会被静默重新生成', () => {
  // 幂等性是硬要求:重新生成密钥会让服务器上已授权的公钥立即失效
  // (表现为莫名其妙的 Permission denied,本项目真的踩过)
  assert.match(raw, /复用已有密钥/, 'deploy.ps1 应复用已有密钥');
  assert.match(raw, /ssh-keygen 生成密钥失败/, 'ssh-keygen 失败应中止,不能静默继续');
  assert.match(raw, /私钥与公钥不配对/, '应校验配对,避免把坏密钥带到服务器上才报错');
  // 不应存在"存在即重新生成"的写法
  assert.equal(
    /Test-Path \$(keyPath|KeyPath)\)\s*-and\s*-not/.test(raw),
    false,
    '不应出现 if (存在 -and -not 开关) 这类语义容易写反的判断',
  );
  // 实现只有一份:setup-local.ps1 是转发器,不应再自己决定是否生成密钥
  const setup = readFileSync(join(PROJECT, 'setup-local.ps1'), 'utf8');
  assert.equal(/ssh-keygen|ForceKeygen/.test(setup), false, 'setup-local.ps1 不应再管密钥生成');
});

test('免粘贴模式(-ViaExistingUser)存在的必要约束', () => {
  assert.match(raw, /\[string\]\$ViaExistingUser/, '应有 -ViaExistingUser 开关');
  // 必须经统一包装调用:否则 ssh 失败会因 $ErrorActionPreference='Stop' 直接中断脚本,
  // 而不是走"降级为人工粘贴"的分支(这一点被测试抓到过一次)
  assert.match(raw, /Invoke-Ssh -SshArgs \$sshArgs -Target "\$ViaExistingUser@\$Host_" -RemoteCommand 'bash -s' -Stdin/,
    '免粘贴模式应经 Invoke-Ssh(含 -Stdin)调用');
  // 借用了权限更大的账户,必须显式提示收回
  assert.match(raw, /借用了权限更大的账户/, '应提示收回被借用账户的临时访问权');
  // 必须支持无免密 sudo 的情况
  assert.match(raw, /\[switch\]\$NoSudo/, '应支持 -NoSudo(该账户无免密 sudo 时)');
  // 失败要降级,不能卡死
  assert.match(raw, /请改用人工粘贴方式/, '失败时应降级为人工粘贴指引');
});

test('引导命令同时写入文件(长 base64 从终端复制容易漏字符)', () => {
  assert.match(raw, /bootstrap\.txt/, '应把待粘贴命令落到 bootstrap.txt');
  assert.match(raw, /避免漏字符|整段复制/, '应说明为何落文件');
  assert.match(raw, /Lock-Acl \$bootstrapPath -StripEveryone/, 'bootstrap.txt 也应收紧 ACL');
});

test('给出撤销指引', () => {
  for (const hint of ['authorized_keys', '90-ops-us', 'userdel -r ops-us', 'enabled 改回 false']) {
    assert.ok(raw.includes(hint), `应包含撤销指引:${hint}`);
  }
});

test('凭据位置由用户环境决定,兼容入口不注入未指定的 KeyName', () => {
  const setup = readFileSync(join(PROJECT, 'setup-local.ps1'), 'utf8');
  assert.match(raw, /VPS_OPS_CRED_DIR/);
  assert.match(raw, /SpecialFolder]::UserProfile/);
  assert.match(raw, /\.ssh\\vps-ops-mcp/);
  assert.match(setup, /\$forward = @\{\}/);
  assert.match(setup, /PSBoundParameters.ContainsKey/);
  assert.equal(/CanonicalCredDir|CredCandidates|foundKeys/.test(raw), false);
});

test('零参数即可一键部署(从清单 default 推断目标)', () => {
  // 目标:-TargetHost 不再是必填,未指定时按清单 default / 唯一条目推断
  assert.equal(
    /\[Parameter\(Mandatory\s*=\s*\$true\)\]\[Alias\('Host'\)\]/.test(raw),
    false,
    '-TargetHost 不应是 Mandatory(否则无法零参数运行)',
  );
  assert.match(raw, /按清单 default 推断/, '应能从清单 default 推断目标');
  assert.match(raw, /清单里有多台服务器且未设 default/, '多台且无 default 时应报错而不是猜');
});

test('DSH profile 只在显式传入时更新,否则生成通用配置', () => {
  assert.match(raw, /\[string\]\$ProfileFile,/);
  assert.match(raw, /if \(\$ProfileFile\)/);
  assert.match(raw, /configure-mcp\.js/);
  assert.equal(raw.includes('profiles\\web'), false);
});
