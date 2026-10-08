#!/usr/bin/env pwsh
<#
.SYNOPSIS
  一键部署 dsh-vps-ops MCP 到一台 Linux 服务器。

.DESCRIPTION
  一条命令完成全部可自动化的环节:

    本机侧: 生成/复用专用密钥 → 收紧 ACL → 写入 servers.json(含指纹占位)
    服务器侧:生成一段"自包含待粘贴命令"(server-setup.sh 以 base64 内嵌,无需上传文件)
    指纹:   探测公钥;首次或换钥需独立核对,已有固定值则校验一致性
    验收:   登录 → 核对指纹 → 核验提权面 → 采一次状态
    接入:   生成通用 MCP 客户端配置;仅显式提供 ProfileFile 时更新 DSH

  唯一无法自动化的一步:在服务器上以 root 粘贴那段命令(建立 ops-us 账户)。
  这是有意的 —— AI 不应能自己在别人服务器上开 sudo 账户。
  脚本会在需要时停下并把那段命令打印出来;你粘贴完再跑一次本脚本即可。

.PARAMETER Host
  服务器地址(IP 或域名)。

.PARAMETER Name
  清单里的服务器名(字母数字下划线连字符,≤32 字符),默认取 Host 的短名。

.PARAMETER Force
  允许更换固定指纹,仍需 -ExpectedFingerprint 独立核对。

.EXAMPLE
  .\deploy.ps1 -Host 192.0.2.10
  .\deploy.ps1 -Host 192.0.2.10 -Name web1
#>
[CmdletBinding()]
param(
  # 注意:不能叫 $Host —— 那是 PowerShell 的自动变量(只读),会冲突。
  # 留空时自动从 servers.json 的 default(或唯一条目)推断,从而支持真正的零参数一键部署。
  [Alias('Host')][string]$TargetHost,
  [ValidatePattern('^[A-Za-z0-9_-]{1,32}$')][string]$Name,
  [ValidateRange(1,65535)][int]$Port = 22,
  [string]$ExpectedFingerprint,
  [switch]$Force,
  # 凭据目录:显式参数 > 环境变量 VPS_OPS_CRED_DIR > 已有清单密钥 > 用户目录默认值。
  [string]$CredDir,
  [string]$KeyName = 'vps_ops_ed25519',
  # 只做"服务器侧 + 清单"部分,不改 DSH 配置。适合先只接入、稍后再启用通道。
  [switch]$BootstrapOnly,
  # 借助一个**已能登录**的账户(通常是 ubuntu)代为创建 ops-us,从而免去手工粘贴那一大段命令。
  # 代价:该账户权限更大,所以用完必须把这个开关带来的影响收回去(见该模式末尾的提示)。
  [string]$ViaExistingUser,
  # 该账户本身为 root 时可跳过 sudo
  [switch]$NoSudo,
  [switch]$UpdateServer,
  [string]$ProfileFile,
  [string]$InventoryPath = $(if ($env:DSH_VPS_INVENTORY) { $env:DSH_VPS_INVENTORY } else { Join-Path $PSScriptRoot 'servers.json' })
)

$ErrorActionPreference = 'Stop'
$ProjectDir = $PSScriptRoot
# 此自动部署入口使用 Windows ACL;其他平台按 README 手工接入。
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'deploy.ps1 需要 Windows;其他平台请使用 README 的手工接入流程' }
$InventoryPath = [IO.Path]::GetFullPath($InventoryPath)
if (-not $CredDir -and $env:VPS_OPS_CRED_DIR) { $CredDir = $env:VPS_OPS_CRED_DIR }

# --- 目标主机:未指定时从清单推断,支持零参数一键部署 ---
if (-not $TargetHost) {
  if (-not (Test-Path $InventoryPath)) {
    Write-Host "[失败] 未指定 -TargetHost,且找不到清单 $InventoryPath" -ForegroundColor Red
    Write-Host '  首次部署请给出目标:. \deploy.ps1 -TargetHost <IP>' -ForegroundColor Red
    exit 1
  }
  $inv0 = Get-Content $InventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $names = @($inv0.servers.PSObject.Properties.Name)
  if ($names.Count -eq 0) {
    Write-Host '[失败] 清单为空,无法推断目标。请用 -TargetHost <IP> 指定' -ForegroundColor Red
    exit 1
  }
  $pick = if ($Name -and $names -contains $Name) { $Name } elseif ($inv0.default -and $names -contains $inv0.default) { $inv0.default } elseif ($names.Count -eq 1) { $names[0] } else { $null }
  if (-not $pick) {
    Write-Host '[失败] 清单里有多台服务器且未设 default,请显式指定其一:' -ForegroundColor Red
    $names | ForEach-Object { Write-Host "    .\deploy.ps1 -TargetHost <IP> -Name $_" -ForegroundColor Red }
    exit 1
  }
  $TargetHost = $inv0.servers.$pick.host
  if (-not $PSBoundParameters.ContainsKey('Port') -and $inv0.servers.$pick.port) { $Port = [int]$inv0.servers.$pick.port }
  if (-not $Name) { $Name = $pick }
  Write-Host "[i] 未指定 -TargetHost,按清单 default 推断为: $pick ($TargetHost)" -ForegroundColor DarkGray
}
$Host_ = $TargetHost
if ($Host_ -notmatch '^[A-Za-z0-9][A-Za-z0-9.:-]*$') { throw 'TargetHost 必须是 IP 或域名,不能包含空白或 shell 字符' }
if ($ViaExistingUser -and $ViaExistingUser -notmatch '^[A-Za-z_][A-Za-z0-9_-]*$') { throw 'ViaExistingUser 格式无效' }
if ($KeyName -notmatch '^[A-Za-z0-9_.-]+$' -or $KeyName -in @('.', '..')) { throw 'KeyName 必须是文件名' }
# 复用现有条目的实际密钥与端口,避免授权和验证使用不同密钥。
if (Test-Path $InventoryPath) {
  $prior = Get-Content $InventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $priorEntry = if ($Name) { $prior.servers.$Name } else { ($prior.servers.PSObject.Properties | Where-Object { $_.Value.host -eq $Host_ } | Select-Object -First 1).Value }
  if ($priorEntry -and $priorEntry.host -ne $Host_) { throw 'Name 已指向另一台主机,请使用新的 Name' }
  if ($priorEntry -and -not $PSBoundParameters.ContainsKey('Port') -and $priorEntry.port) { $Port = [int]$priorEntry.port }
  if ($priorEntry -and -not $CredDir -and -not $PSBoundParameters.ContainsKey('KeyName') -and $priorEntry.key) {
    $existingKey = [regex]::Replace([string]$priorEntry.key, '\$\{([A-Za-z_][A-Za-z0-9_]*)\}', {
      param($match)
      $value = [Environment]::GetEnvironmentVariable($match.Groups[1].Value)
      if (-not $value) { throw "未设置密钥环境变量 $($match.Groups[1].Value)" }
      return $value
    })
    if (-not [IO.Path]::IsPathRooted($existingKey)) { $existingKey = Join-Path (Split-Path -Parent $InventoryPath) $existingKey }
    if (-not (Test-Path -LiteralPath $existingKey)) { throw '清单引用的已有私钥不存在;请恢复密钥或显式指定 -CredDir 与 -KeyName,避免误生成替代密钥' }
    $CredDir = Split-Path -Parent $existingKey
    $KeyName = Split-Path -Leaf $existingKey
  }
}

# 新安装的凭据默认在仓库外;不搜索其他应用的私有目录。
if (-not $CredDir) {
  $userDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
  if (-not $userDir) { throw '无法确定用户目录;请显式指定 -CredDir' }
  $CredDir = Join-Path $userDir '.ssh\vps-ops-mcp'
}
$CredDir = [IO.Path]::GetFullPath($CredDir)
$KeyPath = Join-Path $CredDir $KeyName
$PubPath = "$KeyPath.pub"

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    [!]  $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "`n[失败] $m`n" -ForegroundColor Red; exit 1 }

# Windows PowerShell 5.1 drops empty native arguments. Launch directly so -N/-P
# always receive an actual empty string, and encrypted keys fail without prompting.
function Invoke-Keygen {
  param([string[]]$KeygenArgs)
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = (Get-Command ssh-keygen -CommandType Application).Source
  $quoted = foreach ($arg in $KeygenArgs) { '"' + $arg.Replace('"', '\"') + '"' }
  $start.Arguments = $quoted -join ' '
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = [System.Diagnostics.Process]::Start($start)
  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  $process.WaitForExit()
  $result = [pscustomobject]@{ Output = $stdout.Trim(); Error = $stderr.Trim(); ExitCode = $process.ExitCode }
  $process.Dispose()
  return $result
}

# ssh 失败时会往 stderr 写字,而 PowerShell 把原生命令的 stderr 当作 terminating error
# (配合 $ErrorActionPreference='Stop' 会直接中断整个脚本)。统一包一层:
# 临时放宽错误偏好,并显式回传退出码,让"连不上"成为可判断的结果而不是崩溃。
function Invoke-Ssh {
  param([string[]]$SshArgs, [string]$Target, [string]$RemoteCommand, [string]$Stdin)
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    if ($Stdin) {
      # 把脚本经 stdin 喂给远端(配合远端 `bash -s`),避免引号/换行在网络层被改写
      $out = $Stdin | & ssh @SshArgs $Target $RemoteCommand 2>&1
    } elseif ($RemoteCommand) {
      $out = & ssh @SshArgs $Target $RemoteCommand 2>&1
    } else {
      $out = & ssh @SshArgs $Target 2>&1
    }
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $prev
  }
  [pscustomobject]@{ Output = (($out | Out-String).Trim()); ExitCode = $code }
}

if (-not $Name) {
  # 先看清单里是否已有指向同一 host 的条目 —— 有就沿用它的名字。
  # 否则会按 IP 推导出一个新名字,于是同一台服务器出现两条记录
  # (一条旧的带人工备注、一条新建的),既混乱又会让 default 指向错误的名字。
  $known = $null
  if (Test-Path $InventoryPath) {
    try {
      $probe = Get-Content $InventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
      foreach ($p in $probe.servers.PSObject.Properties) {
        if ($p.Value.host -eq $Host_) { $known = $p.Name; break }
      }
    } catch { $known = $null }
  }
  if ($known) {
    $Name = $known
    Write-Host "`n[i] 清单中已有指向 $Host_ 的条目,沿用其名字: $Name" -ForegroundColor DarkGray
  } else {
    $Name = ($Host_ -replace '[^A-Za-z0-9-]', '-').Trim('-')
    if ($Name.Length -gt 32) { $Name = $Name.Substring(0, 32).Trim('-') }
    if (-not $Name) { $Name = 'vps1' }
  }
}

Write-Host "`n========================================" -ForegroundColor White
Write-Host " dsh-vps-ops 一键部署" -ForegroundColor White
Write-Host "  目标: $Host_  (清单名: $Name)" -ForegroundColor White
Write-Host "========================================" -ForegroundColor White

$me = "$env:COMPUTERNAME\$env:USERNAME"
function Lock-Acl([string]$target, [switch]$StripEveryone) {
  if (-not (Test-Path $target)) { return }
  # Build only a new DACL. Copying the security descriptor from ssh-keygen may
  # also copy a SACL that requires SeSecurityPrivilege for a normal user to set.
  $acl = if ((Get-Item -LiteralPath $target).PSIsContainer) {
    New-Object System.Security.AccessControl.DirectorySecurity
  } else {
    New-Object System.Security.AccessControl.FileSecurity
  }
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($identity in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, [System.Security.Principal.SecurityIdentifier]'S-1-5-18', [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
    $inherit = if ((Get-Item -LiteralPath $target).PSIsContainer) { 'ContainerInherit, ObjectInherit' } else { 'None' }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', $inherit, 'None', 'Allow')))
  }
  $item = Get-Item -LiteralPath $target
  if ($PSVersionTable.PSVersion.Major -ge 6) {
    [System.IO.FileSystemAclExtensions]::SetAccessControl($item, $acl)
  } else {
    $item.SetAccessControl($acl)
  }

}

# ---------------------------------------------------------------- 1. 本机密钥
Step '1/6 本机凭据(密钥 + ACL)'
if (-not (Test-Path $CredDir)) { New-Item -ItemType Directory -Path $CredDir -Force | Out-Null }
Lock-Acl $CredDir
if (Test-Path $KeyPath) {
  # 已存在就复用:重新生成会让服务器上已授权的公钥立即失效(表现为莫名的 Permission denied)
  Ok "复用已有密钥: $KeyPath"
} else {
  $generated = Invoke-Keygen -KeygenArgs @('-t', 'ed25519', '-f', $KeyPath, '-C', 'dsh-vps-ops', '-N', '', '-q')
  if ($generated.ExitCode -ne 0) { Die "ssh-keygen 生成密钥失败: $($generated.Error)" }
  Ok "已生成新密钥: $KeyPath"
}
Lock-Acl $KeyPath -StripEveryone
Lock-Acl $PubPath
$pubText = (Get-Content $PubPath -Raw).Trim()

# 生成/复用后校验配对:避免把一把坏密钥带进后续流程,到服务器上才以 Permission denied 暴露
$derivedResult = Invoke-Keygen -KeygenArgs @('-y', '-P', '', '-f', $KeyPath)
if ($derivedResult.ExitCode -ne 0) { Die "无法读取无口令专用私钥: $($derivedResult.Error)" }
$derived = $derivedResult.Output
$derivedB64 = ($derived -split '\s+')[1]
$storedB64 = ($pubText -split '\s+')[1]
if (-not $derivedB64 -or $derivedB64 -cne $storedB64) {
  Die "私钥与公钥不配对(或私钥有口令)。请核对私钥与 .pub 文件,不要覆盖已授权的密钥"
}
Ok '私钥/公钥配对校验通过'
Ok "公钥: $($pubText.Substring(0, [Math]::Min(50, $pubText.Length)))..."

# ---------------------------------------------------------------- 2. 连通性
Step "2/6 探测 $Host_ 的 SSH 可达性与主机指纹"
$tcp = Test-NetConnection -ComputerName $Host_ -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $tcp) { Die "无法连接 ${Host_}:$Port —— 检查 IP、安全组是否放行 22 端口" }
Ok "$Port 端口可达"

$probeScript = Join-Path $ProjectDir 'scripts\verify-host-fingerprint.js'
$probeOut = & node $probeScript $Host_ $Port --json
if ($LASTEXITCODE -ne 0) { Die "未能取得主机指纹: $probeOut" }
$probeData = ($probeOut | Out-String) | ConvertFrom-Json
$observed = $probeData.observedFingerprint
if (-not $observed -or -not $probeData.observedPublicKey) { Die '探测未返回完整主机公钥' }
Ok "观测指纹: $observed"

# ---------------------------------------------------------------- 3. 写入清单
Step '3/6 写入服务器清单'
$inventoryDir = Split-Path -Parent $InventoryPath
if (-not (Test-Path $inventoryDir)) { New-Item -ItemType Directory -Path $inventoryDir -Force | Out-Null }
if (-not (Test-Path $InventoryPath)) {
  [IO.File]::WriteAllText($InventoryPath, '{"servers":{}}', (New-Object Text.UTF8Encoding($false)))
}
$inv = Get-Content $InventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
$existing = $inv.servers.$Name
$pins = @($existing.fingerprints | ForEach-Object { ($_ -split '\s+')[-1].TrimEnd('=') })
if ($existing.fingerprints -and -not $Force -and $pins -notcontains $observed) {
  Die '指纹不一致 —— 核对后加 -Force 覆盖,并传入 -ExpectedFingerprint'
}
if ($Force -or $pins -notcontains $observed) {
  if (-not $ExpectedFingerprint) {
    Write-Host '请在服务器控制台执行 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub,独立核对指纹'
    $ExpectedFingerprint = Read-Host '输入核对后的 SHA256 指纹(留空中止)'
  }
  if ($ExpectedFingerprint.TrimEnd('=') -cne $observed) { Die '独立核对指纹未匹配,未写入信任记录' }
}
$knownHostsPath = Join-Path $CredDir "known_hosts-$Name"
$knownHost = if ($Port -eq 22) { $Host_ } else { "[${Host_}]:$Port" }
[IO.File]::WriteAllText($knownHostsPath, "$knownHost $($probeData.observedPublicKey)`n", (New-Object Text.UTF8Encoding($false)))
Lock-Acl $knownHostsPath -StripEveryone
if ($existing) {
  if ($existing.user -ne 'ops-us') { Die 'deploy.ps1 只接入 ops-us 账户,请核对清单' }
  if ([IO.Path]::GetFullPath($(if ([IO.Path]::IsPathRooted($existing.key)) { $existing.key } else { Join-Path $ProjectDir $existing.key })) -ne [IO.Path]::GetFullPath($KeyPath)) { Die '指定密钥与现有清单不同,请先核对并修改清单' }
  $existing | Add-Member -NotePropertyName fingerprints -NotePropertyValue @($observed) -Force
  $existing | Add-Member -NotePropertyName port -NotePropertyValue $Port -Force
  Ok "清单已有 $Name 条目,保留现有设置"
} else {
  $entry = [pscustomobject]@{
    note = "由 deploy.ps1 接入"; host = $Host_; port = $Port; user = 'ops-us'; key = $KeyPath
    fingerprints = @($observed); connectTimeoutMs = 15000; hardTimeoutMs = 120000; maxOutputBytes = 262144
  }
  $inv.servers | Add-Member -NotePropertyName $Name -NotePropertyValue $entry
}
if (-not $inv.default) { $inv | Add-Member -NotePropertyName default -NotePropertyValue $Name -Force }
[IO.File]::WriteAllText($InventoryPath, ($inv | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
Ok "已写入 $Name → ops-us@${Host_}:$Port,指纹已固定"

# ---------------------------------------------------------------- 4. 等服务端就绪
Step '4/6 检查服务器侧是否已就绪(ops-us 账户)'
$sshArgs = @(
  '-p', "$Port", '-i', $KeyPath, '-o', "UserKnownHostsFile=$knownHostsPath", '-o', 'GlobalKnownHostsFile=NUL', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
  '-o', 'ConnectTimeout=10', '-o', 'NumberOfPasswordPrompts=0'
)
$probeUser = Invoke-Ssh -SshArgs $sshArgs -Target "ops-us@$Host_" -RemoteCommand 'id'
if ($probeUser.ExitCode -ne 0 -or $UpdateServer) {
  Warn 'ops-us 还登不上 —— 需要在服务器上执行一次初始化(见下)'

  $setupSh = Join-Path $ProjectDir 'server-setup.sh'
  if (-not (Test-Path $setupSh)) { Die "找不到 $setupSh" }
  $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($setupSh))

  # 落一份到文件:终端复制长 base64 容易漏字符,从文件整段复制更稳
  $bootstrapPath = Join-Path $CredDir 'bootstrap.txt'
  & node (Join-Path $ProjectDir 'scripts\build-bootstrap.js') $PubPath $bootstrapPath
  if ($LASTEXITCODE -ne 0) { Die '生成引导命令失败' }
  $bootstrapLines = Get-Content $bootstrapPath

  Lock-Acl $bootstrapPath -StripEveryone

  # ---- 若有可用的"既有账户",就免掉手工粘贴:直接把脚本送上去执行 ----
  if ($ViaExistingUser) {
    Step "4b/6 借助既有账户 $ViaExistingUser 自动完成服务器侧初始化"
    $sudoPrefix = if ($NoSudo) { '' } else { 'sudo -n ' }
    $b64Path = Join-Path $CredDir 'server-setup.sh.b64'
    Set-Content -Path $b64Path -Value $b64 -Encoding ascii
    Lock-Acl $b64Path -StripEveryone

    $mode = if ($NoSudo) { @() } else { @('--sudo') }
    $remotePath = Join-Path $CredDir 'bootstrap-via.txt'
    & node (Join-Path $ProjectDir 'scripts\build-bootstrap.js') $PubPath $remotePath @mode
    if ($LASTEXITCODE -ne 0) { Die '生成自动初始化命令失败' }
    Lock-Acl $remotePath -StripEveryone
    $remote = Get-Content $remotePath -Raw

    # 经统一包装调用(失败不会中断脚本,而是走下面的降级分支)
    $via = Invoke-Ssh -SshArgs $sshArgs -Target "$ViaExistingUser@$Host_" -RemoteCommand 'bash -s' -Stdin $remote
    $code = $via.ExitCode
    ($via.Output) -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" }

    if ($code -eq 0) {
      Ok "服务器侧初始化已完成(由 $ViaExistingUser 代为执行)"
      Write-Host ''
      Write-Host '    安全提示:本次借用了权限更大的账户。建议现在收回它的临时访问权:' -ForegroundColor Yellow
      Write-Host "      ssh $ViaExistingUser@$Host_  然后删掉 authorized_keys 里本机那把(若原本就有则无需处理)" -ForegroundColor Yellow
      Write-Host '    本工具后续只使用受限账户 ops-us。' -ForegroundColor Yellow
      Write-Host ''
      # 重新探测 ops-us
      $recheck = Invoke-Ssh -SshArgs $sshArgs -Target "ops-us@$Host_" -RemoteCommand 'id'
      if ($recheck.ExitCode -eq 0) {
        Ok "ops-us 已可用: $($recheck.Output)"
      } else {
        Warn 'ops-us 仍登不上 —— 可能是 AllowUsers 未包含它(见上面脚本输出中的提示)'
        Warn "请查看 $ViaExistingUser 上执行时打印的 AllowUsers 提示"
      }
    } else {
      Warn "通过 $ViaExistingUser 执行初始化失败(exit $code),请改用人工粘贴方式:"
      Write-Host "    $bootstrapPath" -ForegroundColor Yellow
    }
  }

  # 若仍未就绪,打印人工粘贴指引
  $final = Invoke-Ssh -SshArgs $sshArgs -Target "ops-us@$Host_" -RemoteCommand 'id'
  if ($final.ExitCode -ne 0) {
    Write-Host "`n--------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host ' 请 SSH 登入服务器,以 root 执行下面这一整段(自包含,无需上传文件):' -ForegroundColor Yellow
    Write-Host " 也可从文件整段复制(推荐,避免漏字符): $bootstrapPath" -ForegroundColor Yellow
    Write-Host '--------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host ''
    $bootstrapLines | ForEach-Object { Write-Host $_ }
    Write-Host ''
    Write-Host "--------------------------------------------------------------" -ForegroundColor Yellow
    # 打印公钥指纹与全文:避免"我到底嵌了哪把钥匙"的歧义(调试时踩过这个坑)
    $fpLine = (& ssh-keygen -lf $PubPath 2>&1 | Out-String).Trim()
    Write-Host ' 本机公钥指纹(核对上面命令里嵌的是哪把钥匙):' -ForegroundColor Yellow
    Write-Host "   $fpLine" -ForegroundColor Yellow
    Write-Host "   完整公钥: $pubText" -ForegroundColor DarkGray
    Write-Host '--------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host ' 也可以让脚本代劳(免粘贴),前提是该服务器上有一个你已能登录的账户:' -ForegroundColor Yellow
    Write-Host '   1) 把上面那行完整公钥追加进该账户的 ~/.ssh/authorized_keys' -ForegroundColor Yellow
    Write-Host "   2) 运行:  .\deploy.ps1 -ViaExistingUser ubuntu" -ForegroundColor Yellow
    Write-Host '--------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host ' 跑完后重新执行(零参数即可):' -ForegroundColor Yellow
    Write-Host '   .\deploy.ps1' -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------`n" -ForegroundColor Yellow
    exit 2
  }
  Ok "ops-us 已就绪: $($final.Output)"
}
Ok "已登录: $($probeUser.Output)"

# ---------------------------------------------------------------- 5. 验收
Step '5/6 安全验收(提权面核验)'
$checks = @(
  @{ cmd = 'id'; expect = 'identity'; label = '受限账户身份正确' },
  @{ cmd = 'hostname'; expect = 'ok'; label = '主机名可读' },
  @{ cmd = 'sudo -n /usr/local/sbin/mcp-readonly docker ps -q'; expect = 'ok'; label = 'docker 只读提权可用' },
  @{ cmd = 'sudo -n /usr/local/sbin/mcp-readonly journalctl -n 1 --no-pager'; expect = 'ok'; label = 'journalctl 只读提权可用' },
  @{ cmd = 'sudo -n -l -- systemctl start docker'; expect = 'deny'; label = 'systemctl start 被拒' },
  @{ cmd = 'sudo -n -l -- systemctl edit docker'; expect = 'deny'; label = 'systemctl edit 被拒' },
  @{ cmd = 'sudo -n -l -- docker run --rm alpine true'; expect = 'deny'; label = 'docker run 被拒' },
  @{ cmd = 'sudo -n -l -- docker volume rm x'; expect = 'deny'; label = 'docker volume rm 被拒' },
  @{ cmd = 'sudo -n -l -- cat /etc/shadow'; expect = 'deny'; label = '读 shadow 被拒' },
  @{ cmd = 'sudo -n -l -- useradd hacker'; expect = 'deny'; label = '建账户被拒' },
  @{ cmd = 'sudo -n -l -- journalctl --rotate'; expect = 'deny'; label = '日志维护被拒' },
  @{ cmd = 'sudo -n -l -- dmesg -C'; expect = 'deny'; label = '清内核日志被拒' },
  @{ cmd = 'sudo -n -l -- ss -K'; expect = 'deny'; label = '断开连接被拒' },
  @{ cmd = 'id -nG'; expect = 'groups'; label = '无特权组' }
)
$failed = @()
foreach ($c in $checks) {
  $r = Invoke-Ssh -SshArgs $sshArgs -Target "ops-us@$Host_" -RemoteCommand $c.cmd
  $pass = if ($c.expect -eq 'ok') { $r.ExitCode -eq 0 } elseif ($c.expect -eq 'identity') { $r.ExitCode -eq 0 -and $r.Output -match 'uid=[1-9][0-9]*\(ops-us\)' } elseif ($c.expect -eq 'groups') { $r.ExitCode -eq 0 -and $r.Output -notmatch '\b(root|sudo|wheel|docker|lxd|incus-admin|disk)\b' } else { $r.ExitCode -eq 1 }
  if ($pass) {
    Write-Host "    ✓ $($c.label)" -ForegroundColor Green
  } else {
    Write-Host "    ✗ $($c.label)  ← 与预期不符!" -ForegroundColor Red
    $failed += $c.label
  }
}
if ($failed.Count -gt 0) {
  Warn "明细请跑:node scripts/verify-onboarding.js $Name"
  Warn '已有旧版账户请加 -UpdateServer 更新服务端包装程序,或按 README 的手工方式重新初始化'
  Die "安全验收失败($($failed -join ', ')),未执行 MCP 启用步骤"
} else {
  Ok "全部 $($checks.Count) 项符合预期"
}

# ---------------------------------------------------------------- 6. 启用 MCP
if ($BootstrapOnly) {
  Step '6/6 跳过启用(-BootstrapOnly)'
  Warn '未生成或更新客户端配置;下次去掉 -BootstrapOnly 通过验收后生成配置'
  Write-Host "`n[完成] 服务器已接入清单,MCP 未启用`n" -ForegroundColor Green
  exit 0
}

Step '6/6 配置 MCP 客户端'
if ($ProfileFile) {
  & node (Join-Path $ProjectDir 'scripts\configure-profile.js') $ProfileFile --enable --inventory $InventoryPath
  if ($LASTEXITCODE -ne 0) { Die 'profile 写入失败,部署未完成' }
  Ok '显式指定的 DSH profile 已更新并启用'
} else {
  $clientConfig = Join-Path $ProjectDir 'output\mcp-config.json'
  & node (Join-Path $ProjectDir 'scripts\configure-mcp.js') $clientConfig --inventory $InventoryPath
  if ($LASTEXITCODE -ne 0) { Die '客户端配置生成失败,部署未完成' }
  Ok "客户端配置已生成:$clientConfig;请将 mcpServers.vps 合并到 MCP 客户端配置"
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " 部署完成" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host @"

下一步:
  1. 合并生成的配置后重启 MCP 客户端;显式接入 DSH 时重启 DSH
  2. 详细验收:  node scripts/verify-onboarding.js $Name
  3. 查看清单:  node -e "import('./src/inventory.js').then(m=>console.log(m.loadInventory({}).list.map(m.describeServer)))"

撤销(随时):
  本机:  从客户端删除 vps 条目;DSH 中把 mcp-vps-ops 的 enabled 改回 false
  服务器: sed -i '/dsh-vps-ops/d' /home/ops-us/.ssh/authorized_keys
          rm -f /etc/sudoers.d/90-ops-us
          rm -f /etc/ssh/sshd_config.d/60-ops-us-allowusers.conf && systemctl reload ssh
          userdel -r ops-us

"@ -ForegroundColor Gray
