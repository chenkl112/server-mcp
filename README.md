# dsh-vps-ops-mcp

通过 SSH 管理多台 Linux 服务器的本地 MCP 服务。提供状态快照、受限只读命令、逐次批准的写操作和审计日志。当前版本：0.4.0。

源码和示例不绑定盘符、用户名称、凭据目录或 MCP 客户端。Windows 支持自动部署;Linux/macOS 可手工接入。私人服务器清单、密钥和历史文件不属于发布内容。

## 快速部署

Windows 自动部署需要 Windows PowerShell 5.1 或 PowerShell 7、Node.js 22+、pnpm 11 和 Windows OpenSSH 客户端。MCP 运行时本身支持 Node.js 18+;本项目使用 Node.js 22/24 验证发布流程。目标服务器需要 Bash、sudo/visudo、OpenSSH 服务端、Docker、journalctl、dmesg 和 ss。

```powershell
cd server-mcp  # 克隆仓库后进入项目目录
pnpm install --frozen-lockfile
pnpm verify
```

首次接入前，在服务器控制台或已信任的管理员会话中获取主机指纹：

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

再在本机部署，使用实际的 IP 和指纹替换示例值：

```powershell
.\deploy.ps1 -TargetHost 192.0.2.10 -Name web1 -ExpectedFingerprint 'SHA256:实际核对后的值'
```

脚本生成或复用专用密钥，重建凭据 ACL，探测主机公钥，并将核对后的公钥写入专用 `known_hosts-web1`。所有 OpenSSH 调用均启用严格主机验证，使用该文件。

如果 `ops-us` 尚不能登录，脚本生成项目外的 `bootstrap.txt`，打印完整初始化命令并以退出码 **2** 结束。在目标服务器的 **root 会话**执行该文件中的整段命令，再运行部署脚本。引导命令通过管道传输内嵌脚本，不使用可预测的 `/tmp/server-setup.sh`。

已有能登录的管理员账户时，可以自动初始化：

```powershell
.\deploy.ps1 -Name web1 -ViaExistingUser ubuntu
```

管理员账户需已授权同一把专用公钥并具有免密 sudo；若该账户本身是 root，使用 `-NoSudo`。脚本使用 `sudo -n`，不会等待密码输入。

安全验收全部通过后生成 `output/mcp-config.json`，将其 `mcpServers.vps` 合并到支持 stdio 的 MCP 客户端配置并重启客户端。只有显式传入 `-ProfileFile <文件>` 时才备份并更新 DSH YAML、启用 `mcp-vps-ops`。任一权限检查、身份检查或 SSH 查询异常都会以退出码 **1** 终止，跳过启用步骤。已经启用的配置不会被脚本自动关闭。

### 更新已有服务器

旧版 sudoers 直接放行日志工具，需重新安装本版服务端规则：

```powershell
.\deploy.ps1 -Name web1 -UpdateServer -ViaExistingUser ubuntu
```

没有可用管理员 SSH 通道时，独立生成手工引导文件：

```powershell
node scripts/build-bootstrap.js (Join-Path $env:USERPROFILE '.ssh/vps-ops-mcp/vps_ops_ed25519.pub') .\bootstrap-update.txt
```

在服务器 root 会话执行生成的命令后，删除本机临时引导文件并重新部署。单独验收：

```powershell
node scripts/verify-onboarding.js web1
```

### 常用参数

| 参数 | 用途 |
|---|---|
| `-TargetHost` / `-Host` | IP 或域名；省略时从指定 Name、default 或唯一条目推断 |
| `-Name` | 服务器名称；可只指定 Name 接入已有记录 |
| `-Port 2222` | 自定义 SSH 端口；默认复用已有条目的端口 |
| `-CredDir <目录>` | 显式指定项目外的凭据目录 |
| `-KeyName <文件名>` | 专用密钥文件名，默认 `vps_ops_ed25519` |
| `-ExpectedFingerprint SHA256:...` | 首次或换钥时独立核对得到的指纹；省略时交互输入 |
| `-Force` | 允许更新原固定指纹，仍必须独立核对新指纹 |
| `-UpdateServer` | 即使 ops-us 已能登录，也重新安装服务端规则 |
| `-BootstrapOnly` | 接入和验收，但不生成或修改客户端配置 |
| `-ProfileFile <文件>` | 可选 DSH YAML 文件;不指定时生成通用 MCP JSON |
| `-InventoryPath <文件>` | 私有清单路径;默认 `DSH_VPS_INVENTORY` 或项目内 `servers.json` |

新安装默认凭据目录为用户目录下的 `.ssh/vps-ops-mcp`。选择顺序为 `-CredDir`、环境变量 `VPS_OPS_CRED_DIR`、已有清单条目的密钥位置、用户目录默认值。已有条目引用的密钥丢失时中止，不悄悄生成替代密钥；只有显式指定目录或密钥名时才切换。Windows ACL 仅保留当前用户、SYSTEM 和 Administrators，清除其他显式和继承授权。自动部署使用无口令专用密钥；加密密钥可由 MCP 运行时通过清单口令加载，部署脚本会明确拒绝并避免等待输入。

`setup-local.ps1` 是兼容转发入口，支持上述部署参数；它的 `-Directory` 转发为 `-CredDir`，`-KeyName` 和开关按名称转发。

## 清单与配置

`servers.json` 位于项目根目录；新安装可从 `servers.example.json` 复制。加服务器只需编辑清单，不必修改源码，保存后热生效。

```json
{
  "default": "web1",
  "servers": {
    "web1": {
      "host": "192.0.2.10",
      "port": 22,
      "user": "ops-us",
      "key": "${VPS_OPS_KEY}",
      "fingerprints": ["SHA256:实际核对后的值"],
      "connectTimeoutMs": 15000,
      "hardTimeoutMs": 120000,
      "maxOutputBytes": 262144
    }
  }
}
```

环境变量占位符 `${VARIABLE}` 可用于 host、port、user、key 和 passphrase。未替换值、无效端口、私钥不存在或不可解析、错误口令、缺少指纹都会使认证操作拒绝执行。口令保留首尾空格。相对密钥路径相对于清单目录解析。

首次 `host_key` 探测只要求合法 host 和 port，不读取或提交认证密钥。它提供的是**观测指纹**，需要独立核对后才能加入信任；普通工具仍要求完整认证材料和固定指纹。`DSH_VPS_ALLOW_TOFU` 不会开启自动信任。兼容的全局指纹变量仍可使用，但建议逐服务器配置。

| 环境变量 | 用途 |
|---|---|
| `DSH_VPS_INVENTORY` | 覆盖清单路径 |
| `DSH_VPS_AUDIT_LOG` | 覆盖审计 JSONL 路径 |
| `DSH_VPS_HOST_FINGERPRINTS` | 兼容的全局兜底指纹，建议留空 |

### 通用 MCP 客户端

```sh
node scripts/configure-mcp.js output/mcp-config.json
# 清单位于仓库外时:
node scripts/configure-mcp.js output/mcp-config.json --inventory /path/to/servers.json
```

生成器用当前 Node 可执行文件和项目路径生成绝对路径，不要求清单已存在，不发起 SSH。复制生成的 `mcpServers.vps` 到客户端配置。也可显式传入现有客户端 JSON，更新时保留其他服务并先备份。生成的配置包含本机路径，应留在私有文件或被忽略的 `output/` 下。移动项目或 Node 后重新生成。

### 可选 DSH 接入

```sh
node scripts/configure-profile.js <profile.yml> --disabled
# 完成服务端初始化和验收后:
node scripts/configure-profile.js <profile.yml> --enable --inventory <servers.json>
```

`dsh-profile-snippet.yml` 仅为含占位符的禁用模板。生成器保留其他条目、注释和扩展配置，拒绝重复条目或非法 YAML，写入前备份。不会搜索或修改默认个人 profile。

### Linux/macOS 手工接入

```sh
pnpm install --frozen-lockfile
mkdir -p "$HOME/.ssh/vps-ops-mcp"
chmod 700 "$HOME/.ssh/vps-ops-mcp"
ssh-keygen -t ed25519 -f "$HOME/.ssh/vps-ops-mcp/vps_ops_ed25519"
chmod 600 "$HOME/.ssh/vps-ops-mcp/vps_ops_ed25519"
node scripts/build-bootstrap.js "$HOME/.ssh/vps-ops-mcp/vps_ops_ed25519.pub" bootstrap.txt
cp servers.example.json servers.json
```

在目标服务器的 root 会话运行 `bootstrap.txt` 的整段命令，然后删除该本机文件。编辑私有 `servers.json` 的实际 host 和独立核对后的指纹，并将 `VPS_OPS_KEY` 设为私钥绝对路径。若使用加密私钥，可在清单中配置 `"passphrase": "${VPS_OPS_PASSPHRASE}"`，通过环境变量提供口令。MCP 客户端需继承这些环境变量，或在私有清单中填写实际路径。运行 `node scripts/verify-onboarding.js web1` 通过验收后再生成客户端配置。

## 工具

| 工具 | 行为 |
|---|---|
| `list_servers` | 列出服务器及就绪问题，不建立连接 |
| `host_key` | 无认证 SSH 握手探测，不自动信任 |
| `test_connection` | 验证登录、身份、Docker 可用性和部分权限情况 |
| `status_snapshot` | 采集 identity/resources/docker/network/security/logs；支持分组及最多 5 台服务器 |
| `read_only_command` | 白名单和 shell 结构校验后的只读命令，禁止用户提供 sudo |
| `read_file` | 读取确定的绝对路径，默认最多 256 KiB，拒绝凭据形态及引号、转义、展开 |
| `ssh_exec_approved` | 支持的运维命令，要求明确批准并通过硬性禁止检查 |
| `read_audit_log` | 查询命令尝试、结果或最近记录的汇总 |
| `policy_info` | 查看策略、指纹固定状态和限制 |

状态快照的 Docker 和日志诊断可以调用服务端只读包装程序；每台同时最多 4 条 SSH 命令。其他只读命令受账户本身权限限制。

## 安全边界

SSH 的 exec 请求最终由**远端 shell**执行。命令守卫先识别支持的 shell 结构，再检查命令、参数和路径；拒绝变量展开、命令替换、反斜杠变形、未闭合引号、控制字符、后台执行和不支持的语法。只读命令可使用分号及有限的过滤管道，写重定向被拒绝，`1>/dev/null` 和 `2>/dev/null` 除外。只读工具的写文件或改状态参数另行限制。

批准通道也不接受任意程序或解释器；文件写操作要求确定的绝对路径，禁止触碰账户、sudoers、计划任务、主机私钥、关键系统目录等对象，以及删除 Docker 数据卷、批量清理和磁盘破坏。每个命令片段分别检查，避免前一条正常操作掩盖后一条危险操作。

服务端创建非 root 的 `ops-us`，拒绝已有特权组成员身份。账户 home、`.ssh` 和公钥授权文件由 root 所有，避免账户自行替换授权或对初始化路径发起符号链接攻击。已有 AllowUsers 必须包含 ops-us；未设置时保留原管理员登录策略。

sudo 只放行 root 所有的 `/usr/local/sbin/mcp-readonly`。该程序逐 argv 校验 Docker 只读子命令、journalctl 查询、dmesg 展示和 ss 状态选项，并在干净环境里执行固定二进制。直接 sudo 执行原始工具均不在新规则中。日志/内核工具禁用 pager，Docker 日志与 stats 有固定输出/流限制。

权限自检使用 `sudo -n -l -- <command>` **查询授权**，不会通过实际停止 Docker、创建账户或清空日志来探测权限。既有系统额外的 sudo 配置仍需管理员核对；脚本的拒绝查询覆盖常见提权能力，不能代替对整台主机的安全审计。

`approvedByUser` 是调用方对明确批准的声明，不是独立的身份认证或密码验证。MCP 客户端应向用户展示完整命令、影响和回滚方式后再提交批准。服务器受限账户和 sudo 规则是另一层限制，客户端字符串检查不构成完整操作系统沙箱，也不解析远端符号链接。

只读输出可能包含日志、Docker 配置或应用主动打印的敏感值；凭据路径拦截不是通用内容脱敏。请按实际用途选择可见内容。

SSH 的 stdout 和 stderr **各自**按 `maxOutputBytes` 限制，支持跨 chunk 的 UTF-8；截断处的不完整字符不会变成乱码。超时返回 `timedOut` 并断开连接，不能据此认定远端动作已停止或已回滚。

## 审计与验证

默认审计文件为 `audit/approved-writes.jsonl`，支持用环境变量覆盖。记录命令、目标、原因、哈希、结果及输出字节数，不记录 stdout/stderr 内容。批准执行前必须先写入 `authorized` 记录，失败时不发送命令；执行后追加结果。命令文本超过 2000 字符会截断，完整 SHA-256 保留。只读任意命令及被拒绝尝试也会留痕；内置状态快照不逐条记录审计。请按需管理日志轮转与保留时间。

```powershell
pnpm test       # 临时密钥、本地 SSH 服务、隔离的 PowerShell 部署及 Bash 包装程序测试
pnpm smoke      # stdio MCP 握手、9 个工具、拒绝策略和审计；只连接本机测试地址
pnpm audit --prod
```

测试不读取正式私钥或用户的 live profile，不连接正式服务器。安全修复及验证范围见 [SECURITY-REVIEW.md](SECURITY-REVIEW.md)。GitHub Actions 在 Windows/Linux 与 Node.js 22/24 的矩阵中执行相同验证;Windows 自动部署行为仅在 Windows 上测试。

## 撤销

先删除 MCP 客户端的 `vps` 条目;DSH 用户将 `mcp-vps-ops` 关闭。在服务器管理员会话中撤销：

```bash
rm -f /etc/sudoers.d/90-ops-us /usr/local/sbin/mcp-readonly
rm -f /home/ops-us/.ssh/authorized_keys
# 确认无需保留该账户下的资料后：
userdel -r ops-us
```

如之前手动添加过 SSH 登录规则，按实际配置移除 ops-us 并执行 `sshd -t` 后重载 SSH。专用密钥可能被多台服务器共用，删除本机凭据前先检查所有清单条目。

## 发布到 GitHub

```sh
pnpm verify
pnpm release:export
```

导出目录位于 `output/github-ready-*`，仅复制明确列出的源码、测试、示例、文档和 CI，并附 SHA-256 清单。导出前检查固定 Windows 绝对路径、私钥材料及部分令牌形态。`servers.json`、密钥、审计日志、历史记录、备份和生成配置保留本机，Git 忽略它们。检查导出内容后可将该目录作为发布源，或从当前仓库提交公开文件。

```sh
git status --short
git add .
git diff --cached --stat
# 检查暂存内容后提交,并关联你自己的 GitHub 仓库地址:
git commit -m "Prepare portable MCP server"
git remote add origin <YOUR_GITHUB_REPOSITORY_URL>
git push -u origin main
```

导出检查不替代人工检查后续新增内容;自定义私有配置请保存在 `output/`、仓库外或 `*.local.*` 文件中。当前 `private: true` 阻止误发布到 npm，不影响上传 GitHub。仓库未预设远程地址、作者身份或许可证;公开分发前请选择适合项目的许可证。
