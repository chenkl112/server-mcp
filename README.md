# dsh-vps-ops-mcp

通过 SSH 管理多台 Linux 服务器的本地 MCP 服务。提供状态快照、受限只读命令、**浏览器人工审批**的写操作和审计日志。当前版本：0.5.0。

**0.5.0 的关键变化：批准不再是一个布尔参数。** 所有写操作（含 `sudo_exec` / `delete_path` / `fetch_url`）都会在用户浏览器里弹出一次性页面，显示命令原文、风险等级、逐条风险点与回滚建议；人在页面上点"允许"才执行。被提示注入的模型无法代替这次点击。

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
| `-FullSudo` | 服务端给 ops-us **完整 sudo**（root）。会取消服务器侧所有边界，见「sudo 的两种模式」 |

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

### Codex CLI 接入

Codex 用 TOML（`~/.codex/config.toml`），所以有独立的生成器（`configure-mcp.js` 只出 JSON）：

```powershell
node scripts/configure-codex.js                  # 只看会写成什么，不落盘
node scripts/configure-codex.js --write          # 合并写回（自动备份原文件）
node scripts/configure-codex.js --config <路径>  # 指定配置文件（默认 $CODEX_HOME 或 ~/.codex）
```

合并规则（全部有测试守着）：

| 规则 | 说明 |
|---|---|
| 只动两张表 | `[mcp_servers.vps]` 与 `[mcp_servers.vps.env]`，其他表与注释逐字节保留 |
| 保留扩展键 | 表里它不认识的键（例如你加的 `cwd`、额外环境变量）原样留着 |
| 幂等 | 同样的配置跑两次，第二次报"已经是目标状态" |
| 看不懂就拒绝 | 内联表 `mcp_servers.vps = {…}`、跨行数组 → 报错让你手工改，不猜 |

**必须写 `default_tools_approval_mode = "approve"`。** Codex 自己也有 MCP 工具审批层，默认 `auto` 会按工具的 `destructiveHint` 判��，把本项目的写工具拦在**调用服务端之前**：

```
mcp: vps/sudo_exec (failed)
MCP tool call requires approval, but approval policy is never
```

这时请求根本没发出去，用户会误以为服务端坏了。本项目的审批是自己在 MCP 进程内做的（浏览器一次性页面），所以正确接法是让 Codex 放行、由这一层问人。合法值：`auto` / `prompt` / `writes` / `approve`（由 Codex 的 serde 校验给出）。

生成的片段长这样（注意 `tool_timeout_sec` 必须大于审批等待的 45 秒）：

```toml
[mcp_servers.vps]
command = "…\\node.exe"
args = ["…\\server-mcp\\src\\index.js"]
enabled = true
default_tools_approval_mode = "approve"
startup_timeout_sec = 20
tool_timeout_sec = 620

[mcp_servers.vps.env]
DSH_VPS_INVENTORY = "…\\server-mcp\\servers.json"
DSH_VPS_ALLOW_TOFU = "0"
```

**已经验证过**（Codex CLI 0.163.0）：

| 验证项 | 结果 |
|---|---|
| 只要能启动并列出工具 | ✅ `codex mcp list` 显示 `vps` enabled |
| 只读工具调用 | ✅ `policy_info` 返回 `approval.mode: prompt`、`writeChannels: 4` |
| 写工具是否被 Codex 自己拦 | ✅ 默认 `auto` 会被拦（报上面那条错误）；`approve` 后放行 |
| 放行后是否由本服务端把关 | ✅ 用 `DSH_VPS_APPROVAL_MODE=deny` 覆盖时返回 `status: denied` |
| 完整链路 | ✅ Codex 调用 `sudo_exec` → 浏览器弹审批页 → 点"允许" → 返回 `status: executed`；审计留下 `outcome=authorized`/`executed`、`approval.source=local-ui`、`pageLoaded=true` |

Codex 自己的 `approval` 策略与这里的闸门是**两层**：Codex 那层决定"这个工具调用要不要让客户端插手"，本项目的闸门决定"这条命令要不要人点"。两层都开着会双重打扰，所以配 `approve` 把判断权交给本闸门。

### 验证审批弹窗能不能打开

```powershell
node scripts/verify-approval-page.js
```

它只在本地起一个演示页面（不连接任何服务器、不执行任何命令），然后看浏览器是否真的打开了它。**失败就意味着所有写操作都会返回 denied**，因为闸门是 fail-closed 的。排查项：默认浏览器关联、`rundll32 url.dll,FileProtocolHandler` 是否被组策略/安全软件拦截。

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
| `review_command` | **只审查不执行**：返回风险等级、逐条风险点、回滚建议、会不会被硬拦 |
| `ssh_exec_approved` | 普通写操作（非 root）；两阶段，需用户回复确认 |
| `sudo_exec` | 以 root 执行；两阶段，需用户回复确认 |
| `delete_path` | 结构化删除（绝对路径 + `recursive`），删除类强制置顶审查 |
| `fetch_url` | 只下载到指定路径、**绝不执行**，回传 sha256 便于核对 |
| `approval_resume` | 把用户的回复落实为审批结果（`decision` + `userReply`），或继续等浏览器页面 |
| `read_audit_log` | 查询命令尝试、审批来源、风险等级与结果，或最近记录的汇总 |
| `policy_info` | 查看策略、审批模式、指纹固定状态和限制 |

状态快照的 Docker 和日志诊断可以调用服务端只读包装程序；每台同时最多 4 条 SSH 命令。其他只读命令受账户本身权限限制。

## 人工审批闸门（0.5.0）

**为什么不是布尔参数。** 早期版本只要求调用方传 `approvedByUser: true`。那是**模型自己填的字段**：被提示注入的 agent 写个 `true` 就执行了，审计里也分不出"用户真的同意过"和"它自己声明的"。

默认是**对话确认（chat）**，写操作分两阶段：

```
第 1 次调用 sudo_exec
  → { status: "awaiting-user", approvalId, promptForUser }
      promptForUser：命令原文 + 风险等级 + 逐条风险点 + 回滚建议
  → 模型把这段原样发给你，结束本轮，等你回复
你回「允许执行」
  → 模型调用 approval_resume(approvalId, decision="allow", userReply="允许执行")
  → 这时才真正执行
```

三道防"模型自己批准"的闸：

| 闸 | 作用 |
|---|---|
| 两阶段 | 第一次调用**绝不执行**，只返回确认稿 |
| 必须带 `userReply` | 缺了就返回 `needs-user-reply`；那句原话进审计，编造了事后看得见 |
| `minDelayMs`（默认 8 秒） | 同一轮里立刻批准 → `too-fast`。用户不可能在 8 秒内读完风险报告 |

**这个模式比浏览器模式弱，得说清楚**：服务端无法验证"用户真的回复过"，只能验证"模型带来了原话"和"时间上说得通"。需要强保证时用 `prompt` 模式——浏览器一次性页面（令牌 256 位、一次性、5 分钟过期、非法尝试 10 次即关闭），那条路径模型无法伪造。

| 模式 | 值 | 谁做决定 |
|---|---|---|
| chat（默认） | `DSH_VPS_APPROVAL_MODE=chat` | 你在对话里回话，模型转交 |
| prompt | `DSH_VPS_APPROVAL_MODE=prompt` | 你在浏览器页面上点"允许" |
| deny | `DSH_VPS_APPROVAL_MODE=deny` | 一律拒绝（无人值守） |
| allow | `DSH_VPS_APPROVAL_MODE=allow` | 跳过（仅测试，启动告警） |

`prompt` 模式的确认强度随等级变化（**服务端二次校验**，不依赖浏览器 `required`）：高危及致命需勾选"已阅读风险"，致命还需手输 `确认执行`。

环境变量：`DSH_VPS_APPROVAL_TTL_MS`（chat 默认 30 分钟 / prompt 默认 5 分钟）、`DSH_VPS_CHAT_MIN_DELAY_MS`（默认 8000）、`DSH_VPS_APPROVAL_WAIT_MS`（仅 prompt，默认 45000）。

**它挡住什么、挡不住什么。** 挡住了"模型自己声明批准就执行"，也挡住了"模型悄悄换一条命令执行"。**没挡住**一个能直接控制 MCP 进程的对手；真正的硬边界是服务端 sudo 规则（见下）。

## 风险审查引擎（0.5.0）

`src/risk.js` 对命令做**可解释的静态判定**，产出等级、类别、逐条风险点与回滚建议；它不决定能否执行，只决定用户被怎样提醒。六类扫描：删除、下载、提权、服务与系统、不可静态评估（解释器/`eval`/`xargs`）、凭据。

两处刻意设计：**删除与下载是强制审查类别**，即使等级只有"中"也会在审批页置顶标红；扫描**跑两遍**（原文 + 去引号形态），否则 `bash -c "rm -rf /opt"` 里的 `rm` 会因前面是引号而漏判。

## sudo 的两种模式

| 模式 | sudoers | 谁还能兜底 |
|---|---|---|
| `readonly`（默认） | 只有 root 所有的 `mcp-readonly` 包装程序 | 服务端仍是硬边界：`systemctl start`、`rm -rf /root`、`apt install` 一律被拒 |
| `--full-sudo` | `ops-us ALL=(ALL) NOPASSWD: ALL` | **没有服务端边界了**。能不能做某事只取决于审批页有没有人点"允许" |

```bash
sudo bash server-setup.sh 'ssh-ed25519 AAAA... comment'                # 只读（默认）
sudo bash server-setup.sh 'ssh-ed25519 AAAA... comment' --full-sudo    # 完整 sudo
# 收回：用 --readonly 重跑同一份脚本
```

两种模式下 `sudo_exec` 都会硬拦：磁盘/分区级破坏（`mkfs`/`wipefs`/`fdisk`/`parted`）、裸写块设备（`dd of=/dev/*`、`> /dev/sda`）、删根（`rm -rf /`、`--no-preserve-root`、fork bomb）、系统授权根文件（`/etc/passwd`、`/etc/sudoers`、`/etc/shadow`、`authorized_keys`）。

> 与批准通道的差别是**刻意**的：`ssh_exec_approved` 仍不接受解释器、账户变更、防火墙变更；`sudo_exec` 只拦上面四类，其余交给"每次人工点击 + 致命级手输短语"。选了完整 sudo，就是把判断权交回给人，而不是假装系统还拦得住。

## 安全边界

SSH 的 exec 请求最终由**远端 shell**执行。命令守卫先识别支持的 shell 结构，再检查命令、参数和路径；拒绝变量展开、命令替换、反斜杠变形、未闭合引号、控制字符、后台执行和不支持的语法。只读命令可使用分号及有限的过滤管道，写重定向被拒绝，`1>/dev/null` 和 `2>/dev/null` 除外。只读工具的写文件或改状态参数另行限制。

批准通道也不接受任意程序或解释器；文件写操作要求确定的绝对路径，禁止触碰账户、sudoers、计划任务、主机私钥、关键系统目录等对象，以及删除 Docker 数据卷、批量清理和磁盘破坏。每个命令片段分别检查，避免前一条正常操作掩盖后一条危险操作。

服务端创建非 root 的 `ops-us`，拒绝已有特权组成员身份。账户 home、`.ssh` 和公钥授权文件由 root 所有，避免账户自行替换授权或对初始化路径发起符号链接攻击。已有 AllowUsers 必须包含 ops-us；未设置时保留原管理员登录策略。

sudo 只放行 root 所有的 `/usr/local/sbin/mcp-readonly`。该程序逐 argv 校验 Docker 只读子命令、journalctl 查询、dmesg 展示和 ss 状态选项，并在干净环境里执行固定二进制。直接 sudo 执行原始工具均不在新规则中。日志/内核工具禁用 pager，Docker 日志与 stats 有固定输出/流限制。

权限自检使用 `sudo -n -l -- <command>` **查询授权**，不会通过实际停止 Docker、创建账户或清空日志来探测权限。既有系统额外的 sudo 配置仍需管理员核对；脚本的拒绝查询覆盖常见提权能力，不能代替对整台主机的安全审计。

`approvedByUser` 只是调用方"我已经把这事跟用户说过"的声明，**真正生效的是浏览器里那次点击**（见「人工审批闸门」）。服务器受限账户和 sudo 规则是另一层限制，客户端字符串检查不构成完整操作系统沙箱，也不解析远端符号链接。

只读输出可能包含日志、Docker 配置或应用主动打印的敏感值；凭据路径拦截不是通用内容脱敏。请按实际用途选择可见内容。

SSH 的 stdout 和 stderr **各自**按 `maxOutputBytes` 限制，支持跨 chunk 的 UTF-8；截断处的不完整字符不会变成乱码。超时返回 `timedOut` 并断开连接，不能据此认定远端动作已停止或已回滚。

## 审计与验证

默认审计文件为 `audit/approved-writes.jsonl`，支持用环境变量覆盖。记录命令、目标、原因、哈希、**工具名、是否 root、风险等级与类别、审批来源与等待时长**、结果及输出字节数，不记录 stdout/stderr 内容。批准执行前必须先写入 `authorized` 记录，失败时不发送命令；执行后追加结果。命令文本超过 2000 字符会截断，完整 SHA-256 保留。只读任意命令及被拒绝尝试也会留痕；内置状态快照不逐条记录审计。请按需管理日志轮转与保留时间。

```powershell
pnpm test       # 139 个测试:临时密钥、本地 SSH 服务、审批闸门真发 HTTP、Codex TOML 合并、隔离的 PowerShell 部署及 Bash 包装程序
pnpm smoke      # stdio MCP 握手、14 个工具、拒绝策略和审计；只连接本机测试地址
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
