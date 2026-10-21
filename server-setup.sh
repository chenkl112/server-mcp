#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 在目标服务器上执行一次:创建受限运维账户、专用 SSH 公钥、sudo 规则。
#
# 用法(在服务器上以 root 运行):
#   sudo bash server-setup.sh 'ssh-ed25519 AAAA... comment'                  # 只读 sudo(默认,推荐)
#   sudo bash server-setup.sh 'ssh-ed25519 AAAA... comment' --full-sudo      # 完整 sudo(全部 root 权限)
#
# 两种模式的区别:
#
#   readonly(默认)
#     sudo 只授权给 root 所有的只读包装程序 mcp-readonly,逐 argv 校验后再执行固定二进制。
#     这是**服务器侧**的硬边界:即使 MCP 的审批被绕过,agent 也拿不到能改系统的权限。
#
#   --full-sudo
#     ops-us 拿到 `NOPASSWD: ALL`,即整台机器的 root。
#     此时**没有任何服务器侧边界**:能不能做某事,只取决于 MCP 侧的审批页面有没有人点"允许"。
#     只有在你确实需要 AI 做部署、重启服务、清理 /root 之类的活时才用;用完请重跑 --readonly。
#
# 其他安全设计(两种模式都生效):
#   * 专用账户 ops-us,不加入 docker 组(docker 组等价 root)
#   * 已有 AllowUsers 必须包含 ops-us;未配置时不改变管理员登录策略
#   * 不安装任何常驻服务、不开放任何新端口
# ---------------------------------------------------------------------------
set -euo pipefail

PUBKEY=""
MODE="readonly"
for arg in "$@"; do
  case "$arg" in
    --full-sudo) MODE="full" ;;
    --readonly)  MODE="readonly" ;;
    *)
      if [[ -z "$PUBKEY" ]]; then
        PUBKEY="$arg"
      else
        echo "错误: 多余的参数 '$arg'" >&2; exit 1
      fi
      ;;
  esac
done

OPS_USER="ops-us"
SUDOERS_FILE="/etc/sudoers.d/90-${OPS_USER}"
SSHD_DROPIN="/etc/ssh/sshd_config.d/60-ops-us-allowusers.conf"
WRAPPER="/usr/local/sbin/mcp-readonly"

die() { echo "错误: $*" >&2; exit 1; }

[[ -n "$PUBKEY" ]] || die "用法: sudo bash server-setup.sh 'ssh-ed25519 AAAA... comment' [--full-sudo]"
[[ "$PUBKEY" != *$'\n'* && "$PUBKEY" != *$'\r'* && "$PUBKEY" =~ ^(ssh-|ecdsa-|sk-) ]] || die "公钥格式不对(应以 ssh-ed25519 / ssh-rsa / ecdsa- 开头)"
[[ "$(id -u)" -eq 0 ]] || die "请用 root 运行(或 sudo)"
key_tmp="$(mktemp)"
printf '%s\n' "$PUBKEY" > "$key_tmp"
if ! ssh-keygen -lf "$key_tmp" >/dev/null 2>&1; then
  rm -f "$key_tmp"
  die "SSH 公钥无法解析"
fi
rm -f "$key_tmp"

# --- 解析二进制绝对路径(sudoers 需要绝对路径,且不同发行版位置不同)---
need_path() {
  local p
  p="$(command -v "$1" 2>/dev/null || true)"
  [[ -n "$p" ]] || die "找不到命令 $1,请先确认已安装"
  printf '%s' "$p"
}
DOCKER_BIN="$(need_path docker)"
JOURNALCTL_BIN="$(need_path journalctl)"
DMESG_BIN="$(need_path dmesg)"
SS_BIN="$(need_path ss)"

# 注意:systemctl 刻意**不**授予任何 sudo。原因:
#   sudoers 的 systemctl 参数通配无法可靠地只放行只读子命令 ——
#   一旦放行 `systemctl *`,就等于给了 `systemctl edit`(可注入以 root 运行的单元文件)
#   和 `systemctl start`(可启动任意服务)。而查看服务状态本来就不需要 root:
#   普通用户执行 `systemctl status xxx` / `list-units` 完全可用。
#   因此这里只用 docker 的只读子命令白名单来满足"读容器状态"的需求。

echo "==> 1/7 创建账户 ${OPS_USER}(不加入 docker 组)"
if id "$OPS_USER" >/dev/null 2>&1; then
  echo "    账户已存在,跳过创建"
else
  useradd --create-home --shell /bin/bash "$OPS_USER"
fi
[[ "$(id -u "$OPS_USER")" -ne 0 ]] || die "ops-us 不得是 root"
[[ "$(getent passwd "$OPS_USER" | cut -d: -f6)" == "/home/${OPS_USER}" ]] || die "ops-us 的 home 与预期不同,请先检查账户"
for group in $(id -nG "$OPS_USER"); do
  case "$group" in root|sudo|wheel|docker|lxd|incus-admin|disk) die "ops-us 已属于特权组 $group,请先移除权限" ;; esac
done
[[ ! -L "/home/${OPS_USER}" && ! -L "/home/${OPS_USER}/.ssh" && ! -L "/home/${OPS_USER}/.ssh/authorized_keys" ]] || die "账户目录和 authorized_keys 不得是符号链接"
passwd -l "$OPS_USER" >/dev/null 2>&1 || true   # 锁定密码,只允许密钥登录

echo "==> 2/7 写入专用公钥"
# Root owns the path so a previously compromised ops-us cannot race a symlink
# into the setup script or replace the authorized key after onboarding.
chown root:root "/home/${OPS_USER}"
chmod 755 "/home/${OPS_USER}"
install -d -m 755 -o root -g root "/home/${OPS_USER}/.ssh"
printf 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding %s\n' "$PUBKEY" \
  > "/home/${OPS_USER}/.ssh/authorized_keys"
chown root:root "/home/${OPS_USER}/.ssh/authorized_keys"
chmod 644 "/home/${OPS_USER}/.ssh/authorized_keys"

echo "==> 3/7 安装 root 所有的只读包装程序与 sudo 规则(模式:${MODE})"
# sudo 只授权包装程序,不授权原始 docker/journalctl/dmesg/ss。
# 逐 argv 验证后,在干净环境中执行固定绝对路径的二进制。
[[ ! -L /usr/local/sbin && ! -L "$WRAPPER" ]] || die "包装程序路径不得为符号链接"
install -d -o root -g root -m 755 /usr/local/sbin
wrapper_tmp="$(mktemp /usr/local/sbin/.mcp-readonly.XXXXXX)"
cat > "$wrapper_tmp" <<'WRAPPER_EOF'
#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
reject() { echo "mcp-readonly: arguments denied" >&2; exit 64; }
number() { [[ "$1" =~ ^[0-9]{1,6}$ ]] && (( 10#$1 <= 100000 )); }
identifier() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,255}$ ]]; }
kind="${1:-}"
[[ $# -gt 0 ]] || reject
shift
case "$kind" in
  docker)
    sub="${1:-}"; [[ $# -gt 0 ]] || reject; shift
    args=("$sub")
    case "$sub" in
      ps|images|stats|logs|inspect|version|info|top|port) ;;
      system) [[ "${1:-}" == df ]] || reject; args+=("$1"); shift ;;
      volume|network) [[ "${1:-}" == ls ]] || reject; args+=("$1"); shift ;;
      *) reject ;;
    esac
    while [[ $# -gt 0 ]]; do
      arg="$1"; shift
      case "$arg" in
        -a|--all|-q|--quiet|--no-trunc|--no-stream|--timestamps|-t|--size|-s|--digests|--verbose|-v) ;;
        --format|-f|--filter|--since|--until|--tail|-n)
          [[ $# -gt 0 && "$1" != -* && "$1" != *$'\n'* && "$1" != *$'\r'* ]] || reject
          if [[ "$arg" == --tail || "$arg" == -n ]]; then number "$1" || reject; fi
          args+=("$arg" "$1"); shift; continue ;;
        -*) reject ;;
        *) identifier "$arg" || reject ;;
      esac
      args+=("$arg")
    done
    [[ "$sub" != stats ]] || args+=(--no-stream)
    [[ "$sub" != logs ]] || args+=(--tail 1000)
    exec env -i PATH="$PATH" LC_ALL=C HOME=/root DOCKER_CONFIG=/root/.docker DOCKER_HOST=unix:///var/run/docker.sock MCP_DOCKER_PATH "${args[@]}"
    ;;
  journalctl)
    args=(--no-pager -n 1000)
    while [[ $# -gt 0 ]]; do
      arg="$1"; shift
      case "$arg" in
        --no-pager|-k|--dmesg|--utc|--reverse|-r) args+=("$arg") ;;
        -n|--lines) [[ $# -gt 0 ]] && number "$1" || reject; args+=("$arg" "$1"); shift ;;
        -u|--unit) [[ $# -gt 0 ]] && identifier "$1" || reject; args+=("$arg" "$1"); shift ;;
        -p|--priority) [[ "${1:-}" =~ ^(emerg|alert|crit|err|warning|notice|info|debug|[0-7])$ ]] || reject; args+=("$arg" "$1"); shift ;;
        --since|--until) [[ $# -gt 0 && "$1" =~ ^[A-Za-z0-9[:space:]:+.-]{1,64}$ ]] || reject; args+=("$arg" "$1"); shift ;;
        -b|--boot) args+=("$arg") ;;
        *) reject ;;
      esac
    done
    exec env -i PATH="$PATH" LC_ALL=C SYSTEMD_PAGER=cat MCP_JOURNALCTL_PATH "${args[@]}"
    ;;
  dmesg)
    for arg in "$@"; do
      case "$arg" in -T|--ctime|--color=never|-H|--human|-x|--decode|-L|--nopager) ;; *) reject ;; esac
    done
    exec env -i PATH="$PATH" LC_ALL=C MCP_DMESG_PATH --color=never "$@" --nopager
    ;;
  ss)
    for arg in "$@"; do [[ "$arg" =~ ^-[lntupaxse46orh]+$ ]] || reject; done
    exec env -i PATH="$PATH" LC_ALL=C MCP_SS_PATH "$@"
    ;;
  *) reject ;;
esac
WRAPPER_EOF
# 路径由 root 的 command -v 获取,拒绝 shell 元字符后替换占位符。
for bin in "$DOCKER_BIN" "$JOURNALCTL_BIN" "$DMESG_BIN" "$SS_BIN"; do
  [[ "$bin" =~ ^/[A-Za-z0-9_./-]+$ ]] || die "二进制路径不安全: $bin"
done
sed -i "s|MCP_DOCKER_PATH|$DOCKER_BIN|g; s|MCP_JOURNALCTL_PATH|$JOURNALCTL_BIN|g; s|MCP_DMESG_PATH|$DMESG_BIN|g; s|MCP_SS_PATH|$SS_BIN|g" "$wrapper_tmp"
bash -n "$wrapper_tmp" || die "包装程序语法错误"
chown root:root "$wrapper_tmp"
chmod 755 "$wrapper_tmp"
mv -f "$wrapper_tmp" "$WRAPPER"
sudoers_tmp="$(mktemp)"
if [[ "$MODE" == "full" ]]; then
  # 完整提权。刻意单独成块:这一段一旦生效,服务器侧就不再有任何边界。
  cat > "$sudoers_tmp" <<EOF
# 由 server-setup.sh --full-sudo 生成
#
# ⚠ 完整提权:${OPS_USER} 可以以 root 执行任意命令。
# 服务器侧已经没有边界了 —— 剩下的唯一约束是 MCP 侧的审批页面(每次执行都要人点"允许")。
# 恢复只读模式: sudo bash server-setup.sh '<公钥>' --readonly
Defaults:${OPS_USER} env_reset
${OPS_USER} ALL=(ALL) NOPASSWD: ALL
EOF
else
  cat > "$sudoers_tmp" <<EOF
# root-owned argv validator; never grant the underlying binaries.
Defaults:${OPS_USER} env_reset
${OPS_USER} ALL=(root) NOPASSWD: ${WRAPPER} *
EOF
fi
chmod 440 "$sudoers_tmp"
visudo -cf "$sudoers_tmp" >/dev/null || { rm -f "$sudoers_tmp"; die "sudoers 语法校验失败,未安装"; }
install -o root -g root -m 440 "$sudoers_tmp" "$SUDOERS_FILE"
rm -f "$sudoers_tmp"
echo "    已写入 $SUDOERS_FILE"

echo "==> 4/7 收紧 sshd 登录账户白名单"
if [[ -d /etc/ssh/sshd_config.d ]]; then
  EXISTING_USERS="$(grep -rhiE '^\s*AllowUsers' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | sed -E 's/^\s*AllowUsers\s+//' || true)"
  if [[ -n "$EXISTING_USERS" ]]; then
    # 已有 AllowUsers 时**不能**只发个警告就完事:AllowUsers 是白名单,
    # 若其中没有 ops-us,新账户照样登不进来 —— 那会出现"脚本说成功、实际连不上"的假成功。
    echo "    检测到已有 AllowUsers 规则:${EXISTING_USERS}"
    if [[ " $EXISTING_USERS " == *" ${OPS_USER} "* ]]; then
      echo "    其中已包含 ${OPS_USER},无需改动"
    else
      echo "    ⚠ 其中**不包含** ${OPS_USER} —— 该账户将无法登录。"
      echo "      请手工把 ${OPS_USER} 追加到那条 AllowUsers 里,例如:"
      echo "        AllowUsers ${EXISTING_USERS} ${OPS_USER}"
      echo "      改完执行:sshd -t && systemctl reload ssh"
      ALLOWUSERS_NEEDS_MANUAL=yes
    fi
  else
    echo "    未配置 AllowUsers,保留现有登录策略(避免锁出管理员)"

  fi
else
  echo "    无 /etc/ssh/sshd_config.d,跳过(如需限制请手工编辑 sshd_config)"
fi

echo "==> 5/7 主机密钥指纹(填进本地 DSH_VPS_HOST_FINGERPRINTS)"
for f in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub /etc/ssh/ssh_host_ecdsa_key.pub; do
  [[ -f "$f" ]] && ssh-keygen -lf "$f"
done

echo "==> 6/7 权限自检(关键:确认提权面被正确收窄)"
sudo -u "$OPS_USER" -H bash -lc 'id'
pass_count=0
fail_count=0
expect_ok() {  # 应当可用的能力
  if sudo -u "$OPS_USER" -H bash -lc "$1" >/dev/null 2>&1; then
    echo "    ✓ $2"; pass_count=$((pass_count+1))
  else
    echo "    ✗ $2(应为可用,请检查 sudoers)"; fail_count=$((fail_count+1))
  fi
}
expect_denied() {  # 仅查询 sudo 授权,绝不执行被测命令
  local label="$1"; shift
  local rc=0
  sudo -u "$OPS_USER" -H sudo -n -l -- "$@" >/dev/null 2>&1 || rc=$?
  if [[ "$rc" -eq 1 ]]; then
    echo "    ✓ 已正确拒绝:$label"; pass_count=$((pass_count+1))
  else
    echo "    ✗ 严重:$label 授权或查询异常(rc=$rc)!请检查 $SUDOERS_FILE"; fail_count=$((fail_count+1))
  fi
}
expect_ok "sudo -n $WRAPPER docker ps -q" "读容器列表"
expect_ok "sudo -n $WRAPPER journalctl -n 1 --no-pager" "读系统日志"

if [[ "$MODE" == "full" ]]; then
  # 完整 sudo 模式下,"能否提权"是设计意图,所以自检变成"确认提权确实生效",
  # 同时把代价明确印出来 —— 不让"全绿"给人虚假的安全感。
  expect_ok "sudo -n id -u | grep -qx 0" "sudo 免密提权到 root"
  expect_ok "sudo -n head -n 1 /etc/shadow" "读 shadow(只读模式里这是被拒的)"

  echo "    ---- 自检小结:通过 ${pass_count} 项,失败 ${fail_count} 项 ----"
  cat <<WARN

    ⚠⚠⚠ 完整 sudo 模式已生效:${OPS_USER} 现在可以以 root 执行任意命令。
        服务器侧已经没有边界:服务启停、rm -rf、apt、iptables、读 shadow 全部可用。
        唯一剩下的约束是 MCP 侧的审批页面 —— 每次执行都必须有人在那里点"允许"。
        请确认 DSH 侧审批模式是 prompt(不要设 DSH_VPS_APPROVAL_MODE=allow)。

    用完想收回权限,把同一份脚本用 --readonly 重跑一次即可。

WARN
else
expect_denied "docker run" "$DOCKER_BIN" run --rm alpine true
expect_denied "docker exec" "$DOCKER_BIN" exec x true
expect_denied "docker volume rm" "$DOCKER_BIN" volume rm x
expect_denied "systemctl start" "$(need_path systemctl)" start docker
expect_denied "systemctl edit" "$(need_path systemctl)" edit docker
expect_denied "systemctl stop" "$(need_path systemctl)" stop docker
expect_denied "cat /etc/shadow" "$(need_path cat)" /etc/shadow
expect_denied "useradd" "$(need_path useradd)" hacker
expect_denied "journalctl --rotate" "$JOURNALCTL_BIN" --rotate
expect_denied "dmesg -C" "$DMESG_BIN" -C
expect_denied "ss -K" "$SS_BIN" -K

echo "    ---- 自检小结:通过 ${pass_count} 项,失败 ${fail_count} 项 ----"
fi
if [[ "$fail_count" -gt 0 ]]; then
  die "自检未全部通过,请勿继续使用这个账户。"
fi

echo "==> 7/7 撤销方式(请记录)"
cat <<EOF
    撤销公钥:        sed -i '\\#${PUBKEY:0:40}#d' /home/${OPS_USER}/.ssh/authorized_keys
    撤销提权:        rm -f ${SUDOERS_FILE}
    撤销登录白名单:  rm -f ${SSHD_DROPIN} && systemctl reload ssh
    彻底移除账户:    userdel -r ${OPS_USER}
EOF

[[ "${ALLOWUSERS_NEEDS_MANUAL:-no}" != yes ]] || die "请先将 ops-us 加入现有 AllowUsers 后重新运行"
echo
echo "完成。下一步:在本地把 IP + 上面的指纹 + 专用私钥路径填进 DSH 的 MCP 配置。"
