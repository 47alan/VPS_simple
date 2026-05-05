#!/usr/bin/env bash
set -Eeuo pipefail

# Configure SSH public-key login safely on Ubuntu/Debian.
# Defaults are conservative: add key and keep password login enabled.

SSH_USER="${SSH_USER:-${SUDO_USER:-root}}"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"
SSH_PUBLIC_KEY_FILE="${SSH_PUBLIC_KEY_FILE:-}"
SSH_PORT="${SSH_PORT:-}"
KEEP_OLD_SSH_PORT="${KEEP_OLD_SSH_PORT:-1}"
DISABLE_PASSWORD_LOGIN="${DISABLE_PASSWORD_LOGIN:-0}"
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-}"
CONFIG_FILE="${CONFIG_FILE:-/etc/ssh/sshd_config.d/99-vps-key-login.conf}"

log() { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[ERR]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
SSH 公钥登录配置脚本

常用示例:
  sudo SSH_USER=root SSH_PUBLIC_KEY='ssh-ed25519 AAAA...' bash ./setup-ssh-key-login.sh

修改 SSH 端口，默认保留旧端口一起监听:
  sudo SSH_USER=root SSH_PORT=22222 SSH_PUBLIC_KEY='ssh-ed25519 AAAA...' bash ./setup-ssh-key-login.sh

确认密钥和新端口能登录后，再关闭密码登录并移除旧端口:
  sudo SSH_USER=root SSH_PORT=22222 KEEP_OLD_SSH_PORT=0 DISABLE_PASSWORD_LOGIN=1 SSH_PUBLIC_KEY='ssh-ed25519 AAAA...' bash ./setup-ssh-key-login.sh

环境变量:
  SSH_USER=root
  SSH_PUBLIC_KEY='ssh-ed25519 AAAA...'
  SSH_PUBLIC_KEY_FILE=/path/to/id_ed25519.pub
  SSH_PORT=22222
  KEEP_OLD_SSH_PORT=1
  DISABLE_PASSWORD_LOGIN=0
  PERMIT_ROOT_LOGIN=prohibit-password（可选；默认不改 PermitRootLogin）
EOF
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请使用 root 执行，例如：sudo bash ./setup-ssh-key-login.sh"
  fi
}

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|y|Y) return 0 ;;
    *) return 1 ;;
  esac
}

validate_flag() {
  local name="$1"
  local value="$2"
  case "${value}" in
    0|1|true|TRUE|false|FALSE|yes|YES|no|NO|y|Y|n|N|"") ;;
    *) err "${name} 只能使用 0/1/true/false/yes/no：${value}" ;;
  esac
}

validate_port() {
  local name="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    return
  fi
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    err "${name} 必须是数字：${value}"
  fi
  if (( value < 1 || value > 65535 )); then
    err "${name} 必须在 1-65535 范围内：${value}"
  fi
}

ensure_openssh_server() {
  if command -v sshd >/dev/null 2>&1; then
    return
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    err "未找到 sshd，且当前系统没有 apt-get，无法自动安装 openssh-server"
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y openssh-server
}

load_public_key() {
  if [[ -n "${SSH_PUBLIC_KEY_FILE}" ]]; then
    [[ -f "${SSH_PUBLIC_KEY_FILE}" ]] || err "SSH_PUBLIC_KEY_FILE 不存在：${SSH_PUBLIC_KEY_FILE}"
    SSH_PUBLIC_KEY="$(tr -d '\r' < "${SSH_PUBLIC_KEY_FILE}" | sed -n '1p')"
  fi

  if [[ -z "${SSH_PUBLIC_KEY}" && -t 0 ]]; then
    echo "请粘贴你的 SSH 公钥，格式类似 ssh-ed25519 AAAA...，然后回车："
    read -r SSH_PUBLIC_KEY
  fi

  if [[ -z "${SSH_PUBLIC_KEY}" ]]; then
    err "缺少 SSH_PUBLIC_KEY。请传入公钥，不要把私钥上传到服务器。"
  fi

  case "${SSH_PUBLIC_KEY}" in
    ssh-rsa\ *|ssh-ed25519\ *|ecdsa-sha2-nistp256\ *|ecdsa-sha2-nistp384\ *|ecdsa-sha2-nistp521\ *) ;;
    *) err "SSH_PUBLIC_KEY 格式不像 OpenSSH 公钥：${SSH_PUBLIC_KEY%% *}" ;;
  esac
}

user_home_dir() {
  local user="$1"
  getent passwd "${user}" | cut -d: -f6
}

install_public_key() {
  if ! id "${SSH_USER}" >/dev/null 2>&1; then
    err "用户不存在：${SSH_USER}"
  fi

  local home_dir ssh_dir auth_file
  home_dir="$(user_home_dir "${SSH_USER}")"
  [[ -n "${home_dir}" && -d "${home_dir}" ]] || err "无法识别用户家目录：${SSH_USER}"

  ssh_dir="${home_dir}/.ssh"
  auth_file="${ssh_dir}/authorized_keys"

  mkdir -p "${ssh_dir}"
  touch "${auth_file}"

  if ! grep -Fxq "${SSH_PUBLIC_KEY}" "${auth_file}"; then
    printf '%s\n' "${SSH_PUBLIC_KEY}" >> "${auth_file}"
    log "已写入公钥：${auth_file}"
  else
    log "公钥已存在：${auth_file}"
  fi

  local user_group
  user_group="$(id -gn "${SSH_USER}")"
  chown -R "${SSH_USER}:${user_group}" "${ssh_dir}"
  chmod 700 "${ssh_dir}"
  chmod 600 "${auth_file}"
}

detect_current_ports() {
  local ports
  ports="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -n -u || true)"
  if [[ -z "${ports}" ]]; then
    echo 22
  else
    printf '%s\n' "${ports}"
  fi
}

open_firewall_port() {
  local port="$1"
  if [[ -z "${port}" ]]; then
    return
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw allow "${port}/tcp"
    log "UFW 已放行：${port}/tcp"
  fi
}

ensure_sshd_include_dir() {
  mkdir -p /etc/ssh/sshd_config.d
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    local backup="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
    cp -a /etc/ssh/sshd_config "${backup}"
    printf 'Include /etc/ssh/sshd_config.d/*.conf\n' | cat - /etc/ssh/sshd_config > /etc/ssh/sshd_config.tmp
    mv /etc/ssh/sshd_config.tmp /etc/ssh/sshd_config
    log "已为 sshd_config 添加 Include，备份：${backup}"
  fi
}

write_sshd_dropin() {
  local password_auth="yes"
  local keyboard_auth="yes"
  local permit_root_login="${PERMIT_ROOT_LOGIN}"
  if is_truthy "${DISABLE_PASSWORD_LOGIN}"; then
    password_auth="no"
    keyboard_auth="no"
    permit_root_login="${permit_root_login:-prohibit-password}"
  fi

  local tmp_file
  tmp_file="$(mktemp)"
  {
    echo "# Managed by setup-ssh-key-login.sh"
    if [[ -n "${SSH_PORT}" ]]; then
      echo "Port ${SSH_PORT}"
      if is_truthy "${KEEP_OLD_SSH_PORT}"; then
        local port
        while read -r port; do
          [[ -z "${port}" || "${port}" == "${SSH_PORT}" ]] && continue
          echo "Port ${port}"
        done < <(detect_current_ports)
      fi
    fi
    echo "PubkeyAuthentication yes"
    echo "AuthorizedKeysFile .ssh/authorized_keys"
    echo "PasswordAuthentication ${password_auth}"
    echo "KbdInteractiveAuthentication ${keyboard_auth}"
    if [[ -n "${permit_root_login}" ]]; then
      echo "PermitRootLogin ${permit_root_login}"
    fi
    echo "UsePAM yes"
  } > "${tmp_file}"

  if [[ -f "${CONFIG_FILE}" && ! -f "${CONFIG_FILE}.first.bak" ]]; then
    cp -a "${CONFIG_FILE}" "${CONFIG_FILE}.first.bak"
  fi
  cp "${tmp_file}" "${CONFIG_FILE}"
  rm -f "${tmp_file}"
  chmod 644 "${CONFIG_FILE}"
  log "已写入 SSH 配置：${CONFIG_FILE}"
}

test_and_reload_sshd() {
  sshd -t || err "sshd 配置测试失败，未重载服务"

  if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    systemctl reload ssh || systemctl restart ssh
  elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
    systemctl reload sshd || systemctl restart sshd
  else
    service ssh reload || service ssh restart
  fi
  log "SSH 服务已重载"
}

print_summary() {
  local ports
  ports="$(detect_current_ports | paste -sd ',' -)"
  cat <<EOF

================ SSH KEY LOGIN ================
用户              : ${SSH_USER}
authorized_keys   : $(user_home_dir "${SSH_USER}")/.ssh/authorized_keys
配置文件          : ${CONFIG_FILE}
当前 sshd 端口    : ${ports}
密码登录          : $(is_truthy "${DISABLE_PASSWORD_LOGIN}" && echo disabled || echo enabled)
保留旧端口        : ${KEEP_OLD_SSH_PORT}

下一步:
  1. 不要关闭当前 Xshell 窗口。
  2. 新开一个 Xshell 会话，用私钥测试登录。
  3. 如果设置了新端口，确认云厂商安全组已放行该 TCP 端口。
  4. 确认密钥登录成功后，再设置 DISABLE_PASSWORD_LOGIN=1 关闭密码登录。
===============================================
EOF
}

main() {
  case "${1:-}" in
    -h|--help|help)
      usage
      return 0
      ;;
  esac

  need_root
  validate_flag KEEP_OLD_SSH_PORT "${KEEP_OLD_SSH_PORT}"
  validate_flag DISABLE_PASSWORD_LOGIN "${DISABLE_PASSWORD_LOGIN}"
  validate_port SSH_PORT "${SSH_PORT}"
  ensure_openssh_server
  load_public_key
  install_public_key
  ensure_sshd_include_dir
  if [[ -n "${SSH_PORT}" ]]; then
    open_firewall_port "${SSH_PORT}"
  fi
  write_sshd_dropin
  test_and_reload_sshd
  print_summary
}

main "$@"
