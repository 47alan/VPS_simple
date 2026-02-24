#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# One-click: Nginx + Xray(VLESS WS) + Hysteria2 + Cloudflare Origin Cert
# Tested: Ubuntu/Debian
# =========================

# --------- Config (can override by env) ----------
DOMAIN="${DOMAIN:-example.com}"                 # 站点域名（VLESS 使用）
UUID="${UUID:-}"                                # VLESS UUID，可留空自动生成
WSPATH="${WSPATH:-/ray}"                        # WebSocket path，必须以 / 开头
VLESS_PORT="${VLESS_PORT:-443}"                 # VLESS 对外 TLS 端口（Nginx 监听）
XRAY_LISTEN="${XRAY_LISTEN:-127.0.0.1}"
XRAY_PORT="${XRAY_PORT:-10000}"                 # 本地回环端口，Nginx 反代到这里

# HY2 可选安装（默认关闭）
HY2_ENABLE="${HY2_ENABLE:-0}"                    # 0=不安装 HY2，1=安装
# HY2 默认独立域名/端口，便于与 Cloudflare 代理策略分离
HY2_DOMAIN="${HY2_DOMAIN:-${DOMAIN}}"           # HY2 客户端连接域名
HY2_SNI="${HY2_SNI:-${HY2_DOMAIN}}"             # HY2 TLS SNI
HY2_PORT="${HY2_PORT:-8443}"                    # HY2 UDP 端口
HY2_PASSWORD="${HY2_PASSWORD:-}"                # HY2 密码，可留空自动生成
HY2_INSECURE="${HY2_INSECURE:-1}"               # 用 CF Origin 证书时建议 1
HY2_MASQ_URL="${HY2_MASQ_URL:-https://www.cloudflare.com/}"
SOCKS_ENABLE="${SOCKS_ENABLE:-0}"
SOCKS_PORT="${SOCKS_PORT:-}"
SOCKS_BIND="${SOCKS_BIND:-0.0.0.0}"
SOCKS_USER="${SOCKS_USER:-}"
SOCKS_PASS="${SOCKS_PASS:-}"
SOCKS_ALLOW="${SOCKS_ALLOW:-}"
SOCKS_CONN_LIMIT_SECONDS="${SOCKS_CONN_LIMIT_SECONDS:-60}"
SOCKS_CONN_LIMIT_HITCOUNT="${SOCKS_CONN_LIMIT_HITCOUNT:-20}"
SOCKS_REQUIRE_ATTACK_BEFORE_RESET="${SOCKS_REQUIRE_ATTACK_BEFORE_RESET:-0}"
SOCKS_ALERT_WINDOW_SECONDS="${SOCKS_ALERT_WINDOW_SECONDS:-600}"
SOCKS_ALERT_MIN_EVENTS="${SOCKS_ALERT_MIN_EVENTS:-2}"
SOCKS_SECURITY_LOG_FILE="${SOCKS_SECURITY_LOG_FILE:-/var/log/vps_socks_security.log}"
SOCKS_ALERT=0
SOCKS_RECENT_ALERTS=0
SOCKS_ALERT_LEVEL="none"
TG_NOTIFY_ENABLE="${TG_NOTIFY_ENABLE:-0}"
TG_BOT_TOKEN="${TG_BOT_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"
TG_API_BASE_URL="${TG_API_BASE_URL:-https://api.telegram.org}"
TG_NOTIFY_LEVEL="${TG_NOTIFY_LEVEL:-strong}"
TG_NOTIFY_COOLDOWN_SECONDS="${TG_NOTIFY_COOLDOWN_SECONDS:-300}"
SOCKS_WATCHDOG_INTERVAL_SECONDS="${SOCKS_WATCHDOG_INTERVAL_SECONDS:-60}"
SOCKS_WATCHDOG_SCRIPT="/usr/local/bin/socks5-watchdog.sh"
SOCKS_WATCHDOG_ENV="/etc/default/socks5-watchdog"
SOCKS_WATCHDOG_SERVICE="/etc/systemd/system/socks5-watchdog.service"
SOCKS_WATCHDOG_TIMER="/etc/systemd/system/socks5-watchdog.timer"
SOCKS_WATCHDOG_STATE="/var/lib/socks5-watchdog/state"
STOPPED_SERVICES=()
INSTALL_STEP=0
INSTALL_TOTAL_STEPS=0
ORIGIN_DIR="/etc/ssl/private"
ORIGIN_PEM="${ORIGIN_DIR}/origin.pem"
ORIGIN_KEY="${ORIGIN_DIR}/origin.key"

NGINX_SITE_DIR="/var/www/html"
NGINX_CONF="/etc/nginx/conf.d/v2ray.conf"

XRAY_INSTALL_URL="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"
XRAY_CFG="/usr/local/etc/xray/config.json"

HY2_INSTALL_URL="https://get.hy2.sh/"
HY2_CFG="/etc/hysteria/config.yaml"

# --------- Helpers ----------
log() { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERR]\033[0m $*"; exit 1; }

prepare_install_steps() {
  INSTALL_STEP=0
  INSTALL_TOTAL_STEPS=5
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    INSTALL_TOTAL_STEPS=$((INSTALL_TOTAL_STEPS + 1))
  fi
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    INSTALL_TOTAL_STEPS=$((INSTALL_TOTAL_STEPS + 1))
    if [[ "${TG_NOTIFY_ENABLE}" -eq 1 ]]; then
      INSTALL_TOTAL_STEPS=$((INSTALL_TOTAL_STEPS + 1))
    fi
  fi
}

start_install_step() {
  local message="$1"
  INSTALL_STEP=$((INSTALL_STEP + 1))
  echo
  echo ">>> [步骤 ${INSTALL_STEP}/${INSTALL_TOTAL_STEPS}] ${message}"
}

print_runtime_status() {
  local all_ok=1

  echo
  echo "================ 运行状态检查 ================"
  for svc in nginx xray; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
      echo "${svc}                 : active"
    else
      echo "${svc}                 : inactive"
      all_ok=0
    fi
  done

  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
      echo "hysteria-server       : active"
    else
      echo "hysteria-server       : inactive"
      all_ok=0
    fi
  fi

  if [[ "${SOCKS_ENABLE}" -eq 1 && "${TG_NOTIFY_ENABLE}" -eq 1 ]]; then
    if systemctl is-active --quiet socks5-watchdog.timer 2>/dev/null; then
      echo "socks5-watchdog.timer : active"
    else
      echo "socks5-watchdog.timer : inactive"
      all_ok=0
    fi
  fi
  echo "=============================================="

  if [[ "${all_ok}" -eq 1 ]]; then
    log "安装完成标记：INSTALL_DONE=1（核心服务已启动）"
  else
    warn "安装流程已走完，但存在未运行服务，请执行 systemctl status <service> 排查。"
  fi
}

on_install_error() {
  local exit_code="$1"
  local line_no="$2"
  local cmd="$3"
  if [[ "${exit_code}" -eq 0 ]]; then
    return
  fi
  echo -e "\033[1;31m[ERR]\033[0m 安装未完成：步骤 ${INSTALL_STEP}/${INSTALL_TOTAL_STEPS} 失败（line ${line_no}）" >&2
  echo -e "\033[1;31m[ERR]\033[0m 失败命令：${cmd}" >&2
  echo -e "\033[1;31m[ERR]\033[0m 可根据上方步骤号定位失败阶段后重试。" >&2
}

random_alphanum() {
  local length="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$((length * 2))" | tr -dc 'A-Za-z0-9' | cut -c1-"${length}"
  else
    cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-"${length}"
  fi
}

generate_openssl_password() {
  local length="$1"
  openssl rand -base64 "${length}" | tr -d '\r\n'
}

generate_socks_password() {
  local raw
  if command -v openssl >/dev/null 2>&1; then
    raw="$(openssl rand -hex 8)"
  else
    raw="$(cat /proc/sys/kernel/random/uuid | tr -d '-')"
  fi
  printf '%s\n' "${raw:0:12}"
}

get_primary_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}'
}

pick_random_socks_port() {
  local tries port port_info
  if ! command -v ss >/dev/null 2>&1; then
    err "缺少 ss 命令，无法自动挑选 SOCKS5 端口"
  fi
  for tries in {1..30}; do
    port=$((50000 + RANDOM % 15000))
    port_info="$(ss -ltnH "sport = :${port}" 2>/dev/null || true)"
    if [[ -z "${port_info}" ]]; then
      echo "${port}"
      return 0
    fi
  done
  err "无法在 50000-64999 范围内找到可用端口（尝试 30 次均失败）"
}

prompt_with_default() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="$3"
  local input_value=""
  read -r -p "${prompt_text} [${default_value}]: " input_value
  input_value="${input_value:-${default_value}}"
  printf -v "${var_name}" '%s' "${input_value}"
}

interactive_config() {
  if [[ ! -t 0 ]]; then
    return
  fi

  echo
  echo "================ 交互配置向导 ================"
  echo "直接按回车可使用默认值（方括号内）"
  echo "=============================================="
  echo

  local domain_default="${DOMAIN}"
  local input_value=""

  if [[ "${domain_default}" == "example.com" ]]; then
    domain_default=""
  fi

  while true; do
    if [[ -n "${domain_default}" ]]; then
      read -r -p "请输入你的域名 DOMAIN [${domain_default}]: " input_value
      input_value="${input_value:-${domain_default}}"
    else
      read -r -p "请输入你的域名 DOMAIN（必填）: " input_value
    fi

    if [[ -n "${input_value}" && "${input_value}" != "example.com" ]]; then
      DOMAIN="${input_value}"
      break
    fi
    warn "DOMAIN 不能为空，且不能是 example.com"
  done

  prompt_with_default "VLESS_PORT" "请输入 VLESS_PORT（VLESS 对外端口）" "${VLESS_PORT}"
  prompt_with_default "WSPATH" "请输入 WSPATH（VLESS 的 WS 路径）" "${WSPATH}"

  read -r -p "是否安装 Hysteria2（HY2）？[y/N]: " input_value
  input_value="${input_value:-N}"
  case "${input_value}" in
    Y|y) HY2_ENABLE=1 ;;
    *) HY2_ENABLE=0 ;;
  esac

  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    local hy2_domain_default="${HY2_DOMAIN}"
    if [[ -z "${hy2_domain_default}" || "${hy2_domain_default}" == "example.com" ]]; then
      hy2_domain_default="${DOMAIN}"
    fi
    prompt_with_default "HY2_DOMAIN" "请输入 HY2_DOMAIN（HY2 连接域名）" "${hy2_domain_default}"

    local hy2_sni_default="${HY2_SNI}"
    if [[ -z "${hy2_sni_default}" || "${hy2_sni_default}" == "example.com" ]]; then
      hy2_sni_default="${HY2_DOMAIN}"
    fi
    prompt_with_default "HY2_SNI" "请输入 HY2_SNI（TLS SNI）" "${hy2_sni_default}"

    prompt_with_default "HY2_PORT" "请输入 HY2_PORT（UDP 端口）" "${HY2_PORT}"
    prompt_with_default "HY2_INSECURE" "请输入 HY2_INSECURE（0/1）" "${HY2_INSECURE}"
    prompt_with_default "HY2_MASQ_URL" "请输入 HY2_MASQ_URL（伪装地址）" "${HY2_MASQ_URL}"
  fi

  read -r -p "是否启用公网 SOCKS5 出口（配合安全配置，默认不启用）？[y/N]: " input_value
  input_value="${input_value:-N}"
  case "${input_value}" in
    Y|y) SOCKS_ENABLE=1 ;;
    *) SOCKS_ENABLE=0 ;;
  esac

  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    if [[ -z "${SOCKS_PORT}" ]]; then
      SOCKS_PORT="$(pick_random_socks_port)"
    fi
    prompt_with_default "SOCKS_PORT" "请输入 SOCKS5 端口（50000-64999）" "${SOCKS_PORT}"

    if [[ -z "${SOCKS_USER}" ]]; then
      SOCKS_USER="usr$(random_alphanum 6)"
    fi
    prompt_with_default "SOCKS_USER" "请输入 SOCKS5 用户名" "${SOCKS_USER}"

    read -r -s -p "请输入 SOCKS5 密码（留空自动生成 12 位）： " input_value
    echo
    if [[ -n "${input_value}" ]]; then
      SOCKS_PASS="${input_value}"
    elif [[ -z "${SOCKS_PASS}" ]]; then
      SOCKS_PASS="$(generate_socks_password)"
    fi

    read -r -p "设定允许访问的 IP（留空表示任意）： " input_value
    SOCKS_ALLOW="${input_value}"
    echo
    if [[ -n "${SOCKS_ALLOW}" ]]; then
      if ! python3 - "${SOCKS_ALLOW}" <<'PY'
import ipaddress
import sys
value = sys.argv[1]
try:
    ipaddress.ip_network(value, strict=False)
except Exception:
    sys.exit(1)
PY
      then
        err "SOCKS_ALLOW 值非法：${SOCKS_ALLOW}"
      fi
    fi

    read -r -p "是否启用 Telegram 告警推送（默认不启用）？[y/N]: " input_value
    input_value="${input_value:-N}"
    case "${input_value}" in
      Y|y) TG_NOTIFY_ENABLE=1 ;;
      *) TG_NOTIFY_ENABLE=0 ;;
    esac

    if [[ "${TG_NOTIFY_ENABLE}" -eq 1 ]]; then
      prompt_with_default "TG_CHAT_ID" "请输入 Telegram Chat ID" "${TG_CHAT_ID}"

      read -r -p "请输入 Telegram Bot Token（明文输入，留空沿用已有值）: " input_value
      echo
      if [[ -n "${input_value}" ]]; then
        TG_BOT_TOKEN="${input_value}"
      fi

      prompt_with_default "TG_NOTIFY_LEVEL" "告警级别（strong/all）" "${TG_NOTIFY_LEVEL}"
      prompt_with_default "TG_NOTIFY_COOLDOWN_SECONDS" "告警冷却秒数" "${TG_NOTIFY_COOLDOWN_SECONDS}"
      prompt_with_default "SOCKS_WATCHDOG_INTERVAL_SECONDS" "监控检测间隔秒数" "${SOCKS_WATCHDOG_INTERVAL_SECONDS}"
    fi
  fi

  read -r -p "请输入 UUID（留空自动生成）: " input_value
  if [[ -n "${input_value}" ]]; then
    UUID="${input_value}"
  fi

  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    read -r -p "请输入 HY2_PASSWORD（留空自动生成）: " input_value
    if [[ -n "${input_value}" ]]; then
      HY2_PASSWORD="${input_value}"
    fi
  fi

  echo
  echo "------------- 你的配置 -------------"
  echo "DOMAIN=${DOMAIN}"
  echo "VLESS_PORT=${VLESS_PORT}"
  echo "WSPATH=${WSPATH}"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    echo "HY2_DOMAIN=${HY2_DOMAIN}"
    echo "HY2_SNI=${HY2_SNI}"
    echo "HY2_PORT=${HY2_PORT}"
    echo "HY2_INSECURE=${HY2_INSECURE}"
    echo "HY2_MASQ_URL=${HY2_MASQ_URL}"
  else
    echo "HY2_ENABLE=0（不安装 Hysteria2）"
  fi
  if [[ -n "${UUID}" ]]; then
    echo "UUID=已设置"
  else
    echo "UUID=自动生成"
  fi
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    if [[ -n "${HY2_PASSWORD}" ]]; then
      echo "HY2_PASSWORD=已设置"
    else
      echo "HY2_PASSWORD=自动生成"
    fi
  fi
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    if [[ "${TG_NOTIFY_ENABLE}" -eq 1 ]]; then
      echo "TG_NOTIFY_ENABLE=1（已启用 Telegram 告警）"
      echo "TG_CHAT_ID=${TG_CHAT_ID}"
      echo "TG_NOTIFY_LEVEL=${TG_NOTIFY_LEVEL}"
      echo "TG_NOTIFY_COOLDOWN_SECONDS=${TG_NOTIFY_COOLDOWN_SECONDS}"
      echo "SOCKS_WATCHDOG_INTERVAL_SECONDS=${SOCKS_WATCHDOG_INTERVAL_SECONDS}"
    else
      echo "TG_NOTIFY_ENABLE=0（未启用 Telegram 告警）"
    fi
  fi
  echo "------------------------------------"
  echo

  read -r -p "确认继续安装？[Y/n]: " input_value
  input_value="${input_value:-Y}"
  case "${input_value}" in
    Y|y) ;;
    *) err "用户取消安装" ;;
  esac
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请用 root 执行：sudo bash ./install.sh"
  fi
}

check_domain() {
  if [[ "${DOMAIN}" == "example.com" || -z "${DOMAIN}" ]]; then
    err "请设置域名：可直接运行脚本后按提示输入，或用 DOMAIN=你的域名.com bash ./install.sh"
  fi
  if [[ ! "${DOMAIN}" =~ ^[A-Za-z0-9.-]+$ ]]; then
    err "DOMAIN 格式不合法：${DOMAIN}"
  fi
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    if [[ ! "${HY2_DOMAIN}" =~ ^[A-Za-z0-9.-]+$ ]]; then
      err "HY2_DOMAIN 格式不合法：${HY2_DOMAIN}"
    fi
    if [[ ! "${HY2_SNI}" =~ ^[A-Za-z0-9.-]+$ ]]; then
      err "HY2_SNI 格式不合法：${HY2_SNI}"
    fi
  fi
}

check_ws_path() {
  if [[ -z "${WSPATH}" || "${WSPATH}" != /* ]]; then
    err "WSPATH 必须以 / 开头，例如 /ray"
  fi
  if [[ "${WSPATH}" =~ [[:space:]] ]]; then
    err "WSPATH 不能包含空白字符"
  fi
}

check_port() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    err "${name} 必须是数字：${value}"
  fi
  if (( value < 1 || value > 65535 )); then
    err "${name} 必须在 1-65535 范围：${value}"
  fi
}

check_positive_int() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ ]] || (( value < 1 )); then
    err "${name} 必须是正整数：${value}"
  fi
}

validate_socks_allow() {
  if [[ -z "${SOCKS_ALLOW}" ]]; then
    return
  fi

  if ! python3 - "${SOCKS_ALLOW}" <<'PY'
import ipaddress
import sys

value = sys.argv[1]
try:
    ipaddress.ip_network(value, strict=False)
except Exception:
    sys.exit(1)
PY
  then
    err "SOCKS_ALLOW 值非法：${SOCKS_ALLOW}"
  fi
}

validate_socks_security_options() {
  if [[ "${SOCKS_ENABLE}" -ne 1 ]]; then
    return
  fi

  check_port "SOCKS_PORT" "${SOCKS_PORT}"
  check_positive_int "SOCKS_CONN_LIMIT_SECONDS" "${SOCKS_CONN_LIMIT_SECONDS}"
  check_positive_int "SOCKS_CONN_LIMIT_HITCOUNT" "${SOCKS_CONN_LIMIT_HITCOUNT}"
  check_positive_int "SOCKS_ALERT_WINDOW_SECONDS" "${SOCKS_ALERT_WINDOW_SECONDS}"
  check_positive_int "SOCKS_ALERT_MIN_EVENTS" "${SOCKS_ALERT_MIN_EVENTS}"
  if [[ ! "${SOCKS_REQUIRE_ATTACK_BEFORE_RESET}" =~ ^[0-1]$ ]]; then
    err "SOCKS_REQUIRE_ATTACK_BEFORE_RESET 只能是 0 或 1"
  fi
  if [[ -z "${SOCKS_SECURITY_LOG_FILE}" ]]; then
    err "SOCKS_SECURITY_LOG_FILE 不能为空"
  fi
}

validate_telegram_notify_options() {
  if [[ "${TG_NOTIFY_ENABLE}" -ne 1 ]]; then
    return
  fi
  if [[ "${SOCKS_ENABLE}" -ne 1 ]]; then
    err "启用 Telegram 告警前请先启用 SOCKS5（SOCKS_ENABLE=1）"
  fi
  if [[ -z "${TG_BOT_TOKEN}" ]]; then
    err "TG_BOT_TOKEN 不能为空（TG_NOTIFY_ENABLE=1 时必填）"
  fi
  if [[ -z "${TG_CHAT_ID}" ]]; then
    err "TG_CHAT_ID 不能为空（TG_NOTIFY_ENABLE=1 时必填）"
  fi
  if [[ -z "${TG_API_BASE_URL}" ]]; then
    err "TG_API_BASE_URL 不能为空"
  fi
  if [[ ! "${TG_API_BASE_URL}" =~ ^https?:// ]]; then
    err "TG_API_BASE_URL 必须以 http:// 或 https:// 开头"
  fi
  case "${TG_NOTIFY_LEVEL}" in
    strong|all) ;;
    *) err "TG_NOTIFY_LEVEL 仅支持 strong 或 all" ;;
  esac
  check_positive_int "TG_NOTIFY_COOLDOWN_SECONDS" "${TG_NOTIFY_COOLDOWN_SECONDS}"
  check_positive_int "SOCKS_WATCHDOG_INTERVAL_SECONDS" "${SOCKS_WATCHDOG_INTERVAL_SECONDS}"
}

extract_peer_ips_from_ss() {
  local ss_output="$1"
  if [[ -z "${ss_output}" ]]; then
    return
  fi
  printf '%s\n' "${ss_output}" | awk '{print $5}' | sed -E 's/^\[?([^]]+)\]?:[0-9]+$/\1/' | sed '/^[[:space:]]*$/d'
}

count_outside_allowlist_ips() {
  local allow_cidr="$1"
  local ip_list="$2"

  if [[ -z "${allow_cidr}" || -z "${ip_list}" ]]; then
    echo 0
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo 0
    return
  fi

  printf '%s\n' "${ip_list}" | python3 - "${allow_cidr}" <<'PY'
import ipaddress
import sys

allow = ipaddress.ip_network(sys.argv[1], strict=False)
outside = set()

for raw in sys.stdin:
    value = raw.strip()
    if not value:
        continue
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        continue
    if ip not in allow:
        outside.add(value)

print(len(outside))
PY
}

ensure_socks_security_log_file() {
  local log_dir
  log_dir="$(dirname "${SOCKS_SECURITY_LOG_FILE}")"
  mkdir -p "${log_dir}"
  touch "${SOCKS_SECURITY_LOG_FILE}"
  chmod 600 "${SOCKS_SECURITY_LOG_FILE}" >/dev/null 2>&1 || true
}

append_socks_security_event() {
  local now_epoch="$1"
  local instant_alert="$2"
  local severe_alert="$3"
  local total_established="$4"
  local unique_ip_count="$5"
  local top_ip_count="$6"
  local drop_packets="$7"
  local outside_allowlist_count="$8"

  ensure_socks_security_log_file
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "${now_epoch}" "${instant_alert}" "${severe_alert}" "${total_established}" \
    "${unique_ip_count}" "${top_ip_count}" "${drop_packets}" "${outside_allowlist_count}" >> "${SOCKS_SECURITY_LOG_FILE}"

  local line_count
  line_count="$(wc -l < "${SOCKS_SECURITY_LOG_FILE}" 2>/dev/null | tr -d ' ')"
  if [[ "${line_count}" =~ ^[0-9]+$ ]] && (( line_count > 5000 )); then
    tail -n 2000 "${SOCKS_SECURITY_LOG_FILE}" > "${SOCKS_SECURITY_LOG_FILE}.tmp" && mv "${SOCKS_SECURITY_LOG_FILE}.tmp" "${SOCKS_SECURITY_LOG_FILE}"
  fi
}

count_recent_socks_alerts() {
  local now_epoch="$1"
  if [[ ! -f "${SOCKS_SECURITY_LOG_FILE}" ]]; then
    echo 0
    return
  fi

  awk -F'|' -v now="${now_epoch}" -v win="${SOCKS_ALERT_WINDOW_SECONDS}" '
    $1 ~ /^[0-9]+$/ && (now - $1) <= win && $2 == "1" { c++ }
    END { print c + 0 }
  ' "${SOCKS_SECURITY_LOG_FILE}" 2>/dev/null || echo 0
}

last_socks_drop_packets_from_log() {
  if [[ ! -f "${SOCKS_SECURITY_LOG_FILE}" ]]; then
    echo ""
    return
  fi
  tail -n 1 "${SOCKS_SECURITY_LOG_FILE}" 2>/dev/null | awk -F'|' '{print $7}'
}

check_socks_security_status() {
  SOCKS_ALERT=0
  SOCKS_RECENT_ALERTS=0
  SOCKS_ALERT_LEVEL="none"
  if [[ "${SOCKS_ENABLE}" -ne 1 ]]; then
    return
  fi
  if ! command -v ss >/dev/null 2>&1; then
    warn "缺少 ss，跳过 SOCKS5 安全检测"
    return
  fi

  local established_conn peer_ips total_established unique_ip_count top_line top_ip top_ip_count
  local drop_packets prev_drop_packets drop_delta_packets outside_allowlist_count now_epoch recent_alerts instant_alert severe_alert
  established_conn="$(ss -Htn state established "sport = :${SOCKS_PORT}" 2>/dev/null || true)"
  peer_ips="$(extract_peer_ips_from_ss "${established_conn}")"
  total_established=0
  unique_ip_count=0
  top_ip="-"
  top_ip_count=0
  drop_packets=0
  prev_drop_packets=0
  drop_delta_packets=0
  outside_allowlist_count=0
  now_epoch="$(date +%s)"
  instant_alert=0
  severe_alert=0

  if [[ -n "${peer_ips}" ]]; then
    total_established="$(printf '%s\n' "${peer_ips}" | wc -l | tr -d ' ')"
    unique_ip_count="$(printf '%s\n' "${peer_ips}" | sort -u | wc -l | tr -d ' ')"
    top_line="$(printf '%s\n' "${peer_ips}" | sort | uniq -c | sort -nr | head -n1)"
    if [[ -n "${top_line}" ]]; then
      top_ip_count="$(awk '{print $1}' <<< "${top_line}")"
      top_ip="$(awk '{print $2}' <<< "${top_line}")"
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    local drop_value
    drop_value="$(iptables -nvxL SOCKS5_LIM 2>/dev/null | awk '/DROP/ {print $1; exit}')"
    if [[ "${drop_value}" =~ ^[0-9]+$ ]]; then
      drop_packets="${drop_value}"
    fi
  fi

  prev_drop_packets="$(last_socks_drop_packets_from_log)"
  if [[ ! "${prev_drop_packets}" =~ ^[0-9]+$ ]]; then
    prev_drop_packets="${drop_packets}"
  fi
  if (( drop_packets >= prev_drop_packets )); then
    drop_delta_packets="$((drop_packets - prev_drop_packets))"
  else
    drop_delta_packets=0
  fi

  if [[ -n "${SOCKS_ALLOW}" && -n "${peer_ips}" ]]; then
    outside_allowlist_count="$(count_outside_allowlist_ips "${SOCKS_ALLOW}" "${peer_ips}")"
    if [[ ! "${outside_allowlist_count}" =~ ^[0-9]+$ ]]; then
      outside_allowlist_count=0
    fi
  fi

  local -a reasons=()
  if (( drop_delta_packets > 0 )); then
    reasons+=("本次检测窗口新增限速丢弃 ${drop_delta_packets} 次")
    instant_alert=1
    severe_alert=1
  fi
  if (( top_ip_count >= SOCKS_CONN_LIMIT_HITCOUNT )); then
    reasons+=("单一来源连接数接近/超过限速阈值")
    instant_alert=1
  fi
  if [[ -n "${SOCKS_ALLOW}" ]] && (( outside_allowlist_count > 0 )); then
    reasons+=("存在白名单外来源IP")
    instant_alert=1
    severe_alert=1
  fi
  if [[ -z "${SOCKS_ALLOW}" ]] && (( unique_ip_count >= 5 )); then
    reasons+=("未设置白名单且来源IP较多")
    instant_alert=1
  fi

  append_socks_security_event "${now_epoch}" "${instant_alert}" "${severe_alert}" "${total_established}" "${unique_ip_count}" "${top_ip_count}" "${drop_packets}" "${outside_allowlist_count}"
  recent_alerts="$(count_recent_socks_alerts "${now_epoch}")"
  if [[ ! "${recent_alerts}" =~ ^[0-9]+$ ]]; then
    recent_alerts=0
  fi
  SOCKS_RECENT_ALERTS="${recent_alerts}"

  echo
  echo "================ SOCKS5 安全检测 ================"
  echo "SOCKS5 端口             : ${SOCKS_PORT}/tcp (UDP disabled)"
  echo "当前建立连接数          : ${total_established}"
  echo "当前来源 IP 数          : ${unique_ip_count}"
  echo "连接最多来源            : ${top_ip} (${top_ip_count})"
  echo "限速丢弃计数(iptables)  : ${drop_packets}"
  echo "本次新增丢弃计数        : ${drop_delta_packets}"
  if [[ -n "${SOCKS_ALLOW}" ]]; then
    echo "白名单外活跃 IP 数      : ${outside_allowlist_count}"
  fi
  echo "历史窗口告警数          : ${SOCKS_RECENT_ALERTS}/${SOCKS_ALERT_MIN_EVENTS} (最近 ${SOCKS_ALERT_WINDOW_SECONDS} 秒)"
  echo "安全日志文件            : ${SOCKS_SECURITY_LOG_FILE}"
  echo "================================================"

  if (( severe_alert == 1 || SOCKS_RECENT_ALERTS >= SOCKS_ALERT_MIN_EVENTS )); then
    SOCKS_ALERT=1
    SOCKS_ALERT_LEVEL="strong"
    if (( ${#reasons[@]} > 0 )); then
      warn "检测结论：疑似被攻击或被他人使用（${reasons[*]}）"
    else
      warn "检测结论：疑似被攻击或被他人使用（历史窗口已达到阈值）"
    fi
  elif (( instant_alert == 1 )); then
    SOCKS_ALERT=1
    SOCKS_ALERT_LEVEL="weak"
    warn "检测到单次异常（历史窗口未达到强告警阈值），继续执行并建议持续观察。"
  else
    log "检测结论：未发现明显攻击或他人使用痕迹"
  fi

  if [[ "${SOCKS_REQUIRE_ATTACK_BEFORE_RESET}" -eq 1 && "${SOCKS_ALERT}" -eq 0 ]]; then
    err "按策略要求，未检测到攻击/他人使用时不继续。可设置 SOCKS_REQUIRE_ATTACK_BEFORE_RESET=0 强制继续。"
  fi
}

write_socks_watchdog_env() {
  mkdir -p "$(dirname "${SOCKS_WATCHDOG_ENV}")"
  mkdir -p "$(dirname "${SOCKS_WATCHDOG_STATE}")"

  {
    printf 'SOCKS_PORT=%q\n' "${SOCKS_PORT}"
    printf 'SOCKS_ALLOW=%q\n' "${SOCKS_ALLOW}"
    printf 'SOCKS_CONN_LIMIT_HITCOUNT=%q\n' "${SOCKS_CONN_LIMIT_HITCOUNT}"
    printf 'SOCKS_ALERT_WINDOW_SECONDS=%q\n' "${SOCKS_ALERT_WINDOW_SECONDS}"
    printf 'SOCKS_ALERT_MIN_EVENTS=%q\n' "${SOCKS_ALERT_MIN_EVENTS}"
    printf 'SOCKS_SECURITY_LOG_FILE=%q\n' "${SOCKS_SECURITY_LOG_FILE}"
    printf 'SOCKS_WATCHDOG_STATE=%q\n' "${SOCKS_WATCHDOG_STATE}"
    printf 'TG_NOTIFY_ENABLE=%q\n' "${TG_NOTIFY_ENABLE}"
    printf 'TG_BOT_TOKEN=%q\n' "${TG_BOT_TOKEN}"
    printf 'TG_CHAT_ID=%q\n' "${TG_CHAT_ID}"
    printf 'TG_API_BASE_URL=%q\n' "${TG_API_BASE_URL}"
    printf 'TG_NOTIFY_LEVEL=%q\n' "${TG_NOTIFY_LEVEL}"
    printf 'TG_NOTIFY_COOLDOWN_SECONDS=%q\n' "${TG_NOTIFY_COOLDOWN_SECONDS}"
  } > "${SOCKS_WATCHDOG_ENV}"
  chmod 600 "${SOCKS_WATCHDOG_ENV}"
}

write_socks_watchdog_script() {
  cat > "${SOCKS_WATCHDOG_SCRIPT}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/default/socks5-watchdog"
[[ -f "${ENV_FILE}" ]] || exit 0
# shellcheck disable=SC1090
source "${ENV_FILE}"

: "${SOCKS_PORT:=}"
: "${SOCKS_ALLOW:=}"
: "${SOCKS_CONN_LIMIT_HITCOUNT:=20}"
: "${SOCKS_ALERT_WINDOW_SECONDS:=600}"
: "${SOCKS_ALERT_MIN_EVENTS:=2}"
: "${SOCKS_SECURITY_LOG_FILE:=/var/log/vps_socks_security.log}"
: "${SOCKS_WATCHDOG_STATE:=/var/lib/socks5-watchdog/state}"
: "${TG_NOTIFY_ENABLE:=0}"
: "${TG_BOT_TOKEN:=}"
: "${TG_CHAT_ID:=}"
: "${TG_API_BASE_URL:=https://api.telegram.org}"
: "${TG_NOTIFY_LEVEL:=strong}"
: "${TG_NOTIFY_COOLDOWN_SECONDS:=300}"

[[ -n "${SOCKS_PORT}" ]] || exit 0
[[ "${TG_NOTIFY_ENABLE}" -eq 1 ]] || exit 0
[[ -n "${TG_BOT_TOKEN}" && -n "${TG_CHAT_ID}" ]] || exit 0

extract_peer_ips_from_ss() {
  local ss_output="$1"
  [[ -n "${ss_output}" ]] || return 0
  printf '%s\n' "${ss_output}" | awk '{print $5}' | sed -E 's/^\[?([^]]+)\]?:[0-9]+$/\1/' | sed '/^[[:space:]]*$/d'
}

count_outside_allowlist_ips() {
  local allow_cidr="$1"
  local ip_list="$2"
  if [[ -z "${allow_cidr}" || -z "${ip_list}" ]]; then
    echo 0
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo 0
    return
  fi

  printf '%s\n' "${ip_list}" | python3 - "${allow_cidr}" <<'PY'
import ipaddress
import sys

allow = ipaddress.ip_network(sys.argv[1], strict=False)
outside = set()
for raw in sys.stdin:
    value = raw.strip()
    if not value:
        continue
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        continue
    if ip not in allow:
        outside.add(value)
print(len(outside))
PY
}

ensure_log_file() {
  mkdir -p "$(dirname "${SOCKS_SECURITY_LOG_FILE}")"
  touch "${SOCKS_SECURITY_LOG_FILE}"
  chmod 600 "${SOCKS_SECURITY_LOG_FILE}" >/dev/null 2>&1 || true
}

append_event() {
  local now_epoch="$1"
  local instant_alert="$2"
  local severe_alert="$3"
  local total_established="$4"
  local unique_ip_count="$5"
  local top_ip_count="$6"
  local drop_packets="$7"
  local outside_allowlist_count="$8"

  ensure_log_file
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "${now_epoch}" "${instant_alert}" "${severe_alert}" "${total_established}" \
    "${unique_ip_count}" "${top_ip_count}" "${drop_packets}" "${outside_allowlist_count}" >> "${SOCKS_SECURITY_LOG_FILE}"

  local line_count
  line_count="$(wc -l < "${SOCKS_SECURITY_LOG_FILE}" 2>/dev/null | tr -d ' ')"
  if [[ "${line_count}" =~ ^[0-9]+$ ]] && (( line_count > 5000 )); then
    tail -n 2000 "${SOCKS_SECURITY_LOG_FILE}" > "${SOCKS_SECURITY_LOG_FILE}.tmp" && mv "${SOCKS_SECURITY_LOG_FILE}.tmp" "${SOCKS_SECURITY_LOG_FILE}"
  fi
}

count_recent_alerts() {
  local now_epoch="$1"
  if [[ ! -f "${SOCKS_SECURITY_LOG_FILE}" ]]; then
    echo 0
    return
  fi
  awk -F'|' -v now="${now_epoch}" -v win="${SOCKS_ALERT_WINDOW_SECONDS}" '
    $1 ~ /^[0-9]+$/ && (now - $1) <= win && $2 == "1" { c++ }
    END { print c + 0 }
  ' "${SOCKS_SECURITY_LOG_FILE}" 2>/dev/null || echo 0
}

last_drop_packets_from_log() {
  if [[ ! -f "${SOCKS_SECURITY_LOG_FILE}" ]]; then
    echo ""
    return
  fi
  tail -n 1 "${SOCKS_SECURITY_LOG_FILE}" 2>/dev/null | awk -F'|' '{print $7}'
}

read_notify_state() {
  local state_line
  LAST_NOTIFY_EPOCH=0
  LAST_NOTIFY_LEVEL="none"
  if [[ ! -f "${SOCKS_WATCHDOG_STATE}" ]]; then
    return
  fi
  state_line="$(cat "${SOCKS_WATCHDOG_STATE}" 2>/dev/null || true)"
  IFS='|' read -r LAST_NOTIFY_EPOCH LAST_NOTIFY_LEVEL <<< "${state_line}"
  [[ "${LAST_NOTIFY_EPOCH}" =~ ^[0-9]+$ ]] || LAST_NOTIFY_EPOCH=0
  case "${LAST_NOTIFY_LEVEL}" in
    strong|weak|none) ;;
    *) LAST_NOTIFY_LEVEL="none" ;;
  esac
}

write_notify_state() {
  local now_epoch="$1"
  local level="$2"
  mkdir -p "$(dirname "${SOCKS_WATCHDOG_STATE}")"
  printf '%s|%s\n' "${now_epoch}" "${level}" > "${SOCKS_WATCHDOG_STATE}"
  chmod 600 "${SOCKS_WATCHDOG_STATE}" >/dev/null 2>&1 || true
}

should_notify() {
  local now_epoch="$1"
  local level="$2"
  if [[ "${level}" == "none" ]]; then
    return 1
  fi
  if [[ "${TG_NOTIFY_LEVEL}" == "strong" && "${level}" != "strong" ]]; then
    return 1
  fi

  read_notify_state
  if (( now_epoch - LAST_NOTIFY_EPOCH < TG_NOTIFY_COOLDOWN_SECONDS )); then
    if [[ "${level}" == "strong" && "${LAST_NOTIFY_LEVEL}" != "strong" ]]; then
      return 0
    fi
    return 1
  fi
  return 0
}

send_telegram() {
  local msg="$1"
  local endpoint="${TG_API_BASE_URL%/}/bot${TG_BOT_TOKEN}/sendMessage"
  curl -fsS --max-time 12 -X POST "${endpoint}" \
    --data-urlencode "chat_id=${TG_CHAT_ID}" \
    --data-urlencode "text=${msg}" >/dev/null
}

main() {
  command -v ss >/dev/null 2>&1 || exit 0
  command -v curl >/dev/null 2>&1 || exit 0

  local established_conn peer_ips total_established unique_ip_count top_line top_ip top_ip_count
  local drop_packets prev_drop_packets drop_delta_packets outside_allowlist_count now_epoch recent_alerts instant_alert severe_alert alert_level
  local host_name server_ip notify_message

  established_conn="$(ss -Htn state established "sport = :${SOCKS_PORT}" 2>/dev/null || true)"
  peer_ips="$(extract_peer_ips_from_ss "${established_conn}")"
  total_established=0
  unique_ip_count=0
  top_ip="-"
  top_ip_count=0
  drop_packets=0
  prev_drop_packets=0
  drop_delta_packets=0
  outside_allowlist_count=0
  now_epoch="$(date +%s)"
  instant_alert=0
  severe_alert=0
  alert_level="none"

  if [[ -n "${peer_ips}" ]]; then
    total_established="$(printf '%s\n' "${peer_ips}" | wc -l | tr -d ' ')"
    unique_ip_count="$(printf '%s\n' "${peer_ips}" | sort -u | wc -l | tr -d ' ')"
    top_line="$(printf '%s\n' "${peer_ips}" | sort | uniq -c | sort -nr | head -n1)"
    if [[ -n "${top_line}" ]]; then
      top_ip_count="$(awk '{print $1}' <<< "${top_line}")"
      top_ip="$(awk '{print $2}' <<< "${top_line}")"
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    local drop_value
    drop_value="$(iptables -nvxL SOCKS5_LIM 2>/dev/null | awk '/DROP/ {print $1; exit}')"
    if [[ "${drop_value}" =~ ^[0-9]+$ ]]; then
      drop_packets="${drop_value}"
    fi
  fi

  prev_drop_packets="$(last_drop_packets_from_log)"
  if [[ ! "${prev_drop_packets}" =~ ^[0-9]+$ ]]; then
    prev_drop_packets="${drop_packets}"
  fi
  if (( drop_packets >= prev_drop_packets )); then
    drop_delta_packets="$((drop_packets - prev_drop_packets))"
  else
    drop_delta_packets=0
  fi

  if [[ -n "${SOCKS_ALLOW}" && -n "${peer_ips}" ]]; then
    outside_allowlist_count="$(count_outside_allowlist_ips "${SOCKS_ALLOW}" "${peer_ips}")"
    if [[ ! "${outside_allowlist_count}" =~ ^[0-9]+$ ]]; then
      outside_allowlist_count=0
    fi
  fi

  if (( drop_delta_packets > 0 )); then
    instant_alert=1
    severe_alert=1
  fi
  if (( top_ip_count >= SOCKS_CONN_LIMIT_HITCOUNT )); then
    instant_alert=1
  fi
  if [[ -n "${SOCKS_ALLOW}" ]] && (( outside_allowlist_count > 0 )); then
    instant_alert=1
    severe_alert=1
  fi
  if [[ -z "${SOCKS_ALLOW}" ]] && (( unique_ip_count >= 5 )); then
    instant_alert=1
  fi

  append_event "${now_epoch}" "${instant_alert}" "${severe_alert}" "${total_established}" "${unique_ip_count}" "${top_ip_count}" "${drop_packets}" "${outside_allowlist_count}"
  recent_alerts="$(count_recent_alerts "${now_epoch}")"
  [[ "${recent_alerts}" =~ ^[0-9]+$ ]] || recent_alerts=0

  if (( severe_alert == 1 || recent_alerts >= SOCKS_ALERT_MIN_EVENTS )); then
    alert_level="strong"
  elif (( instant_alert == 1 )); then
    alert_level="weak"
  fi

  should_notify "${now_epoch}" "${alert_level}" || exit 0

  host_name="$(hostname 2>/dev/null || echo unknown-host)"
  server_ip="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')"
  server_ip="${server_ip:-unknown-ip}"

  notify_message="$(cat <<MSG
[SOCKS5 告警]
级别: ${alert_level}
主机: ${host_name} (${server_ip})
端口: ${SOCKS_PORT}
当前连接: ${total_established}
来源IP数: ${unique_ip_count}
最大单IP连接: ${top_ip_count}
限速丢弃计数: ${drop_packets}
本次新增丢弃: ${drop_delta_packets}
白名单外IP数: ${outside_allowlist_count}
窗口告警: ${recent_alerts}/${SOCKS_ALERT_MIN_EVENTS} (${SOCKS_ALERT_WINDOW_SECONDS}s)
时间: $(date '+%F %T %z')
MSG
)"

  send_telegram "${notify_message}" && write_notify_state "${now_epoch}" "${alert_level}"
}

main "$@"
EOF
  chmod 700 "${SOCKS_WATCHDOG_SCRIPT}"
}

write_socks_watchdog_systemd_units() {
  cat > "${SOCKS_WATCHDOG_SERVICE}" <<EOF
[Unit]
Description=SOCKS5 Security Watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SOCKS_WATCHDOG_SCRIPT}
EOF

  cat > "${SOCKS_WATCHDOG_TIMER}" <<EOF
[Unit]
Description=Run SOCKS5 Security Watchdog every ${SOCKS_WATCHDOG_INTERVAL_SECONDS}s

[Timer]
OnBootSec=2min
OnUnitActiveSec=${SOCKS_WATCHDOG_INTERVAL_SECONDS}s
Persistent=true
Unit=socks5-watchdog.service

[Install]
WantedBy=timers.target
EOF
}

disable_socks_watchdog() {
  systemctl disable --now socks5-watchdog.timer >/dev/null 2>&1 || true
  systemctl stop socks5-watchdog.service >/dev/null 2>&1 || true
}

configure_socks_watchdog() {
  if [[ "${SOCKS_ENABLE}" -ne 1 || "${TG_NOTIFY_ENABLE}" -ne 1 ]]; then
    disable_socks_watchdog
    return
  fi

  write_socks_watchdog_env
  write_socks_watchdog_script
  write_socks_watchdog_systemd_units

  systemctl daemon-reload
  systemctl enable --now socks5-watchdog.timer >/dev/null 2>&1 || err "启用 socks5-watchdog.timer 失败"
  log "Telegram 告警已启用：socks5-watchdog.timer 每 ${SOCKS_WATCHDOG_INTERVAL_SECONDS} 秒检测一次"
}

restore_stopped_services_on_failure() {
  local exit_code="$1"
  if [[ "${exit_code}" -eq 0 ]]; then
    return
  fi
  if (( ${#STOPPED_SERVICES[@]} == 0 )); then
    return
  fi
  warn "安装异常退出，尝试恢复已停止服务..."
  local svc
  for svc in "${STOPPED_SERVICES[@]}"; do
    if systemctl start "${svc}" >/dev/null 2>&1; then
      warn "已恢复服务：${svc}"
    else
      warn "恢复服务失败：${svc}，请手动执行 systemctl start ${svc}"
    fi
  done
}

ensure_uuid() {
  if [[ -z "${UUID}" ]]; then
    UUID="$(cat /proc/sys/kernel/random/uuid)"
    warn "未提供 UUID，已生成：${UUID}"
  fi
}

ensure_hy2_password() {
  if [[ -z "${HY2_PASSWORD}" ]]; then
    if command -v openssl >/dev/null 2>&1; then
      HY2_PASSWORD="$(generate_openssl_password 24)"
    else
      HY2_PASSWORD="$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-20)"
    fi
    warn "未提供 HY2_PASSWORD，已生成：${HY2_PASSWORD}"
  fi
}

ensure_socks_creds() {
  if [[ "${SOCKS_ENABLE}" -ne 1 ]]; then
    return
  fi
  if [[ -z "${SOCKS_PORT}" ]]; then
    SOCKS_PORT="$(pick_random_socks_port)"
  fi
  if [[ -z "${SOCKS_USER}" ]]; then
    SOCKS_USER="usr$(random_alphanum 6)"
  fi
  if [[ -z "${SOCKS_PASS}" ]]; then
    SOCKS_PASS="$(generate_socks_password)"
  fi
  log "SOCKS5 凭据已就绪（详见安装完成后的 SUMMARY）"
}

apply_socks_iptables_rules() {
  if [[ "${SOCKS_ENABLE}" -ne 1 ]]; then
    return
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    warn "iptables 不可用，无法设置 SOCKS5 连接限制"
    return
  fi

  local chain="SOCKS5_LIM"
  if ! iptables -nL "${chain}" >/dev/null 2>&1; then
    iptables -N "${chain}"
  else
    iptables -F "${chain}"
  fi

  iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" -j "${chain}" >/dev/null 2>&1 || true
  if [[ -n "${SOCKS_ALLOW}" ]]; then
    iptables -D INPUT -p tcp -s "${SOCKS_ALLOW}" --dport "${SOCKS_PORT}" -j ACCEPT >/dev/null 2>&1 || true
    iptables -I INPUT -p tcp -s "${SOCKS_ALLOW}" --dport "${SOCKS_PORT}" -j ACCEPT
  fi
  iptables -A INPUT -p tcp --dport "${SOCKS_PORT}" -j "${chain}"

  iptables -A "${chain}" -m conntrack --ctstate NEW -m recent --set --name socks5 --rsource
  iptables -A "${chain}" -m conntrack --ctstate NEW -m recent --update --seconds "${SOCKS_CONN_LIMIT_SECONDS}" --hitcount "${SOCKS_CONN_LIMIT_HITCOUNT}" --name socks5 --rsource -j DROP
  iptables -A "${chain}" -j ACCEPT

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || warn "netfilter-persistent save 失败"
  fi
  log "SOCKS5 限速已启用：每个 IP 每 ${SOCKS_CONN_LIMIT_SECONDS} 秒最多 ${SOCKS_CONN_LIMIT_HITCOUNT} 个新连接（仅 TCP）"
}

check_port_conflict() {
  local port="$1"
  local proto="${2:-tcp}"
  local port_info

  if ! command -v ss >/dev/null 2>&1; then
    err "缺少 ss 命令，无法进行端口占用检测"
  fi

  case "${proto}" in
    tcp)
      port_info="$(ss -ltnH "sport = :${port}" 2>/dev/null || true)"
      ;;
    udp)
      port_info="$(ss -lunH "sport = :${port}" 2>/dev/null || true)"
      ;;
    *)
      err "不支持的协议类型：${proto}"
      ;;
  esac

  if [[ -n "${port_info}" ]]; then
    warn "端口 ${port}/${proto} 已被占用："
    echo "${port_info}"
    err "请先停止占用 ${port}/${proto} 的进程，或更换端口后重试"
  fi
}

validate_origin_cert_format() {
  local invalid=0

  if ! grep -q 'BEGIN CERTIFICATE' "${ORIGIN_PEM}"; then
    invalid=1
  fi
  if ! grep -Eq 'BEGIN .*PRIVATE KEY' "${ORIGIN_KEY}"; then
    invalid=1
  fi

  if [[ "${invalid}" -ne 0 ]]; then
    rm -f "${ORIGIN_PEM}" "${ORIGIN_KEY}"
    err "Origin 证书或私钥格式错误（缺少 BEGIN CERTIFICATE/BEGIN PRIVATE KEY），已删除并终止"
  fi
}

nginx_use_http2_on_directive() {
  local nginx_ver
  nginx_ver="$(nginx -v 2>&1 | sed -nE 's#^nginx version: nginx/([0-9.]+).*$#\1#p')"

  if [[ -z "${nginx_ver}" ]]; then
    warn "无法识别 Nginx 版本，回退到 listen ... ssl http2 语法"
    return 1
  fi

  if command -v dpkg >/dev/null 2>&1; then
    dpkg --compare-versions "${nginx_ver}" ge "1.25.1"
    return $?
  fi

  if [[ "$(printf '%s\n%s\n' "1.25.1" "${nginx_ver}" | sort -V | tail -n1)" == "${nginx_ver}" ]]; then
    return 0
  fi
  return 1
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl nginx ca-certificates qrencode python3
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    apt-get install -y iptables-persistent netfilter-persistent
  fi
}

set_sensitive_config_permissions() {
  local file_path="$1"
  local service_name="$2"
  local service_user service_group

  service_user="$(systemctl show -p User --value "${service_name}" 2>/dev/null | tr -d '[:space:]')"
  service_user="${service_user:-root}"

  if [[ "${service_user}" == "root" ]]; then
    chown root:root "${file_path}" >/dev/null 2>&1 || true
    chmod 600 "${file_path}"
    return
  fi

  service_group="$(id -gn "${service_user}" 2>/dev/null || true)"
  if [[ -n "${service_group}" ]]; then
    chown root:"${service_group}" "${file_path}" >/dev/null 2>&1 || true
    chmod 640 "${file_path}"
  else
    warn "无法识别 ${service_name} 的用户组，${file_path} 权限回退为 600"
    chown root:root "${file_path}" >/dev/null 2>&1 || true
    chmod 600 "${file_path}"
  fi
}

write_origin_cert_interactive() {
  mkdir -p "${ORIGIN_DIR}"
  chmod 700 "${ORIGIN_DIR}"

  if [[ -f "${ORIGIN_PEM}" && -f "${ORIGIN_KEY}" ]]; then
    log "检测到已存在 Origin 证书：${ORIGIN_PEM}, ${ORIGIN_KEY}（将直接使用）"
    validate_origin_cert_format
    chmod 600 "${ORIGIN_PEM}" "${ORIGIN_KEY}"
    return
  fi

  warn "未检测到 Origin 证书，将进入粘贴模式。"
  echo
  echo "请从 Cloudflare 面板复制 PEM 证书内容（包含 BEGIN/END 行），粘贴后按 Ctrl+D 结束："
  cat > "${ORIGIN_PEM}"

  if ! grep -q 'BEGIN CERTIFICATE' "${ORIGIN_PEM}"; then
    rm -f "${ORIGIN_PEM}"
    err "PEM 证书格式不正确，缺少 BEGIN CERTIFICATE 行"
  fi

  echo
  echo "请复制 KEY 私钥内容（包含 BEGIN/END 行），粘贴后按 Ctrl+D 结束："
  cat > "${ORIGIN_KEY}"

  validate_origin_cert_format

  chmod 600 "${ORIGIN_PEM}" "${ORIGIN_KEY}"
  log "Origin 证书已写入并设置权限 600"
}

setup_nginx_index() {
  mkdir -p "${NGINX_SITE_DIR}"
  cat > "${NGINX_SITE_DIR}/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         display: flex; justify-content: center; align-items: center; min-height: 100vh;
         margin: 0; background: #f5f5f5; color: #333; }
  .container { text-align: center; padding: 2rem; }
  h1 { font-size: 2rem; font-weight: 300; margin-bottom: 0.5rem; }
  p { color: #666; font-size: 0.95rem; }
</style>
</head>
<body>
<div class="container">
  <h1>It works!</h1>
  <p>The server is running normally.</p>
</div>
</body>
</html>
HTMLEOF
  chown -R www-data:www-data "${NGINX_SITE_DIR}"
  chmod -R 755 "${NGINX_SITE_DIR}"
  log "伪装站点已写入：${NGINX_SITE_DIR}/index.html"
}

install_xray() {
  if command -v xray >/dev/null 2>&1; then
    log "xray 已安装，跳过安装步骤"
    return
  fi
  warn "即将在线安装 xray：${XRAY_INSTALL_URL}"
  bash <(curl -fsSL "${XRAY_INSTALL_URL}")
  log "xray 安装完成"
}

write_xray_config() {
  mkdir -p "$(dirname "${XRAY_CFG}")"
  local socks_inbound=""
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    socks_inbound="
    ,
    {
      \"tag\": \"socks-local\",
      \"protocol\": \"socks\",
      \"port\": ${SOCKS_PORT},
      \"listen\": \"${SOCKS_BIND}\",
      \"settings\": {
        \"auth\": \"password\",
        \"udp\": false,
        \"accounts\": [
          {
            \"user\": \"${SOCKS_USER}\",
            \"pass\": \"${SOCKS_PASS}\"
          }
        ]
      },
      \"streamSettings\": {
        \"network\": \"tcp\"
      }
    }"
  fi
  cat > "${XRAY_CFG}" <<EOF
{
  "inbounds": [
    {
      "port": ${XRAY_PORT},
      "listen": "${XRAY_LISTEN}",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${WSPATH}"
        }
      }
    }${socks_inbound}
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

  set_sensitive_config_permissions "${XRAY_CFG}" "xray.service"
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  log "xray 配置写入并重启：${XRAY_CFG}"
}

write_nginx_conf() {
  # 检测 Nginx 版本，1.25.1+ 使用独立 http2 on 指令
  local http2_listen http2_directive
  if nginx_use_http2_on_directive; then
    # nginx >= 1.25.1
    http2_listen="listen ${VLESS_PORT} ssl;"
    http2_directive="    http2 on;"
  else
    http2_listen="listen ${VLESS_PORT} ssl http2;"
    http2_directive=""
  fi

  cat > "${NGINX_CONF}" <<EOF
# =========================
# Nginx + Xray VLESS WS TLS + Cloudflare Origin Cert
# =========================

server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host:${VLESS_PORT}\$request_uri;
}

server {
    ${http2_listen}
    server_name ${DOMAIN};
${http2_directive}
    # Cloudflare Origin SSL 证书
    ssl_certificate     ${ORIGIN_PEM};
    ssl_certificate_key ${ORIGIN_KEY};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    # 网站伪装页
    root ${NGINX_SITE_DIR};
    index index.html;

    # 反代 WebSocket
    location ${WSPATH} {
        proxy_redirect off;
        proxy_pass http://${XRAY_LISTEN}:${XRAY_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

  nginx -t || err "nginx 配置测试失败，请检查 ${NGINX_CONF}"
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl reload nginx
  log "nginx 配置写入并通过测试：${NGINX_CONF}"
}

install_hysteria2() {
  if command -v hysteria >/dev/null 2>&1; then
    log "hysteria 已安装，跳过安装步骤"
    return
  fi
  warn "即将在线安装 hysteria2：${HY2_INSTALL_URL}"
  bash <(curl -fsSL "${HY2_INSTALL_URL}")
  log "hysteria2 安装完成"
}

write_hy2_config() {
  mkdir -p "$(dirname "${HY2_CFG}")"

  cat > "${HY2_CFG}" <<EOF
listen: :${HY2_PORT}

tls:
  cert: ${ORIGIN_PEM}
  key: ${ORIGIN_KEY}

auth:
  type: password
  password: ${HY2_PASSWORD}

masquerade:
  type: proxy
  proxy:
    url: ${HY2_MASQ_URL}
    rewriteHost: true
EOF

  set_sensitive_config_permissions "${HY2_CFG}" "hysteria-server.service"
  systemctl enable hysteria-server.service >/dev/null 2>&1 || true
  systemctl restart hysteria-server.service
  log "hysteria2 配置写入并重启：${HY2_CFG}"
}

optional_ufw() {
  if ! command -v ufw >/dev/null 2>&1; then
    apt-get install -y ufw
  fi
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow "${VLESS_PORT}/tcp"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    ufw allow "${HY2_PORT}/udp"
  fi
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    ufw allow "${SOCKS_PORT}/tcp"
  fi
  ufw --force enable
  local ufw_summary="ufw 已启用，仅放行 22/tcp 80/tcp ${VLESS_PORT}/tcp"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    ufw_summary+=" ${HY2_PORT}/udp"
  fi
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    ufw_summary+=" ${SOCKS_PORT}/tcp(SOCKS5)"
  fi
  log "${ufw_summary}"
}

urlencode() {
  local string="$1"
  local encoded=""
  encoded="$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "${string}" 2>/dev/null)" || {
    # fallback: ASCII-only byte-level encoding
    local length="${#string}" c i
    for (( i = 0; i < length; i++ )); do
      c="${string:i:1}"
      case "$c" in
        [A-Za-z0-9._~-]) printf '%s' "$c" ;;
        *) printf '%%%02X' "'$c" ;;
      esac
    done
    echo
    return
  }
  printf '%s\n' "${encoded}"
}

print_qr() {
  local title="$1"
  local link="$2"
  echo
  echo "===== ${title} 链接 ====="
  echo "${link}"
  echo
  echo "===== ${title} 二维码 ====="
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 "${link}" || warn "${title} 二维码输出失败，请复制链接导入"
  else
    warn "未安装 qrencode，无法输出二维码"
  fi
}

print_summary() {
  local ws_path_enc
  local hy2_password_enc=""
  local vless_uri
  local hy2_uri=""
  local socks_ip

  ws_path_enc="$(urlencode "${WSPATH}")"
  vless_uri="vless://${UUID}@${DOMAIN}:${VLESS_PORT}?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=${ws_path_enc}&sni=${DOMAIN}#CF-Nginx-Xray"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    hy2_password_enc="$(urlencode "${HY2_PASSWORD}")"
    hy2_uri="hy2://${hy2_password_enc}@${HY2_DOMAIN}:${HY2_PORT}/?sni=${HY2_SNI}&insecure=${HY2_INSECURE}#CF-HY2"
  fi

  echo
  echo "==================== SUMMARY ===================="
  echo "Domain        : ${DOMAIN}"
  echo "VLESS Port    : ${VLESS_PORT}"
  echo "UUID          : ${UUID}"
  echo "WS Path       : ${WSPATH}"
  echo "Xray Listen   : ${XRAY_LISTEN}:${XRAY_PORT}"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    echo "HY2 Domain    : ${HY2_DOMAIN}"
    echo "HY2 Port(UDP) : ${HY2_PORT}"
    echo "HY2 Password  : ${HY2_PASSWORD}"
  else
    echo "HY2           : 未安装"
  fi
  echo "Origin PEM    : ${ORIGIN_PEM}"
  echo "Origin KEY    : ${ORIGIN_KEY}"
  echo "Nginx Conf    : ${NGINX_CONF}"
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    socks_ip="$(get_primary_ip)"
    echo "Socks5 本地代理：127.0.0.1:${SOCKS_PORT}（${SOCKS_USER}/${SOCKS_PASS}）"
    echo "Socks5 公网直连：${socks_ip}:${SOCKS_PORT}（${SOCKS_USER}/${SOCKS_PASS}）"
    echo ""
    echo "===== SOCKS5 快速复制 ====="
    echo "${socks_ip}:${SOCKS_PORT}:${SOCKS_USER}:${SOCKS_PASS}"
    echo "==========================="
    if [[ -n "${SOCKS_ALLOW}" ]]; then
      echo "SOCKS5 Allow  : ${SOCKS_ALLOW}"
    else
      echo "SOCKS5 Allow  : 0.0.0.0/0（任意 IP）"
    fi
    echo "SOCKS5 UDP    : disabled (TCP only)"
    echo "SOCKS5 Limit  : ${SOCKS_CONN_LIMIT_HITCOUNT} new conn / ${SOCKS_CONN_LIMIT_SECONDS}s per IP"
    echo "SOCKS5 Window : ${SOCKS_RECENT_ALERTS}/${SOCKS_ALERT_MIN_EVENTS} alerts in ${SOCKS_ALERT_WINDOW_SECONDS}s"
    echo "SOCKS5 Log    : ${SOCKS_SECURITY_LOG_FILE}"
    if [[ "${TG_NOTIFY_ENABLE}" -eq 1 ]]; then
      echo "TG Notify     : enabled (${TG_NOTIFY_LEVEL}, cooldown ${TG_NOTIFY_COOLDOWN_SECONDS}s)"
      echo "TG Chat ID    : ${TG_CHAT_ID}"
      echo "TG API Base   : ${TG_API_BASE_URL}"
      echo "TG Watchdog   : socks5-watchdog.timer (${SOCKS_WATCHDOG_INTERVAL_SECONDS}s)"
    else
      echo "TG Notify     : disabled"
    fi
    if [[ "${SOCKS_ALERT_LEVEL}" == "strong" ]]; then
      echo "SOCKS5 Alert  : suspicious activity detected"
    elif [[ "${SOCKS_ALERT_LEVEL}" == "weak" ]]; then
      echo "SOCKS5 Alert  : single anomaly detected (observe)"
    else
      echo "SOCKS5 Alert  : no obvious suspicious activity"
    fi
  fi
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    echo "HY2 Conf      : ${HY2_CFG}"
  fi
  echo "================================================="
  echo
  echo "Cloudflare 面板建议："
  echo "1) VLESS 使用域名 ${DOMAIN}:${VLESS_PORT} 可开橙云（SSL/TLS 选 Full(strict)）"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    echo "2) HY2 使用域名 ${HY2_DOMAIN} 建议 DNS only（灰云），并放行 UDP ${HY2_PORT}"
    echo "3) 若 HY2 使用 Origin 证书，客户端需允许 insecure=1 或使用证书 pin"
  fi
  echo

  print_qr "VLESS" "${vless_uri}"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    print_qr "HY2" "${hy2_uri}"
  fi
}

main() {
  trap 'on_install_error $? ${LINENO} "${BASH_COMMAND}"' ERR
  trap 'restore_stopped_services_on_failure $?' EXIT
  need_root
  interactive_config
  check_domain
  check_ws_path
  check_port "VLESS_PORT" "${VLESS_PORT}"
  check_port "XRAY_PORT" "${XRAY_PORT}"
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    check_port "HY2_PORT" "${HY2_PORT}"
    if [[ ! "${HY2_INSECURE}" =~ ^[0-1]$ ]]; then
      err "HY2_INSECURE 只能是 0 或 1"
    fi
    if [[ "${VLESS_PORT}" == "${HY2_PORT}" ]]; then
      warn "VLESS_PORT 与 HY2_PORT 相同（${VLESS_PORT}），依赖 TCP/UDP 协议区分。请确认防火墙/云平台支持"
    fi
  fi

  ensure_uuid
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    ensure_hy2_password
  fi
  ensure_socks_creds
  validate_socks_allow
  validate_socks_security_options
  validate_telegram_notify_options
  prepare_install_steps
  start_install_step "执行 SOCKS5 安全预检查"
  check_socks_security_status

  # 幂等：停止已有服务，避免重跑时端口冲突
  start_install_step "准备安装环境（停止旧服务、检测端口、安装依赖）"
  local svc_list=(nginx xray)
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    svc_list+=(hysteria-server)
  fi
  for svc in "${svc_list[@]}"; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
      warn "停止已有服务 ${svc} 以便重新配置..."
      systemctl stop "${svc}"
      STOPPED_SERVICES+=("${svc}")
    fi
  done

  # 检查端口占用
  check_port_conflict 80 tcp
  check_port_conflict "${VLESS_PORT}" tcp
  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    check_port_conflict "${HY2_PORT}" udp
  fi
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    check_port "SOCKS_PORT" "${SOCKS_PORT}"
    check_port_conflict "${SOCKS_PORT}" tcp
  fi
  apt_install
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl start nginx

  start_install_step "写入伪装站点并配置证书"
  setup_nginx_index
  write_origin_cert_interactive

  start_install_step "安装并配置 Xray + Nginx"
  install_xray
  write_xray_config
  write_nginx_conf

  if [[ "${HY2_ENABLE}" -eq 1 ]]; then
    start_install_step "安装并配置 Hysteria2"
    install_hysteria2
    write_hy2_config
  else
    log "已跳过 Hysteria2 安装（HY2_ENABLE=0）"
  fi

  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    start_install_step "应用 SOCKS5 防护规则（iptables）"
    apply_socks_iptables_rules
    if [[ "${TG_NOTIFY_ENABLE}" -eq 1 ]]; then
      start_install_step "启用 Telegram 告警 Watchdog"
      configure_socks_watchdog
    else
      configure_socks_watchdog
    fi
  else
    configure_socks_watchdog
  fi

  # 可选：启用防火墙（如不需要，注释掉下一行）
  # optional_ufw

  start_install_step "输出安装结果与运行状态"
  print_summary
  print_runtime_status
  STOPPED_SERVICES=()
  trap - ERR
  trap - EXIT
  log "全部完成。VLESS/HY2 链接与二维码已输出。"
}

main "$@"
