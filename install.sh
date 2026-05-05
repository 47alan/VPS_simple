#!/usr/bin/env bash
set -Eeuo pipefail

# Docker Nginx reverse proxy one-click initializer.
# Target OS: Ubuntu/Debian. Existing configs are preserved unless OVERWRITE=1.

PROJECT_DIR="${PROJECT_DIR:-/opt/reverse-proxy}"
CONTAINER_NAME="${CONTAINER_NAME:-reverse-proxy}"
NETWORK_NAME="${NETWORK_NAME:-proxy-net}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:stable}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"

XUI_DIR="${XUI_DIR:-/opt/3x-ui}"
XUI_IMAGE="${XUI_IMAGE:-ghcr.io/mhsanaei/3x-ui:latest}"
XUI_CONTAINER_NAME="${XUI_CONTAINER_NAME:-3xui_app}"
XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"
XUI_INFO_FILE="${XUI_INFO_FILE:-}"
XUI_STOP_LEGACY="${XUI_STOP_LEGACY:-ask}"
XUI_DOMAIN="${XUI_DOMAIN:-}"

CLI_PROXY_DIR="${CLI_PROXY_DIR:-/opt/cli-proxy-api}"
CLI_PROXY_IMAGE="${CLI_PROXY_IMAGE:-eceasy/cli-proxy-api:latest}"
CLI_PROXY_CONTAINER_NAME="${CLI_PROXY_CONTAINER_NAME:-cli-proxy-api}"
CLI_PROXY_BIND_IP="${CLI_PROXY_BIND_IP:-127.0.0.1}"
CLI_PROXY_API_PORT="${CLI_PROXY_API_PORT:-8317}"
CLI_PROXY_EXTRA_PORTS="${CLI_PROXY_EXTRA_PORTS:-8085 1455 54545 51121 11451}"
CLI_PROXY_API_KEY="${CLI_PROXY_API_KEY:-}"
CLI_PROXY_MANAGEMENT_SECRET="${CLI_PROXY_MANAGEMENT_SECRET:-}"
CLI_PROXY_DOMAIN="${CLI_PROXY_DOMAIN:-}"

SKRBTSO_DIR="${SKRBTSO_DIR:-/opt/skrbtso-helper}"
SKRBTSO_REPO_URL="${SKRBTSO_REPO_URL:-https://github.com/47alan/skrbtso-helper.git}"
SKRBTSO_BRANCH="${SKRBTSO_BRANCH:-main}"
SKRBTSO_IMAGE="${SKRBTSO_IMAGE:-local/skrbtso-scrapling-helper:latest}"
SKRBTSO_CONTAINER_NAME="${SKRBTSO_CONTAINER_NAME:-skrbtso-scrapling-helper}"
SKRBTSO_SERVICE_NAME="${SKRBTSO_SERVICE_NAME:-skrbtso-helper}"
SKRBTSO_PORT="${SKRBTSO_PORT:-8787}"
SKRBTSO_BIND_IP="${SKRBTSO_BIND_IP:-127.0.0.1}"
SKRBTSO_DOMAIN="${SKRBTSO_DOMAIN:-}"
SKRBTSO_TOKEN="${SKRBTSO_TOKEN:-}"
SKRBTSO_SEARCH_ORIGIN="${SKRBTSO_SEARCH_ORIGIN:-https://skrbtso.top}"
SKRBTSO_ALLOWED_SEARCH_HOSTS="${SKRBTSO_ALLOWED_SEARCH_HOSTS:-skrbtso.top}"

DOMAIN="${DOMAIN:-}"
UPSTREAM="${UPSTREAM:-}"
CREATE_SITE="${CREATE_SITE:-}"
SSL_CERT_PATH="${SSL_CERT_PATH:-}"
SSL_KEY_PATH="${SSL_KEY_PATH:-}"

SYSTEM_UPGRADE="${SYSTEM_UPGRADE:-1}"
INSTALL_DOCKER="${INSTALL_DOCKER:-1}"
START_AFTER_INSTALL="${START_AFTER_INSTALL:-1}"
INSTALL_3XUI="${INSTALL_3XUI:-0}"
INSTALL_CLIPROXY="${INSTALL_CLIPROXY:-0}"
INSTALL_SKRBTSO="${INSTALL_SKRBTSO:-0}"
OVERWRITE="${OVERWRITE:-0}"

COMMAND="${1:-install}"
SITE_CONFIG_ACTIVE=0
SYSTEM_UPGRADE_DONE=0
CLI_PROXY_CONFIG_GENERATED=0

log() { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[ERR]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Docker Nginx 反向代理一键脚本

用法:
  sudo bash ./install.sh menu        打开交互菜单，按序号选择安装/卸载
  sudo bash ./install.sh install     初始化 Docker + Nginx 反代目录和容器
  sudo bash ./install.sh install-3x-ui 只安装/启动 3x-ui Docker 容器
  sudo bash ./install.sh update-3x-ui  拉取并重启 3x-ui 最新镜像
  sudo bash ./install.sh 3x-ui-status  查看 3x-ui Compose 服务状态
  sudo bash ./install.sh 3x-ui-down    停止 3x-ui 容器
  sudo bash ./install.sh 3x-ui-up      启动 3x-ui 容器
  sudo bash ./install.sh install-cli-proxy 只安装/启动 CLIProxyAPI 容器
  sudo bash ./install.sh update-cli-proxy  拉取并重启 CLIProxyAPI 最新镜像
  sudo bash ./install.sh cli-proxy-status  查看 CLIProxyAPI Compose 服务状态
  sudo bash ./install.sh cli-proxy-down    停止 CLIProxyAPI 容器
  sudo bash ./install.sh cli-proxy-up      启动 CLIProxyAPI 容器
  sudo bash ./install.sh install-skrbtso    只安装/启动 SkrBTSo Helper 容器
  sudo bash ./install.sh update-skrbtso     更新 SkrBTSo Helper 仓库并重建容器
  sudo bash ./install.sh skrbtso-status     查看 SkrBTSo Helper Compose 服务状态
  sudo bash ./install.sh skrbtso-down       停止 SkrBTSo Helper 容器
  sudo bash ./install.sh skrbtso-up         启动 SkrBTSo Helper 容器
  sudo bash ./install.sh add-site    为一个域名生成 HTTPS 反代配置
  sudo bash ./install.sh test        检查容器内 Nginx 配置
  sudo bash ./install.sh reload      检查并重载 Nginx
  sudo bash ./install.sh status      查看 Compose 服务状态
  sudo bash ./install.sh down        停止反代容器
  sudo bash ./install.sh up          启动反代容器

常用环境变量:
  PROJECT_DIR=/opt/reverse-proxy
  CONTAINER_NAME=reverse-proxy
  NETWORK_NAME=proxy-net
  NGINX_IMAGE=nginx:stable
  HTTP_PORT=80
  HTTPS_PORT=443
  SYSTEM_UPGRADE=1
  INSTALL_3XUI=0
  INSTALL_CLIPROXY=0
  INSTALL_SKRBTSO=0
  XUI_DIR=/opt/3x-ui
  XUI_IMAGE=ghcr.io/mhsanaei/3x-ui:latest
  XUI_CONTAINER_NAME=3xui_app
  XUI_PANEL_PORT=2053
  XUI_INFO_FILE=/opt/3x-ui/install-info.txt
  XUI_STOP_LEGACY=ask
  XUI_DOMAIN=xui.example.com
  CLI_PROXY_DIR=/opt/cli-proxy-api
  CLI_PROXY_BIND_IP=127.0.0.1
  CLI_PROXY_API_PORT=8317
  CLI_PROXY_DOMAIN=api.example.com
  SKRBTSO_DIR=/opt/skrbtso-helper
  SKRBTSO_DOMAIN=helper.example.com
  SSL_CERT_PATH=/path/to/fullchain.pem
  SSL_KEY_PATH=/path/to/privkey.pem
  DOMAIN=example.com
  UPSTREAM=app-container:8080
  CREATE_SITE=1
  OVERWRITE=0

示例:
  sudo bash ./install.sh menu
  sudo bash ./install.sh install
  sudo bash ./install.sh install-3x-ui
  sudo bash ./install.sh install-cli-proxy
  sudo XUI_DOMAIN=xui.example.com bash ./install.sh install-3x-ui
  sudo CLI_PROXY_DOMAIN=api.example.com bash ./install.sh install-cli-proxy
  sudo SKRBTSO_DOMAIN=helper.example.com bash ./install.sh install-skrbtso
  sudo DOMAIN=example.com UPSTREAM=app-container:8080 bash ./install.sh add-site
EOF
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请使用 root 执行，例如：sudo bash ./install.sh ${COMMAND}"
  fi
}

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|y|Y) return 0 ;;
    *) return 1 ;;
  esac
}

compose_file() {
  printf '%s/docker-compose.yml\n' "${PROJECT_DIR}"
}

compose_cmd() {
  docker compose --project-directory "${PROJECT_DIR}" -f "$(compose_file)" "$@"
}

xui_compose_file() {
  printf '%s/docker-compose.yml\n' "${XUI_DIR}"
}

xui_info_file() {
  if [[ -n "${XUI_INFO_FILE}" ]]; then
    printf '%s\n' "${XUI_INFO_FILE}"
  else
    printf '%s/install-info.txt\n' "${XUI_DIR}"
  fi
}

xui_compose_cmd() {
  docker compose --project-directory "${XUI_DIR}" -f "$(xui_compose_file)" "$@"
}

cli_proxy_compose_file() {
  printf '%s/docker-compose.yml\n' "${CLI_PROXY_DIR}"
}

cli_proxy_compose_cmd() {
  docker compose --project-directory "${CLI_PROXY_DIR}" -f "$(cli_proxy_compose_file)" "$@"
}

skrbtso_compose_file() {
  printf '%s/docker-compose.yml\n' "${SKRBTSO_DIR}"
}

skrbtso_compose_cmd() {
  docker compose --project-directory "${SKRBTSO_DIR}" -f "$(skrbtso_compose_file)" "$@"
}

random_hex() {
  local bytes="${1:-16}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "${bytes}"
  else
    tr -d '-' < /proc/sys/kernel/random/uuid
  fi
}

detect_server_ip() {
  local value=""
  if command -v curl >/dev/null 2>&1; then
    value="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return
    fi
  fi
  if command -v ip >/dev/null 2>&1; then
    value="$(ip route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true)"
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return
    fi
  fi
  if command -v hostname >/dev/null 2>&1; then
    value="$(hostname -I 2>/dev/null | awk '{ print $1 }' || true)"
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return
    fi
  fi
  printf '服务器IP\n'
}

format_url_host() {
  local value="$1"
  if [[ "${value}" == *:* && "${value}" != \[*\] ]]; then
    printf '[%s]\n' "${value}"
  else
    printf '%s\n' "${value}"
  fi
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
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    err "${name} 必须是数字：${value}"
  fi
  if (( value < 1 || value > 65535 )); then
    err "${name} 必须在 1-65535 范围内：${value}"
  fi
}

validate_domain() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    err "DOMAIN 不能为空"
  fi
  if [[ ! "${value}" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
    err "DOMAIN 格式不合法：${value}"
  fi
}

normalize_domain() {
  local value="$1"
  value="${value//$'\r'/}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  value="${value#*://}"
  value="${value%%/*}"
  value="${value%%\?*}"
  value="${value%%#*}"
  value="${value%%:*}"
  value="${value%.}"
  printf '%s\n' "${value,,}"
}

normalize_upstream() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    err "UPSTREAM 不能为空，例如：app-container:8080"
  fi
  if [[ "${value}" =~ [[:space:]\;\{\}] ]]; then
    err "UPSTREAM 不能包含空白、分号或大括号：${value}"
  fi
  case "${value}" in
    http://*|https://*) printf '%s\n' "${value}" ;;
    *) printf 'http://%s\n' "${value}" ;;
  esac
}

prompt_value() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-}"
  local input_value=""

  if [[ -n "${default_value}" ]]; then
    read -r -p "${label} [${default_value}]: " input_value
    input_value="${input_value:-${default_value}}"
  else
    read -r -p "${label}: " input_value
  fi
  printf -v "${var_name}" '%s' "${input_value}"
}

prompt_install_site_if_needed() {
  if [[ "${COMMAND}" != "install" ]]; then
    return
  fi
  if [[ -n "${DOMAIN}" || -n "${UPSTREAM}" ]]; then
    CREATE_SITE="${CREATE_SITE:-1}"
  fi
  if [[ -z "${CREATE_SITE}" && -t 0 ]]; then
    local answer=""
    read -r -p "是否现在创建第一个 HTTPS 站点配置？证书需已放入 ssl/域名/ 下 [y/N]: " answer
    case "${answer}" in
      y|Y|yes|YES) CREATE_SITE=1 ;;
      *) CREATE_SITE=0 ;;
    esac
  fi
  CREATE_SITE="${CREATE_SITE:-0}"

  if is_truthy "${CREATE_SITE}" && [[ -t 0 ]]; then
    if [[ -z "${DOMAIN}" ]]; then
      prompt_value DOMAIN "请输入域名 DOMAIN，例如 example.com"
    fi
    if [[ -z "${UPSTREAM}" ]]; then
      prompt_value UPSTREAM "请输入后端容器和端口 UPSTREAM，例如 app-container:8080"
    fi
  fi
}

ensure_supported_system_for_docker_install() {
  if [[ ! -r /etc/os-release ]]; then
    err "无法识别系统版本，且需要安装 Docker"
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ;;
    *) err "自动安装 Docker 仅支持 Ubuntu/Debian，当前系统 ID=${ID:-unknown}" ;;
  esac
}

run_system_upgrade_once() {
  if [[ "${SYSTEM_UPGRADE_DONE}" -eq 1 ]]; then
    return
  fi
  validate_flag SYSTEM_UPGRADE "${SYSTEM_UPGRADE}"
  if ! is_truthy "${SYSTEM_UPGRADE}"; then
    warn "已跳过系统更新升级：SYSTEM_UPGRADE=${SYSTEM_UPGRADE}"
    SYSTEM_UPGRADE_DONE=1
    return
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "当前系统没有 apt-get，跳过 apt update/upgrade"
    SYSTEM_UPGRADE_DONE=1
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  apt-get autoremove -y
  SYSTEM_UPGRADE_DONE=1
  log "系统更新升级完成"
}

install_docker_engine() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    log "Docker 与 Docker Compose 已存在"
    systemctl enable --now docker >/dev/null 2>&1 || true
    return
  fi

  if ! is_truthy "${INSTALL_DOCKER}"; then
    err "未检测到 Docker 或 docker compose，请先安装，或设置 INSTALL_DOCKER=1 自动安装"
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    err "自动安装 Docker 需要 apt-get"
  fi

  ensure_supported_system_for_docker_install
  # shellcheck disable=SC1091
  . /etc/os-release

  local os_id="${ID}"
  local codename="${VERSION_CODENAME:-}"
  if [[ -z "${codename}" ]]; then
    err "无法识别系统版本代号 VERSION_CODENAME"
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${os_id} ${codename} stable
EOF

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker >/dev/null 2>&1 || true

  docker version >/dev/null 2>&1 || err "Docker 安装后仍不可用"
  docker compose version >/dev/null 2>&1 || err "Docker Compose 插件安装后仍不可用"
  log "Docker 与 Docker Compose 安装完成"
}

write_file() {
  local target="$1"
  local tmp_file
  tmp_file="$(mktemp)"
  cat > "${tmp_file}"

  mkdir -p "$(dirname "${target}")"

  if [[ -f "${target}" ]]; then
    if cmp -s "${tmp_file}" "${target}"; then
      rm -f "${tmp_file}"
      log "文件未变化：${target}"
      return
    fi

    if ! is_truthy "${OVERWRITE}"; then
      rm -f "${tmp_file}"
      warn "文件已存在，保持不变：${target}（如需覆盖请设置 OVERWRITE=1）"
      return
    fi

    local backup="${target}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "${target}" "${backup}"
    cp "${tmp_file}" "${target}"
    rm -f "${tmp_file}"
    log "已覆盖：${target}，备份：${backup}"
    return
  fi

  cp "${tmp_file}" "${target}"
  rm -f "${tmp_file}"
  log "已创建：${target}"
}

ensure_layout() {
  mkdir -p \
    "${PROJECT_DIR}/nginx/conf.d" \
    "${PROJECT_DIR}/nginx/templates" \
    "${PROJECT_DIR}/ssl" \
    "${PROJECT_DIR}/logs"

  chmod 755 "${PROJECT_DIR}" "${PROJECT_DIR}/nginx" "${PROJECT_DIR}/nginx/conf.d" "${PROJECT_DIR}/nginx/templates" "${PROJECT_DIR}/logs"
  chmod 700 "${PROJECT_DIR}/ssl"
  log "目录已就绪：${PROJECT_DIR}"
}

ensure_network() {
  if docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
    log "Docker 网络已存在：${NETWORK_NAME}"
    return
  fi
  docker network create "${NETWORK_NAME}" >/dev/null
  log "Docker 网络已创建：${NETWORK_NAME}"
}

prompt_component_domain_if_needed() {
  local domain_var="$1"
  local component_label="$2"
  local example_domain="$3"
  local current_domain="${!domain_var}"

  if [[ -n "${current_domain}" || ! -t 0 ]]; then
    return
  fi

  local answer=""
  read -r -p "是否为 ${component_label} 配置 HTTPS 域名反代？[y/N]: " answer
  case "${answer}" in
    y|Y|yes|YES)
      prompt_value "${domain_var}" "请输入 ${component_label} 域名，例如 ${example_domain}"
      ;;
  esac
}

connect_container_to_proxy_network_if_needed() {
  local container_name="$1"
  local component_label="$2"

  if ! docker ps -a --format '{{.Names}}' | grep -Fxq "${container_name}"; then
    warn "${component_label} 容器不存在，无法加入反代网络：${container_name}"
    return
  fi

  if docker inspect -f '{{range $name, $network := .NetworkSettings.Networks}}{{println $name}}{{end}}' "${container_name}" | grep -Fxq "${NETWORK_NAME}"; then
    log "${component_label} 已接入 Docker 网络：${NETWORK_NAME}"
    return
  fi

  docker network connect "${NETWORK_NAME}" "${container_name}" >/dev/null
  log "${component_label} 已接入 Docker 网络：${NETWORK_NAME}"
}

xui_reverse_proxy_upstream() {
  local gateway=""
  if [[ -f "$(compose_file)" ]] && grep -q 'host.docker.internal:host-gateway' "$(compose_file)"; then
    if ! container_running || docker exec "${CONTAINER_NAME}" getent hosts host.docker.internal >/dev/null 2>&1; then
      printf 'host.docker.internal:%s\n' "${XUI_PANEL_PORT}"
      return
    fi
  fi

  gateway="$(docker network inspect "${NETWORK_NAME}" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"
  if [[ -n "${gateway}" && "${gateway}" != "<no value>" ]]; then
    printf '%s:%s\n' "${gateway}" "${XUI_PANEL_PORT}"
    return
  fi

  printf 'host.docker.internal:%s\n' "${XUI_PANEL_PORT}"
}

configure_component_reverse_proxy() {
  local component_label="$1"
  local domain_var="$2"
  local upstream_value="$3"
  local domain_value="${!domain_var}"

  if [[ -z "${domain_value}" ]]; then
    warn "未设置 ${component_label} 反代域名，已跳过 Nginx HTTPS 站点配置"
    return
  fi
  if [[ ! -f "$(compose_file)" ]]; then
    warn "未找到 Nginx 反代 Compose 文件，请先安装基础环境 + Nginx 反代，再为 ${component_label} 配置域名"
    return
  fi

  domain_value="$(normalize_domain "${domain_value}")"
  validate_domain "${domain_value}"
  printf -v "${domain_var}" '%s' "${domain_value}"

  DOMAIN="${domain_value}"
  UPSTREAM="${upstream_value}"
  local original_ssl_cert_path="${SSL_CERT_PATH}"
  local original_ssl_key_path="${SSL_KEY_PATH}"
  write_site_config
  SSL_CERT_PATH="${original_ssl_cert_path}"
  SSL_KEY_PATH="${original_ssl_key_path}"

  if [[ "${SITE_CONFIG_ACTIVE}" -eq 1 ]]; then
    if container_running; then
      reload_nginx
    else
      start_proxy
    fi
  else
    warn "${component_label} HTTPS 站点未启用：缺少证书或证书路径未提供"
  fi
}

configure_xui_reverse_proxy() {
  if [[ -z "${XUI_DOMAIN}" ]]; then
    warn "未设置 XUI_DOMAIN，已跳过 Nginx HTTPS 站点配置"
    return
  fi
  if [[ ! -f "$(compose_file)" ]]; then
    warn "未找到 Nginx 反代 Compose 文件，请先安装基础环境 + Nginx 反代，再为 3x-ui 配置域名"
    return
  fi

  ensure_network
  local upstream_value
  upstream_value="$(xui_reverse_proxy_upstream)"
  if [[ "${upstream_value}" != host.docker.internal:* ]]; then
    warn "当前反代 Compose 未配置 host.docker.internal，已使用 Docker 网络网关作为 3x-ui 上游：${upstream_value}"
  fi
  configure_component_reverse_proxy "3x-ui" "XUI_DOMAIN" "${upstream_value}"
}

configure_cli_proxy_reverse_proxy() {
  configure_component_reverse_proxy "CLIProxyAPI" "CLI_PROXY_DOMAIN" "${CLI_PROXY_CONTAINER_NAME}:${CLI_PROXY_API_PORT}"
}

configure_skrbtso_reverse_proxy() {
  configure_component_reverse_proxy "SkrBTSo Helper" "SKRBTSO_DOMAIN" "${SKRBTSO_CONTAINER_NAME}:${SKRBTSO_PORT}"
}

ensure_xui_layout() {
  mkdir -p "${XUI_DIR}/db" "${XUI_DIR}/cert"
  chmod 755 "${XUI_DIR}" "${XUI_DIR}/db" "${XUI_DIR}/cert"
  log "3x-ui 目录已就绪：${XUI_DIR}"
}

write_xui_compose_file() {
  write_file "$(xui_compose_file)" <<EOF
services:
  3xui:
    image: ${XUI_IMAGE}
    container_name: ${XUI_CONTAINER_NAME}
    restart: unless-stopped
    network_mode: host
    tty: true
    environment:
      XRAY_VMESS_AEAD_FORCED: "false"
      XUI_ENABLE_FAIL2BAN: "true"
    volumes:
      - ./db/:/etc/x-ui/
      - ./cert/:/root/cert/
EOF
  chmod 644 "$(xui_compose_file)"
}

legacy_xui_pids() {
  pgrep -f '/usr/local/x-ui/x-ui' 2>/dev/null || true
}

legacy_xui_running() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet x-ui 2>/dev/null; then
    return 0
  fi
  [[ -n "$(legacy_xui_pids)" ]]
}

stop_legacy_xui() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop x-ui >/dev/null 2>&1 || true
    systemctl disable x-ui >/dev/null 2>&1 || true
  fi
  if [[ -n "$(legacy_xui_pids)" ]]; then
    pkill -f '/usr/local/x-ui/x-ui' >/dev/null 2>&1 || true
  fi
  sleep 2
  if legacy_xui_running; then
    err "旧版宿主机 x-ui 仍在运行，请先手动停止：systemctl stop x-ui && pkill -f /usr/local/x-ui/x-ui"
  fi
  log "旧版宿主机 x-ui 已停止并禁用，避免与 Docker 版抢占端口"
}

handle_legacy_xui_before_install() {
  if ! legacy_xui_running; then
    return
  fi

  warn "检测到旧版宿主机 3x-ui 正在运行：/usr/local/x-ui/x-ui"
  warn "如果同时安装 Docker 版 3x-ui，旧版可能占用 2096 等入站端口，导致 Docker 容器反复重启。"

  case "${XUI_STOP_LEGACY}" in
    1|true|TRUE|yes|YES|y|Y)
      stop_legacy_xui
      ;;
    0|false|FALSE|no|NO|n|N)
      warn "已按 XUI_STOP_LEGACY=${XUI_STOP_LEGACY} 保留旧版宿主机 x-ui；如端口冲突，请手动处理。"
      ;;
    ask|"")
      if [[ -t 0 ]]; then
        if confirm_action "是否停止并禁用旧版宿主机 x-ui.service，再启动 Docker 版 3x-ui？"; then
          stop_legacy_xui
        else
          err "已取消安装。请先处理旧版宿主机 x-ui，或设置 XUI_STOP_LEGACY=1 自动停用旧版。"
        fi
      else
        err "检测到旧版宿主机 x-ui 正在运行。非交互执行请设置 XUI_STOP_LEGACY=1 停用旧版，或先手动处理端口冲突。"
      fi
      ;;
    *)
      err "XUI_STOP_LEGACY 只能使用 ask/0/1/true/false：${XUI_STOP_LEGACY}"
      ;;
  esac
}

xui_container_state() {
  docker inspect -f '{{.State.Status}} {{.State.Restarting}}' "${XUI_CONTAINER_NAME}" 2>/dev/null || true
}

check_xui_container_health() {
  local state logs conflict_ports port
  sleep 3
  state="$(xui_container_state)"
  logs="$(docker logs --tail=120 "${XUI_CONTAINER_NAME}" 2>&1 || true)"
  conflict_ports="$(printf '%s\n' "${logs}" | sed -nE 's/.*listen tcp .*:([0-9]+): bind: address already in use.*/\1/p' | sort -n -u | xargs 2>/dev/null || true)"

  if [[ -z "${state}" || "${state}" != "running false" || -n "${conflict_ports}" ]]; then
    warn "3x-ui 容器启动异常。当前状态：${state:-unknown}"
    if [[ -n "${conflict_ports}" ]]; then
      for port in ${conflict_ports}; do
        warn "冲突端口：${port}/tcp"
        if command -v ss >/dev/null 2>&1; then
          ss -lntp | grep ":${port}" || true
        fi
      done
    fi
    cat <<EOF

处理建议:
  1. 查看占用端口的程序：ss -lntp | grep ':端口'
  2. 如果是旧版宿主机 x-ui：systemctl stop x-ui && systemctl disable x-ui
  3. 如果是 3x-ui 里已有入站端口冲突，请进入面板或数据库把重复端口改掉
  4. 修改后重启：cd ${XUI_DIR} && docker compose up -d

最近日志:
$(printf '%s\n' "${logs}" | tail -n 25)
EOF
    err "3x-ui 容器未健康启动，请先处理上面的端口冲突"
  fi

  log "3x-ui 容器健康检查通过：${state}"
}

install_xui() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  validate_flag OVERWRITE "${OVERWRITE}"
  validate_port XUI_PANEL_PORT "${XUI_PANEL_PORT}"
  prompt_component_domain_if_needed "XUI_DOMAIN" "3x-ui 面板" "xui.example.com"

  local existing_db=0
  if [[ -s "${XUI_DIR}/db/x-ui.db" ]]; then
    existing_db=1
  fi

  run_system_upgrade_once
  install_docker_engine
  handle_legacy_xui_before_install
  ensure_xui_layout
  write_xui_compose_file
  xui_compose_cmd up -d

  log "3x-ui 容器已启动：${XUI_CONTAINER_NAME}"
  check_xui_container_health
  configure_xui_reverse_proxy
  write_xui_install_info "${existing_db}"
  print_xui_summary "${existing_db}"
}

update_xui() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  install_docker_engine
  if [[ ! -f "$(xui_compose_file)" ]]; then
    err "未找到 3x-ui Compose 文件：$(xui_compose_file)，请先执行 install-3x-ui"
  fi
  xui_compose_cmd pull
  xui_compose_cmd up -d
  log "3x-ui 镜像已更新并重启"
  check_xui_container_health
}

ensure_cli_proxy_layout() {
  mkdir -p "${CLI_PROXY_DIR}/auths" "${CLI_PROXY_DIR}/logs"
  chmod 755 "${CLI_PROXY_DIR}" "${CLI_PROXY_DIR}/auths" "${CLI_PROXY_DIR}/logs"
  log "CLIProxyAPI 目录已就绪：${CLI_PROXY_DIR}"
}

port_mapping_lines() {
  local port
  printf '      - "%s:%s:%s"\n' "${CLI_PROXY_BIND_IP}" "${CLI_PROXY_API_PORT}" "${CLI_PROXY_API_PORT}"
  for port in ${CLI_PROXY_EXTRA_PORTS}; do
    validate_port CLI_PROXY_EXTRA_PORTS "${port}"
    if [[ "${port}" == "${CLI_PROXY_API_PORT}" ]]; then
      continue
    fi
    printf '      - "%s:%s:%s"\n' "${CLI_PROXY_BIND_IP}" "${port}" "${port}"
  done
}

write_cli_proxy_compose_file() {
  local ports
  ports="$(port_mapping_lines)"
  write_file "$(cli_proxy_compose_file)" <<EOF
services:
  cli-proxy-api:
    image: ${CLI_PROXY_IMAGE}
    pull_policy: always
    container_name: ${CLI_PROXY_CONTAINER_NAME}
    restart: unless-stopped
    ports:
${ports}
    volumes:
      - ./config.yaml:/CLIProxyAPI/config.yaml
      - ./auths:/root/.cli-proxy-api
      - ./logs:/CLIProxyAPI/logs
    networks:
      - proxy

networks:
  proxy:
    external: true
    name: ${NETWORK_NAME}
EOF
  chmod 644 "$(cli_proxy_compose_file)"
}

write_cli_proxy_config() {
  local config_file="${CLI_PROXY_DIR}/config.yaml"
  if [[ -f "${config_file}" ]] && ! is_truthy "${OVERWRITE}"; then
    CLI_PROXY_API_KEY="$(awk '
      /^api-keys:/ { in_keys=1; next }
      in_keys && /^[^[:space:]-]/ { in_keys=0 }
      in_keys && /^[[:space:]]*-/ {
        sub(/^[[:space:]]*-[[:space:]]*/, "")
        gsub(/^"|"$/, "")
        print
        exit
      }
    ' "${config_file}" 2>/dev/null || true)"
    warn "CLIProxyAPI 配置已存在，保持不变：${config_file}（如需覆盖请设置 OVERWRITE=1）"
    return
  fi

  if [[ -z "${CLI_PROXY_API_KEY}" ]]; then
    CLI_PROXY_API_KEY="$(random_hex 16)"
    CLI_PROXY_CONFIG_GENERATED=1
  fi
  if [[ -z "${CLI_PROXY_MANAGEMENT_SECRET}" ]]; then
    CLI_PROXY_MANAGEMENT_SECRET="$(random_hex 16)"
  fi

  write_file "${config_file}" <<EOF
host: 0.0.0.0
port: ${CLI_PROXY_API_PORT}
tls:
  enable: false
  cert: ""
  key: ""
api-keys:
  - "${CLI_PROXY_API_KEY}"
auth-dir: "/root/.cli-proxy-api"
proxy-url: ""
debug: false
logging-to-file: true
logs-max-total-size-mb: 100
remote-management:
  allow-remote: false
  secret-key: "${CLI_PROXY_MANAGEMENT_SECRET}"
EOF
  chmod 600 "${config_file}"
}

install_cli_proxy() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  validate_flag OVERWRITE "${OVERWRITE}"
  validate_port CLI_PROXY_API_PORT "${CLI_PROXY_API_PORT}"
  prompt_component_domain_if_needed "CLI_PROXY_DOMAIN" "CLIProxyAPI" "api.example.com"

  run_system_upgrade_once
  install_docker_engine
  ensure_network
  ensure_cli_proxy_layout
  write_cli_proxy_config
  write_cli_proxy_compose_file
  cli_proxy_compose_cmd up -d
  connect_container_to_proxy_network_if_needed "${CLI_PROXY_CONTAINER_NAME}" "CLIProxyAPI"

  log "CLIProxyAPI 容器已启动：${CLI_PROXY_CONTAINER_NAME}"
  configure_cli_proxy_reverse_proxy
  print_cli_proxy_summary
}

update_cli_proxy() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  install_docker_engine
  if [[ ! -f "$(cli_proxy_compose_file)" ]]; then
    err "未找到 CLIProxyAPI Compose 文件：$(cli_proxy_compose_file)，请先执行 install-cli-proxy"
  fi
  ensure_network
  cli_proxy_compose_cmd pull
  cli_proxy_compose_cmd up -d
  connect_container_to_proxy_network_if_needed "${CLI_PROXY_CONTAINER_NAME}" "CLIProxyAPI"
  log "CLIProxyAPI 镜像已更新并重启"
}

ensure_skrbtso_packages() {
  local missing=()
  for cmd in git openssl curl; do
    command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
  done
  if (( ${#missing[@]} == 0 )); then
    return
  fi
  command -v apt-get >/dev/null 2>&1 || err "缺少命令：${missing[*]}，且当前系统没有 apt-get"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y "${missing[@]}"
}

ensure_skrbtso_layout() {
  mkdir -p "${SKRBTSO_DIR}" "${SKRBTSO_DIR}/skrbtso-browser"
  chmod 755 "${SKRBTSO_DIR}" "${SKRBTSO_DIR}/skrbtso-browser"
  log "SkrBTSo Helper 目录已就绪：${SKRBTSO_DIR}"
}

ensure_skrbtso_repo() {
  local repo_dir="${SKRBTSO_DIR}/repo"
  if [[ -d "${repo_dir}/.git" ]]; then
    git -C "${repo_dir}" fetch --depth 1 origin "${SKRBTSO_BRANCH}"
    git -C "${repo_dir}" checkout -B "${SKRBTSO_BRANCH}" "origin/${SKRBTSO_BRANCH}"
    git -C "${repo_dir}" reset --hard "origin/${SKRBTSO_BRANCH}"
    log "SkrBTSo Helper 仓库已更新：${repo_dir}"
    return
  fi
  if [[ -e "${repo_dir}" ]]; then
    err "SkrBTSo Helper repo 目录已存在但不是 Git 仓库：${repo_dir}"
  fi
  git clone --depth 1 --branch "${SKRBTSO_BRANCH}" "${SKRBTSO_REPO_URL}" "${repo_dir}"
  log "SkrBTSo Helper 仓库已克隆：${repo_dir}"
}

write_skrbtso_env_file() {
  local env_file="${SKRBTSO_DIR}/.env"
  if [[ -f "${env_file}" ]] && ! is_truthy "${OVERWRITE}"; then
    SKRBTSO_TOKEN="$(awk -F= '$1 == "SKRBTSO_HELPER_TOKEN" { print $2; exit }' "${env_file}" 2>/dev/null || true)"
    warn "SkrBTSo Helper .env 已存在，保持不变：${env_file}（如需覆盖请设置 OVERWRITE=1）"
    return
  fi
  if [[ -z "${SKRBTSO_TOKEN}" ]]; then
    SKRBTSO_TOKEN="$(random_hex 32)"
  fi
  write_file "${env_file}" <<EOF
SKRBTSO_HELPER_TOKEN=${SKRBTSO_TOKEN}
SKRBTSO_HELPER_SEARCH_ORIGIN=${SKRBTSO_SEARCH_ORIGIN}
SKRBTSO_HELPER_ALLOWED_SEARCH_HOSTS=${SKRBTSO_ALLOWED_SEARCH_HOSTS}
SKRBTSO_HELPER_PORT=${SKRBTSO_PORT}
SKRBTSO_HELPER_TIMEOUT=180
SKRBTSO_HELPER_FORM_RESULT_WAIT=45
SKRBTSO_HELPER_DETAIL_WAIT=8
SKRBTSO_HELPER_STEALTH_FIRST=1
SKRBTSO_HELPER_FORM_FIRST=1
SKRBTSO_HELPER_MAX_CONCURRENT=1
SKRBTSO_HELPER_DEFAULT_MAX_RESULTS=10
SKRBTSO_HELPER_MAX_RESULTS_LIMIT=20
SKRBTSO_HELPER_KEEP_SESSION=1
SKRBTSO_HELPER_USER_DATA_DIR=/data/.skrbtso-browser
SKRBTSO_HELPER_EXTRA_POPUP_CANDIDATES=2
SKRBTSO_HELPER_CACHE_TTL=21600
SKRBTSO_HELPER_RESULT_POLL_MS=500
SKRBTSO_HELPER_CORS_ORIGIN=*
APP_NAME=${SKRBTSO_CONTAINER_NAME}
HELPER_IMAGE=${SKRBTSO_IMAGE}
HELPER_BIND_HOST=${SKRBTSO_BIND_IP}
HELPER_DOMAIN=${SKRBTSO_DOMAIN}
EOF
  chmod 600 "${env_file}"
}

write_skrbtso_compose_file() {
  write_file "$(skrbtso_compose_file)" <<EOF
services:
  ${SKRBTSO_SERVICE_NAME}:
    build:
      context: ./repo
      dockerfile: tools/skrbtso-helper/Dockerfile
    image: ${SKRBTSO_IMAGE}
    container_name: ${SKRBTSO_CONTAINER_NAME}
    restart: unless-stopped
    shm_size: "1gb"
    env_file:
      - .env
    environment:
      TZ: Asia/Shanghai
      SKRBTSO_HELPER_HOST: 0.0.0.0
      SKRBTSO_HELPER_PORT: ${SKRBTSO_PORT}
      SKRBTSO_HELPER_SEARCH_ORIGIN: ${SKRBTSO_SEARCH_ORIGIN}
      SKRBTSO_HELPER_ALLOWED_SEARCH_HOSTS: ${SKRBTSO_ALLOWED_SEARCH_HOSTS}
      SKRBTSO_HELPER_TIMEOUT: 180
      SKRBTSO_HELPER_FORM_RESULT_WAIT: 45
      SKRBTSO_HELPER_DETAIL_WAIT: 8
      SKRBTSO_HELPER_STEALTH_FIRST: 1
      SKRBTSO_HELPER_FORM_FIRST: 1
      SKRBTSO_HELPER_MAX_CONCURRENT: 1
      SKRBTSO_HELPER_DEFAULT_MAX_RESULTS: 10
      SKRBTSO_HELPER_MAX_RESULTS_LIMIT: 20
      SKRBTSO_HELPER_KEEP_SESSION: 1
      SKRBTSO_HELPER_USER_DATA_DIR: /data/.skrbtso-browser
      SKRBTSO_HELPER_EXTRA_POPUP_CANDIDATES: 2
      SKRBTSO_HELPER_CACHE_TTL: 21600
      SKRBTSO_HELPER_RESULT_POLL_MS: 500
      SKRBTSO_HELPER_CORS_ORIGIN: "*"
    volumes:
      - ./skrbtso-browser:/data/.skrbtso-browser
    ports:
      - "${SKRBTSO_BIND_IP}:${SKRBTSO_PORT}:${SKRBTSO_PORT}"
    networks:
      - proxy

networks:
  proxy:
    external: true
    name: ${NETWORK_NAME}
EOF
  chmod 644 "$(skrbtso_compose_file)"
}

install_skrbtso() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  validate_flag OVERWRITE "${OVERWRITE}"
  validate_port SKRBTSO_PORT "${SKRBTSO_PORT}"
  prompt_component_domain_if_needed "SKRBTSO_DOMAIN" "SkrBTSo Helper" "helper.example.com"

  run_system_upgrade_once
  install_docker_engine
  ensure_skrbtso_packages
  ensure_network
  ensure_skrbtso_layout
  ensure_skrbtso_repo
  write_skrbtso_env_file
  write_skrbtso_compose_file
  skrbtso_compose_cmd up -d --build
  connect_container_to_proxy_network_if_needed "${SKRBTSO_CONTAINER_NAME}" "SkrBTSo Helper"
  log "SkrBTSo Helper 容器已启动：${SKRBTSO_CONTAINER_NAME}"
  configure_skrbtso_reverse_proxy
  print_skrbtso_summary
}

update_skrbtso() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  install_docker_engine
  ensure_skrbtso_packages
  ensure_skrbtso_repo
  if [[ ! -f "$(skrbtso_compose_file)" ]]; then
    err "未找到 SkrBTSo Helper Compose 文件：$(skrbtso_compose_file)，请先执行 install-skrbtso"
  fi
  ensure_network
  skrbtso_compose_cmd up -d --build
  connect_container_to_proxy_network_if_needed "${SKRBTSO_CONTAINER_NAME}" "SkrBTSo Helper"
  log "SkrBTSo Helper 已更新并重启"
}

write_compose_file() {
  write_file "$(compose_file)" <<EOF
services:
  reverse-proxy:
    image: ${NGINX_IMAGE}
    container_name: ${CONTAINER_NAME}
    restart: unless-stopped
    ports:
      - "${HTTP_PORT}:80"
      - "${HTTPS_PORT}:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./ssl:/etc/nginx/ssl:ro
      - ./logs:/var/log/nginx
    extra_hosts:
      - "host.docker.internal:host-gateway"
    networks:
      - proxy

networks:
  proxy:
    external: true
    name: ${NETWORK_NAME}
EOF
  chmod 644 "$(compose_file)"
}

write_nginx_main_conf() {
  write_file "${PROJECT_DIR}/nginx/nginx.conf" <<'EOF'
user  nginx;
worker_processes  auto;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log main;
    error_log   /var/log/nginx/error.log warn;

    sendfile        on;
    keepalive_timeout  65;
    server_tokens off;
    client_max_body_size 100m;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }

    include /etc/nginx/conf.d/*.conf;
}
EOF
  chmod 644 "${PROJECT_DIR}/nginx/nginx.conf"
}

write_default_server() {
  write_file "${PROJECT_DIR}/nginx/conf.d/00-default.conf" <<'EOF'
server {
    listen 80 default_server;
    server_name _;

    return 404;
}
EOF
  chmod 644 "${PROJECT_DIR}/nginx/conf.d/00-default.conf"
}

write_site_template() {
  write_file "${PROJECT_DIR}/nginx/templates/https-site.conf.template" <<'EOF'
server {
    listen 80;
    server_name example.com;

    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;

    server_name example.com;

    ssl_certificate     /etc/nginx/ssl/example.com/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    location / {
        proxy_pass http://app-container:8080;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
EOF
  chmod 644 "${PROJECT_DIR}/nginx/templates/https-site.conf.template"
}

set_cert_permissions() {
  local cert_dir="$1"
  if [[ -f "${cert_dir}/fullchain.pem" ]]; then
    chmod 644 "${cert_dir}/fullchain.pem"
  fi
  if [[ -f "${cert_dir}/privkey.pem" ]]; then
    chmod 600 "${cert_dir}/privkey.pem"
  fi
}

import_custom_cert_files() {
  local cert_dir="$1"
  if [[ -z "${SSL_CERT_PATH}" && -z "${SSL_KEY_PATH}" ]]; then
    return
  fi
  if [[ -z "${SSL_CERT_PATH}" || -z "${SSL_KEY_PATH}" ]]; then
    err "SSL_CERT_PATH 和 SSL_KEY_PATH 必须同时提供"
  fi
  [[ -f "${SSL_CERT_PATH}" ]] || err "找不到证书文件：${SSL_CERT_PATH}"
  [[ -f "${SSL_KEY_PATH}" ]] || err "找不到私钥文件：${SSL_KEY_PATH}"

  mkdir -p "${cert_dir}"
  cp -f "${SSL_CERT_PATH}" "${cert_dir}/fullchain.pem"
  cp -f "${SSL_KEY_PATH}" "${cert_dir}/privkey.pem"
  set_cert_permissions "${cert_dir}"
  log "已从自定义路径读取证书并复制到：${cert_dir}"
}

prompt_custom_cert_paths_if_needed() {
  local cert_dir="$1"
  if [[ ! -t 0 ]]; then
    return
  fi
  if [[ -f "${cert_dir}/fullchain.pem" && -f "${cert_dir}/privkey.pem" ]]; then
    return
  fi
  if [[ -n "${SSL_CERT_PATH}" || -n "${SSL_KEY_PATH}" ]]; then
    return
  fi

  local answer=""
  read -r -p "未找到默认证书，是否从你自己的证书路径读取？[y/N]: " answer
  case "${answer}" in
    y|Y|yes|YES)
      prompt_value SSL_CERT_PATH "请输入 fullchain.pem 证书文件路径"
      prompt_value SSL_KEY_PATH "请输入 privkey.pem 私钥文件路径"
      ;;
  esac
}

write_site_config() {
  SITE_CONFIG_ACTIVE=0
  validate_domain "${DOMAIN}"
  local upstream_url
  upstream_url="$(normalize_upstream "${UPSTREAM}")"

  local cert_dir="${PROJECT_DIR}/ssl/${DOMAIN}"
  local active_conf="${PROJECT_DIR}/nginx/conf.d/${DOMAIN}.conf"
  local disabled_conf="${PROJECT_DIR}/nginx/conf.d/${DOMAIN}.conf.disabled"

  mkdir -p "${cert_dir}"
  chmod 700 "${cert_dir}"
  prompt_custom_cert_paths_if_needed "${cert_dir}"
  import_custom_cert_files "${cert_dir}"
  set_cert_permissions "${cert_dir}"

  local target="${active_conf}"
  if [[ ! -f "${cert_dir}/fullchain.pem" || ! -f "${cert_dir}/privkey.pem" ]]; then
    target="${disabled_conf}"
    warn "未找到证书：${cert_dir}/fullchain.pem 和 ${cert_dir}/privkey.pem"
    warn "将生成未启用模板：${target}"
    warn "放入证书后重新执行：sudo DOMAIN=${DOMAIN} UPSTREAM=${UPSTREAM} bash ./install.sh add-site"
    if [[ -f "${active_conf}" ]]; then
      warn "已存在启用配置：${active_conf}。如果证书已被删除，Nginx 检查会失败，请恢复证书或手动禁用该配置。"
    fi
  else
    SITE_CONFIG_ACTIVE=1
  fi

  write_file "${target}" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    http2 on;

    server_name ${DOMAIN};

    ssl_certificate     /etc/nginx/ssl/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/${DOMAIN}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    location / {
        proxy_pass ${upstream_url};
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;

        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
EOF
  chmod 644 "${target}"

  if [[ "${target}" == "${active_conf}" && -f "${disabled_conf}" ]]; then
    rm -f "${disabled_conf}"
  fi
}

container_exists() {
  docker ps -a --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"
}

container_running() {
  docker ps --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"
}

start_proxy() {
  compose_cmd up -d
  log "反代容器已启动：${CONTAINER_NAME}"
  test_nginx
}

test_nginx() {
  if ! container_running; then
    err "容器未运行：${CONTAINER_NAME}"
  fi
  docker exec "${CONTAINER_NAME}" nginx -t
}

reload_nginx() {
  test_nginx
  docker exec "${CONTAINER_NAME}" nginx -s reload
  log "Nginx 已重载"
}

run_install() {
  prompt_install_site_if_needed
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  validate_flag START_AFTER_INSTALL "${START_AFTER_INSTALL}"
  validate_flag INSTALL_3XUI "${INSTALL_3XUI}"
  validate_flag INSTALL_CLIPROXY "${INSTALL_CLIPROXY}"
  validate_flag INSTALL_SKRBTSO "${INSTALL_SKRBTSO}"
  validate_flag OVERWRITE "${OVERWRITE}"
  validate_port HTTP_PORT "${HTTP_PORT}"
  validate_port HTTPS_PORT "${HTTPS_PORT}"

  run_system_upgrade_once
  install_docker_engine
  ensure_layout
  ensure_network
  write_compose_file
  write_nginx_main_conf
  write_default_server
  write_site_template

  if is_truthy "${CREATE_SITE}"; then
    write_site_config
  fi

  if is_truthy "${START_AFTER_INSTALL}"; then
    start_proxy
  else
    warn "已跳过启动容器：START_AFTER_INSTALL=${START_AFTER_INSTALL}"
  fi

  if is_truthy "${INSTALL_3XUI}"; then
    install_xui
  fi

  if is_truthy "${INSTALL_CLIPROXY}"; then
    install_cli_proxy
  fi

  if is_truthy "${INSTALL_SKRBTSO}"; then
    install_skrbtso
  fi

  print_summary
}

run_add_site() {
  if [[ -t 0 ]]; then
    if [[ -z "${DOMAIN}" ]]; then
      prompt_value DOMAIN "请输入域名 DOMAIN，例如 example.com"
    fi
    if [[ -z "${UPSTREAM}" ]]; then
      prompt_value UPSTREAM "请输入后端容器和端口 UPSTREAM，例如 app-container:8080"
    fi
  fi

  validate_flag OVERWRITE "${OVERWRITE}"
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  install_docker_engine
  ensure_layout
  ensure_network
  write_site_config

  if [[ "${SITE_CONFIG_ACTIVE}" -ne 1 ]]; then
    warn "站点配置尚未启用，已跳过 Nginx 重载"
    return
  fi

  if container_running; then
    reload_nginx
  elif container_exists; then
    start_proxy
  else
    warn "反代容器尚未创建，请先执行：sudo bash ./install.sh install"
  fi
}

compose_file_exists() {
  local file_path="$1"
  [[ -f "${file_path}" ]]
}

down_reverse_proxy() {
  if compose_file_exists "$(compose_file)"; then
    compose_cmd down
    log "反代容器已停止并移除，配置和数据仍保留在：${PROJECT_DIR}"
  else
    warn "未找到反代 Compose 文件：$(compose_file)"
  fi
}

down_xui() {
  if compose_file_exists "$(xui_compose_file)"; then
    xui_compose_cmd down
    log "3x-ui 容器已停止并移除，数据仍保留在：${XUI_DIR}"
  else
    warn "未找到 3x-ui Compose 文件：$(xui_compose_file)"
  fi
}

down_cli_proxy() {
  if compose_file_exists "$(cli_proxy_compose_file)"; then
    cli_proxy_compose_cmd down
    log "CLIProxyAPI 容器已停止并移除，数据仍保留在：${CLI_PROXY_DIR}"
  else
    warn "未找到 CLIProxyAPI Compose 文件：$(cli_proxy_compose_file)"
  fi
}

down_skrbtso() {
  if compose_file_exists "$(skrbtso_compose_file)"; then
    skrbtso_compose_cmd down
    log "SkrBTSo Helper 容器已停止并移除，数据仍保留在：${SKRBTSO_DIR}"
  else
    warn "未找到 SkrBTSo Helper Compose 文件：$(skrbtso_compose_file)"
  fi
}

show_all_status() {
  install_docker_engine
  echo
  echo "================ 容器总览 ================"
  docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

  if compose_file_exists "$(compose_file)"; then
    echo
    echo "---------------- reverse-proxy ----------------"
    compose_cmd ps
  fi
  if compose_file_exists "$(xui_compose_file)"; then
    echo
    echo "---------------- 3x-ui ----------------"
    xui_compose_cmd ps
  fi
  if compose_file_exists "$(cli_proxy_compose_file)"; then
    echo
    echo "---------------- CLIProxyAPI ----------------"
    cli_proxy_compose_cmd ps
  fi
  if compose_file_exists "$(skrbtso_compose_file)"; then
    echo
    echo "---------------- SkrBTSo Helper ----------------"
    skrbtso_compose_cmd ps
  fi
}

update_reverse_proxy() {
  install_docker_engine
  if ! compose_file_exists "$(compose_file)"; then
    warn "未找到反代 Compose 文件：$(compose_file)"
    return
  fi
  compose_cmd pull
  compose_cmd up -d
  test_nginx
  log "反代镜像已更新并重启"
}

update_all_components() {
  update_reverse_proxy
  if compose_file_exists "$(xui_compose_file)"; then
    update_xui
  fi
  if compose_file_exists "$(cli_proxy_compose_file)"; then
    update_cli_proxy
  fi
  if compose_file_exists "$(skrbtso_compose_file)"; then
    update_skrbtso
  fi
}

confirm_action() {
  local prompt="$1"
  local answer=""
  read -r -p "${prompt} [y/N]: " answer
  case "${answer}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

print_menu() {
  cat <<'EOF'

================ VPS 初始化菜单 ================
1) 安装基础环境 + Nginx 反向代理
2) 安装 3x-ui
3) 安装 CLIProxyAPI
4) 安装 SkrBTSo Helper
5) 添加 HTTPS 反代站点
6) 查看所有容器状态
7) 更新所有已安装容器镜像
8) 停止/卸载 Nginx 反代容器（保留配置和证书）
9) 停止/卸载 3x-ui 容器（保留数据）
10) 停止/卸载 CLIProxyAPI 容器（保留配置和日志）
11) 停止/卸载 SkrBTSo Helper 容器（保留数据）
0) 退出
================================================
EOF
}

run_menu() {
  local choice=""
  while true; do
    print_menu
    read -r -p "请输入序号: " choice
    case "${choice}" in
      1)
        CREATE_SITE="${CREATE_SITE:-0}"
        INSTALL_3XUI=0
        INSTALL_CLIPROXY=0
        INSTALL_SKRBTSO=0
        run_install
        ;;
      2)
        install_xui
        ;;
      3)
        install_cli_proxy
        ;;
      4)
        install_skrbtso
        ;;
      5)
        run_add_site
        ;;
      6)
        show_all_status
        ;;
      7)
        update_all_components
        ;;
      8)
        if confirm_action "确认停止/卸载 Nginx 反代容器？数据会保留"; then
          down_reverse_proxy
        fi
        ;;
      9)
        if confirm_action "确认停止/卸载 3x-ui 容器？数据会保留"; then
          down_xui
        fi
        ;;
      10)
        if confirm_action "确认停止/卸载 CLIProxyAPI 容器？数据会保留"; then
          down_cli_proxy
        fi
        ;;
      11)
        if confirm_action "确认停止/卸载 SkrBTSo Helper 容器？数据会保留"; then
          down_skrbtso
        fi
        ;;
      0)
        log "已退出菜单"
        break
        ;;
      *)
        warn "无效序号：${choice}"
        ;;
    esac
  done
}

print_summary() {
  cat <<EOF

==================== SUMMARY ====================
项目目录      : ${PROJECT_DIR}
容器名称      : ${CONTAINER_NAME}
Docker 网络   : ${NETWORK_NAME}
Compose 文件  : ${PROJECT_DIR}/docker-compose.yml
Nginx 主配置  : ${PROJECT_DIR}/nginx/nginx.conf
站点配置目录  : ${PROJECT_DIR}/nginx/conf.d
证书目录      : ${PROJECT_DIR}/ssl
日志目录      : ${PROJECT_DIR}/logs

常用命令:
  cd ${PROJECT_DIR}
  docker compose up -d
  docker exec ${CONTAINER_NAME} nginx -t
  docker exec ${CONTAINER_NAME} nginx -s reload
  docker logs -f ${CONTAINER_NAME}
=================================================
EOF

}

write_xui_install_info() {
  local existing_db="${1:-0}"
  local info_file
  info_file="$(xui_info_file)"

  if [[ -f "${info_file}" ]] && ! is_truthy "${OVERWRITE}"; then
    chmod 600 "${info_file}" 2>/dev/null || true
    warn "3x-ui 安装信息文件已存在，保持不变：${info_file}（如需覆盖请设置 OVERWRITE=1）"
    return
  fi

  local server_ip url_host panel_url reverse_proxy_url account password note
  server_ip="$(detect_server_ip)"
  url_host="$(format_url_host "${server_ip}")"
  panel_url="http://${url_host}:${XUI_PANEL_PORT}"
  reverse_proxy_url="未配置"
  if [[ -n "${XUI_DOMAIN}" ]]; then
    reverse_proxy_url="https://${XUI_DOMAIN}/你的面板路径/"
  fi

  account="admin"
  password="admin"
  note="这是 Docker 全新数据目录的默认账号密码，首次登录后请立即修改。"
  if [[ "${existing_db}" -eq 1 ]]; then
    account="已有数据库，可能已被修改"
    password="已有数据库，可能已被修改"
    note="脚本检测到 ${XUI_DIR}/db/x-ui.db 已存在，不会读取或覆盖你之前修改过的账号密码。"
  fi

  write_file "${info_file}" <<EOF
3x-ui 安装信息
生成时间: $(date '+%Y-%m-%d %H:%M:%S %z')

面板登录地址: ${panel_url}
Nginx 反代地址: ${reverse_proxy_url}
面板端口: ${XUI_PANEL_PORT}
用户名: ${account}
密码: ${password}

安装目录: ${XUI_DIR}
容器名称: ${XUI_CONTAINER_NAME}
镜像: ${XUI_IMAGE}
Compose 文件: ${XUI_DIR}/docker-compose.yml
数据目录: ${XUI_DIR}/db
证书目录: ${XUI_DIR}/cert

说明: ${note}
端口放行: 如果通过 Nginx 反代访问，建议只开放 80/tcp 和 443/tcp；如果要直连面板，再按当前面板端口手动放行 TCP ${XUI_PANEL_PORT}。
EOF
  chmod 600 "${info_file}"
}

print_xui_summary() {
  local existing_db="${1:-0}"
  local server_ip url_host panel_url reverse_proxy_url info_file account password note
  server_ip="$(detect_server_ip)"
  url_host="$(format_url_host "${server_ip}")"
  panel_url="http://${url_host}:${XUI_PANEL_PORT}"
  reverse_proxy_url="未配置"
  if [[ -n "${XUI_DOMAIN}" ]]; then
    reverse_proxy_url="https://${XUI_DOMAIN}/你的面板路径/"
  fi
  info_file="$(xui_info_file)"

  account="admin"
  password="admin"
  note="Docker 全新数据目录默认账号密码如下，首次登录后立即修改。"
  if [[ "${existing_db}" -eq 1 ]]; then
    account="已有数据库，可能已被修改"
    password="已有数据库，可能已被修改"
    note="检测到已有 3x-ui 数据库，账号密码以你之前修改后的为准。"
  fi

  cat <<EOF

==================== 3X-UI ======================
安装目录      : ${XUI_DIR}
容器名称      : ${XUI_CONTAINER_NAME}
镜像          : ${XUI_IMAGE}
Compose 文件  : ${XUI_DIR}/docker-compose.yml
数据目录      : ${XUI_DIR}/db
证书目录      : ${XUI_DIR}/cert
网络模式      : host
面板登录地址  : ${panel_url}
Nginx 反代地址 : ${reverse_proxy_url}
面板端口      : ${XUI_PANEL_PORT}
用户名        : ${account}
密码          : ${password}
安装信息保存  : ${info_file}

重要事项:
  ${note}
  如果使用 Nginx 反代，3x-ui 面板证书路径可以留空，由 Nginx 负责 HTTPS。
  如果直连打不开登录地址，请按当前面板端口手动放行本机防火墙和云安全组的 TCP ${XUI_PANEL_PORT}。
  3x-ui 使用 host 网络，面板端口和你在面板里创建的入站端口都直接占用宿主机端口。

常用命令:
  cd ${XUI_DIR}
  docker compose up -d
  docker compose pull && docker compose up -d
  docker compose logs -f
=================================================
EOF
}

print_cli_proxy_summary() {
  local reverse_proxy_url="未配置"
  if [[ -n "${CLI_PROXY_DOMAIN}" ]]; then
    reverse_proxy_url="https://${CLI_PROXY_DOMAIN}/"
  fi

  cat <<EOF

================== CLIPROXYAPI ==================
安装目录      : ${CLI_PROXY_DIR}
容器名称      : ${CLI_PROXY_CONTAINER_NAME}
镜像          : ${CLI_PROXY_IMAGE}
Compose 文件  : ${CLI_PROXY_DIR}/docker-compose.yml
配置文件      : ${CLI_PROXY_DIR}/config.yaml
认证目录      : ${CLI_PROXY_DIR}/auths
日志目录      : ${CLI_PROXY_DIR}/logs
API 监听      : http://${CLI_PROXY_BIND_IP}:${CLI_PROXY_API_PORT}
Nginx 反代地址 : ${reverse_proxy_url}
额外端口      : ${CLI_PROXY_EXTRA_PORTS}
API Key       : ${CLI_PROXY_API_KEY}

重要事项:
  默认绑定 ${CLI_PROXY_BIND_IP}，不会直接暴露到公网。
  如果使用 Nginx 反代，建议只开放 80/tcp 和 443/tcp，不需要把 API 端口直接暴露公网。
  如果要公网直连访问，设置 CLI_PROXY_BIND_IP=0.0.0.0，并同步放行云防火墙或安全组。
  容器 restart: unless-stopped，Docker 服务 enable 后会随系统开机自动启动。

常用命令:
  cd ${CLI_PROXY_DIR}
  docker compose up -d
  docker compose pull && docker compose up -d
  docker compose logs -f
=================================================
EOF
}

print_skrbtso_summary() {
  cat <<EOF

================ SKRBTSO HELPER ================
安装目录      : ${SKRBTSO_DIR}
仓库目录      : ${SKRBTSO_DIR}/repo
容器名称      : ${SKRBTSO_CONTAINER_NAME}
镜像          : ${SKRBTSO_IMAGE}
Compose 文件  : ${SKRBTSO_DIR}/docker-compose.yml
浏览器资料    : ${SKRBTSO_DIR}/skrbtso-browser
本机监听      : http://${SKRBTSO_BIND_IP}:${SKRBTSO_PORT}
域名          : ${SKRBTSO_DOMAIN:-未配置}
Token         : ${SKRBTSO_TOKEN}

浏览器脚本设置:
  抓取服务地址：https://${SKRBTSO_DOMAIN:-你的域名}/skrbtso/search
  Bearer token：上面的 Token

常用命令:
  cd ${SKRBTSO_DIR}
  docker compose up -d --build
  docker compose logs -f
=================================================
EOF
}

main() {
  case "${COMMAND}" in
    -h|--help|help)
      usage
      ;;
    menu)
      need_root
      run_menu
      ;;
    install)
      need_root
      run_install
      ;;
    install-3x-ui)
      need_root
      install_xui
      ;;
    update-3x-ui)
      need_root
      update_xui
      ;;
    3x-ui-status)
      need_root
      xui_compose_cmd ps
      ;;
    3x-ui-down)
      need_root
      down_xui
      ;;
    3x-ui-up)
      need_root
      xui_compose_cmd up -d
      ;;
    install-cli-proxy)
      need_root
      install_cli_proxy
      ;;
    update-cli-proxy)
      need_root
      update_cli_proxy
      ;;
    cli-proxy-status)
      need_root
      cli_proxy_compose_cmd ps
      ;;
    cli-proxy-down)
      need_root
      down_cli_proxy
      ;;
    cli-proxy-up)
      need_root
      cli_proxy_compose_cmd up -d
      ;;
    install-skrbtso)
      need_root
      install_skrbtso
      ;;
    update-skrbtso)
      need_root
      update_skrbtso
      ;;
    skrbtso-status)
      need_root
      skrbtso_compose_cmd ps
      ;;
    skrbtso-down)
      need_root
      down_skrbtso
      ;;
    skrbtso-up)
      need_root
      skrbtso_compose_cmd up -d
      ;;
    add-site)
      need_root
      run_add_site
      ;;
    test)
      need_root
      test_nginx
      ;;
    reload)
      need_root
      reload_nginx
      ;;
    status)
      need_root
      compose_cmd ps
      ;;
    down)
      need_root
      down_reverse_proxy
      ;;
    up)
      need_root
      start_proxy
      ;;
    *)
      usage
      err "未知命令：${COMMAND}"
      ;;
  esac
}

main "$@"
