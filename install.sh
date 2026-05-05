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

CLI_PROXY_DIR="${CLI_PROXY_DIR:-/opt/cli-proxy-api}"
CLI_PROXY_IMAGE="${CLI_PROXY_IMAGE:-eceasy/cli-proxy-api:latest}"
CLI_PROXY_CONTAINER_NAME="${CLI_PROXY_CONTAINER_NAME:-cli-proxy-api}"
CLI_PROXY_BIND_IP="${CLI_PROXY_BIND_IP:-127.0.0.1}"
CLI_PROXY_API_PORT="${CLI_PROXY_API_PORT:-8317}"
CLI_PROXY_EXTRA_PORTS="${CLI_PROXY_EXTRA_PORTS:-8085 1455 54545 51121 11451}"
CLI_PROXY_API_KEY="${CLI_PROXY_API_KEY:-}"
CLI_PROXY_MANAGEMENT_SECRET="${CLI_PROXY_MANAGEMENT_SECRET:-}"

DOMAIN="${DOMAIN:-}"
UPSTREAM="${UPSTREAM:-}"
CREATE_SITE="${CREATE_SITE:-}"

SYSTEM_UPGRADE="${SYSTEM_UPGRADE:-1}"
INSTALL_DOCKER="${INSTALL_DOCKER:-1}"
START_AFTER_INSTALL="${START_AFTER_INSTALL:-1}"
INSTALL_3XUI="${INSTALL_3XUI:-0}"
INSTALL_CLIPROXY="${INSTALL_CLIPROXY:-0}"
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
  XUI_DIR=/opt/3x-ui
  XUI_IMAGE=ghcr.io/mhsanaei/3x-ui:latest
  XUI_CONTAINER_NAME=3xui_app
  CLI_PROXY_DIR=/opt/cli-proxy-api
  CLI_PROXY_BIND_IP=127.0.0.1
  CLI_PROXY_API_PORT=8317
  DOMAIN=example.com
  UPSTREAM=app-container:8080
  CREATE_SITE=1
  OVERWRITE=0

示例:
  sudo bash ./install.sh menu
  sudo bash ./install.sh install
  sudo INSTALL_3XUI=1 INSTALL_CLIPROXY=1 bash ./install.sh install
  sudo bash ./install.sh install-3x-ui
  sudo bash ./install.sh install-cli-proxy
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

xui_compose_cmd() {
  docker compose --project-directory "${XUI_DIR}" -f "$(xui_compose_file)" "$@"
}

cli_proxy_compose_file() {
  printf '%s/docker-compose.yml\n' "${CLI_PROXY_DIR}"
}

cli_proxy_compose_cmd() {
  docker compose --project-directory "${CLI_PROXY_DIR}" -f "$(cli_proxy_compose_file)" "$@"
}

random_hex() {
  local bytes="${1:-16}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "${bytes}"
  else
    tr -d '-' < /proc/sys/kernel/random/uuid
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

install_xui() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  validate_flag OVERWRITE "${OVERWRITE}"
  validate_port XUI_PANEL_PORT "${XUI_PANEL_PORT}"

  run_system_upgrade_once
  install_docker_engine
  ensure_xui_layout
  write_xui_compose_file
  xui_compose_cmd up -d

  log "3x-ui 容器已启动：${XUI_CONTAINER_NAME}"
  print_xui_summary
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

  run_system_upgrade_once
  install_docker_engine
  ensure_cli_proxy_layout
  write_cli_proxy_config
  write_cli_proxy_compose_file
  cli_proxy_compose_cmd up -d

  log "CLIProxyAPI 容器已启动：${CLI_PROXY_CONTAINER_NAME}"
  print_cli_proxy_summary
}

update_cli_proxy() {
  validate_flag INSTALL_DOCKER "${INSTALL_DOCKER}"
  install_docker_engine
  if [[ ! -f "$(cli_proxy_compose_file)" ]]; then
    err "未找到 CLIProxyAPI Compose 文件：$(cli_proxy_compose_file)，请先执行 install-cli-proxy"
  fi
  cli_proxy_compose_cmd pull
  cli_proxy_compose_cmd up -d
  log "CLIProxyAPI 镜像已更新并重启"
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
4) 全套安装：Nginx 反代 + 3x-ui + CLIProxyAPI
5) 添加 HTTPS 反代站点
6) 查看所有容器状态
7) 更新所有已安装容器镜像
8) 停止/卸载 Nginx 反代容器（保留配置和证书）
9) 停止/卸载 3x-ui 容器（保留数据）
10) 停止/卸载 CLIProxyAPI 容器（保留配置和日志）
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
        run_install
        ;;
      2)
        install_xui
        ;;
      3)
        install_cli_proxy
        ;;
      4)
        CREATE_SITE="${CREATE_SITE:-0}"
        INSTALL_3XUI=1
        INSTALL_CLIPROXY=1
        run_install
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

print_xui_summary() {
  cat <<EOF

==================== 3X-UI ======================
安装目录      : ${XUI_DIR}
容器名称      : ${XUI_CONTAINER_NAME}
镜像          : ${XUI_IMAGE}
Compose 文件  : ${XUI_DIR}/docker-compose.yml
数据目录      : ${XUI_DIR}/db
证书目录      : ${XUI_DIR}/cert
网络模式      : host
默认面板      : http://服务器IP:${XUI_PANEL_PORT}
默认账号      : admin
默认密码      : admin

重要事项:
  首次登录后立即修改默认账号、密码、面板路径和面板端口。
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
额外端口      : ${CLI_PROXY_EXTRA_PORTS}
API Key       : ${CLI_PROXY_API_KEY}

重要事项:
  默认绑定 ${CLI_PROXY_BIND_IP}，不会直接暴露到公网。
  如果要公网访问，设置 CLI_PROXY_BIND_IP=0.0.0.0，并同步放行云防火墙或安全组。
  容器 restart: unless-stopped，Docker 服务 enable 后会随系统开机自动启动。

常用命令:
  cd ${CLI_PROXY_DIR}
  docker compose up -d
  docker compose pull && docker compose up -d
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
