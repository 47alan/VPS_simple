#!/usr/bin/env bash
set -euo pipefail

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

# HY2 默认独立域名/端口，便于与 Cloudflare 代理策略分离
HY2_DOMAIN="${HY2_DOMAIN:-${DOMAIN}}"           # HY2 客户端连接域名
HY2_SNI="${HY2_SNI:-${HY2_DOMAIN}}"             # HY2 TLS SNI
HY2_PORT="${HY2_PORT:-8443}"                    # HY2 UDP 端口
HY2_PASSWORD="${HY2_PASSWORD:-}"                # HY2 密码，可留空自动生成
HY2_INSECURE="${HY2_INSECURE:-1}"               # 用 CF Origin 证书时建议 1
HY2_MASQ_URL="${HY2_MASQ_URL:-https://www.cloudflare.com/}"
SOCKS_ENABLE="${SOCKS_ENABLE:-1}"
SOCKS_PORT="${SOCKS_PORT:-}"
SOCKS_BIND="${SOCKS_BIND:-0.0.0.0}"
SOCKS_USER="${SOCKS_USER:-}"
SOCKS_PASS="${SOCKS_PASS:-}"
SOCKS_ALLOW="${SOCKS_ALLOW:-}"
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

random_alphanum() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"
}

generate_openssl_password() {
  local length="$1"
  openssl rand -base64 "${length}" | tr -d '\r\n'
}

get_primary_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}'
}

pick_random_socks_port() {
  local tries port
  for tries in {1..30}; do
    port=$((50000 + RANDOM % 15000))
    if ! ss -ltn sport = :"${port}" >/dev/null 2>&1; then
      echo "${port}"
      return
    fi
  done
  echo 55000
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

  read -r -p "是否启用公网 SOCKS5 出口（配合安全配置，默认启用）？[Y/n]: " input_value
  input_value="${input_value:-Y}"
  case "${input_value}" in
    N|n) SOCKS_ENABLE=0 ;;
    *) SOCKS_ENABLE=1 ;;
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
      SOCKS_PASS="$(generate_openssl_password 18 | tr -dc 'A-Za-z0-9' | head -c 12)"
    fi

    read -r -p "设定允许访问的 IP（留空表示任意）： " input_value
    SOCKS_ALLOW="${input_value}"
    echo
    if [[ -n "${SOCKS_ALLOW}" ]]; then
      if ! python3 - <<'PY'
import ipaddress, os, sys
value = os.getenv("SOCKS_ALLOW", "")
try:
    ipaddress.ip_network(value, strict=False)
except Exception:
    sys.exit(1)
PY
      then
        err "SOCKS_ALLOW 值非法：${SOCKS_ALLOW}"
      fi
    fi
  fi

  read -r -p "请输入 UUID（留空自动生成）: " input_value
  if [[ -n "${input_value}" ]]; then
    UUID="${input_value}"
  fi

  read -r -p "请输入 HY2_PASSWORD（留空自动生成）: " input_value
  if [[ -n "${input_value}" ]]; then
    HY2_PASSWORD="${input_value}"
  fi

  echo
  echo "------------- 你的配置 -------------"
  echo "DOMAIN=${DOMAIN}"
  echo "VLESS_PORT=${VLESS_PORT}"
  echo "WSPATH=${WSPATH}"
  echo "HY2_DOMAIN=${HY2_DOMAIN}"
  echo "HY2_SNI=${HY2_SNI}"
  echo "HY2_PORT=${HY2_PORT}"
  echo "HY2_INSECURE=${HY2_INSECURE}"
  echo "HY2_MASQ_URL=${HY2_MASQ_URL}"
  if [[ -n "${UUID}" ]]; then
    echo "UUID=已设置"
  else
    echo "UUID=自动生成"
  fi
  if [[ -n "${HY2_PASSWORD}" ]]; then
    echo "HY2_PASSWORD=已设置"
  else
    echo "HY2_PASSWORD=自动生成"
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
  if [[ ! "${HY2_DOMAIN}" =~ ^[A-Za-z0-9.-]+$ ]]; then
    err "HY2_DOMAIN 格式不合法：${HY2_DOMAIN}"
  fi
  if [[ ! "${HY2_SNI}" =~ ^[A-Za-z0-9.-]+$ ]]; then
    err "HY2_SNI 格式不合法：${HY2_SNI}"
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
    SOCKS_PASS="$(generate_openssl_password 18 | tr -dc 'A-Za-z0-9' | head -c 12)"
  fi
  warn "SOCKS5 公网凭据：${SOCKS_USER}/${SOCKS_PASS}"
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
  iptables -A "${chain}" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 8 --name socks5 --rsource -j DROP
  iptables -A "${chain}" -j ACCEPT

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || warn "netfilter-persistent save 失败"
  fi
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
  apt-get install -y curl nginx ca-certificates qrencode
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    apt-get install -y iptables-persistent netfilter-persistent
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
  ufw allow "${HY2_PORT}/udp"
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    ufw allow "${SOCKS_PORT}/tcp"
  fi
  ufw --force enable
  log "ufw 已启用，仅放行 22/tcp 80/tcp ${VLESS_PORT}/tcp ${HY2_PORT}/udp"
}

urlencode() {
  local string="$1"
  local length="${#string}"
  local c i
  for (( i = 0; i < length; i++ )); do
    c="${string:i:1}"
    case "$c" in
      [A-Za-z0-9._~-]) printf '%s' "$c" ;;
      *) printf '%%%02X' "'$c" ;;
    esac
  done
  echo
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
  local hy2_password_enc
  local vless_uri
  local hy2_uri
  local socks_ip

  ws_path_enc="$(urlencode "${WSPATH}")"
  hy2_password_enc="$(urlencode "${HY2_PASSWORD}")"
  vless_uri="vless://${UUID}@${DOMAIN}:${VLESS_PORT}?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=${ws_path_enc}&sni=${DOMAIN}#CF-Nginx-Xray"
  hy2_uri="hy2://${hy2_password_enc}@${HY2_DOMAIN}:${HY2_PORT}/?sni=${HY2_SNI}&insecure=${HY2_INSECURE}#CF-HY2"

  echo
  echo "==================== SUMMARY ===================="
  echo "Domain        : ${DOMAIN}"
  echo "VLESS Port    : ${VLESS_PORT}"
  echo "UUID          : ${UUID}"
  echo "WS Path       : ${WSPATH}"
  echo "Xray Listen   : ${XRAY_LISTEN}:${XRAY_PORT}"
  echo "HY2 Domain    : ${HY2_DOMAIN}"
  echo "HY2 Port(UDP) : ${HY2_PORT}"
  echo "HY2 Password  : ${HY2_PASSWORD}"
  echo "Origin PEM    : ${ORIGIN_PEM}"
  echo "Origin KEY    : ${ORIGIN_KEY}"
  echo "Nginx Conf    : ${NGINX_CONF}"
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    socks_ip="$(get_primary_ip)"
    echo "Socks5 本地代理：127.0.0.1:${SOCKS_PORT}（${SOCKS_USER}/${SOCKS_PASS}）"
    echo "Socks5 公网直连：${socks_ip}:${SOCKS_PORT}（${SOCKS_USER}/${SOCKS_PASS}）"
    if [[ -n "${SOCKS_ALLOW}" ]]; then
      echo "SOCKS5 Allow  : ${SOCKS_ALLOW}"
    else
      echo "SOCKS5 Allow  : 0.0.0.0/0（任意 IP）"
    fi
  fi
  echo "HY2 Conf      : ${HY2_CFG}"
  echo "================================================="
  echo
  echo "Cloudflare 面板建议："
  echo "1) VLESS 使用域名 ${DOMAIN}:${VLESS_PORT} 可开橙云（SSL/TLS 选 Full(strict)）"
  echo "2) HY2 使用域名 ${HY2_DOMAIN} 建议 DNS only（灰云），并放行 UDP ${HY2_PORT}"
  echo "3) 若 HY2 使用 Origin 证书，客户端需允许 insecure=1 或使用证书 pin"
  echo

  print_qr "VLESS" "${vless_uri}"
  print_qr "HY2" "${hy2_uri}"
}

main() {
  need_root
  interactive_config
  check_domain
  check_ws_path
  check_port "VLESS_PORT" "${VLESS_PORT}"
  check_port "XRAY_PORT" "${XRAY_PORT}"
  check_port "HY2_PORT" "${HY2_PORT}"
  if [[ ! "${HY2_INSECURE}" =~ ^[0-1]$ ]]; then
    err "HY2_INSECURE 只能是 0 或 1"
  fi
  if [[ "${VLESS_PORT}" == "${HY2_PORT}" ]]; then
    warn "VLESS_PORT 与 HY2_PORT 相同（${VLESS_PORT}），依赖 TCP/UDP 协议区分。请确认防火墙/云平台支持"
  fi

  ensure_uuid
  ensure_hy2_password
  ensure_socks_creds

  # 检查端口占用
  check_port_conflict 80 tcp
  check_port_conflict "${VLESS_PORT}" tcp
  check_port_conflict "${HY2_PORT}" udp
  if [[ "${SOCKS_ENABLE}" -eq 1 ]]; then
    check_port "SOCKS_PORT" "${SOCKS_PORT}"
    check_port_conflict "${SOCKS_PORT}" tcp
  fi
  apt_install
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl start nginx

  setup_nginx_index
  write_origin_cert_interactive

  install_xray
  write_xray_config
  write_nginx_conf

  install_hysteria2
  write_hy2_config

  apply_socks_iptables_rules

  # 可选：启用防火墙（如不需要，注释掉下一行）
  # optional_ufw

  print_summary
  log "全部完成。VLESS/HY2 链接与二维码已输出。"
}

main "$@"
