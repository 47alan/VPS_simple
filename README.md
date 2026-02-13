# cf-nginx-xray

一个面向 Ubuntu/Debian 的一键部署脚本，快速搭建：

- `Nginx + Xray(VLESS + WS + TLS)`
- `Hysteria2 (HY2)`
- 安装完成自动输出 VLESS/HY2 导入链接和终端二维码

适合个人自建节点场景，强调“少步骤、可复制、可快速导入”。

> 仅用于合法合规用途，请遵守你所在地区及服务提供商的相关规定。

- VLESS 导入链接
- HY2 导入链接
- 两者终端二维码（基于 `qrencode`）

## 目录结构

```text
cf-nginx-xray/
├─ .gitignore
├─ install.sh
└─ README.md
```

## 环境要求

- Ubuntu / Debian（推荐全新系统）
- Root 权限
- 域名已解析到服务器 IP
- 可访问外网（用于在线安装 Xray/Hysteria2）

## 快速使用

推荐：交互向导模式（一步一步输入）

```bash
sudo bash ./install.sh
```

非交互模式（环境变量一次性传入，HY2_PORT 默认 8443）：

```bash
sudo DOMAIN=example.com \
VLESS_PORT=443 \
UUID=11111111-1111-1111-1111-111111111111 \
WSPATH=/ray \
HY2_DOMAIN=hy2.example.com \
HY2_PORT=8443 \
HY2_PASSWORD=yourStrongPassword \
HY2_INSECURE=1 \
bash ./install.sh
```

说明：若脚本运行在非交互终端（如 CI/自动化），会自动跳过提问并使用环境变量或默认值。

## 参数说明

- `DOMAIN`：VLESS 使用的域名（Nginx 443 站点）
- `UUID`：VLESS 用户 ID，不填自动生成
- `WSPATH`：VLESS 的 WS 路径，必须 `/` 开头
- `VLESS_PORT`：VLESS 对外 TLS 端口（Nginx 监听），默认 `443`
- `HY2_DOMAIN`：HY2 连接域名（默认跟 `DOMAIN` 一样）
- `HY2_PORT`：HY2 UDP 端口，默认 `8443`
- `HY2_PASSWORD`：HY2 密码，不填自动生成
- `HY2_INSECURE`：HY2 客户端是否允许不验证证书，`0/1`
- `SOCKS_ENABLE`：默认 `1`，即在 SSL/HY2 之外同时开启公网 SOCKS5，脚本会自动选用 50000+ 随机端口并生成强用户名/密码，同时配置 iptables 限制（必要时可设置 `SOCKS_ENABLE=0`）。
- `SOCKS_PORT`：SOCKS5 监听端口（默认在 `50000-64999` 之间），可提前指定自定义值。
- `SOCKS_USER`：SOCKS5 用户名（默认自动生成）。
- `SOCKS_PASS`：SOCKS5 密码（默认自动生成 12 位字母数字字符串）。
- `SOCKS_ALLOW`：可选，指定允许访问 SOCKS5 的 IP/网段，留空默认为任意来源。

## 重要说明

- 脚本默认使用 Cloudflare Origin 证书（手动粘贴 PEM/KEY）。
- VLESS（经 Cloudflare）可以橙云代理。
- 若 VLESS 走 Cloudflare 橙云，请使用 Cloudflare 支持的 HTTPS 端口（如 `443/8443` 等）。
- HY2 走 UDP，通常建议使用 DNS only（灰云），并放行 `HY2_PORT/udp`。
- 如果 HY2 使用 Origin 证书，客户端通常需要 `insecure=1` 或使用证书 Pin。
- 脚本仍以 VLESS/HY2 为核心，若需要对公网开放 SOCKS5，可开启 `SOCKS_ENABLE=1`，脚本会根据 `SOCKS5_HARDENING.md` 的安全措施自动配置高位端口、强凭据、iptables 限制与可选 IP 白名单。
- 启用 SOCKS5 时 `optional_ufw` 会同时放行该端口，`iptables` 规则会由 `netfilter-persistent` 持久化（见 `SOCKS5_HARDENING.md`）。
- 建议在本地和 VPS 之间用 SSH 隧道（例如 `ssh -N -L 127.0.0.1:1080:127.0.0.1:1080 user@vps`）将远程服务映射到本地 127.0.0.1，避免直接暴露 SOCKS5，除非你确实需要公网访问；
- 只要保留脚本生成的 `UUID`/`HY2_PASSWORD`，就能借助 SSH 隧道复用原有接入信息。
- 安装完成时会打印类似内容，便于本地直接复制粘贴：  
  `Socks5 本地代理：127.0.0.1:10808（usrA3xK2/aBcDeFgH1234）`  
  `Socks5 公网直连：203.0.113.55:10808（usrA3xK2/aBcDeFgH1234）`
- 新服务器上先执行 `sudo apt update && sudo apt install -y git curl`，再 `git clone https://github.com/47alan/VPS_simple.git`、`cd VPS_simple` 并运行 `sudo bash ./install.sh`。

## 输出内容

安装结束后会在终端显示：

- VLESS 分享链接 + 二维码
- HY2 分享链接 + 二维码

可直接复制到支持协议的客户端快速导入。
