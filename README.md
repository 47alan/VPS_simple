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
- `HY2_ENABLE`：是否安装 Hysteria2，`0/1`，默认 `0`（不安装）；设为 `1` 则同时安装 HY2
- `SOCKS_ENABLE`：默认 `0`（更安全），即默认不开放公网 SOCKS5；如需开启可设置 `SOCKS_ENABLE=1`，脚本会自动选用 50000+ 随机端口并生成强用户名/密码，同时配置 iptables 限制。
- `SOCKS_PORT`：SOCKS5 监听端口（默认在 `50000-64999` 之间），可提前指定自定义值。
- `SOCKS_USER`：SOCKS5 用户名（默认自动生成）。
- `SOCKS_PASS`：SOCKS5 密码（默认自动生成 12 位字母数字字符串）。
- `SOCKS_ALLOW`：可选，指定允许访问 SOCKS5 的 IP/网段，留空默认为任意来源。
- `SOCKS_CONN_LIMIT_SECONDS`：SOCKS5 新连接统计窗口（秒），默认 `60`。
- `SOCKS_CONN_LIMIT_HITCOUNT`：每个 IP 在统计窗口内最多允许的新连接数，默认 `20`（受限于 `xt_recent` 内核模块 `ip_pkt_list_tot` 默认上限）。
- `SOCKS_REQUIRE_ATTACK_BEFORE_RESET`：是否“检测到异常才继续重置/修改”，`0/1`，默认 `0`。
- `SOCKS_ALERT_WINDOW_SECONDS`：SOCKS5 检测历史窗口（秒），默认 `600`（10 分钟）。
- `SOCKS_ALERT_MIN_EVENTS`：历史窗口内最少异常事件数阈值，默认 `2`。
- `SOCKS_SECURITY_LOG_FILE`：SOCKS5 安全检测日志文件，默认 `/var/log/vps_socks_security.log`。
- `TG_NOTIFY_ENABLE`：是否启用 Telegram 告警推送，`0/1`，默认 `0`（关闭）。
- `TG_BOT_TOKEN`：Telegram Bot Token（`TG_NOTIFY_ENABLE=1` 时必填）。
- `TG_CHAT_ID`：Telegram Chat ID（`TG_NOTIFY_ENABLE=1` 时必填）。
- `TG_API_BASE_URL`：Telegram Bot API 地址，默认 `https://api.telegram.org`（交互模式默认不询问；如需自定义可通过环境变量传入）。
- `TG_NOTIFY_LEVEL`：推送级别，`strong/all`，默认 `strong`（仅强告警）。
- `TG_NOTIFY_COOLDOWN_SECONDS`：推送冷却时间（秒），默认 `300`。
- `SOCKS_WATCHDOG_INTERVAL_SECONDS`：后台监控检测周期（秒），默认 `60`。

## 重要说明

- 脚本默认使用 Cloudflare Origin 证书（手动粘贴 PEM/KEY）。
- VLESS（经 Cloudflare）可以橙云代理。
- 若 VLESS 走 Cloudflare 橙云，请使用 Cloudflare 支持的 HTTPS 端口（如 `443/8443` 等）。
- HY2 走 UDP，通常建议使用 DNS only（灰云），并放行 `HY2_PORT/udp`。
- 如果 HY2 使用 Origin 证书，客户端通常需要 `insecure=1` 或使用证书 Pin。
- 脚本仍以 VLESS/HY2 为核心，若需要对公网开放 SOCKS5，可开启 `SOCKS_ENABLE=1`，脚本会根据 `SOCKS5_HARDENING.md` 的安全措施自动配置高位端口、强凭据、iptables 限制与可选 IP 白名单。
- SOCKS5 仅开放 TCP，Xray 的 SOCKS 入站显式禁用 UDP（`"udp": false`）。
- SOCKS5 默认限速为”每个 IP 每 60 秒最多 20 个新连接”，用于缓解暴力破解。注意 `xt_recent` 内核模块的 `ip_pkt_list_tot` 默认上限通常为 20，若需更高值请先执行 `echo 100 > /proc/net/xt_recent/ip_pkt_list_tot`。
- 若用于比特浏览器（BitBrowser）等多开浏览器场景，强烈建议设置 `SOCKS_ALLOW` 为你的客户端 IP，白名单 IP 会跳过限速直接放行，避免多窗口并发时被误拦截。
- 脚本会在执行前输出 SOCKS5 安全检测（连接数、来源 IP、iptables 丢弃计数），并记录到 `SOCKS_SECURITY_LOG_FILE`；单次异常记为弱告警，历史窗口（默认 10 分钟）达到阈值记为强告警。
- 若设置 `SOCKS_REQUIRE_ATTACK_BEFORE_RESET=1`，仅在检测到疑似攻击/他人使用时继续。
- 若启用 `TG_NOTIFY_ENABLE=1`，脚本会自动配置 `socks5-watchdog.timer`，按 `SOCKS_WATCHDOG_INTERVAL_SECONDS` 周期检测并推送告警到 Telegram（支持自定义 `TG_API_BASE_URL`）。
- 安装过程会显示 `>>> [步骤 x/y]` 进度；正常结束会显示“`安装完成标记：INSTALL_DONE=1`”和服务运行状态检查结果。
- 交互模式下 Telegram Bot Token 改为明文输入（不再隐藏字符），便于确认输入内容。
- 启用 SOCKS5 时如需启用 UFW 防火墙，可取消 `install.sh` 中 `optional_ufw` 的注释，该函数会同时放行 SOCKS5 端口；`iptables` 规则会由 `netfilter-persistent` 持久化（见 `SOCKS5_HARDENING.md`）。
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
