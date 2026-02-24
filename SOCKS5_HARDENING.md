# 公网 SOCKS5 最低风险配置指南

即使你目前倡导通过 SSH 隧道访问，也可能存在必须在 VPS 上短期开启 SOCKS5 供特定客户端直连的场景。本指南帮你把 SOCKS5 暴露的风险压到最低。

## 1. ✅ 高位随机端口

- 避免使用 `1080`、`1081` 这类默认端口，攻击者通常会扫描常见端口。选用任意大于 20000 的随机、未使用端口，例如 `SOCKS_PORT=32187` 或 `SOCKS_PORT=$((30000 + RANDOM % 10000))`。
- 如果使用 systemd/unit 脚本启动 SOCKS5 服务，请在服务文件或启动脚本中引用该随机端口变量，并确保每次重启后仍是高位端口。

## 2. ✅ 强用户名 / 强密码

- 设置长度 ≥ 12、包含大小写字母和数字的用户名和密码，例如：  
  `SOCKS_USER=proxyAdmin`  
  `SOCKS_PASS="$(openssl rand -base64 18 | tr -d '\r\n')"`
- 绝不使用默认或空密码。生产环境可将生成后的凭据存入受限文件 `/etc/proxy-creds/socks5`，权限设为 600，只允许安装脚本或运营账号读取。

## 3. ✅ 禁止 UDP

- SOCKS5 协议支持 UDP associate，但 UDP 常被用于穿透甚至反弹连接，从安全角度建议只允许 TCP。启动 SOCKS5 服务时明确使用 `-D`（只做动态端口转发）或设置服务器配置为 `udp-associate no`。
- 在使用 `ssh -D` 模式时，SSH 客户端默认仅代理 TCP，因此本地不能直接走 UDP。

## 4. ✅ 脚本集成（`install.sh`）

- 本项目的 `install.sh` 扩展了 SOCKS5 安全配置：`SOCKS_ENABLE` 默认是 `0`（不开放公网 SOCKS5）；只要设置 `SOCKS_ENABLE=1`，安装流程会自动生成一个 50000-64999 的高位端口，并创建强用户名/密码（长度约 12 位）。
- SOCKS5 端口、用户名、密码也可以通过 `SOCKS_PORT`/`SOCKS_USER`/`SOCKS_PASS` 环境变量预先指定；若希望限制连接来源，可使用 `SOCKS_ALLOW` 传入可信 IP 或网段。
- 启用后脚本会在 `write_xray_config` 中附加一个 SOCKS inbound（`"udp": false`，仅 TCP），并在 `apply_socks_iptables_rules` 中创建 `SOCKS5_LIM` 链，限制每个 IP 每 60 秒最多建立 20 条新连接，超过即丢弃（`--hitcount` 受 `xt_recent` 内核模块 `ip_pkt_list_tot` 上限约束，默认通常为 20）。
- 脚本会在执行前运行 `check_socks_security_status`，输出当前连接数、来源 IP 数量、连接最多来源、`SOCKS5_LIM` 丢弃计数，并写入 `SOCKS_SECURITY_LOG_FILE`；单次异常会标记为弱告警，最近 `600` 秒内告警次数达到 `2` 次会升级为强告警。
- 若你希望“只有检测到异常才继续重置/修改”，可设置 `SOCKS_REQUIRE_ATTACK_BEFORE_RESET=1`。
- 若你不想手动看日志，可设置 `TG_NOTIFY_ENABLE=1` 并提供 `TG_BOT_TOKEN` / `TG_CHAT_ID`，脚本会自动启用 `socks5-watchdog.timer` 周期检测并推送到 Telegram（`TG_API_BASE_URL` 可替换为自建电报服务器地址）。
- `SOCKS_ALLOW` 会通过 `python3` 校验 IP/CIDR；若输入格式错误脚本会报错并提示，避免后续 iptables 命令崩溃。
- 如果 VPS 防火墙或云安全组未放行该端口，即使脚本生成了 proxy 监听也无法被公网访问，服务器的安全性不会因此下降。
- 安装完成后，脚本会在终端输出样例 `Socks5 本地代理：127.0.0.1:10808（usrA3xK2/aBcDeFgH1234）` 和 `Socks5 公网直连：203.0.113.55:10808（usrA3xK2/aBcDeFgH1234）`，可以直接复制到代理设置或分享给客户端。

## 5. ✅ iptables 限制连接数

针对 SOCKS5 端口叠加 `iptables` 规则可控制并发连接、防止大量 SYN 攻击：  
```bash
SOCKS_PORT=32187
iptables -N SOCKS5_LIM
iptables -A INPUT -p tcp --dport "${SOCKS_PORT}" -j SOCKS5_LIM
iptables -A SOCKS5_LIM -m conntrack --ctstate NEW -m recent --set --name socks5 --rsource
iptables -A SOCKS5_LIM -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 --name socks5 --rsource -j DROP
iptables -A SOCKS5_LIM -j ACCEPT
```
- 规则说明：每个源 IP 每 60 秒最多新建 20 个连接；超过后直接丢弃，阻断暴力扫描和横向扩展。
- `--hitcount` 值受 `xt_recent` 内核参数 `ip_pkt_list_tot`（默认 20）限制。若设置的值超过该上限，规则将永远不会触发。如需更高阈值，请先执行 `echo 100 > /proc/net/xt_recent/ip_pkt_list_tot`。
- 若用于比特浏览器等多开场景，建议通过 `SOCKS_ALLOW` 设置你的客户端 IP 白名单，白名单 IP 会跳过限速直接放行。

## 6. ✅ 基本抗扫描

- 结合 `iptables`，只允许受信 IP 访问 SOCKS5 端口：  
  `iptables -A INPUT -p tcp -s <trusted-ip>/32 --dport ${SOCKS_PORT} -j ACCEPT`  
  `iptables -A INPUT -p tcp --dport ${SOCKS_PORT} -j DROP`
- 如果无法固定 IP，考虑用 `fail2ban` 监控连接日志，对持续失败的 IP 加入 `denyhosts`。
- 配合 `ssh` 隧道（将 SOCKS5 绑定在 `127.0.0.1`）直接避免扫描；如果必须对公网开放，务必将该规则加入启动脚本并同步到云安全组。

## 7. ✅ 审计与监控

- 定期检查日志 `/var/log/auth.log`、SOCKS5 服务日志（如 `danted`）是否有异常登陆尝试。可用 `journalctl -u danted` 实时观察。
- 安装 `iptables-persistent` 或把规则写入 `rc.local`/systemd unit，确保重启后依旧生效。
- 建议每日自动刷新凭据：解密后通过邮件/运维平台发送给可信用户，并在短期内清除旧凭据。

## 结语

将上述五项措施组合使用，可以在不得不开启 SOCKS5 的场景下显著压缩攻击面，但请始终优先推荐通过 SSH 隧道访问本地 `127.0.0.1` 端口，避免在 VPS 上直接暴露代理。若最终决定不开启 SOCKS5，可参照 `README.md` 中的隧道流程，将风险归零。  
