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

```bash
sudo DOMAIN=your-domain.com bash ./install.sh
```

常用可选参数：

```bash
sudo DOMAIN=example.com \
VLESS_PORT=443 \
UUID=11111111-1111-1111-1111-111111111111 \
WSPATH=/ray \
HY2_DOMAIN=hy2.example.com \
HY2_PORT=443 \
HY2_PASSWORD=yourStrongPassword \
HY2_INSECURE=1 \
bash ./install.sh
```

## 参数说明

- `DOMAIN`：VLESS 使用的域名（Nginx 443 站点）
- `UUID`：VLESS 用户 ID，不填自动生成
- `WSPATH`：VLESS 的 WS 路径，必须 `/` 开头
- `VLESS_PORT`：VLESS 对外 TLS 端口（Nginx 监听），默认 `443`
- `HY2_DOMAIN`：HY2 连接域名（默认跟 `DOMAIN` 一样）
- `HY2_PORT`：HY2 UDP 端口，默认 `443`
- `HY2_PASSWORD`：HY2 密码，不填自动生成
- `HY2_INSECURE`：HY2 客户端是否允许不验证证书，`0/1`

## 重要说明

- 脚本默认使用 Cloudflare Origin 证书（手动粘贴 PEM/KEY）。
- VLESS（经 Cloudflare）可以橙云代理。
- 若 VLESS 走 Cloudflare 橙云，请使用 Cloudflare 支持的 HTTPS 端口（如 `443/8443` 等）。
- HY2 走 UDP，通常建议使用 DNS only（灰云），并放行 `HY2_PORT/udp`。
- 如果 HY2 使用 Origin 证书，客户端通常需要 `insecure=1` 或使用证书 Pin。

## 输出内容

安装结束后会在终端显示：

- VLESS 分享链接 + 二维码
- HY2 分享链接 + 二维码

可直接复制到支持协议的客户端快速导入。
