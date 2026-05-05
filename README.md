# Docker Nginx 反向代理一键部署

这是一套全新的 Docker Nginx 反向代理初始化脚本，用于在 Ubuntu/Debian 新服务器上快速创建统一入口：

- 反代项目目录：`/opt/reverse-proxy`
- 反代容器：`reverse-proxy`
- Docker 网络：`proxy-net`
- 站点配置目录：`/opt/reverse-proxy/nginx/conf.d`
- 证书目录：`/opt/reverse-proxy/ssl`
- 日志目录：`/opt/reverse-proxy/logs`
- 3x-ui 目录：`/opt/3x-ui`
- CLIProxyAPI 目录：`/opt/cli-proxy-api`
- SSH 公钥登录脚本：`setup-ssh-key-login.sh`

脚本用于 Ubuntu 24.04 VPS 初始配置：系统更新升级、Docker、Nginx 反代、可选 3x-ui、可选 CLIProxyAPI，以及独立的 SSH 公钥登录配置。

所有容器均使用 `restart: unless-stopped`，脚本会执行 `systemctl enable --now docker`，服务器重启后 Docker 服务和这些容器会自动启动。

## 环境要求

- Ubuntu 24.04 / Debian
- Root 权限
- 服务器可访问外网，用于安装 Docker 和拉取容器镜像
- 域名已解析到服务器 IP
- SSL 证书已准备好，或后续手动放入指定目录

## Ubuntu 24.04 一条命令安装反代

把仓库发布到 GitHub 后，可以在每台 VPS 上执行同一条命令。下面的 URL 按当前仓库示例写成 `47alan/VPS_simple`，如果你的仓库地址不同，需要替换成自己的 raw 地址。

如果你不想上传到 GitHub，跳过这一节，直接看“本地文件上传到 VPS”。

如果你想自己选择安装内容，推荐进入菜单：

```bash
sudo apt-get update -y && sudo apt-get install -y curl ca-certificates && \
curl -fsSL https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh -o /tmp/reverse-proxy-install.sh && \
sudo bash /tmp/reverse-proxy-install.sh menu
```

菜单里可以按序号选择：

- 安装基础环境 + Nginx 反代
- 安装 3x-ui
- 安装 CLIProxyAPI
- 全套安装
- 添加 HTTPS 反代站点
- 查看状态、更新镜像
- 停止/卸载容器，默认保留配置和数据

```bash
sudo apt-get update -y && sudo apt-get install -y curl ca-certificates && \
curl -fsSL https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh -o /tmp/reverse-proxy-install.sh && \
sudo bash /tmp/reverse-proxy-install.sh install
```

这条命令适合你在 Xshell 登录服务器后直接粘贴执行。脚本会自动安装 Docker、创建反代目录、创建 `proxy-net` 网络并启动 Nginx 容器。

脚本内部会先执行系统初始化更新：

```bash
apt-get update -y
apt-get upgrade -y
apt-get autoremove -y
```

如果某台机器不想升级系统包，可以设置 `SYSTEM_UPGRADE=0`。

## 本地文件上传到 VPS

如果脚本只保存在你的电脑本地，不上传 GitHub，推荐把文件上传到服务器目录后运行。

方式一：用 Xftp 上传：

1. 在服务器上建目录：
   ```bash
   mkdir -p /root/vps-init
   ```
2. 用 Xftp 把这些文件上传到 `/root/vps-init`：
   ```text
   install.sh
   setup-ssh-key-login.sh
   README.md
   说明.md
   ```
3. 在 Xshell 里运行：
   ```bash
   cd /root/vps-init
   chmod +x install.sh setup-ssh-key-login.sh
   sudo bash ./install.sh menu
   ```

方式二：用本仓库的 PowerShell 上传脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\upload_to_vps.ps1 -HostName 你的服务器IP -User root -Port 22
```

上传完成后，在 Xshell 里运行：

```bash
cd /root/vps-init
sudo bash ./install.sh menu
```

如果 SSH 不是 22 端口，把 `-Port 22` 改成你的实际端口。

## Ubuntu 24.04 一条命令安装全套容器

3x-ui 使用官方 Docker 镜像 `ghcr.io/mhsanaei/3x-ui:latest`，独立安装在 `/opt/3x-ui`，使用 `network_mode: host`。默认面板地址通常是：

```text
http://服务器IP:2053
```

一条命令安装反代、3x-ui 和 CLIProxyAPI：

```bash
sudo apt-get update -y && sudo apt-get install -y curl ca-certificates && \
curl -fsSL https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh -o /tmp/reverse-proxy-install.sh && \
sudo INSTALL_3XUI=1 INSTALL_CLIPROXY=1 bash /tmp/reverse-proxy-install.sh install
```

只安装 3x-ui：

```bash
sudo apt-get update -y && sudo apt-get install -y curl ca-certificates && \
curl -fsSL https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh -o /tmp/reverse-proxy-install.sh && \
sudo bash /tmp/reverse-proxy-install.sh install-3x-ui
```

首次登录后必须立即修改默认账号、默认密码、面板路径和面板端口。3x-ui 使用 host 网络，你在面板里创建的入站端口会直接占用宿主机端口，需要同步放行云防火墙或安全组。

只安装 CLIProxyAPI：

```bash
sudo apt-get update -y && sudo apt-get install -y curl ca-certificates && \
curl -fsSL https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh -o /tmp/reverse-proxy-install.sh && \
sudo bash /tmp/reverse-proxy-install.sh install-cli-proxy
```

CLIProxyAPI 默认安装到 `/opt/cli-proxy-api`，镜像为 `eceasy/cli-proxy-api:latest`，默认只绑定 `127.0.0.1:8317`，不会直接暴露到公网。需要公网访问时设置 `CLI_PROXY_BIND_IP=0.0.0.0`，同时放行云防火墙或安全组。

## SSH 公钥登录

服务器初始化时建议先添加公钥，确认私钥登录可用后，再关闭密码登录。

添加公钥，保持密码登录：

```bash
sudo apt-get update -y && sudo apt-get install -y curl ca-certificates && \
curl -fsSL https://raw.githubusercontent.com/47alan/VPS_simple/main/setup-ssh-key-login.sh -o /tmp/setup-ssh-key-login.sh && \
sudo SSH_USER=root SSH_PUBLIC_KEY='ssh-ed25519 AAAA...你的公钥...' bash /tmp/setup-ssh-key-login.sh
```

修改 SSH 端口，默认保留旧端口一起监听，避免锁死：

```bash
sudo SSH_USER=root SSH_PORT=22222 SSH_PUBLIC_KEY='ssh-ed25519 AAAA...你的公钥...' bash /tmp/setup-ssh-key-login.sh
```

确认新 Xshell 会话可以用私钥和新端口登录后，再关闭密码登录并移除旧端口：

```bash
sudo SSH_USER=root SSH_PORT=22222 KEEP_OLD_SSH_PORT=0 DISABLE_PASSWORD_LOGIN=1 SSH_PUBLIC_KEY='ssh-ed25519 AAAA...你的公钥...' bash /tmp/setup-ssh-key-login.sh
```

端口注意事项：

- 不要关闭当前 Xshell 窗口，先新开窗口测试。
- 如果设置了 `SSH_PORT`，要先在云厂商安全组放行该 TCP 端口。
- `KEEP_OLD_SSH_PORT=1` 会同时保留旧端口和新端口。
- `DISABLE_PASSWORD_LOGIN=1` 只应在确认私钥登录成功后使用。

## 本地脚本初始化

```bash
sudo bash ./install.sh install
```

脚本会自动完成：

- 安装 Docker Engine 和 Docker Compose 插件（如果系统尚未安装）
- 创建 `/opt/reverse-proxy` 标准目录
- 创建 Docker 网络 `proxy-net`
- 写入 `docker-compose.yml`
- 写入 Nginx 主配置
- 写入一个安全的 HTTP 默认站点 `00-default.conf`
- 启动 `reverse-proxy` 容器

## 添加一个 HTTPS 反代站点

先放置证书，目录名必须和域名一致：

```bash
sudo mkdir -p /opt/reverse-proxy/ssl/example.com
sudo cp fullchain.pem /opt/reverse-proxy/ssl/example.com/fullchain.pem
sudo cp privkey.pem /opt/reverse-proxy/ssl/example.com/privkey.pem
sudo chmod 644 /opt/reverse-proxy/ssl/example.com/fullchain.pem
sudo chmod 600 /opt/reverse-proxy/ssl/example.com/privkey.pem
```

再生成站点配置并重载 Nginx：

```bash
sudo DOMAIN=example.com UPSTREAM=app-container:8080 bash ./install.sh add-site
```

`UPSTREAM` 可以写成：

```text
app-container:8080
http://app-container:8080
https://app-container:8443
```

如果执行 `add-site` 时证书还不存在，脚本只会生成：

```text
/opt/reverse-proxy/nginx/conf.d/example.com.conf.disabled
```

这样不会让 Nginx 因证书缺失而启动失败。证书放好后重新执行 `add-site` 即可生成正式的 `.conf`。

## 新服务器非交互安装

```bash
sudo PROJECT_DIR=/opt/reverse-proxy \
DOMAIN=example.com \
UPSTREAM=app-container:8080 \
CREATE_SITE=1 \
bash ./install.sh install
```

如果证书已经在 `/opt/reverse-proxy/ssl/example.com/` 下，脚本会直接创建启用的 HTTPS 配置；否则会创建 `.conf.disabled` 模板。

## Xshell 脚本管理器

仓库提供多个 Xshell VBS 模板：

- `scripts/xshell_vps_menu.vbs`：下载脚本并打开数字菜单
- `scripts/xshell_reverse_proxy_install.vbs`：初始化一台 Ubuntu 24.04 VPS
- `scripts/xshell_3xui_install.vbs`：只安装 3x-ui Docker 容器
- `scripts/xshell_cli_proxy_install.vbs`：只安装 CLIProxyAPI Docker 容器
- `scripts/xshell_setup_ssh_key_login.vbs`：配置 SSH 公钥登录、端口和密码登录策略
- `scripts/xshell_reverse_proxy_add_site.vbs`：给已初始化的服务器添加一个 HTTPS 反代站点

使用步骤：

1. 打开 VBS 文件，把 `INSTALL_URL` 改成你自己的 GitHub raw 地址。
2. 在 Xshell 连接到目标服务器。
3. 打开“脚本管理器”，新建或编辑一个 `.vbs` 脚本。
4. 粘贴对应 VBS 内容并运行。

初始化脚本默认只安装反代基础环境，不自动创建站点：

```vbscript
Const CREATE_SITE = "0"
Const SYSTEM_UPGRADE = "1"
Const INSTALL_3XUI = "1"
Const INSTALL_CLIPROXY = "1"
Const DOMAIN = ""
Const UPSTREAM = ""
```

`INSTALL_3XUI="1"` 表示同时安装 3x-ui；如果只想安装反代基础环境，改成 `INSTALL_3XUI="0"`。
`INSTALL_CLIPROXY="1"` 表示同时安装 CLIProxyAPI；如果不需要，改成 `INSTALL_CLIPROXY="0"`。

如果你希望第一次安装时顺便创建站点，可以改成：

```vbscript
Const CREATE_SITE = "1"
Const DOMAIN = "example.com"
Const UPSTREAM = "app-container:8080"
```

前提是证书已经在服务器的 `/opt/reverse-proxy/ssl/example.com/` 目录下；否则脚本会生成 `.conf.disabled`，不会启用该站点。

## 业务容器接入方式

业务容器需要加入同一个 Docker 网络：

```yaml
services:
  app-container:
    image: your-app-image
    container_name: app-container
    restart: unless-stopped
    expose:
      - "8080"
    networks:
      - proxy-net

networks:
  proxy-net:
    external: true
```

后端服务建议使用 `expose`，不要无必要使用 `ports` 暴露到公网。对外入口统一由反代容器的 `80` 和 `443` 提供。

## 常用命令

```bash
sudo bash ./install.sh menu
sudo bash ./install.sh status
sudo bash ./install.sh test
sudo bash ./install.sh reload
sudo bash ./install.sh down
sudo bash ./install.sh up
```

等价的 Docker 命令：

```bash
cd /opt/reverse-proxy
docker compose up -d
docker exec reverse-proxy nginx -t
docker exec reverse-proxy nginx -s reload
docker logs -f reverse-proxy
```

3x-ui 常用命令：

```bash
sudo bash ./install.sh install-3x-ui
sudo bash ./install.sh update-3x-ui
sudo bash ./install.sh 3x-ui-status
sudo bash ./install.sh 3x-ui-down
sudo bash ./install.sh 3x-ui-up
```

CLIProxyAPI 常用命令：

```bash
sudo bash ./install.sh install-cli-proxy
sudo bash ./install.sh update-cli-proxy
sudo bash ./install.sh cli-proxy-status
sudo bash ./install.sh cli-proxy-down
sudo bash ./install.sh cli-proxy-up
```

SSH 公钥登录脚本：

```bash
sudo bash ./setup-ssh-key-login.sh help
```

## 参数说明

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PROJECT_DIR` | `/opt/reverse-proxy` | 反代项目目录 |
| `CONTAINER_NAME` | `reverse-proxy` | Nginx 容器名称 |
| `NETWORK_NAME` | `proxy-net` | 外部 Docker 网络名称 |
| `NGINX_IMAGE` | `nginx:stable` | Nginx 镜像 |
| `HTTP_PORT` | `80` | 宿主机 HTTP 端口 |
| `HTTPS_PORT` | `443` | 宿主机 HTTPS 端口 |
| `SYSTEM_UPGRADE` | `1` | 安装前是否执行 `apt-get update/upgrade` |
| `INSTALL_3XUI` | `0` | `install` 时是否同时安装 3x-ui |
| `XUI_DIR` | `/opt/3x-ui` | 3x-ui Compose 项目目录 |
| `XUI_IMAGE` | `ghcr.io/mhsanaei/3x-ui:latest` | 3x-ui Docker 镜像 |
| `XUI_CONTAINER_NAME` | `3xui_app` | 3x-ui 容器名称 |
| `INSTALL_CLIPROXY` | `0` | `install` 时是否同时安装 CLIProxyAPI |
| `CLI_PROXY_DIR` | `/opt/cli-proxy-api` | CLIProxyAPI Compose 项目目录 |
| `CLI_PROXY_IMAGE` | `eceasy/cli-proxy-api:latest` | CLIProxyAPI Docker 镜像 |
| `CLI_PROXY_BIND_IP` | `127.0.0.1` | CLIProxyAPI 宿主机绑定地址 |
| `CLI_PROXY_API_PORT` | `8317` | CLIProxyAPI API 端口 |
| `DOMAIN` | 空 | 要添加的域名 |
| `UPSTREAM` | 空 | 后端容器名和端口 |
| `CREATE_SITE` | `0` | `install` 时是否顺便创建第一个站点 |
| `INSTALL_DOCKER` | `1` | Docker 不存在时是否自动安装 |
| `START_AFTER_INSTALL` | `1` | 初始化后是否启动容器 |
| `OVERWRITE` | `0` | 是否覆盖已有配置，覆盖前会自动备份 |

SSH 脚本参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `SSH_USER` | `root` 或当前 sudo 用户 | 写入公钥的用户 |
| `SSH_PUBLIC_KEY` | 空 | 要写入的 OpenSSH 公钥 |
| `SSH_PUBLIC_KEY_FILE` | 空 | 服务器上的公钥文件路径 |
| `SSH_PORT` | 空 | 新 SSH 端口，留空则不改端口 |
| `KEEP_OLD_SSH_PORT` | `1` | 修改端口时是否保留旧端口 |
| `DISABLE_PASSWORD_LOGIN` | `0` | 是否关闭密码登录 |
| `PERMIT_ROOT_LOGIN` | 空 | 可手动设置 `yes`、`prohibit-password`、`no` |

## 备份建议

重点备份整个目录：

```bash
sudo tar -czvf reverse-proxy-backup.tar.gz /opt/reverse-proxy
```

最重要的是 `ssl/` 下的私钥文件，不能提交到 Git，也不要写入 Docker 镜像。
