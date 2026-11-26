# Linux 部署指南

`awsquick2api` 是静态编译的纯 Go 单二进制（支持 `amd64` / `arm64`），无需额外运行时，适合直接部署为 `systemd` 服务。

## 1. 部署方式

### 方式 A：Docker Compose（推荐）

仓库根目录提供了多架构 `Dockerfile` 与 `docker-compose.yml`（默认镜像 `ghcr.io/xiangwen-ctrl/awsquick2api:latest`，支持 `linux/amd64` / `linux/arm64`）：

```bash
mkdir -p awsquick2api/storage && cd awsquick2api
curl -fsSLO https://raw.githubusercontent.com/xiangwen-ctrl/awsquick2api/main/docker-compose.yml
PUID=$(id -u) PGID=$(id -g) docker compose up -d
docker compose logs -f
```

- 首次运行会自动在 `./storage/` 下生成 `config.json`、`auths/` 和 `data/`，避免传统单文件挂载因文件不存在被 Docker 建目录的坑。
- 容器默认仅绑定宿主机 `127.0.0.1:8045`；省略 `PUID`/`PGID` 时默认以非 root 用户 `10001:10001` 运行（需先执行 `sudo chown -R 10001:10001 storage`）。
- 内置 `/healthz` 健康检查；如需本地构建并配置 Go 代理，可取消 `docker-compose.yml` 中 `build` 注释并设置 `GOPROXY`。

### 方式 B：静态二进制 + systemd

从 [GitHub Releases](https://github.com/xiangwen-ctrl/awsquick2api/releases) 下载对应架构的二进制文件：

```bash
sudo useradd --system --home-dir /opt/awsquick2api --shell /usr/sbin/nologin awsquick2api
sudo install -o root -g root -m 0755 awsquick2api-linux-amd64 /usr/local/bin/awsquick2api
sudo install -d -o awsquick2api -g awsquick2api -m 0700 /opt/awsquick2api

sudo cp deploy/linux/awsquick2api.service /etc/systemd/system/awsquick2api.service
sudo systemctl daemon-reload
sudo systemctl enable --now awsquick2api
sudo systemctl status awsquick2api
```

首次启动会自动在 `/opt/awsquick2api/` 下生成 `config.json`（默认监听 `127.0.0.1:8045`）和 `data/encryption.key`。

如需配置出站代理，可在 `config.json` 中设置 `upstream.proxy_url`，或在 `systemd` 环境变量中设置 `AWSQUICK_PROXY_URL`。

## 2. 访问管理面板

- **已配置反代域名**（Nginx / Caddy 等）：直接访问 `https://你的域名/panel/`，并在 `config.json` 的 `server.trusted_hosts`（或环境变量 `AWSQUICK_TRUSTED_HOSTS`）中加入该域名。
- **未配域名 / 不暴露公网（推荐）**：通过 SSH 端口转发在本机打开远程面板：

```bash
ssh -L 8045:127.0.0.1:8045 user@YOUR_SERVER
```

浏览器访问 `http://127.0.0.1:8045/panel/`，输入 `/opt/awsquick2api/config.json` 中的 `admin_key` 解锁。

## 3. 在远程服务器添加账号

### 方式一：面板手动粘贴回调地址

1. 在面板点击 **「+ 添加账号」** → **「生成一次性授权链接」**。
2. 在本机浏览器中打开第 1 步链接完成登录；跳转到无法访问的 `http://localhost:18080/callback?...` 时，复制地址栏完整 URL。
3. 展开面板底部的手动粘贴回调框提交该 URL，获得第 2 步 AWS 授权页链接。
4. 打开第 2 步链接并确认授权，再次复制跳转后的 `http://127.0.0.1:18080/?code=...` 完整 URL 粘贴提交即可。

### 方式二：从本机加密迁移

> 迁移前建议停止源端进程，避免两端同时刷新同一账号的 `refresh_token`。

```bash
# 本机导出加密迁移包（输入 ≥ 12 位密码）
./awsquick2api -export-encrypted ./accounts.enc.json

# 若服务正在运行，推荐直接通过面板「导入」上传；
# 如改用命令行离线导入，请先停止服务，以服务用户导入后再重启（避免写入权限错误或与在线刷新竞态）
sudo systemctl stop awsquick2api
sudo -u awsquick2api /usr/local/bin/awsquick2api -config /opt/awsquick2api/config.json -import-encrypted /tmp/accounts.enc.json
sudo systemctl start awsquick2api
```

## 4. 从源码交叉编译

```bash
# Linux / macOS
sh ./scripts/build-linux.sh

# Windows PowerShell
.\scripts\build-linux.ps1
```
