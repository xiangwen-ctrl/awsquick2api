# Linux 部署指南

`awsquick2api` 是静态编译的纯 Go 单二进制（支持 `amd64` / `arm64`），无需额外运行时，适合直接部署为 `systemd` 服务。

## 1. 下载并安装

从 [GitHub Releases](https://github.com/xiangwen-ctrl/awsquick2api/releases) 下载对应架构的二进制文件：

```bash
sudo useradd --system --home-dir /opt/awsquick2api --shell /usr/sbin/nologin awsquick2api
sudo install -d -o awsquick2api -g awsquick2api -m 0700 /opt/awsquick2api
sudo install -o awsquick2api -g awsquick2api -m 0755 awsquick2api-linux-amd64 /opt/awsquick2api/awsquick2api
sudo chown -R awsquick2api:awsquick2api /opt/awsquick2api

sudo cp deploy/linux/awsquick2api.service /etc/systemd/system/awsquick2api.service
sudo systemctl daemon-reload
sudo systemctl enable --now awsquick2api
sudo systemctl status awsquick2api
```

首次启动会自动在 `/opt/awsquick2api/` 下生成 `config.json`（默认监听 `127.0.0.1:8045`）和 `data/encryption.key`。

如需配置出站代理，可在 `config.json` 中设置 `upstream.proxy_url`，或在 `systemd` 环境变量中设置 `AWSQUICK_PROXY_URL`。

## 2. 访问管理面板

通过 SSH 端口转发在本机打开远程面板：

```bash
ssh -L 8045:127.0.0.1:8045 user@YOUR_SERVER
```

浏览器访问 `http://127.0.0.1:8045/panel/`，输入 `/opt/awsquick2api/config.json` 中的 `admin_key` 解锁。

## 3. 在远程服务器添加账号

### 方式一：面板手动粘贴回调地址

1. 在面板点击 **「+ 添加账号」** → **「生成一次性授权链接」**。
2. 在本机浏览器的无痕窗口中打开第 1 步链接完成登录；跳转到无法访问的 `http://localhost:18080/callback?...` 时，复制地址栏完整 URL。
3. 展开面板底部的手动粘贴回调框提交该 URL，获得第 2 步 AWS 授权页链接。
4. 打开第 2 步链接并确认授权，再次复制跳转后的 `http://127.0.0.1:18080/?code=...` 完整 URL 粘贴提交即可。

### 方式二：从本机加密迁移

> 迁移前建议停止源端进程，避免两端同时刷新同一账号的 `refresh_token`。

```bash
# 本机导出加密迁移包（输入 ≥ 12 位密码）
./awsquick2api -export-encrypted ./accounts.enc.json

# 上传到服务器后以服务用户导入（避免以 root 执行生成无权读取的凭据文件；也可直接在面板「导入」上传）
sudo -u awsquick2api /opt/awsquick2api/awsquick2api -config /opt/awsquick2api/config.json -import-encrypted /tmp/accounts.enc.json
```

## 4. 从源码交叉编译

```bash
# Linux / macOS
sh ./scripts/build-linux.sh

# Windows PowerShell
.\scripts\build-linux.ps1
```
