# AWSQuick2API

[![CI](https://github.com/xiangwen-ctrl/awsquick2api/actions/workflows/ci.yml/badge.svg)](https://github.com/xiangwen-ctrl/awsquick2api/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/xiangwen-ctrl/awsquick2api)](https://github.com/xiangwen-ctrl/awsquick2api/releases)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](./go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

AWSQuick2API 是一个纯 Go 编写的自托管网关，可将 Amazon Quick 账号封装为标准的 OpenAI、Anthropic（Claude Code）与 Codex Responses 兼容 API，并内置单页 Web 管理面板。

## 功能特性

- **多协议兼容**：支持 OpenAI (`/v1/chat/completions`)、Anthropic (`/v1/messages` 及 `count_tokens`) 与 Codex Responses (`/v1/responses`)，覆盖流式 / 非流式输出、思考链、工具调用、JSON 模式与图片输入。
- **原生 OAuth 登录**：在管理面板发起个人或企业账号 PKCE 登录，本机自动回调，远程服务器支持粘贴回调地址，无需提取浏览器 Cookie。
- **多账号调度与容错**：支持按剩余额度加权 / 轮询 / 顺序选号，自动刷新令牌、按官方重置时间冷却与异常熔断，并支持多轮会话线程复用。
- **内嵌 Web 管理面板**：单二进制打包，访问 `/panel/` 即可管理账号、测试连通性、查看额度与请求统计、在线热更新配置。
- **单文件跨平台运行**：`CGO_ENABLED=0` 零外部依赖，提供 Windows（系统托盘版与控制台版）、Linux（`amd64` / `arm64`）与 macOS 预编译二进制。
- **密钥分离与本地加密**：默认仅监听 `127.0.0.1:8045`，推理密钥（`api_key`）与管理面板密钥（`admin_key`）分离，本地账号凭据使用 AES-256-GCM 加密存储。

## 安装与使用

### 1. 下载并启动

从 [GitHub Releases](https://github.com/xiangwen-ctrl/awsquick2api/releases) 下载对应平台的可执行文件：

- **Windows**：双击 `awsquick2api-windows-amd64.exe` 启动（后台常驻并显示系统托盘图标，首次启动会自动打开管理面板）。
- **Linux / macOS**：
  ```bash
  chmod +x awsquick2api-linux-amd64
  ./awsquick2api-linux-amd64
  ```

首次运行会在同目录生成 `config.json`（包含随机生成的 `api_key` 和 `admin_key`）及 `data/encryption.key`。

### 2. 登录面板并添加账号

1. 浏览器访问 `http://127.0.0.1:8045/panel/`。
2. 输入 `config.json` 中的 `admin_key` 解锁面板（Windows 可右键系统托盘图标一键复制）。
3. 点击右上角 **「+ 添加账号」**，按页面引导完成 Amazon Quick 授权，之后可点击「测试」与「额度」检查账号状态。

> 添加多个账号时，建议为每个账号使用独立的无痕 / 隐私窗口，不要在网页端退出前一个账号，以免撤销已授权会话。

### 3. 接入客户端

外部客户端统一填写 `config.json` 中的 `api_key`（或在面板「模型与接入」页直接复制）：

**OpenAI 兼容客户端（Cherry Studio / OpenCode / SDK）**
- Base URL：`http://127.0.0.1:8045/v1`
- API Key：`config.json` 中的 `api_key`
- 常用模型：`amazon-smart`、`amazon-balanced`、`amazon-fast`

**Claude Code**
```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8045"
export ANTHROPIC_API_KEY="你的 api_key"
claude
```
```powershell
# Windows PowerShell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8045"
$env:ANTHROPIC_API_KEY  = "你的 api_key"
claude
```

**Codex CLI (`~/.codex/config.toml`)**
```toml
model_provider = "awsquick"
model = "amazon-smart"

[model_providers.awsquick]
name = "AWSQuick2API"
base_url = "http://127.0.0.1:8045/v1"
env_key = "AWSQUICK_API_KEY"
wire_api = "responses"
```
启动前设置环境变量 `AWSQUICK_API_KEY="你的 api_key"`。

## API 端点与模型

| 方法 | 路径 | 说明 | 鉴权密钥 |
| --- | --- | --- | --- |
| `POST` | `/v1/chat/completions` | OpenAI Chat Completions | `api_key` |
| `GET` | `/v1/models` | 获取可用模型列表 | `api_key` |
| `POST` | `/v1/messages`（及 `/messages`） | Anthropic Messages | `api_key` |
| `POST` | `/v1/messages/count_tokens` | Anthropic Token 估算 | `api_key` |
| `POST` | `/v1/responses`（及 `/responses`） | OpenAI / Codex Responses | `api_key` |
| `GET` | `/healthz` | 健康检查 | 无 |
| `GET` | `/panel/` | Web 管理面板（接口位于 `/panel/api/*`） | `admin_key` |

内置模型映射如下，可在模型名后直接拼接 `-off` / `-low` / `-medium` / `-high` 控制思考强度（如 `amazon-smart-high`），并默认支持 `claude-opus-*` / `claude-sonnet-*` / `claude-haiku-*` 别名：

| 模型 ID | 对应档位 | 内置别名 |
| --- | --- | --- |
| `amazon-smart` | `smart` | `smart`, `qw-smart`, `aws-quick/smart` |
| `amazon-balanced` | `balanced` | `balanced`, `qw-balanced`, `aws-quick/balanced` |
| `amazon-fast` | `fast` | `fast`, `qw-fast`, `aws-quick/fast` |
| `amazon-auto` | `auto` | `auto`, `qw-auto`, `aws-quick/auto` |
| `amazon-advanced` | `advanced` | `advanced`, `qw-advanced`（账号开通后可见） |

## 配置说明

完整配置项参考 [`config.example.json`](./config.example.json)，面板保存后大部分配置即时生效。Linux 服务器 `systemd` 部署及无头登录见 [`docs/LINUX.md`](./docs/LINUX.md)。

| 环境变量 | 说明 |
| --- | --- |
| `AWSQUICK_LISTEN` | 监听地址（默认 `127.0.0.1:8045`） |
| `AWSQUICK_API_KEY` | 覆盖推理密钥 |
| `AWSQUICK_ADMIN_KEY` | 覆盖管理面板密钥 |
| `AWSQUICK_PROXY_URL` | 可选出站代理（`http://`、`https://`、`socks5://`、`socks5h://`） |
| `AWSQUICK_ENCRYPTION_KEY` | 自定义本地凭据加密密钥 |
| `AWSQUICK_CALLBACK_PORT` | 本地 OAuth 回调端口（默认 `18080`） |

跨机迁移账号可在面板导出 / 导入，或使用命令行（迁移前请先停止源端进程）：

```bash
./awsquick2api -export-encrypted ./accounts.enc.json
./awsquick2api -import-encrypted ./accounts.enc.json
```

## 从源码构建

需要 Go 1.26+：

```bash
# Linux / macOS
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o awsquick2api ./cmd/awsquick2api

# Windows（系统托盘版）
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H=windowsgui" -o awsquick2api.exe ./cmd/awsquick2api

# 运行测试
CGO_ENABLED=0 go test ./...
```

## 注意事项与许可

- 本项目为非官方协议适配工具，与 Amazon / AWS 无隶属关系，仅供个人学习与自有账号在本地或私有网络中使用。
- 请勿公开或提交 `config.json`、`data/encryption.key`、`auths/`、`data/` 与 `*.enc.json`；更多安全说明见 [`SECURITY.md`](./SECURITY.md)。
- 基于 [MIT License](./LICENSE) 开源。
