# Campus Net Client

基于 Srun / 深澜认证协议的 Windows 桌面校园网客户端。它面向日常使用：多账号登录、认证状态同步、自动重连、系统托盘运行，以及通过 GitHub Releases 获取更新。

## 简介

`campus-net-client` 适合需要在校园网环境下频繁登录、登出或切换运营商账号的用户。程序会优先使用认证服务器返回的在线状态判断当前账号是否真正在线，而不是只看登录接口是否返回成功。

核心协议保持兼容常见 Srun 部署：

- 登录挑战：`get_challenge`
- 登录/登出：`srun_portal`
- 在线状态：`rad_user_info?callback=sdu`
- 常用参数：`acid`、`n`、`type`、`double_stack`

## 功能

- 多账号管理：添加、编辑、删除、登录、登出、一键登录和一键登出。
- 在线状态同步：通过 `rad_user_info` 获取当前在线账号、认证 IP、在线时长、剩余流量和套餐信息。
- 自动重连：以 `rad_user_info` 为权威状态来源，只有状态同步异常时才使用降级探测。
- 网卡绑定：支持按网卡名称绑定，适合 DHCP 环境下 IP 会变化的校园网。
- 系统托盘：支持最小化到托盘、显示窗口、快速登录/登出和退出。
- 自动更新：从 GitHub Releases 检查新版本，固定下载资产名为 `campus-net-client.exe`。
- 日志诊断：运行日志写入 `C:\ProgramData\CampusNetClient\app.log`。
- 语言切换：支持中文和 English 界面。
- IPv4 外网探测：默认关闭，仅用于路由诊断，不作为登录状态的权威来源。

## 下载与安装

1. 打开 [GitHub Releases](https://github.com/uchihazzj/campus_net/releases)。
2. 下载最新版本中的 `campus-net-client.exe`。
3. 将程序放到用户可写目录，例如 `%USERPROFILE%\CampusNet\`。
4. 双击运行，并在程序中添加校园网账号。

不建议把程序放在 `C:\Program Files` 下，除非你准备手动更新或用合适权限运行。自动更新需要能够替换当前 exe 文件。

## 使用步骤

1. 启动程序。
2. 设置认证服务器地址，常见格式类似 `http://10.0.0.55`。
3. 点击添加用户。
4. 输入用户名和密码。
5. 尽量选择一个固定的网卡名称进行绑定。
6. 点击登录。

登录接口返回成功后，程序会进入等待确认状态。只有 `rad_user_info` 确认在线后，界面才会显示为已登录。

## 运营商后缀

部分 Srun / 深澜部署通过用户名后缀区分运营商线路：

| 线路 | 示例 |
| --- | --- |
| 移动 | `username@cmcc` |
| 联通 | `username@unicom` |
| 电信 | `username@chinanet` |

如果学校不要求后缀，直接填写原始学号或账号即可。客户端不会额外改写运营商信息，需要什么后缀就按学校说明填写什么用户名。

## 配置与数据位置

运行时数据默认保存在：

```text
C:\ProgramData\CampusNetClient\
```

主要文件：

| 文件 | 说明 |
| --- | --- |
| `config.json` | 当前配置和账号列表 |
| `config.json.bak` | 最近一次成功写入前保留的有效配置备份 |
| `config.json.bad-<timestamp>` | 发现配置 JSON 损坏时保存的坏文件副本 |
| `app.log` | 持久运行日志 |

从 `v1.1.9` 开始，配置保存会先写入临时文件，再替换正式配置，并维护 `config.json.bak`。如果启动时发现 `config.json` 已损坏，程序会先把坏文件备份为 `config.json.bad-<timestamp>`，再尝试从 `config.json.bak` 恢复。只有主配置和备份都不可用时，才会使用默认配置，并在启动日志和界面日志中提示。

旧版本曾经放在 exe 同目录的 `config.json` 会在启动时迁移到 `C:\ProgramData\CampusNetClient\`。

配置示例：

```json
{
  "server": "http://10.0.0.55",
  "detect_ip": false,
  "strict_bind": false,
  "double_stack": false,
  "n": 200,
  "type": 1,
  "acid": 8,
  "retry_delay": 1000,
  "auto_reconnect": true,
  "check_update_on_startup": true,
  "language": "zh-CN",
  "users": []
}
```

常用配置项：

| 字段 | 说明 |
| --- | --- |
| `server` | 校园网认证服务器地址 |
| `acid` | Srun 区域或接入点参数 |
| `n` | Srun 登录参数，常见值为 `200` |
| `type` | Srun 登录类型参数 |
| `double_stack` | 是否启用双栈参数 |
| `detect_ip` | 是否执行 IPv4 外网连通性探测，默认关闭 |
| `strict_bind` | 是否严格要求绑定网卡可用 |
| `auto_reconnect` | 是否启用自动重连 |
| `check_update_on_startup` | 是否启动时检查更新 |

密码只按本地配置数据保存，不要把真实 `config.json`、日志、截图或账号信息提交到仓库或发给他人。

## 网卡与 IP 选择

登录或登出时，客户端按以下顺序选择客户端 IP：

1. 优先使用用户绑定的网卡名称，并解析该网卡当前 IPv4 地址。
2. 如果没有绑定网卡，则使用用户配置中的 `ip`。
3. 如果仍不可用，则尝试当前检测到的校园网 IPv4 地址，例如 `10.x.x.x`。

推荐绑定网卡名称，而不是手动写死 IP。校园网 DHCP 可能更换 IP，网卡名称通常更稳定。

## 更新说明

程序会在启动时检查 GitHub 最新 Release，并在发现新版本后显示更新按钮。发布新版本时需要保持这些约定：

- tag 使用 `vX.Y.Z` 格式。
- Release 资产名必须精确为 `campus-net-client.exe`。
- 自动更新需要当前 exe 所在目录可写。

更新时，程序会下载新的 exe，保存配置，生成 PowerShell 替换脚本，退出当前进程，替换旧 exe，然后启动新版本。

## 排错

日志文件位置：

```text
C:\ProgramData\CampusNetClient\app.log
```

如果在 Windows PowerShell 5.1 中查看日志时中文显示异常，请用 UTF-8 读取：

```powershell
Get-Content C:\ProgramData\CampusNetClient\app.log -Encoding UTF8
```

常见问题：

| 现象 | 建议检查 |
| --- | --- |
| 登录失败 | 认证服务器地址、用户名、密码、校园网连接、网卡选择 |
| 登录后一直等待确认 | 查看 `app.log` 中的 `rad_user_info` 和 `[OnlineInfo]` 日志 |
| 自动重连没有触发 | 确认 `auto_reconnect` 已开启，并且不是手动登出后的抑制状态 |
| 自动更新失败 | 确认 exe 目录可写，并且能访问 GitHub Releases |
| 配置被恢复或重置 | 检查 `config.json.bad-<timestamp>` 和 `config.json.bak` |
| 中文日志乱码 | 使用 `Get-Content -Encoding UTF8` |

## 开发构建

需要：

- Rust MSVC 工具链
- Visual Studio 2022 Build Tools，包含 C++ build tools

构建 release：

```powershell
.\build-release.ps1
```

或：

```powershell
cargo build --release
```

输出文件：

```text
target\release\campus-net-client.exe
```

## 已知限制

- 主要支持 Windows。
- 不同学校的 Srun / 深澜部署可能不同，`server`、`acid`、`n`、`type` 可能需要按学校实际情况调整。
- 自动更新依赖 GitHub Releases 和固定资产名，目前不做 SHA256 或签名校验。
- IPv4 外网探测只是诊断能力，不应作为登录状态判断来源。
- 账号匹配优先使用 `rad_user_info.user_name` 精确匹配；去后缀匹配只在能唯一对应本地账号时使用。

## License

Apache License 2.0
