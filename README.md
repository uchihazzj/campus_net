# Campus Net Client

基于 Srun / 深澜认证协议的 Windows 桌面校园网客户端。

## 功能

- **多账号管理**：添加、编辑、删除用户，支持一键登录/登出
- **登录 / 登出**：基于 srun 协议 (HMAC-MD5 + x_encode + SHA1)
- **系统托盘**：最小化到托盘，左键单击/双击显示窗口，右键菜单快捷操作（显示窗口、一键登录、一键登出、退出）
- **认证状态同步**：通过校园网认证服务器接口 (`rad_user_info`) 读取当前在线状态，包括当前账号、认证 IP、在线时长、剩余流量等
- **登录后自动刷新**：登录成功后自动刷新认证状态，UI 同步显示在线时长和剩余流量
- **手动刷新**：服务器地址旁提供「刷新状态」按钮，可随时手动查询认证服务器
- **界面反馈**：在线用户卡片上显示「已确认」标签，表示服务器已验证该用户在线
- **自动重连**：基于认证服务器状态判断，支持指数退避，可在设置中开启/关闭
- **版本更新**：启动时自动检查 GitHub Release 更新，支持程序内一键自动更新
- **IPv4 外网探测开关**：可选的 IPv4 外网可达性诊断功能（默认关闭），关闭后不访问任何外网探测 URL
- **开机自启**：通过 Windows 注册表 Run 键
- **中 / English 语言切换**
- **窗口大小记忆**：关闭时自动保存
- **无控制台窗口**：`#![windows_subsystem = "windows"]`

## 认证状态同步

程序通过校园网认证服务器的 `/cgi-bin/rad_user_info` 接口读取当前在线状态。该接口无需额外认证即可返回已登录用户信息。

**当前支持读取的信息**：

- 当前在线账号
- 认证分配的 IP 地址
- 在线时长（小时）
- 剩余流量
- 当前套餐名称
- 账户余额

**状态同步时机**：

- 程序启动时自动检测一次
- 登录成功后自动刷新（延迟 500ms 等待服务器状态更新）
- 登出成功后自动刷新
- 后台每 30 秒（可配置）周期刷新
- 点击「刷新状态」按钮手动刷新

**UI 显示原则**：

- Portal 登录请求成功后显示「等待确认」(PendingConfirm)，只有认证服务器确认匹配后才显示「已确认」
- 当前在线账号完整显示在 UI 中
- 在线时长、剩余流量、套餐名称显示在已登录用户卡片内
- MAC 地址和真实姓名默认不显示
- 在线时长仅显示小时数，向下取整

## 自动重连

自动重连逻辑优先根据校园网认证服务器返回的登录状态判断是否需要重连：

- 认证服务器确认已登录 → 不重连
- 认证服务器确认未登录 → 触发重连
- 认证服务器请求失败（Unknown）→ 不立即重连，等待下次周期确认
- 连续 3 次请求失败后降级为原有 HTTP 重定向检测

自动重连可在设置中开启或关闭。当 IPv4 外网探测开关关闭时，自动重连不依赖外网探测结果。

## IPv4 外网探测开关

该功能用于诊断 IPv4 外网可达性，通过向多个公共 URL（baidu.com、miui.com、msftconnecttest.com、cloudflare.com）发送 HTTP 请求来判断 IPv4 外网是否通畅。

| 设置 | 行为 |
|------|------|
| **关闭（默认）** | 不访问外网探测 URL；UI 不显示 IPv4 外网状态；仍通过校园网认证服务器刷新登录状态 |
| **开启** | 执行外网 IPv4 探测；UI 显示 IPv4 外网可达性；仅作诊断参考，不作为唯一登录状态依据 |

推荐普通用户保持关闭。需要排查校园网 IPv4 路由问题时再打开。

此开关在设置面板中，中文显示为「启用外网 IPv4 探测」，英文显示为「Enable IPv4 internet probe」。

## 自动更新

程序启动时会自动检查 GitHub latest release 是否有新版本。

- 检测到新版本时，UI 显示最新版本号、[自动更新] 按钮和 [打开 GitHub Release] 按钮
- 点击 [自动更新] 后，程序下载 `campus-net-client.exe`、生成 PowerShell 替换脚本、保存配置后退出旧进程
- Release Assets 中必须包含文件名 `campus-net-client.exe`
- 自动更新需要当前程序目录有写入权限
- 如果程序放在 `Program Files` 等受保护目录，自动更新可能因权限不足失败
- 更新失败时可查看 exe 所在目录下的 `app.log`

## 安装和升级

1. 从 [GitHub Releases](https://github.com/uchihazzj/campus_net/releases) 下载 `campus-net-client.exe`
2. 将 exe 放在普通用户有写权限的目录（推荐 `%USERPROFILE%\CampusNet\`）
3. 首次运行后自动生成 `config.json`
4. 升级时只需替换 exe 文件，保留 `config.json` 即可沿用旧配置
5. 后续版本可使用程序内自动更新

## 编译

### 前提

- [Rust](https://rustup.rs/)（MSVC toolchain）
- [Visual Studio 2022 Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)（勾选 "C++ build tools"）

### 编译

```powershell
.\build-release.ps1
```

产物：`target\release\campus-net-client.exe`

### 手动编译

```powershell
cargo build --release
```

## 使用

1. 启动 `campus-net-client.exe`（无控制台窗口）
2. 顶部输入校园网认证服务器地址，例如 `http://10.0.0.55`
3. 点击「+ 添加用户」，填写用户名和密码
4. 点击「登录」
5. 登录成功后，用户卡片自动显示已确认状态、认证 IP、在线时长、剩余流量

### 网卡绑定

推荐在用户设置中绑定网卡名（如 `Ethernet0`），而不是固定 IP。程序会通过网卡名实时解析当前校园网 IP。不推荐填写固定 IP — 校园网 DHCP 重新分配 IP 后会导致登录失败。

### 配置文件

配置文件存储在 `C:\ProgramData\CampusNetClient\config.json`，首次运行自动生成，可通过 GUI 或手动编辑。旧版本中 exe 所在目录的 `config.json` 会在首次运行时自动迁移到新位置。

```json
{
  "server": "http://10.0.0.55",
  "detect_ip": false,
  "strict_bind": false,
  "double_stack": false,
  "n": 200,
  "type": 1,
  "acid": 8,
  "os": "Windows 10",
  "name": "Windows",
  "retry_delay": 1000,
  "retry_times": 3,
  "monitor_interval_secs": 30,
  "auto_reconnect": true,
  "minimize_to_tray": true,
  "auto_start": true,
  "enable_ipv4_internet_probe": false,
  "language": "zh",
  "users": [
    {
      "username": "your_account",
      "encrypted_password": "base64...",
      "ip": null,
      "if_name": "Ethernet0"
    }
  ]
}
```

### 配置项说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server` | string | `http://10.0.0.55` | 认证服务器地址 |
| `detect_ip` | bool | `false` | 登录时通过 get_challenge 自动检测 IP |
| `strict_bind` | bool | `false` | 将出站连接绑定到指定 IP |
| `double_stack` | bool | `false` | 启用 IPv4 + IPv6 双栈 |
| `n` | int | `200` | srun 认证参数 |
| `type` | int | `1` | srun 认证类型 |
| `acid` | int | `8` | srun 认证域 ID |
| `os` | string | `Windows 10` | 上报给认证服务器的 OS 标识 |
| `name` | string | `Windows` | 上报给认证服务器的设备名 |
| `retry_delay` | int | `1000` | 登录重试间隔（毫秒） |
| `retry_times` | int | `3` | 登录重试次数 |
| `monitor_interval_secs` | int | `30` | 网络检测间隔（秒），范围 15–300 |
| `auto_reconnect` | bool | `true` | 断网自动重连 |
| `minimize_to_tray` | bool | `true` | 关闭窗口时最小化到托盘 |
| `auto_start` | bool | `true` | 开机自启 |
| `enable_ipv4_internet_probe` | bool | `false` | 启用 IPv4 外网探测（诊断用，默认关闭） |
| `language` | string | `zh` | 语言：`zh` 中文 / `en` English |
| `window_width` | float | — | 上次窗口宽度（自动保存） |
| `window_height` | float | — | 上次窗口高度（自动保存） |

### 用户配置

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | 校园网账号 |
| `encrypted_password` | string | 密码（base64 编码本地存储） |
| `ip` | string \| null | 固定 IP（不推荐填写；程序优先通过网卡名实时解析） |
| `if_name` | string \| null | 网卡名（推荐填写，如 `Ethernet0`） |

### IP 解析优先级

登录和登出时，程序按以下优先级确定使用的 IP：

1. 网卡名精确匹配 → 实时 IPv4 地址（推荐方式，适配 DHCP 变化）
2. 用户手动配置的 `user.ip`
3. 自动检测当前 `10.x.x.x` 校园网 IPv4（自动过滤 Docker、WSL、Hyper‑V、VPN 等虚拟网卡）

`if_name` 匹配优先精确相等，仅当精确匹配不存在时尝试 contains 模糊匹配（歧义时返回无匹配并记录日志）。

### 运营商选择

深澜认证系统通常对接了移动、联通、电信三家运营商的出口带宽。在用户名末尾添加运营商后缀即可选择出口线路：

- 移动：`username@cmcc`
- 联通：`username@unicom`
- 电信：`username@chinanet`

不加后缀则走学校默认出口。路由判断由认证服务端根据后缀完成，客户端无需特殊处理，直接填写带后缀的用户名即可。

## 日志与排错

程序运行时自动生成 `app.log`（位于 `C:\ProgramData\CampusNetClient\app.log`），记录运行状态和错误信息。

| 问题 | 排查方向 |
|------|---------|
| 登录失败 | 检查认证服务器地址、账号密码、网卡/IP 配置、校园网连接状态 |
| 自动更新失败 | 检查当前目录是否有写入权限、能否访问 GitHub |
| 认证状态刷新失败 | 查看 `app.log` 中 `[OnlineInfo]` / `[WARN]` 相关日志 |
| 自动重连未触发 | 确认设置中 `auto_reconnect` 已开启 |

## 已知限制

- 当前主要面向 Windows 平台
- 认证接口 (`rad_user_info`) 和返回字段依赖具体校园网的深澜认证系统版本，不同学校可能不同
- 不同学校的 `acid`、`n`、`type`、认证服务器地址等参数可能需要手动调整
- 自动更新仅校验文件名，未做 SHA/签名校验
- IPv4 外网探测仅用于网络诊断，不应作为登录状态的唯一判断依据
- 账号匹配：服务器返回的 `user_name` 与本地配置精确匹配优先；本地配置带运营商后缀（如 `abc@cmcc`）而服务器返回裸账号（`abc`）时，仅当本地只有一个匹配候选时确认，多个候选同名不同后缀时拒绝匹配

## 项目结构

```
src/
├── main.rs              # 入口：tokio runtime + eframe + CJK 字体加载 + tracing 日志
├── app.rs               # GUI 入口：CampusNetApp + 顶部栏 + 主渲染循环
├── app/
│   ├── edit_dialog.rs   # 添加 / 编辑用户弹窗
│   ├── icon.rs          # 窗口和托盘图标生成
│   ├── settings.rs      # 设置面板
│   ├── tray.rs          # 系统托盘 + Win32 显示 / 隐藏 / 退出
│   ├── update_ui.rs     # 版本检查和自动更新 UI
│   └── users.rs         # 用户列表和用户卡片
├── path.rs              # 统一路径：C:\ProgramData\CampusNetClient\config.json / app.log
├── core/
│   ├── srun.rs          # srun 认证协议（async reqwest）
│   ├── xencode.rs       # x_encode 加密算法
│   └── utils.rs         # 网卡枚举
├── service/
│   ├── auth.rs          # 异步登录 / 登出 + 一键登录/登出
│   ├── config.rs        # 配置读写
│   ├── detection.rs     # 校园网 IP 检测 + 认证服务器探测 + 外网可达性检测
│   ├── http_client.rs   # 共享 reqwest::Client 构建器
│   ├── monitor.rs       # 后台监控 + 自动重连 + 指数退避
│   ├── online_info.rs   # rad_user_info 查询 + 在线状态同步 + 启动任务编排
│   ├── mod.rs           # AppState / SharedState / 状态枚举
│   ├── update.rs        # 版本更新检查 + 下载 + PowerShell 更新脚本
│   ├── update_scheduler.rs # 后台定时检查更新
│   └── user_ip.rs       # 用户 IP 解析优先级 helper
├── platform/
│   ├── autostart.rs     # Windows 注册表开机自启
│   └── secure_store.rs  # 密码 base64 编解码存储
└── ui/
    ├── mod.rs           # UI 公共工具（format_bytes 等）
    ├── l10n.rs          # 中英文 UI 文案
    └── log_panel.rs     # 日志面板渲染
```

## 技术栈

| 用途 | 依赖 |
|------|------|
| GUI | [egui](https://github.com/emilk/egui) 0.29 / [eframe](https://github.com/emilk/egui/tree/master/crates/eframe) |
| 系统托盘 | [tray-icon](https://github.com/tauri-apps/tray-icon) 0.17 |
| 异步运行时 | [tokio](https://tokio.rs/) (rt-multi-thread) |
| HTTP 客户端 | [reqwest](https://github.com/seanmonstar/reqwest) 0.12 (rustls-tls, no default features) |
| 序列化 | [serde](https://serde.rs/) + serde_json |
| 网卡枚举 | [if-addrs](https://github.com/sajuthy/if-addrs) 0.13 |
| 加密算法 | md-5 + sha-1 + base64（自实现 HMAC-MD5 + x_encode + SHA1） |
| 日志 | [tracing](https://github.com/tokio-rs/tracing) + tracing-subscriber |

## License

GPL-3.0
