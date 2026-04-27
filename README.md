# Campus Net Client

基于 srun 协议的 Windows 桌面校园网认证客户端。

## 功能

- **深澜 / srun 校园网认证**：登录 / 登出，支持多用户管理
- **四层网络状态检测（仅 IPv4）**：
  - Layer 1 — 校园网 IPv4 检测：枚举 `10.*.*.*` 地址
  - Layer 2 — 认证服务器可达性：检测 srun 认证服务器是否响应
  - Layer 3 — 认证状态检测：通过 HTTP 重定向判断是否已登录
  - Layer 4 — IPv4 外网可达性：多端点 HTTP/HTTPS 检测，强制绑定 IPv4
- **IPv4-only 检测**：所有网络检测通过 `local_address` 绑定到校园网 IPv4 地址，避免 IPv6 可访问导致的误判
- **断网自动重连**：连续确认后触发，支持指数退避
- **系统托盘**：最小化到托盘，右键菜单快捷操作
- **中 / English 语言切换**
- **开机自启**：Windows 注册表 Run 键
- **严格绑定 IP**：将出站连接绑定到指定 IP 地址
- **运营商选择**：用户名后缀 `@cmcc` / `@unicom` / `@chinanet`
- **窗口大小记忆**：关闭时保存窗口尺寸
- **无控制台窗口**：`#![windows_subsystem = "windows"]`

## 截图

```
┌──────────────────────────────────────────────────┐
│  校园网客户端                                     │
│  服务器: [http://10.0.0.55_______________]        │
├──────────────────────────────────────────────────┤
│  校园网 IPv4: 10.x.x.x  IPv4 外网: 可访问          │
├──────────────────────────────────────────────────┤
│  ┌ user1 ───────────────────────── 编辑 删除     │
│  │ ● 在线   用户: user1   IP: 10.x.x.x           │
│  └───────────────────────────────────────────────┘│
│  ┌ user2 ─────────────────────────── 编辑 删除   │
│  │ ○ 离线  用户: user2   IP: 自动检测            │
│  └───────────────────────────────────────────────┘│
│  [+ 添加用户]    [一键登录] [一键登出]             │
├──────────────────────────────────────────────────┤
│  ▼ 设置                                          │
│  ▼ 日志                                          │
│       github.com/uchihazzj/campus_net             │
└──────────────────────────────────────────────────┘
```

## 网络检测机制

软件采用四层检测，**全程仅使用 IPv4 HTTP/HTTPS，不使用 ICMP ping**，适配 Clash TUN mode、双栈网络等环境。

### 检测前提

在笔者的校园网环境中，未完成校园网认证时 **IPv6 仍然可以正常访问外网**，只有 IPv4 访问外网需要认证。因此本软件的网络检测必须满足：

- 不能因为 IPv6 可达就显示"互联网正常"
- 必须强制使用 IPv4 进行所有外网可达性检测
- 校园网认证状态必须独立判断，不能用公网可达性替代

### 四层检测详解

| 层级 | 检测内容 | 检测方式 | 说明 |
|------|---------|---------|------|
| **Layer 1** | 校园网 IPv4 | 枚举所有 IPv4 地址，匹配 `10.*.*.*` | 未检测到 10 段 IP 时停止后续检测和自动重连 |
| **Layer 2** | 认证服务器 | HTTP GET `{server}/cgi-bin/get_challenge` | 任何 HTTP 响应 = Reachable；连接失败 = Unreachable |
| **Layer 3** | 校园网认证 | HTTP GET `baidu.com`，禁用自动跳转 | 被 portal 劫持重定向 → Not logged in |
| **Layer 4** | IPv4 外网 | 多 URL 串行检测，强制绑定校园网 IPv4 | 连续失败 2 次才判定 Unreachable |

### IPv4 强制绑定

Layer 2、Layer 3 和 Layer 4 的 HTTP 客户端通过 `reqwest::ClientBuilder::local_address()` 绑定到检测到的校园网 IPv4 地址（即 `10.*.*.*`），确保：

- HTTP 流量走 IPv4 而不是 IPv6
- 流量走校园网物理接口而不是 TUN 虚拟接口
- DNS 解析结果自动过滤 IPv6 地址（因为 IPv4 socket 无法连接 IPv6 地址）

同时启用 `no_proxy()` 避免应用层 HTTP 代理干扰。

### Layer 2 — 认证服务器可达性检测

向认证服务器的 `/cgi-bin/get_challenge` 发起 HTTP GET 请求：

| 响应 | 判断 |
|------|------|
| 任何 HTTP 响应（200 / 4xx / 5xx） | `Reachable` |
| 连接失败 / 超时 | `Unreachable` |

### Layer 3 — 认证状态检测

向 `http://www.baidu.com` 发起 HTTP GET 请求，不跟随重定向：

| 响应 | 判断 |
|------|------|
| 200 OK | `Logged in` |
| 30x 重定向到 portal（含 `srun_portal` / `ac_id=` / `wlanuserip` 等） | `Not logged in` |
| 30x 重定向到非 portal URL（如 http→https 升级） | `Logged in` |
| 连接失败 / 超时 | `Unknown` |

### Layer 4 — IPv4 外网可达性检测

先绑定校园网 IPv4 探测，全部失败后执行 unbound fallback：

| 检测 URL | 成功条件 |
|----------|---------|
| `http://www.baidu.com` | 200 且 body ≥ 1000 字节 |
| `http://connect.rom.miui.com/generate_204` | 204 No Content |
| `http://www.msftconnecttest.com/connecttest.txt` | 200 OK |
| `http://cp.cloudflare.com/` | 200 OK |

**Bound probe**：HTTP 客户端绑定校园网 IPv4，任意端点成功 → `Reachable`，portal 重定向 → `CaptivePortal`，全部失败 → 进入 fallback。

**Unbound fallback**：仅信任 `CaptivePortal`（portal 重定向在任何 IP 协议上都是真实的）。若 unbound 返回 `Reachable`，视为 `ProbeFailed`——因为无法确认是否经由 IPv6 到达，避免误报。

连续 2 次确认后更新 UI 状态。

### 自动重连逻辑

- 检测间隔：默认 **30 秒**，通过 UI 可配置范围 15–300 秒
- 无校园网 IPv4 时：**不自动重连**
- 触发条件（任一满足且连续 2 次确认）：
  - `IPv4 Internet` 为 `CaptivePortal`（IPv4 被门户劫持）
  - `Campus Auth` 为 `NotLoggedIn`（认证已丢失）
  - `LoggedIn` 但 `IPv4 Internet` 为 `Unreachable`（已登录但外网不通）
- 重连目标：首次检测到问题时快照所有 Online 用户；若没有 Online 用户则重连全部配置的用户
- 重连失败后采用**指数退避**：从当前检测间隔开始翻倍，最大 300s
- 重连成功后重置为当前检测间隔，清空重连目标

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
3. 点击「添加用户」，填写用户名和密码
4. 点击「登录」

### 配置文件

程序运行目录自动生成 `config.json`，可通过 GUI 或手动编辑。

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
  "language": "zh",
  "users": [
    {
      "username": "your_account",
      "encrypted_password": "base64...",
      "ip": null,
      "if_name": null
    }
  ]
}
```

### 配置项说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server` | string | `http://10.0.0.55` | 认证服务器地址，**不是你本机的 IP** |
| `detect_ip` | bool | `false` | 登录时自动检测 IP（通过 get_challenge 接口） |
| `strict_bind` | bool | `false` | 将出站连接绑定到用户配置的 IP |
| `double_stack` | bool | `false` | 启用 IPv4 + IPv6 双栈 |
| `n` | int | `200` | srun 认证参数 |
| `type` | int | `1` | srun 认证类型 |
| `acid` | int | `8` | srun 认证域 ID |
| `os` | string | `Windows 10` | 上报给认证服务器的 OS 标识 |
| `name` | string | `Windows` | 上报给认证服务器的设备名 |
| `retry_delay` | int | `1000` | 登录重试间隔（毫秒） |
| `retry_times` | int | `3` | 登录重试次数 |
| `monitor_interval_secs` | int | `30` | 网络检测间隔（秒），范围 15–300，通过 UI 设置面板调整 |
| `auto_reconnect` | bool | `true` | 断网自动重连 |
| `minimize_to_tray` | bool | `true` | 关闭窗口时最小化到托盘 |
| `auto_start` | bool | `true` | 开机自启 |
| `language` | string | `zh` | 语言：`zh` 中文 / `en` English |
| `window_width` | float | — | 上次窗口宽度（自动保存） |
| `window_height` | float | — | 上次窗口高度（自动保存） |

### 用户配置

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | 校园网账号 |
| `encrypted_password` | string | 密码（base64 编码存储） |
| `ip` | string \| null | 静态 IP，留空则自动检测 |
| `if_name` | string \| null | 指定网卡名（如 `Ethernet0`），用于多网卡环境 |

### 运营商选择

在用户名末尾添加运营商后缀：

- 移动：`username@cmcc`
- 联通：`username@unicom`
- 电信：`username@chinanet`

## 项目结构

```
src/
├── main.rs              # 入口：tokio runtime + eframe + CJK 字体加载
├── app.rs               # GUI 渲染 + 系统托盘 + 用户增删改
├── core/
│   ├── srun.rs          # srun 认证协议（async reqwest）
│   ├── xencode.rs       # x_encode 加密算法
│   └── utils.rs         # 网卡枚举
├── service/
│   ├── auth.rs          # 异步登录 / 登出
│   ├── config.rs        # 配置读写
│   ├── detection.rs     # 四层网络检测（IPv4-only）
│   ├── monitor.rs       # 后台监控 + 自动重连 + 指数退避
│   └── mod.rs           # AppState / SharedState / 状态枚举
├── platform/
│   ├── autostart.rs     # Windows 注册表开机自启
│   └── secure_store.rs  # 密码 base64 编解码
└── ui/
    └── l10n.rs          # 中英文 UI 文案
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
| 加密算法（自实现） | md-5 + sha-1 + base64 |
| 日志 | [tracing](https://github.com/tokio-rs/tracing) + tracing-subscriber |
| srun 协议 | 自实现：HMAC-MD5 + x_encode + SHA1 |

## License

GPL-3.0
