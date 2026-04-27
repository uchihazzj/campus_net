# Campus Net Client

基于 [srun](https://github.com/zu1k/srun) 协议的 Windows 桌面校园网认证客户端。

## 功能

- 深澜 / srun 校园网认证：登录 / 登出，支持多用户
- 三层网络状态检测：校园 IP → 认证状态 → 互联网可达性
- 断网自动重连（连续确认后触发）
- 系统托盘，最小化到托盘
- 中 / English 语言切换
- 开机自启、严格绑定 IP、运营商选择
- **不使用 ping 检测网络**，全程 HTTP/HTTPS

## 截图

```
┌──────────────────────────────────────┐
│  校园网客户端                        │
│  服务器: [http://10.0.0.55_____]     │
├──────────────────────────────────────┤
│  校园IP: 10.x.x.x   认证: 已登录     │
│  互联网: 可访问      在线: 1/2       │
├──────────────────────────────────────┤
│  ┌ user1 ────────────────── 编辑 删除┐
│  │ ● 在线   用户: user1   IP: 10.x  │
│  └──────────────────────────────────┘│
│  ┌ user2 ───────────────── 编辑 删除 │
│  │ ○ 离线  用户: user2   IP: 自动检测│
│  └──────────────────────────────────┘│
│  [+ 添加用户]    [全部登录] [全部登出]│
├──────────────────────────────────────┤
│  ▼ 设置                             │
│  ▼ 日志                             │
│       github.com/uchihazzj/campus_net│
└──────────────────────────────────────┘
```

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
2. 在顶部输入校园网认证服务器地址，例如 `http://10.0.0.55`
3. 点击「添加用户」，填写用户名和密码
4. 点击「登录」

### 配置文件

程序会在运行目录自动生成 `config.json`，可以手动编辑或通过 GUI 管理。

```json
{
  "server": "http://10.0.0.55",
  "acid": 8,
  "n": 200,
  "type": 1,
  "os": "Windows 10",
  "name": "Windows",
  "language": "zh",
  "auto_reconnect": false,
  "minimize_to_tray": true,
  "users": [
    {
      "username": "your_account",
      "encrypted_password": "...",
      "ip": null,
      "if_name": null
    }
  ]
}
```

- IP 留空则自动检测
- 多网卡拨号可填写 `if_name`（网卡名），或使用 `--select-ip` 查看可用网卡
- 运营商选择：在用户名末尾添加 `@cmcc`（移动）、`@unicom`（联通）、`@chinanet`（电信）

## 网络检测机制

三层检测，**不使用 ICMP ping**，适配 Clash TUN mode 等代理环境：

| 层 | 检测方式 | 说明 |
|------|------|------|
| Campus IP | 枚举本机 IPv4，匹配 `10.*.*.*` | 识别校园网接口 |
| Campus Auth | HTTP GET baidu.com，禁用自动跳转 | 被 portal 劫持重定向 = 未登录 |
| Internet | 多 URL 串行检测（HTTPS baidu / Cloudflare / 204 端点），body 长度验证，连续 3 次失败才判定离线 | 避免瞬断误报 |

## 技术栈

- GUI：[egui](https://github.com/emilk/egui) / [eframe](https://github.com/emilk/egui/tree/master/crates/eframe)
- 系统托盘：[tray-icon](https://github.com/tauri-apps/tray-icon)
- 异步运行时：[tokio](https://tokio.rs/)
- HTTP：[reqwest](https://github.com/seanmonstar/reqwest)（rustls-tls）
- srun 认证协议：自实现 HMAC-MD5 + x_encode + SHA1

## 项目结构

```
src/
├── main.rs              # 入口：tokio runtime + eframe + CJK 字体加载
├── app.rs               # GUI + 系统托盘 + 用户管理
├── core/
│   ├── srun.rs          # srun 认证协议（async reqwest）
│   ├── xencode.rs       # x_encode 加密算法
│   └── utils.rs         # IP 枚举 + TCP ping
├── service/
│   ├── auth.rs          # 异步登录 / 登出
│   ├── config.rs        # 配置读写
│   ├── detection.rs     # 三层网络检测
│   └── monitor.rs       # 后台监控 + 自动重连
├── platform/
│   ├── autostart.rs     # Windows 注册表开机自启
│   └── secure_store.rs  # 密码存储
└── ui/
    └── l10n.rs          # 中英文 UI 文本
```

## License

GPL-3.0
