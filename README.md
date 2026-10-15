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

登录、登出及自动重连共享同一个操作锁。操作期间，账号编辑、删除和认证设置暂时禁用，避免请求完成后写到其他账号。手动登出从操作开始就抑制自动重连；再次手动登录可解除抑制。旧的状态查询结果不会覆盖后续认证操作。

`v1.1.12` 中，状态刷新进行时会显示加载标记并合并重复请求。只有服务器明确返回 `not_online` 或 `not_online_error` 才按离线处理；不完整或未知响应按查询失败处理，支持 UTF-8 / GBK 响应。过期数据不再显示“服务器已确认”。修改服务器或相关账号后，旧会话信息会失效，等待下一次状态确认。

登录成功后会清除登录前的离线判断，避免等待确认时重复重连。自动重连在实际执行前再次检查当前状态，启动重连和后台探测的旧结果也会在手动操作后失效。登出失败会显示错误并保留重试入口，继续抑制自动重连。

## v1.1.13 维护修复

- 一键登录在服务器已确认在线或登录仍等待确认时保留当前会话，避免重复认证；相同用户名的多个本地条目按歧义处理，不再自动确认第一个条目。
- 状态查询优先保留绑定网卡上仍有效的会话 IPv4；DHCP 地址变化时不再永久绑定旧会话 IP，旧地址转移到其它网卡也不会覆盖原网卡绑定。同一网卡有多个 IPv4 时仍可按完整或唯一部分名称匹配。迟到结果仍需通过认证、查询代次和校园 IP 检查。服务器确认离线时保留原在线账号作为优先重连目标，手动登出的抑制仍生效。
- 配置及备份使用每次写入独占的临时文件，避免多个进程共享临时文件而损坏 JSON；失败时只清理本次文件。支持带 UTF-8 BOM 的主配置和备份。
- 修改其它设置不再覆盖自动启动失败后的回滚结果。自动更新检查与手动检查的认领在同一锁内完成，忙碌跳过不会把失败重试延后至 24 小时。
- 状态响应格式异常时不将响应正文写入日志；日志面板减少一次不必要的整段文本复制。
- 冷启动查询优先使用首个待登录账号的绑定网卡或有效静态 IP；可选外网探测也沿用状态查询的 IP 选择规则。外网可达不再清除校园认证的重连目标，普通网站的 `login/redirect/portal` 链接不再误报校园门户。未绑定请求的结果不作为校园 IPv4 登录状态依据；关闭探测后，缓存的降级“未登录”判断不再触发重连。

## 窗口与托盘

关闭窗口默认隐藏到托盘；托盘左键单击、双击或右键菜单“显示窗口”可再次打开。显示、隐藏指令由 UI 线程统一处理，恢复最小化窗口时保留原有最大化状态；托盘不可用时关闭窗口会正常退出。

从 `v1.1.12` 开始，窗口最小尺寸为 420 × 280，异常的已保存尺寸（例如极小、非有限数值或超大尺寸）自动回退为 520 × 350。只记忆普通窗口的有效尺寸，隐藏、最小化和最大化不会覆盖该尺寸。旧配置中的异常尺寸无需手工修改。

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

从 `v1.1.11` 开始，主配置丢失但备份存在时也会恢复备份，并优先于旧目录迁移。界面修改在后台合并保存，正常退出和自动更新前会再保存最新配置。配置中缺少默认字段时，补写失败不会丢弃已成功读取的账号和设置。

旧版本曾经放在 exe 同目录的 `config.json` 会在启动时迁移到 `C:\ProgramData\CampusNetClient\`。

配置示例：

```json
{
  "server": "http://10.0.0.55",
  "detect_ip": false,
  "strict_bind": false,
  "double_stack": false,
  "n": 200,
  "utype": 1,
  "acid": 8,
  "retry_delay": 1000,
  "auto_reconnect": true,
  "enable_ipv4_internet_probe": false,
  "monitor_interval_secs": 30,
  "language": "zh",
  "users": []
}
```

常用配置项：

| 字段 | 说明 |
| --- | --- |
| `server` | 校园网认证服务器地址 |
| `acid` | Srun 区域或接入点参数 |
| `n` | Srun 登录参数，常见值为 `200` |
| `utype` | Srun 登录类型参数；读取旧配置时兼容 `type` |
| `double_stack` | 是否启用双栈参数 |
| `detect_ip` | 是否通过认证服务器辅助识别客户端 IP，默认关闭 |
| `enable_ipv4_internet_probe` | 是否执行 IPv4 外网连通性探测，默认关闭 |
| `strict_bind` | 是否严格要求绑定网卡可用 |
| `auto_reconnect` | 是否启用自动重连 |
| `monitor_interval_secs` | 状态检查间隔，默认 30 秒 |
| `language` | `zh` 或 `en` |

当前密码字段只使用 Base64 编码，可被还原，不属于加密保护。配置及备份都包含这些字段，存储目录位于机器级 ProgramData；不要把真实 `config.json`、备份、日志、截图或账号信息提交到仓库或发给他人。改用 Windows 凭据保护及用户独立目录时，需要兼容旧配置后再迁移。

## 网卡与 IP 选择

登录或登出时，客户端按以下顺序选择客户端 IP：

1. 优先使用用户绑定的网卡名称，并解析该网卡当前 IPv4 地址。
2. 如果没有绑定网卡，则使用用户配置中的 `ip`。
3. 如果仍不可用，则尝试当前检测到的校园网 IPv4 地址，例如 `10.x.x.x`。

推荐绑定网卡名称，而不是手动写死 IP。校园网 DHCP 可能更换 IP，网卡名称通常更稳定。

## 启动、状态检查与 Clash TUN

默认 `auto_start=true`、`auto_reconnect=true`。启动会先检测网卡并查询 `rad_user_info`，只有服务器明确报告未登录才按账号顺序自动尝试登录；已在线、等待确认或状态未知时保留当前会话并等待下一次检查。开机自启与手动启动共用这条流程。手动登出的重连抑制在当前进程内生效。

`rad_user_info` 是权威依据。查询前两次失败时等待，不把超时、格式异常或外网不通当成校园掉线。连续失败至少三次后才进入可选降级判断；外网探测默认关闭，关闭时不会向外网探测地址发请求，也不会使用旧的外网探测结果触发重连。服务器明确确认在线时，即使外网探测失败，也只提示路由问题。

启用外网探测后，源 IP 优先取当前会话或重连目标的网卡绑定；外网可达不会改变校园账号状态或清除重连目标。门户重定向必须指向配置的认证服务器主机，或包含明确的 Srun 路径/参数。绑定失败后的未绑定回退可能经过 TUN、IPv6 或其它网卡，其成功和门户结果均归为 `ProbeFailed`，不据此触发重连。认证状态探测没有有效 IPv4 绑定时直接保持 `Unknown`。

`no_proxy()` 禁用 HTTP 代理，`local_address` 设置源 IP，二者都不修改 Windows 路由，不能保证绕过 Clash TUN。`strict_bind` 默认仍为 `false`，因此账号网卡绑定默认用于选择 Srun 协议中的 IP，认证连接是否绑定源 IP 由该设置控制；状态查询会使用源 IPv4 绑定。程序不会自动关闭 Clash/TUN 或改写系统路由。常见虚拟网卡通过名称及地址筛选，但任意自定义网卡名无法保证被识别，推荐明确绑定实际校园网网卡。

相关行为说明：[reqwest 源 IP 绑定与代理设置](https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html#method.local_address)、[Mihomo TUN 自动路由](https://wiki.metacubex.one/config/inbound/tun/#auto-route)。

## 更新说明

程序会在启动时检查 GitHub 最新 Release，并在发现新版本后显示更新按钮。发布新版本时需要保持这些约定：

- tag 使用 `vX.Y.Z` 格式。
- Release 资产名必须精确为 `campus-net-client.exe`。
- 自动更新需要当前 exe 所在目录可写。

更新时，程序会下载新的 exe，保存配置，生成 PowerShell 替换脚本，退出当前进程，替换旧 exe，然后启动新版本。

`v1.1.11` 会在退出前检查下载文件大小和 PE 文件头，并确认配置保存成功。替换脚本使用实际运行的 exe 路径，支持文件改名，只等待发起更新的进程退出。旧程序备份会保留至新程序通过短暂启动检查；替换或启动失败时尝试恢复旧程序。`updater.log` 会留在 exe 目录供排错，普通启动不再删除 `.exe.bak`。

GitHub 检查先直连，失败后尝试环境变量代理；下载先尝试环境变量代理，再回退直连。当前依赖配置不读取 Windows 系统代理设置。若仍无法访问，可以从 Release 页面手动下载。启动检查失败后按 1、5、15 分钟及后续每 30 分钟重试；正常检查间隔为 24 小时。

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
| 启动后看不到主窗口、只有极小窗口 | 使用 `v1.1.12` 或更新版本，启动时会自动恢复异常窗口尺寸；通过托盘“显示窗口”唤出 |
| 登出失败 | 查看界面错误；保留原账号状态及登出按钮，可直接重试 |
| 自动更新失败 | 确认 exe 目录可写，并且能访问 GitHub Releases |
| 更新替换或重启失败 | 查看 exe 目录的 `updater.log`，保留 `.exe.bak` 以便恢复 |
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

如果当前客户端正从默认构建目录运行，构建时可附加 `--target-dir target/review-build`，将新 exe 输出到独立目录，避免覆盖正在运行的文件。构建完成后不必立即启动或替换现有客户端。

发布前验证（依赖已经缓存时可附加 `--offline`）：

```powershell
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
cargo build --release --locked
```

默认测试不发起真实校园网或外网探测；三个需要实际网络的测试标记为 `ignored`。需要联调时，仅在允许进行探测的环境中单独运行相应测试。

发布新版本时，先同步 `Cargo.toml` 与 `Cargo.lock` 中的应用版本，提交并推送源码，再为该提交创建对应的 `vX.Y.Z` tag。按照历史 Release 的约定，将上述 Windows 构建产物以 `campus-net-client.exe` 为资产名上传，并在发布说明中记录修复内容和验证结果。Release、tag 和应用内版本号必须一致。

## 已知限制

- 主要支持 Windows。
- 不同学校的 Srun / 深澜部署可能不同，`server`、`acid`、`n`、`type` 可能需要按学校实际情况调整。
- 自动更新依赖 GitHub Releases 和固定资产名，目前不做 SHA256 或签名校验。
- 自动更新在创建 PowerShell 进程后退出，尚未等待脚本就绪确认；脚本未能启动执行时需要手动重启客户端。后续可加入交接确认，失败时保留当前进程。
- 尚无单实例保护。多个客户端进程会各自监控和重连；独占临时文件能避免配置混写，但多个实例修改配置仍采用最后一次完整写入的结果。
- IPv4 外网探测不替代 `rad_user_info` 权威查询，仅在状态同步持续失败时作为可选的降级判断依据，默认关闭。
- 账号匹配优先使用 `rad_user_info.user_name` 唯一精确匹配；重复精确匹配按歧义处理，去后缀匹配也只在能唯一对应本地账号时使用。

## License

Apache License 2.0
