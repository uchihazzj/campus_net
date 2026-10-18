# 开发与发布

[返回首页](../README.md)

## 构建环境

- Windows x64。
- Rust MSVC 工具链。
- Visual Studio 2022 Build Tools，安装 C++ build tools。

项目使用 Rust、eframe/egui 和 Tokio。构建时保留锁定依赖：

```powershell
cargo build --release --locked --target-dir target/build
```

输出为 `target\build\release\campus-net-client.exe`。独立输出目录可避免覆盖正从其他构建目录运行的客户端；构建完成不需要启动程序。

也可使用仓库根目录的 `build-release.ps1`，其默认输出为 `target\release\campus-net-client.exe`；使用前确认该路径没有正在运行的客户端。

`-Clean` 只清理脚本所在项目的绝对 `target` 路径，与调用时所在目录无关；遇到链接目录会停止，避免误删其他位置的文件。

## 验证

```powershell
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

依赖已缓存时，可为 Cargo 的检查、测试及构建命令添加 `--offline`。默认测试不发起真实校园网或外网探测，需要实际网络的测试标记为 `ignored`。只有在明确允许真实网络测试的环境中，才单独运行它们。

UI 预览测试使用合成账号、IP 和内存状态，不调用原生客户端构造函数，不触发认证、自启或更新。设置 `CNET_UI_PREVIEW_DIR` 为 `target` 下目录后，可导出渲染用纹理与三角形 JSON：

```powershell
$env:CNET_UI_PREVIEW_DIR = Join-Path (Get-Location) 'target/ui-preview'
try {
    cargo test --locked --offline app::preview_tests
} finally {
    Remove-Item Env:CNET_UI_PREVIEW_DIR
}
```

## 维护约定

UI 渲染线程不执行网络、文件或慢速网卡查询；不要持有共享状态锁跨越 `.await` 或慢速操作。后台状态变更后请求重绘，迟到结果需要校验认证和查询上下文。

托盘显示请求通过私有 Windows 消息交给 UI 线程，在绘制前校验实际客户区尺寸，避免窗口客户区为零时只依赖重绘。主窗口句柄直接从 eframe 获取，不按标题枚举桌面窗口。为安装消息钩子，Windows 目标显式引用 eframe 已使用的同一版本 winit，不增加新的依赖包或版本。消息钩子读取配置使用 `try_lock`，竞争或锁异常时使用默认尺寸，并通过原生失效区域请求重绘。

尺寸修复使用窗口自己的 DPI，并通过 [AdjustWindowRectExForDpi](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-adjustwindowrectexfordpi) 计算包含边框的大小；只在实际最小化时调用 `SW_RESTORE`，防止普通显示操作取消最大化。最大化时单独校验 `WINDOWPLACEMENT` 的普通恢复尺寸，修复异常值时保留位置、可见性和最大化状态。egui 显示命令同时保留退出优先、显示优先于旧关闭事件的规则。离线测试覆盖零尺寸、缩放和窗口状态，并创建始终隐藏的临时 Win32 窗口验证普通及最大化时的恢复尺寸，不枚举或操作正在运行的客户端。

监控的 Healthy 收尾与请求结果一样，需要同锁核对认证代次、查询代次和当前状态，再清理重连目标。认证 HTTP 客户端保留正常重定向兼容，但关闭 [reqwest 自动 Referer](https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html#method.referer)，避免把原登录 URL 中的凭据派生参数传给重定向目标。更新进入准备重启阶段，与认证及诊断的开始共用 AppState 锁互斥；下载阶段不阻止认证。

账号在线 IP 的实现位于 `src/service/online_sessions/` 及同名模块，独立于校园网认证与重连。使用 [scraper 0.24 的 HTML 解析与选择器](https://docs.rs/scraper/0.24.0/scraper/) 识别服务端表格，并为各账号创建独立的 [reqwest 0.12 内存 Cookie 存储](https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html#method.cookie_store)；这也是增加 HTML 解析依赖、启用现有 HTTP 库 Cookie 功能的原因。测试注入合成响应，不访问真实服务或读取运行配置。

手动诊断位于 `src/service/diagnostics/` 及同名模块，只由设置按钮启动。默认只读模式复用自服务的请求白名单和解析器，不调用认证或恢复函数。显式完整测试由 `functional.rs` 协调，通过 `auth::DiagnosticSession` 整轮占用现有认证操作锁，复用真实登录、登出、恢复和重连判定代码；预检保存可恢复的会话身份，再测试并在退出路径上尝试恢复。网络步骤通过 [Tokio select 的取消语义](https://docs.rs/tokio/1/tokio/macro.select.html#cancellation-safety) 丢弃未完成请求，恢复步骤有独立预算且不响应测试取消，恢复任务自身异常也按恢复失败处理。完整模式认证期间不等待磁盘：先完成恢复尝试并释放认证锁，再后台保存；只读模式逐项保存。每次写入独占临时文件，提交时校验原子运行序号，避免迟到写入覆盖新报告。认证事件只在完整测试内采集受控分类与数字代码，不复制原始错误或运行日志。测试注入合成后端、认证回调及临时报告路径，覆盖取消、超时、上下文变化、任务异常、恢复失败、磁盘等待不阻塞恢复、迟到写入和脱敏，不运行真实网络或认证测试。

配置、日志、缓存、诊断和发布二进制属于运行产物，不提交真实账号或凭据。协议兼容点包括 `get_challenge`、`srun_portal`、`rad_user_info?callback=sdu`，以及学校相关的 `acid`、`n`、`type`、`double_stack` 参数。

## 发布流程

1. 同步 `Cargo.toml` 与 `Cargo.lock` 中的应用版本。
2. 完成离线检查、测试、代码审查，并在独立目录构建 Windows exe。
3. 提交并推送源码，为对应提交创建 `vX.Y.Z` 标签。
4. 在 GitHub Release 中记录本次变更、验证方法及已知限制，上传构建产物。
5. 核对源提交、标签、应用版本及上传文件一致后发布。

自动更新要求资产名精确为 **`campus-net-client.exe`**。发布时核对文件大小及 SHA-256；客户端当前没有自动进行 SHA-256 或签名校验。

逐版本变更统一维护在 [GitHub Releases](https://github.com/uchihazzj/campus_net/releases)，README 保留当前使用说明。仅修改文档时，更新仓库页面即可，无需增加应用版本或重新发布同一份安装包。
