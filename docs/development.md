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

配置、日志、缓存、诊断和发布二进制属于运行产物，不提交真实账号或凭据。协议兼容点包括 `get_challenge`、`srun_portal`、`rad_user_info?callback=sdu`，以及学校相关的 `acid`、`n`、`type`、`double_stack` 参数。

## 发布流程

1. 同步 `Cargo.toml` 与 `Cargo.lock` 中的应用版本。
2. 完成离线检查、测试、代码审查，并在独立目录构建 Windows exe。
3. 提交并推送源码，为对应提交创建 `vX.Y.Z` 标签。
4. 在 GitHub Release 中记录本次变更、验证方法及已知限制，上传构建产物。
5. 核对源提交、标签、应用版本及上传文件一致后发布。

自动更新要求资产名精确为 **`campus-net-client.exe`**。发布时核对文件大小及 SHA-256；客户端当前没有自动进行 SHA-256 或签名校验。

逐版本变更统一维护在 [GitHub Releases](https://github.com/uchihazzj/campus_net/releases)，README 保留当前使用说明。仅修改文档时，更新仓库页面即可，无需增加应用版本或重新发布同一份安装包。
