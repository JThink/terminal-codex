# 仓库指南

## 项目结构与模块组织

本仓库是支持 macOS 与 Windows 的终端应用，基于 Tauri（前端静态页面 + Rust
后端）。主要目录如下：

- `src/`：前端页面与样式
- `src/index.html`：页面骨架，加载 xterm.js / addon-fit / split.js，本地静态资源入口
- `src/main.js`：标签页、分屏、快捷键、字体设置、窗口拖拽等核心交互逻辑
- `src/platform.mjs`：平台识别、默认快捷键、快捷键存储键和修饰键显示
- `src/platform.test.mjs`：使用 Node 内置测试运行器的平台纯函数测试
- `src/ssh-connections.mjs`：SSH Profile 搜索、表单 payload、LaunchSpec 与终端字节转换纯函数
- `src/ssh-connections.test.mjs`：使用 Node 内置测试运行器的前端 SSH 单元测试
- `src/styles.css`：深色主题、标签栏、分屏、快捷键弹窗与菜单样式
- `src/vendor/`：本地前端依赖（xterm.js、addon-fit.js、split.js 与 xterm.css）
- `docs/superpowers/specs/`：功能设计规格
- `docs/superpowers/plans/`：可执行实施计划与验证步骤
- `src-tauri/src/lib.rs`：PTY 会话、Tauri 命令与事件桥接逻辑
- `src-tauri/src/platform.rs`：Shell、OpenSSH、HOME、路径与进程平台适配
- `src-tauri/src/ssh/`：SSH 参数、本地 vault 凭据事务与 ASKPASS broker
- `src-tauri/vendor/portable-pty/`：`portable-pty 0.9.0` 与 Windows kill 上游补丁
- `src-tauri/tauri.conf.json`：平台公共窗口、安全与图标配置
- `src-tauri/tauri.macos.conf.json`：macOS Overlay 标题栏与 app/dmg 配置
- `src-tauri/tauri.windows.conf.json`：Windows 系统标题栏、NSIS 与 WebView2 配置
- `.github/workflows/cross-platform.yml`：macOS 与 Windows 原生测试和打包

## 构建、测试与开发命令

- `npm ci --ignore-scripts`：按 lockfile 安装 Tauri CLI
- `npm run tauri:dev`：启动当前平台桌面应用开发模式
- `npm run tauri:build`：构建当前平台发行包
- `npm run tauri:build:mac-arm64`：构建 macOS Apple Silicon app/dmg
- `npm run tauri:build:mac-x64`：构建 macOS Intel app/dmg
- `npm run tauri:build:windows`：在 Windows 构建 x64 NSIS 安装包
- `npm test`：运行全部前端纯函数测试
- `npm run check`：检查前端主脚本语法
- `cargo test --locked`（在 `src-tauri/` 下）：运行 Rust 单元测试
- `cargo clippy --locked --all-targets -- -D warnings`（在 `src-tauri/` 下）：严格 Rust 静态检查
- `PATH="$(brew --prefix llvm)/bin:$PATH" cargo check --locked --target x86_64-pc-windows-msvc --all-targets`（在 `src-tauri/` 下）：macOS 使用 Homebrew LLVM 检查 Windows 条件编译

## 编码风格与命名约定

- Rust：遵循 `rustfmt` 默认格式，错误信息使用中文描述
- 前端：函数职责清晰，命名简洁统一；页面类名采用 `kebab-case`
- 资源文件：第三方脚本放入 `src/vendor/`，保持与上游文件名一致
- vendored Rust 依赖：保留许可证，并在 `PATCHES.md` 记录版本、补丁来源与上游提交
- 平台逻辑：系统能力集中在 `platform.rs` 或 `platform.mjs`，业务代码避免散落平台判断

## 核心功能与交互

- 标签页：新建、关闭、重命名、克隆，右键菜单提供常用操作
- 分屏：单标签内左右分屏，拖拽分隔条调整比例，双击重置 50/50
- 快捷键：macOS 使用 Command 组合键，Windows 使用 Ctrl+Shift / Ctrl+Alt；均可自定义
- 字体：支持放大、缩小、重置，设置写入 localStorage 并应用到所有会话
- 窗口：macOS 使用 Overlay 和自定义红绿灯，Windows 使用系统标题栏
- SSH 连接：macOS `Command+E`、Windows `Ctrl+Shift+E` 打开连接中心，支持 Profile CRUD、搜索、测试、Agent/私钥/密码认证
- SSH 会话：支持标签克隆、左右分屏、恢复和断线重连，主界面不增加连接按钮

## 前后端通信与会话模型

- 前端通过 `invoke` 调用本地会话命令和 SSH Profile / 测试 / 启动命令
- 后端通过 `terminal-output` 推送 PTY 原始字节，并用 `terminal-exit` / `terminal-error` 报告生命周期事件
- `portable-pty` 在 macOS 使用 Unix PTY，在 Windows 使用 ConPTY
- macOS 使用 `$SHELL -l`；Windows 依次选择 `pwsh.exe`、`powershell.exe`、`ComSpec` 或 `cmd.exe`
- macOS 克隆读取现有进程的实时目录与环境；Windows 克隆使用保存的启动目录和环境快照
- macOS SSH 固定验证 `/usr/bin/ssh`；Windows 优先系统 OpenSSH，再从 `PATH` 查找
- 后端在 `setup` 中设置窗口背景色，并启用 `tauri-plugin-opener`

## 前端状态与交互细节

- 字号：`codex-terminal-font-size` 存本地，默认 15，范围 10-22
- macOS 快捷键沿用 `codex-terminal-hotkeys`；Windows 使用 `codex-terminal-hotkeys-windows-v1`
- 分屏实现：使用 CSS Grid + 自定义拖拽分隔条，不依赖 split.js 的运行时能力
- 终端实例：xterm.js + FitAddon，窗口尺寸变化或分屏拖拽会触发 `resize_session`
- 窗格启动状态：使用 `{ kind: "local", cwd }` 或 `{ kind: "ssh", profileId }`，旧 cwd 状态读取时自动迁移
- SSH Profile：写入应用配置目录的 `ssh-profiles.json`，密码不写入 JSON 或 localStorage

## SSH 凭据与 ASKPASS

- 密码使用 AES-256-GCM 加密写入 `ssh-secrets.vault`，随机密钥写入同目录的 `ssh-secrets.key`
- 应用不使用 macOS Keychain 或 Windows Credential Manager，因此不会触发系统密码框
- Unix 文件和目录收紧为当前用户权限；Windows 依赖当前用户 AppData 目录 ACL
- 本地 vault 防止明文落盘，但不抵御已取得当前用户文件读取权限的恶意程序
- ASKPASS 通过短期一次性 capability 返回密码，并校验应用、OpenSSH 和 helper 进程链
- macOS 使用 Unix socket；Windows 10 1809+ 使用 AF_UNIX 和 Win32 进程身份 API

## Tauri 配置要点

- `withGlobalTauri: true` 以便前端直接访问 `window.__TAURI__`
- 公共窗口默认 1100×720，`csp: null` 允许加载打包内的本地脚本资源
- macOS 平台配置生成 `.app` / `.dmg` 并使用 ad-hoc 签名
- Windows 平台配置生成 NSIS `.exe`，缺少 WebView2 时使用下载引导程序

## 测试指南

前端纯函数使用 Node 内置 `node:test`；Rust 测试位于对应模块的 `#[cfg(test)]` 中。
涉及 Unix socket、AF_UNIX 或本机 SSH 的测试在受限沙箱中可能需要额外系统权限，不能把
`Operation not permitted` 当作业务断言失败。macOS 本地的 Windows target 只能证明条件
编译，并需要先安装 Homebrew LLVM；Windows 原生 GitHub Actions 才能证明测试、Clippy
和 NSIS 打包。Windows 测试包含真实 ConPTY 输入、resize、输出和进程关闭冒烟用例。

## 提交与合并请求规范

目前无强制提交规范，建议使用简洁祈使句并带范围，例如 `feat: add split panes`、
`docs: update guide`。合并请求应包含变更摘要、运行说明，以及双平台测试结果或复现步骤。

## 运行与配置提示

应用默认启动当前平台 Shell，不会自动执行 `codex`。需要时请在终端内手动运行 `codex`；
若需改为其他默认命令，请同步更新前端提示与后端启动逻辑。Windows 运行 SSH 前必须在
“可选功能”中安装 OpenSSH Client。前端主题与背景色会同步设置到 Tauri 窗口背景。

## 代理更新说明

后续新增工具、脚本、平台配置或目录时，请同步更新本指南，并保持文档全部使用中文。
