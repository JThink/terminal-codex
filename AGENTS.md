# 仓库指南

## 项目结构与模块组织

本仓库是面向 macOS 的终端原型，基于 Tauri（前端静态页面 + Rust 后端）。主要目录如下：

- `src/`：前端页面与样式
- `src/index.html`：页面骨架，加载 xterm.js / addon-fit / split.js，本地静态资源入口
- `src/main.js`：标签页、分屏、快捷键、字体设置、窗口拖拽等核心交互逻辑
- `src/ssh-connections.mjs`：SSH Profile 搜索、表单 payload、LaunchSpec 与终端字节转换纯函数
- `src/ssh-connections.test.mjs`：使用 Node 内置测试运行器的前端 SSH 单元测试
- `src/styles.css`：深色主题样式、标签栏、分屏拖拽条、快捷键弹窗与菜单样式
- `src/vendor/`：本地前端依赖（xterm.js、addon-fit.js、split.js 与 xterm.css）
- `docs/superpowers/specs/`：功能设计规格
- `docs/superpowers/plans/`：可执行实施计划与验证步骤
- `src-tauri/`：Tauri 后端与配置
- `src-tauri/src/lib.rs`：PTY 会话与事件桥接逻辑
- `src-tauri/src/ssh/`：SSH 参数、Keychain 凭据事务与 ASKPASS broker
- `src-tauri/src/main.rs`：桌面入口，调用 `tauri_app_lib::run()`
- `src-tauri/tauri.conf.json`：窗口标题/尺寸、macOS Overlay 标题栏、图标等配置

## 构建、测试与开发命令

- `npm install`：安装前端依赖并准备本地资源
- `npm run tauri dev`：启动桌面应用开发模式
- `npm run tauri build`：构建桌面应用发行版本
- `cargo build`（在 `src-tauri/` 下）：仅编译 Rust 后端
- `node --test src/ssh-connections.test.mjs`：运行前端 SSH 纯函数测试
- `node --check src/main.js`：检查前端主脚本语法
- `cargo test --locked`（在 `src-tauri/` 下）：运行 Rust 单元测试
- `cargo clippy --locked --all-targets -- -D warnings`（在 `src-tauri/` 下）：执行严格 Rust 静态检查

## 编码风格与命名约定

- Rust：遵循 `rustfmt` 默认格式，错误信息使用中文描述
- 前端：函数职责清晰，命名简洁统一；页面类名采用 `kebab-case`
- 资源文件：第三方脚本放入 `src/vendor/`，保持与上游文件名一致

## 核心功能与交互

- 标签页：新建/关闭/重命名/克隆，右键菜单提供常用操作
- 分屏：单标签内左右分屏，拖拽中间分隔条调整比例，双击分隔条重置 50/50
- 快捷键：内置默认组合键，可在“快捷键设置”弹窗中自定义并持久化到本地存储
- 字体：支持放大/缩小/重置字号，设置写入本地存储并应用到所有会话
- 窗口：标签栏支持拖拽移动窗口，双击空白区域切换最大化，并同步设置窗口背景色避免闪烁
- 右键菜单：自定义 DOM 菜单，包含分屏、字体与快捷键入口，点击外部自动关闭
- SSH 连接：`Command+E` 打开连接中心，支持 Profile CRUD、搜索、测试、Agent/私钥/密码认证
- SSH 会话：支持标签克隆、左右分屏、恢复和断线重连，主界面不增加连接按钮

## 前后端通信与会话模型

- 前端通过 `invoke` 调用本地会话命令和 `list_ssh_profiles` / `save_ssh_profile` / `delete_ssh_profile` / `test_ssh_profile` / `start_ssh_session`
- 后端通过 `terminal-output` 推送 PTY 原始字节，并用 `terminal-exit` / `terminal-error` 报告生命周期事件
- Rust 端维护会话表与计数器，基于 `portable-pty` 启动登录 Shell（`-l`）并在独立线程读取输出
- 会话启动时优先使用克隆出的 `SHELL`，否则读取系统 `SHELL`，并设置 `PWD`
- 克隆会话在 macOS 上读取现有进程的工作目录与环境变量；非 macOS 平台会返回不支持的错误信息
- 后端在 `setup` 中设置窗口背景色，并启用 `tauri-plugin-opener`

## 前端状态与交互细节

- 字号：`codex-terminal-font-size` 存本地，默认 15，范围 10-22
- 快捷键：`codex-terminal-hotkeys` 存本地，弹窗内捕获组合键，Esc 取消、Delete 清空
- 分屏实现：使用 CSS Grid + 自定义拖拽分隔条，不依赖 split.js 的运行时能力
- 终端实例：xterm.js + FitAddon，窗口尺寸变化或分屏拖拽会触发 `resize_session`
- 窗格启动状态：使用 `{ kind: "local", cwd }` 或 `{ kind: "ssh", profileId }`，旧 cwd 状态读取时自动迁移
- SSH Profile：写入应用配置目录的 `ssh-profiles.json`；密码只进入 macOS Keychain 的随机 revision account，Profile UUID account 仅保存无秘密指针，不写入 JSON 或 localStorage

## Tauri 配置要点

- `withGlobalTauri: true` 以便前端直接访问 `window.__TAURI__`
- macOS 使用 Overlay 标题栏并自定义红绿灯位置；窗口默认 1100×720
- `csp: null` 允许加载本地脚本资源

## 测试指南

前端 SSH 纯函数使用 Node 内置 `node:test`；Rust 测试位于对应模块的 `#[cfg(test)]` 中。涉及
Keychain、Unix socket 或本机 SSH 的测试在受限沙箱中可能需要额外系统权限，不能把
`Operation not permitted` 当作业务断言失败。

## 提交与合并请求规范

目前无强制提交规范，建议使用简洁祈使句并带范围，例如 `feat: add split panes`、`docs: update guide`。合并请求应包含变更摘要、运行说明，以及测试结果或复现步骤。

## 运行与配置提示

应用默认启动系统 `SHELL`（如 `/bin/zsh`），不会自动执行 `codex`。需要时请在终端内手动运行 `codex`，若需改为其他默认命令，请同步更新前端提示与后端启动逻辑。
前端主题与背景色会同步设置到 Tauri 窗口背景，避免透明导致的闪烁。

## 代理更新说明

后续新增工具、脚本或目录时，请同步更新本指南，并保持文档全部使用中文。
