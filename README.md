# terminal-codex

`terminal-codex` 是一个支持 macOS 与 Windows 的轻量终端，使用 Tauri、Rust、
xterm.js 和 `portable-pty` 构建。应用支持标签页、左右分屏、会话克隆、快捷键配置、
Codex 会话历史，以及可持久化的 SSH 连接。

Windows 运行环境要求 Windows 10 1809 或更高版本，并启用系统 OpenSSH Client。
本地终端优先启动 PowerShell 7，缺失时依次回退到 Windows PowerShell 和
`cmd.exe`；macOS 继续启动系统登录 Shell。

## SSH 连接

macOS 按 `Command+E`、Windows 按 `Ctrl+Shift+E` 打开连接中心。连接中心支持：

- 搜索、新建、编辑和直接删除 SSH 连接；
- Agent、指定私钥、密码三种认证方式；
- 保存前测试连接，以及保存并连接；
- SSH 标签的克隆、左右分屏、状态恢复和断线重连。

macOS 使用系统 `/usr/bin/ssh`。Windows 优先使用
`%WINDIR%\System32\OpenSSH\ssh.exe`，再从 `PATH` 查找 `ssh.exe`；找不到时会提示
安装 OpenSSH Client。首次遇到新主机时使用 OpenSSH 的 `accept-new` 策略写入系统
`known_hosts`。当前版本不支持跳板机、SFTP、端口转发、2FA 和
keyboard-interactive 认证。

## 凭据安全

Profile 保存在 Tauri 应用配置目录的 `ssh-profiles.json`。密码不会写入 Profile、
localStorage、命令行参数或普通子进程环境变量，而是使用 AES-256-GCM 加密保存到
`ssh-secrets.vault`，随机密钥保存在同目录的 `ssh-secrets.key`。应用不调用 macOS
Keychain 或 Windows Credential Manager，因此读取和保存 SSH 密码不会触发系统密码框。

本地 vault 依赖当前用户配置目录的文件权限，能够避免明文落盘和普通误读，但不能抵御
已经取得当前用户文件读取权限的恶意程序。密码认证由一次性 ASKPASS broker 提供；每次
启动 SSH 都会生成短期 capability，并绑定实际应用、SSH 和 helper 进程身份。

## 开发

需要 Node.js 20+、Rust stable 和当前平台的 Tauri 系统依赖。Windows 还需要
Microsoft C++ Build Tools 与 WebView2，运行 SSH 需要 OpenSSH Client。

```bash
npm ci --ignore-scripts
npm run tauri:dev
```

只编译 Rust 后端：

```bash
cd src-tauri
cargo build --locked
```

## 打包

macOS Apple Silicon：

```bash
npm run tauri:build:mac-arm64
```

macOS Intel：

```bash
npm run tauri:build:mac-x64
```

Windows x64（需在 Windows 构建机执行）：

```powershell
npm run tauri:build:windows
```

macOS 产物位于 `src-tauri/target/<target>/release/bundle/macos` 和 `bundle/dmg`；
Windows NSIS 安装包位于 `src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis`。

## 验证

```bash
npm test
npm run check
cd src-tauri
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
PATH="$(brew --prefix llvm)/bin:$PATH" \
  cargo check --locked --target x86_64-pc-windows-msvc --all-targets
```

最后一项是在 macOS 上进行 Windows 条件编译检查，需要先执行 `brew install llvm`；
Windows 原生环境不需要设置这段 PATH。

GitHub Actions 在 macOS 与 Windows 原生 runner 上重复测试、Clippy 和打包，并上传
`.app`、`.dmg` 与 NSIS `.exe`。Windows runner 是 Windows 运行和安装包兼容性的权威
构建证据。

## 目录

- `src/main.js`：标签、分屏、终端和连接中心交互；
- `src/platform.mjs`：平台识别、快捷键默认值与存储键；
- `src/ssh-connections.mjs`：可独立测试的 SSH 前端纯函数；
- `src-tauri/src/lib.rs`：Tauri 命令、PTY 会话和事件桥接；
- `src-tauri/src/platform.rs`：Shell、OpenSSH、HOME 与进程平台适配；
- `src-tauri/src/ssh/`：SSH 参数、本地 vault 事务和 ASKPASS broker；
- `src-tauri/tauri.*.conf.json`：公共、macOS 与 Windows 打包配置；
- `.github/workflows/cross-platform.yml`：双平台原生测试与打包。
