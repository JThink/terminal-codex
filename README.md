# terminal-codex

`terminal-codex` 是一个面向 macOS 的轻量终端原型，使用 Tauri、Rust、xterm.js 和
`portable-pty` 构建。应用支持标签页、左右分屏、会话克隆、快捷键配置、Codex 会话历史，
以及可持久化的 SSH 连接。

## SSH 连接

按 `Command+E` 打开连接中心。主界面不会增加额外的连接或设置按钮。

连接中心支持：

- 搜索、新建、编辑和删除 SSH 连接；
- Agent、指定私钥、密码三种认证方式；
- 保存前测试连接，以及保存并连接；
- SSH 标签的克隆、左右分屏、状态恢复和断线重连。

SSH 会话使用系统 `/usr/bin/ssh`，首次遇到新主机时采用 OpenSSH 的 `accept-new`
策略写入系统 `known_hosts`。当前版本不支持跳板机、SFTP、端口转发、2FA 和
keyboard-interactive 认证。

## 凭据安全

Profile 保存在应用配置目录的 `ssh-profiles.json`，文件使用版本化格式、原子写入和
`0600` 权限。密码不写入 Profile、localStorage、命令行参数或普通子进程环境变量，只保存
在 macOS Keychain 中。Profile UUID 对应的 Keychain 项只保存无秘密 revision 指针，真正的
版本化凭据记录保存在不可预测的 revision account，避免固定 account 被预占后继承其访问权限。

密码认证由应用内一次性 ASKPASS broker 提供。每次启动 SSH 都会生成短期 capability，
并绑定实际 SSH/helper 进程身份；capability 过期、重放或身份校验失败时不会返回密码。

## 开发

```bash
npm install
npm run tauri -- dev
```

只编译 Rust 后端：

```bash
cd src-tauri
cargo build --locked
```

构建 macOS 应用：

```bash
npm run tauri -- build
```

## 验证

```bash
node --test src/ssh-connections.test.mjs
node --check src/main.js
cd src-tauri
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
```

Rust 测试覆盖 SSH Profile、命令参数、Keychain 事务、ASKPASS broker 和 PTY 生命周期；
Node 测试覆盖搜索、表单 payload、LaunchSpec 迁移/持久化与终端字节转换。

## 目录

- `src/main.js`：标签、分屏、终端和连接中心交互；
- `src/ssh-connections.mjs`：可独立测试的 SSH 前端纯函数；
- `src-tauri/src/lib.rs`：Tauri 命令、PTY 会话和事件桥接；
- `src-tauri/src/ssh/`：SSH 参数、Keychain 事务和 ASKPASS broker；
- `docs/superpowers/specs/`：功能设计；
- `docs/superpowers/plans/`：实施与验收计划。
