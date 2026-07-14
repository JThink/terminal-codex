# macOS 与 Windows 双平台终端设计

## 目标

在不回退现有 macOS 功能和 SSH 安全边界的前提下，让应用原生运行于 macOS 与
Windows 10 1809 及以上版本。Windows 首期支持 x86_64，覆盖本地终端、标签页、
分屏、会话克隆、目录打开、快捷键、SSH Profile CRUD、连接测试，以及
Agent、私钥和本地 vault 密码认证。

完成标准如下：

- macOS 继续使用系统登录 Shell、Unix PTY 和现有 ASKPASS 进程链校验。
- Windows 使用 ConPTY，优先启动 PowerShell 7，并在缺失时依次回退到 Windows
  PowerShell 和 `cmd.exe`。
- Windows 使用系统 OpenSSH Client 的 `ssh.exe`，缺失时返回明确的中文安装提示。
- SSH 密码仍只存入应用配置目录的加密 vault，不引入 Keychain、Credential
  Manager 或明文配置。
- Windows ASKPASS 与 macOS 一样校验主应用、`ssh` 和 helper 的真实进程链，且
  capability 只能消费一次。
- macOS 能生成 `.app` 和 `.dmg`；Windows 能生成 NSIS `.exe` 安装包。
- 两个平台均有自动化编译验证，平台无关逻辑在本机完整运行单元测试。

## 方案比较

### 方案一：原生平台适配层

保留 Tauri、xterm.js 和 `portable-pty`，把 Shell、OpenSSH 路径、用户目录、
进程信息和本地 IPC 收敛到小型平台适配层。macOS 使用现有实现；Windows 使用
ConPTY、Win32 进程 API 和 AF_UNIX。

优点是用户无需安装 WSL，现有功能和安全模型均可保留。缺点是 Windows 进程身份
查询和 AF_UNIX peer PID 需要少量 Win32 代码。

### 方案二：WSL 驱动

Windows 始终启动 `wsl.exe`，并把 SSH 也交给 WSL。实现较快，但依赖用户预装并
配置发行版，Windows 路径、密钥和环境变量语义也会改变，不满足原生 Windows
终端的目标。

### 方案三：环回 TCP ASKPASS

本地终端仍使用 ConPTY，密码 broker 改用 `127.0.0.1` TCP。实现简单，但无法像
AF_UNIX 一样可靠取得对端 helper PID，会削弱现有进程链校验。

采用方案一。

## 架构

### 平台能力边界

新增 `src-tauri/src/platform.rs`，只暴露以下能力：

- 解析默认本地 Shell 和对应启动参数。
- 解析用户主目录和 Codex 数据目录。
- 解析系统 OpenSSH 可执行文件。
- 获取本地会话可用的工作目录信息。

业务模块不直接判断 `target_os`，平台差异通过该模块返回的结构化结果进入现有
PTY 和 SSH 流程。macOS 专用的 `proc_pidinfo` 代码移入该模块；Windows 会话无法
可靠读取运行中 Shell 的当前目录时，使用会话启动目录作为稳定回退，保证克隆和
“打开目录”可用而不是直接报错。

### 本地终端

`portable-pty` 已在 Windows 使用 ConPTY，无需替换终端引擎。Shell 解析规则为：

1. 若调用方提供合法覆盖值，使用覆盖值。
2. macOS 使用 `SHELL`，缺失时回退 `/bin/zsh`，并添加 `-l`。
3. Windows 在 `PATH` 中依次查找 `pwsh.exe`、`powershell.exe`，最后使用
   `ComSpec` 或 `cmd.exe`，不添加 Unix 参数。

会话记录保存启动目录和经过过滤的环境快照。macOS 克隆继续读取运行中进程的
实时目录和环境；Windows 克隆使用保存的启动快照。PTY 的读取、写入、调整尺寸、
关闭和事件桥接保持共享实现。

### OpenSSH 与 ASKPASS

SSH 参数生成不再写死 `/usr/bin/ssh`。平台层返回可执行文件：macOS 固定验证
`/usr/bin/ssh`，Windows 优先 `%WINDIR%\\System32\\OpenSSH\\ssh.exe`，然后在
`PATH` 中查找 `ssh.exe`。

broker 的协议、ticket registry、超时、配额和一次性消费规则保持不变，仅替换
传输和进程检查实现：

- macOS：`std::os::unix::net::{UnixListener, UnixStream}`。
- Windows：`uds_windows::{UnixListener, UnixStream}`，要求 Windows 10 1809+
  提供 AF_UNIX。
- macOS peer PID：`LOCAL_PEERPID`。
- Windows peer PID：对 socket 调用 `WSAIoctl(SIO_AF_UNIX_GETPEERPID)`。
- Windows 进程事实：`OpenProcess`、`QueryFullProcessImageNameW`、
  `GetProcessTimes` 和 ToolHelp 进程快照提供路径、启动时间和父 PID；文件 ID 与
  修改信息生成稳定代码身份摘要。

这样 helper 必须与主应用使用同一可执行映像，helper 的父进程必须是已绑定的
OpenSSH 进程，OpenSSH 的父进程必须是主应用。任何检查失败都不会读取或消费
capability token。

### 配置与凭据

SSH Profile、事务日志、vault 和 vault key 继续存放在 Tauri 的应用配置目录。
Unix 使用 `0600`/`0700` 权限；Windows 依赖当前用户 AppData 目录 ACL，并使用
同样的原子临时文件替换流程。Windows 替换已存在文件时先使用平台安全替换函数，
避免 `std::fs::rename` 的目标已存在语义差异。

私钥路径的 `~/` 和 `~\\` 前缀在 macOS 使用 `HOME`，Windows 使用
`USERPROFILE`。Profile JSON 格式和 vault 格式不变，因此本次不引入迁移版本。

### 前端交互

前端在启动时判定 `macos` 或 `windows`，并把平台写入根元素的 `data-platform`。
macOS 默认快捷键保持现状；Windows 的命令快捷键使用 `Ctrl+Shift` 或
`Ctrl+Alt`，避免占用 Shell 常见的 `Ctrl+C`、`Ctrl+D` 和 `Ctrl+E`。

快捷键存储新增平台版本键，防止旧的 macOS 默认值被误当成 Windows 默认值。
捕获逻辑继续支持用户自定义。Windows 使用系统标题栏，macOS 保留 Overlay 和
红绿灯偏移；CSS 只对 macOS 预留红绿灯空间。

### 构建与发布

`tauri.conf.json` 仅保留公共窗口和 bundle 字段；新增：

- `tauri.macos.conf.json`：Overlay 标题栏、红绿灯、`.app`/`.dmg` 和 ad-hoc
  签名。
- `tauri.windows.conf.json`：普通系统标题栏、NSIS target 和 WebView2 配置。

`package.json` 收敛为当前 Tauri 原型真实需要的依赖和脚本，并与现有
`package-lock.json` 对齐，使全新 checkout 可以执行 `npm ci`。构建脚本提供公共
开发命令、macOS arm64/x64 构建和 Windows x64 构建。

GitHub Actions 分别在 `macos-latest` 和 `windows-latest` 运行前端检查、Rust
测试、Clippy 和 Tauri bundle。Windows runner 的原生结果是 Windows 运行与安装包
验证的权威证据；macOS 本机继续执行实际 `.app`/`.dmg` 构建验证。

## 错误处理

- 找不到 Windows OpenSSH 时，提示在“可选功能”中安装 OpenSSH Client，不把
  `CreateProcess` 原始错误直接暴露给用户。
- Windows 版本不支持 AF_UNIX 时，仅阻止密码认证，Agent、私钥和本地终端继续
  可用，并在 SSH 子系统状态中返回明确原因。
- 平台进程身份、socket peer PID 或可执行路径无法验证时 fail closed，不返回
  vault 密码。
- 会话克隆实时目录不可用时使用已记录启动目录；记录也不可用时回退用户主目录。
- 所有新增系统错误保持中文上下文，日志和 `Debug` 输出不得包含密码或 capability。

## 测试策略

- 平台纯函数使用 Rust 单元测试覆盖 Shell 顺序、HOME 回退、OpenSSH 查找和路径
  前缀展开。
- SSH process spec 测试分别注入 macOS 与 Windows OpenSSH 路径，断言参数不经
  Shell 拼接，ASKPASS 环境完整且 token 会清零。
- broker 的 registry 测试保持平台无关；socket 和真实进程测试按平台条件编译。
- Windows 编译门禁使用 `cargo check --target x86_64-pc-windows-msvc --all-targets`，
  防止 Unix import 泄漏。
- 前端纯函数测试覆盖平台默认快捷键和平台标记。
- 完整回归包括 Node 测试、JS 语法检查、Rust 测试、Clippy、macOS Tauri build，
  以及 GitHub Actions 的 Windows 原生测试与 NSIS 构建。

## 非目标

- 本次不增加 Linux 支持。
- 本次不把本地 vault 改为 Keychain、Credential Manager 或在线同步。
- 本次不要求 macOS 与 Windows 共享配置目录或自动迁移配置。
- 本次不实现 Windows on ARM 安装包。
