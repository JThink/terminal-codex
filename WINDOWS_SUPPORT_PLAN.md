# macOS 与 Windows 双平台终端实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan
> task-by-task. Steps use checkbox syntax for tracking.

**目标：** 在 `dev-win` 分支实现 Windows 10/11 x64 原生终端，同时保持 macOS
本地终端、SSH 和打包行为不回退。

**架构：** 继续使用 Tauri、xterm.js 和 `portable-pty`。平台差异进入 Rust
`platform` 模块、ASKPASS socket/进程检查的条件实现，以及前端快捷键平台纯函数；
其余会话和 SSH 业务逻辑保持共享。

**技术栈：** Tauri 2、Rust 2021、portable-pty/ConPTY、Windows AF_UNIX、
windows-sys、uds_windows、原生 JavaScript、node:test、GitHub Actions。

---

## 文件结构

- 新增 `src-tauri/src/platform.rs`：Shell、HOME、OpenSSH、运行目录和 Windows
  进程基础能力。
- 新增 `src-tauri/src/ssh/local_socket.rs`：按平台导出 ASKPASS listener、stream
  和 peer PID。
- 修改 `src-tauri/src/lib.rs`：调用平台层并为会话保存 Windows 克隆回退快照。
- 修改 `src-tauri/src/ssh.rs`：跨平台 HOME 展开和原子文件替换。
- 修改 `src-tauri/src/ssh/process.rs`：通过参数注入 OpenSSH 可执行路径。
- 修改 `src-tauri/src/ssh/broker.rs`：复用 local socket，增加 Windows 进程身份。
- 修改 `src-tauri/src/ssh/askpass.rs`：复用 local socket client。
- 修改 `src-tauri/src/ssh/credentials.rs` 和 `transaction.rs`：使用跨平台原子替换。
- 新增 `src/platform.mjs` 和 `src/platform.test.mjs`：平台识别和默认快捷键。
- 修改 `src/main.js` 和 `src/styles.css`：应用平台快捷键及标题栏留白。
- 修改 `package.json` 与 `package-lock.json`：收敛 Tauri 依赖和双平台脚本。
- 拆分 `src-tauri/tauri.conf.json`，新增 `tauri.macos.conf.json` 和
  `tauri.windows.conf.json`。
- 新增 `.github/workflows/cross-platform.yml`：macOS 与 Windows 原生门禁。
- 修改 `README.md` 和 `AGENTS.md`：记录支持范围、命令和平台行为。

## Task 1：修复基线重试测试的时钟假设

**文件：**

- 修改：`src-tauri/src/ssh/broker.rs:2408`

- [ ] **Step 1：运行现有失败测试并保存 RED 证据**

```bash
cd src-tauri
cargo test --locked ssh::broker::tests::bind_keeps_retrying_for_the_full_bind_wait_window -- --exact
```

预期：FAIL，70 次 `10ms` 调度休眠在当前系统超过 `900ms`，返回
`SSH process has not execed yet`。

- [ ] **Step 2：只放宽测试预算，不修改生产重试逻辑**

将测试的 bind wait 从 `Duration::from_millis(900)` 改为：

```rust
Duration::from_millis(1_500)
```

保留 70 次瞬态失败和 `attempts > 50` 断言，使测试仍证明重试不会在短窗口提前停止。

- [ ] **Step 3：验证 GREEN 和整套 Rust 基线**

```bash
cargo test --locked ssh::broker::tests::bind_keeps_retrying_for_the_full_bind_wait_window -- --exact
cargo test --locked
```

预期：单测 1/1 通过，整套 144/144 通过。

- [ ] **Step 4：提交**

```bash
git add src-tauri/src/ssh/broker.rs
git commit -m "test: 放宽 ASKPASS 重试测试时钟预算"
```

## Task 2：建立可测试的平台解析模块

**文件：**

- 新增：`src-tauri/src/platform.rs`
- 修改：`src-tauri/src/lib.rs:16`
- 测试：`src-tauri/src/platform.rs`

- [ ] **Step 1：为 HOME 和程序搜索写失败测试**

在 `platform.rs` 的测试模块定义不访问真实环境的输入：

```rust
#[test]
fn windows_home_prefers_userprofile_and_falls_back_to_home() {
    let vars = HashMap::from([
        ("USERPROFILE".to_string(), r"C:\\Users\\levi".to_string()),
        ("HOME".to_string(), r"C:\\fallback".to_string()),
    ]);
    assert_eq!(
        home_from_vars(PlatformKind::Windows, &vars),
        Some(PathBuf::from(r"C:\\Users\\levi"))
    );
}

#[test]
fn windows_shell_order_is_pwsh_powershell_then_comspec() {
    let existing = HashSet::from(["powershell.exe".to_string()]);
    let spec = shell_spec_with(
        PlatformKind::Windows,
        None,
        None,
        |name| existing.contains(name).then(|| PathBuf::from(name)),
        Some(r"C:\\Windows\\System32\\cmd.exe"),
    );
    assert_eq!(spec.program, PathBuf::from("powershell.exe"));
    assert!(spec.args.is_empty());
}
```

同时覆盖 macOS `/bin/zsh -l`、Windows `cmd.exe` 回退、空覆盖值拒绝和
`CODEX_HOME` 优先级。

- [ ] **Step 2：确认测试因 API 尚不存在而失败**

```bash
cd src-tauri
cargo test --locked platform::tests --no-run
```

预期：编译失败，缺少 `PlatformKind`、`home_from_vars` 和 `shell_spec_with`。

- [ ] **Step 3：实现最小平台 API**

实现以下公共边界：

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformKind { MacOs, Windows }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShellSpec {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) cwd: PathBuf,
}

pub(crate) fn current_platform() -> PlatformKind;
pub(crate) fn user_home() -> Result<PathBuf, String>;
pub(crate) fn codex_home() -> Result<PathBuf, String>;
pub(crate) fn shell_spec(
    shell_override: Option<&str>,
    cwd: Option<&str>,
) -> Result<ShellSpec, String>;
pub(crate) fn resolve_ssh_executable() -> Result<PathBuf, String>;
```

程序搜索只接受实际普通文件；Windows 搜索时应用 `PATHEXT`，并优先检查
`%WINDIR%\\System32\\OpenSSH\\ssh.exe`。

- [ ] **Step 4：验证平台纯函数**

```bash
cargo test --locked platform::tests
cargo clippy --locked --all-targets -- -D warnings
```

预期：平台测试通过，Clippy 无警告。

- [ ] **Step 5：提交**

```bash
git add src-tauri/src/platform.rs src-tauri/src/lib.rs
git commit -m "feat: 增加双平台 Shell 与路径解析"
```

## Task 3：让本地 PTY 与会话克隆跨平台

**文件：**

- 修改：`src-tauri/src/lib.rs:148-1655`
- 测试：`src-tauri/src/lib.rs`

- [ ] **Step 1：写会话快照和 Shell 参数失败测试**

增加纯函数测试，断言 Windows 不接收 `-l`，并且克隆实时进程信息不可用时返回
启动快照：

```rust
#[test]
fn clone_source_falls_back_to_recorded_launch_snapshot() {
    let snapshot = LocalLaunchSnapshot {
        cwd: PathBuf::from(r"C:\\work"),
        env: HashMap::from([("TERM".into(), "xterm-256color".into())]),
    };
    let source = clone_source_from(None, None, &snapshot).unwrap();
    assert_eq!(source.cwd, PathBuf::from(r"C:\\work"));
    assert_eq!(source.env["TERM"], "xterm-256color");
}
```

- [ ] **Step 2：确认新测试失败**

```bash
cargo test --locked clone_source_falls_back_to_recorded_launch_snapshot -- --exact
```

预期：编译失败，缺少 `LocalLaunchSnapshot` 和 `clone_source_from`。

- [ ] **Step 3：实现会话启动快照**

为 `Session` 增加：

```rust
local_launch: Option<LocalLaunchSnapshot>,
```

本地会话保存规范化 cwd 和过滤后的环境；SSH 会话保存 `None`。`spawn_session`
使用 `platform::shell_spec` 创建 `CommandBuilder` 并逐个添加平台参数。macOS
`get_session_cwd/get_session_env` 成功时优先使用实时值；Windows 使用快照。

- [ ] **Step 4：让目录打开错误文案跨平台**

保留 Tauri opener，命令名兼容前端，但错误改为：

```rust
format!("无法在文件管理器中打开目录：{error}")
```

- [ ] **Step 5：验证会话逻辑**

```bash
cargo test --locked clone_source
cargo test --locked task_three_tests
```

预期：快照和既有会话生命周期测试全部通过。

- [ ] **Step 6：提交**

```bash
git add src-tauri/src/lib.rs
git commit -m "feat: 支持 Windows 本地 PTY 会话"
```

## Task 4：跨平台化 SSH 路径与持久化

**文件：**

- 修改：`src-tauri/src/ssh.rs:160-364`
- 修改：`src-tauri/src/ssh/process.rs:128-263`
- 修改：`src-tauri/src/ssh/credentials.rs:360-398`
- 修改：`src-tauri/src/ssh/transaction.rs:130-180`
- 测试：上述 Rust 模块

- [ ] **Step 1：写 Windows 路径与可执行注入失败测试**

```rust
#[test]
fn expands_windows_home_prefix_for_key_identity() {
    assert_eq!(
        expand_home_prefix_with(r"~\\.ssh\\id_ed25519", Some(Path::new(r"C:\\Users\\levi")))
            .unwrap(),
        PathBuf::from(r"C:\\Users\\levi\\.ssh\\id_ed25519")
    );
}

#[test]
fn process_spec_uses_injected_windows_ssh_executable() {
    let spec = build_ssh_process_spec_for_runtime(
        &fixture_profile(SshAuthType::Agent),
        Path::new(r"C:\\app\\terminal.exe"),
        Path::new(r"C:\\Windows\\System32\\OpenSSH\\ssh.exe"),
        None,
        SshMode::Interactive,
    ).unwrap();
    assert_eq!(spec.program, r"C:\\Windows\\System32\\OpenSSH\\ssh.exe");
}
```

- [ ] **Step 2：确认测试失败**

```bash
cargo test --locked expands_windows_home_prefix_for_key_identity -- --exact
cargo test --locked process_spec_uses_injected_windows_ssh_executable -- --exact
```

预期：测试编译失败，因为 helper 和 SSH 路径参数尚不存在。

- [ ] **Step 3：实现 HOME 注入和 OpenSSH 路径注入**

`validate_profile_for_connection` 使用平台 home 展开私钥路径；
`build_ssh_process_spec` 调用 `platform::resolve_ssh_executable`，内部测试 builder
显式接收 `ssh_executable: &Path`。所有参数继续通过 `CommandBuilder::args` 传递，
不拼接 Shell 字符串。

- [ ] **Step 4：新增跨平台原子替换 helper**

在 `ssh.rs` 提供：

```rust
pub(super) fn replace_file_atomically(source: &Path, destination: &Path) -> Result<(), String>;
```

Unix 使用 `fs::rename`。Windows 使用 `MoveFileExW`，标志为
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`。Profile、vault、vault key
和事务日志全部调用此 helper。

- [ ] **Step 5：验证 SSH 与持久化测试**

```bash
cargo test --locked ssh::process::tests
cargo test --locked ssh::credentials
cargo test --locked ssh::tests
```

预期：现有事务、vault 和参数测试通过，新增 Windows 路径测试通过。

- [ ] **Step 6：提交**

```bash
git add src-tauri/src/ssh.rs src-tauri/src/ssh/process.rs \
  src-tauri/src/ssh/credentials.rs src-tauri/src/ssh/transaction.rs
git commit -m "feat: 跨平台化 SSH 路径与持久化"
```

## Task 5：实现 Windows ASKPASS local socket

**文件：**

- 新增：`src-tauri/src/ssh/local_socket.rs`
- 修改：`src-tauri/src/ssh.rs:1-20`
- 修改：`src-tauri/src/ssh/askpass.rs:1-160`
- 修改：`src-tauri/src/ssh/broker.rs:1-1305`
- 修改：`src-tauri/Cargo.toml`
- 修改：`src-tauri/Cargo.lock`

- [ ] **Step 1：写 local socket API 编译测试**

模块导出统一类型与函数：

```rust
pub(crate) type LocalListener;
pub(crate) type LocalStream;
pub(crate) fn bind(path: &Path) -> io::Result<LocalListener>;
pub(crate) fn connect(path: &Path) -> io::Result<LocalStream>;
pub(crate) fn peer_pid(stream: &LocalStream) -> Result<u32, String>;
```

现有真实 socket 测试改为通过这些 API 建立连接，并继续断言 peer PID 等于当前
进程 PID。

- [ ] **Step 2：确认 Windows target 暴露 Unix import**

```bash
rustup target add x86_64-pc-windows-msvc
cargo check --locked --target x86_64-pc-windows-msvc --all-targets
```

预期：RED，`std::os::unix` 和 macOS-only broker 实现无法编译。

- [ ] **Step 3：增加条件依赖**

```toml
[target.'cfg(windows)'.dependencies]
uds_windows = "1.1"
windows-sys = { version = "0.60", features = [
  "Win32_Foundation",
  "Win32_Networking_WinSock",
  "Win32_Storage_FileSystem",
  "Win32_System_Diagnostics_ToolHelp",
  "Win32_System_Threading",
] }
```

- [ ] **Step 4：实现平台 socket**

Unix re-export `std::os::unix::net`；Windows re-export `uds_windows`。Windows
`peer_pid` 对 `AsRawSocket` 调用 `WSAIoctl`，控制码使用
`SIO_AF_UNIX_GETPEERPID`，并检查 `SOCKET_ERROR`、返回字节数和非零 PID。

broker 的 `ConnectionAcceptor`、worker channel、frame reader 和 askpass client
全部改用 `LocalStream`，协议字节不变。目录权限操作放入 Unix 条件函数；Windows
创建当前用户临时目录并依赖其 ACL。

- [ ] **Step 5：验证两端编译**

```bash
cargo test --locked ssh::askpass::tests
cargo test --locked ssh::broker::tests
cargo check --locked --target x86_64-pc-windows-msvc --all-targets
```

预期：macOS broker 测试通过，Windows target 不再出现 Unix socket 编译错误。

- [ ] **Step 6：提交**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/ssh.rs \
  src-tauri/src/ssh/local_socket.rs src-tauri/src/ssh/askpass.rs \
  src-tauri/src/ssh/broker.rs
git commit -m "feat: 支持 Windows ASKPASS 本地通信"
```

## Task 6：实现 Windows ASKPASS 进程身份校验

**文件：**

- 修改：`src-tauri/src/ssh/broker.rs:74-339`
- 测试：`src-tauri/src/ssh/broker.rs`

- [ ] **Step 1：写平台无关身份摘要测试**

```rust
#[test]
fn file_identity_digest_changes_when_process_image_identity_changes() {
    let first = file_identity_digest(Path::new("terminal.exe"), 1, 2, 3, 4);
    let second = file_identity_digest(Path::new("terminal.exe"), 1, 2, 3, 5);
    assert_ne!(first, second);
}
```

已有 fake inspector 测试继续覆盖 helper 路径、父 PID、启动时间、SSH 路径和主应用
快照变化时 capability 不被消费。

- [ ] **Step 2：确认摘要 helper 缺失**

```bash
cargo test --locked file_identity_digest_changes_when_process_image_identity_changes -- --exact
```

预期：编译失败，缺少 `file_identity_digest`。

- [ ] **Step 3：实现 Windows RealProcessInspector**

Windows 条件实现执行以下顺序：

1. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)`。
2. `QueryFullProcessImageNameW` 并规范化路径。
3. `GetProcessTimes` 读取 64 位 creation FILETIME。
4. ToolHelp snapshot 查找 `th32ProcessID == pid` 并读取 `th32ParentProcessID`。
5. 使用 `MetadataExt` 的 volume serial、file index、last write time 和 file size，
   经 SHA-256 截取 20 字节作为 `CodeIdentity`。
6. 所有 Win32 handle 在每条返回路径关闭。

`ProcessIdentityVerifier::production` 使用平台解析出的 OpenSSH 路径，不再写死
`/usr/bin/ssh`。

- [ ] **Step 4：交叉编译全部测试目标**

```bash
cargo check --locked --target x86_64-pc-windows-msvc --all-targets
```

预期：exit 0，包含 broker tests 的 Windows 条件代码完成类型检查。

- [ ] **Step 5：运行 macOS 安全回归**

```bash
cargo test --locked ssh::broker::tests
cargo clippy --locked --all-targets -- -D warnings
```

预期：broker 测试通过且 Clippy 无警告。

- [ ] **Step 6：提交**

```bash
git add src-tauri/src/ssh/broker.rs src-tauri/src/platform.rs
git commit -m "feat: 校验 Windows ASKPASS 进程身份"
```

## Task 7：增加平台快捷键与标题栏样式

**文件：**

- 新增：`src/platform.mjs`
- 新增：`src/platform.test.mjs`
- 修改：`src/main.js:263-294,3580-3643`
- 修改：`src/styles.css`

- [ ] **Step 1：写平台纯函数失败测试**

```javascript
test("uses Command defaults on macOS and Ctrl+Shift defaults on Windows", () => {
  assert.equal(buildDefaultHotkeyDefinitions("macos").find(({ id }) => id === "openSshConnections").defaultKey, "⌘-E");
  assert.equal(buildDefaultHotkeyDefinitions("windows").find(({ id }) => id === "openSshConnections").defaultKey, "Ctrl-Shift-E");
});

test("detects Windows without treating Linux as macOS", () => {
  assert.equal(detectPlatform("Win32", "Windows NT 10.0"), "windows");
  assert.equal(detectPlatform("MacIntel", "Macintosh"), "macos");
});
```

- [ ] **Step 2：确认测试失败**

```bash
node --test src/platform.test.mjs
```

预期：FAIL，`src/platform.mjs` 尚不存在。

- [ ] **Step 3：实现平台快捷键**

导出 `detectPlatform`、`buildDefaultHotkeyDefinitions` 和
`hotkeyStorageKeyForPlatform`。Windows 字母命令使用 `Ctrl-Shift`，分屏方向使用
`Ctrl-Alt`；macOS 值保持原样。`main.js` 导入这些函数，并设置：

```javascript
document.documentElement.dataset.platform = APP_PLATFORM;
```

Windows 使用独立 localStorage key，`eventToHotkey` 保留现有 Ctrl、Meta、Shift、
Alt 组合序列化。

- [ ] **Step 4：调整 CSS**

把红绿灯预留空间限定为：

```css
html[data-platform="macos"] .tabs-bar {
  padding-left: 76px;
}

html[data-platform="windows"] .tabs-bar {
  padding-left: 8px;
}
```

不得改变 SSH 弹层尺寸、搜索、删除或键盘循环选择行为。

- [ ] **Step 5：验证前端**

```bash
node --test src/platform.test.mjs src/ssh-connections.test.mjs
node --check src/main.js
```

预期：全部 Node 测试通过，主脚本语法检查 exit 0。

- [ ] **Step 6：提交**

```bash
git add src/platform.mjs src/platform.test.mjs src/main.js src/styles.css
git commit -m "feat: 增加 Windows 快捷键与标题栏适配"
```

## Task 8：拆分双平台 Tauri 配置和构建脚本

**文件：**

- 修改：`package.json`
- 修改：`package-lock.json`
- 修改：`src-tauri/tauri.conf.json`
- 新增：`src-tauri/tauri.macos.conf.json`
- 新增：`src-tauri/tauri.windows.conf.json`

- [ ] **Step 1：验证当前 clean install 配置失败**

```bash
npm ci --ignore-scripts
```

预期：FAIL，当前 `package.json` 的 Electron workspace 依赖与 Tauri
`package-lock.json` 不一致。

- [ ] **Step 2：收敛 package manifest**

根 package 只保留：

```json
{
  "name": "terminal-codex",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "test": "node --test src/*.test.mjs",
    "check": "node --check src/main.js",
    "tauri": "tauri",
    "tauri:dev": "tauri dev",
    "tauri:build": "tauri build",
    "tauri:build:mac-arm64": "tauri build --target aarch64-apple-darwin",
    "tauri:build:mac-x64": "tauri build --target x86_64-apple-darwin",
    "tauri:build:windows": "tauri build --target x86_64-pc-windows-msvc"
  },
  "devDependencies": { "@tauri-apps/cli": "^2.9.6" }
}
```

执行 `npm install --package-lock-only --ignore-scripts` 更新 lock。

- [ ] **Step 3：拆分 Tauri 配置**

公共配置保留标题、1100x720、图标和 CSP。macOS 配置包含 Overlay、hiddenTitle、
trafficLightPosition、`["app", "dmg"]` 和 signingIdentity `-`。Windows 配置包含
普通 decorations、target `["nsis"]` 和 `webviewInstallMode.type = "downloadBootstrapper"`。

- [ ] **Step 4：验证 manifest 与 macOS 配置**

```bash
npm ci --ignore-scripts
npm test
npm run check
npm run tauri build -- --debug --no-bundle
```

预期：clean install 成功，测试通过，macOS debug app 编译成功。

- [ ] **Step 5：提交**

```bash
git add package.json package-lock.json src-tauri/tauri.conf.json \
  src-tauri/tauri.macos.conf.json src-tauri/tauri.windows.conf.json
git commit -m "build: 增加 macOS 与 Windows 打包配置"
```

## Task 9：增加原生双平台 CI

**文件：**

- 新增：`.github/workflows/cross-platform.yml`

- [ ] **Step 1：创建 matrix workflow**

workflow 对 `main`、`dev-win` 和 pull request 触发，matrix 为
`macos-latest` 与 `windows-latest`。每个 runner 使用其原生 Rust host target，避免
把交叉编译结果误当成运行测试。每个 job 执行：

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
    cache: npm
- uses: dtolnay/rust-toolchain@stable
  with:
    components: clippy
- run: npm ci --ignore-scripts
- run: npm test
- run: npm run check
- run: cargo test --locked --manifest-path src-tauri/Cargo.toml
- run: cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
- run: npm run tauri:build
```

Windows job 上传 `src-tauri/target/release/bundle/nsis/*.exe`；macOS job 上传
`src-tauri/target/release/bundle/macos/*.app` 和 `bundle/dmg/*.dmg`。

- [ ] **Step 2：本地检查 YAML 关键字段**

```bash
rg -n "windows-latest|macos-latest|cargo test|cargo clippy|tauri build|upload-artifact" .github/workflows/cross-platform.yml
git diff --check
```

预期：两个 runner、测试、Clippy、构建和 artifact 上传均存在，diff 无空白错误。

- [ ] **Step 3：提交并推送以触发 workflow**

```bash
git add .github/workflows/cross-platform.yml
git commit -m "ci: 验证 macOS 与 Windows 原生构建"
git push origin dev-win
```

- [ ] **Step 4：检查 GitHub Actions 结果**

```bash
gh run list --branch dev-win --workflow cross-platform.yml --limit 1
gh run watch --exit-status
```

预期：macOS 和 Windows matrix job 均为 success，Windows NSIS artifact 存在。

## Task 10：更新仓库指南并完成验收

**文件：**

- 修改：`README.md`
- 修改：`AGENTS.md`

- [ ] **Step 1：更新文档**

README 记录 Windows 10 1809+、OpenSSH Client、PowerShell 回退、快捷键和双平台
构建命令。AGENTS 将“面向 macOS”改为“双平台”，更新 local vault、AF_UNIX、
ConPTY、配置拆分、测试命令和 Windows CI；删除 Keychain 旧描述。

- [ ] **Step 2：运行完整本地门禁**

```bash
npm test
npm run check
cd src-tauri
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo check --locked --target x86_64-pc-windows-msvc --all-targets
```

预期：所有命令 exit 0，无失败和警告。

- [ ] **Step 3：构建并验证 macOS 产物**

```bash
npm run tauri:build:mac-arm64
codesign --verify --deep --strict --verbose=2 "src-tauri/target/aarch64-apple-darwin/release/bundle/macos/LeviQian专属Codex.app"
hdiutil verify "src-tauri/target/aarch64-apple-darwin/release/bundle/dmg/LeviQian专属Codex_0.1.0_aarch64.dmg"
```

预期：Tauri build、codesign 和 hdiutil 均 exit 0。

- [ ] **Step 4：核对 Windows 原生证据**

确认最新 GitHub Actions Windows job 的 `cargo test`、Clippy 和 Tauri build 成功，
下载 artifact 并确认至少一个非空 NSIS `.exe`。记录 workflow run URL 和 artifact
文件名。

- [ ] **Step 5：提交文档并推送**

```bash
git add README.md AGENTS.md WINDOWS_SUPPORT_PLAN.md
git commit -m "docs: 更新双平台终端使用指南"
git push origin dev-win
```

- [ ] **Step 6：最终状态审计**

```bash
git status --short --branch
git log --oneline --decorate main..dev-win
git diff --check main...dev-win
git diff --stat main...dev-win
```

预期：工作区干净，`dev-win` 与 `origin/dev-win` 同步，所有变更均属于双平台目标。
