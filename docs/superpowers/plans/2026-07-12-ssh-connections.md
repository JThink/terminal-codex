# SSH Connections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 terminal-codex 实现由 `Command+E` 打开的安全 SSH 连接管理与远程 PTY 会话。

**Architecture:** Rust `ssh` 模块拥有 Profile、Keychain 和 SSH 参数，`lib.rs` 负责 Tauri/PTY 桥接；前端以 LaunchSpec 区分 local/ssh，并让连接中心复用现有弹窗与快捷键模式。密码只进入 macOS Keychain，SSH 通过应用自身 ASKPASS 辅助模式读取。

**Tech Stack:** Tauri 2、Rust、portable-pty、security-framework、uuid、Vanilla JavaScript、xterm.js、Node `node:test`。

**仓库约束:** 当前目录没有 `.git`，无法创建 worktree、提交或推送；每项以测试和 diff 审查替代提交检查点。

---

### Task 1: SSH 领域模型、校验与持久化

**Files:**
- Create: `src-tauri/src/ssh.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/Cargo.lock`

- [x] **Step 1: 写失败测试**

在 `ssh.rs` 的 `#[cfg(test)]` 中先定义期望 API，覆盖：合法 Profile、空 host、非法端口、key 缺少文件、版本不支持、保存后重读一致、损坏 JSON 报错。

```rust
#[test]
fn rejects_empty_host() {
    let mut profile = fixture_profile();
    profile.host = " ".into();
    assert_eq!(validate_profile(&profile).unwrap_err(), "主机地址不能为空。");
}

#[test]
fn round_trips_profile_document() {
    let dir = unique_test_dir();
    let path = dir.join("ssh-profiles.json");
    save_profiles(&path, &[fixture_profile()]).unwrap();
    assert_eq!(load_profiles(&path).unwrap(), vec![fixture_profile()]);
    std::fs::remove_dir_all(dir).unwrap();
}
```

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::tests -- --nocapture`

Expected: FAIL，原因是 `ssh` 模块/API 尚不存在，而不是测试语法错误。

- [x] **Step 3: 最小实现**

实现 `SshAuthType`、`SshProfile`、`SshProfilesDocument`、`validate_profile`、`load_profiles`、`save_profiles` 和 `generate_profile_id`。JSON 使用 camelCase，文档版本固定为 1；同目录临时文件写入、同步并重命名，Unix 权限 `0600`。

```rust
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SshProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: SshAuthType,
    pub identity_file: Option<String>,
    pub connect_timeout: u16,
}
```

- [x] **Step 4: 验证 GREEN**

Run: `cd src-tauri && cargo test --locked ssh::tests -- --nocapture`

Expected: 所有模型、校验和持久化测试 PASS。

### Task 2: Keychain、ASKPASS 与 SSH 参数

**Files:**
- Modify: `src-tauri/src/ssh.rs`
- Modify: `src-tauri/src/main.rs`
- Modify: `src-tauri/Cargo.toml`

- [x] **Step 1: 写失败测试**

先测试 `CredentialStore` 的内存替身、密码 Profile 新建必须有凭据、空密码更新保留旧值、切换认证删除凭据，以及三种认证对应的参数/环境差异。

```rust
#[test]
fn password_command_uses_profile_id_without_secret() {
    let profile = fixture_password_profile();
    let spec = build_ssh_process_spec(&profile, Path::new("/tmp/app"), SshMode::Interactive)
        .unwrap();
    assert_eq!(spec.env.get(ASKPASS_PROFILE_ENV), Some(&profile.id));
    assert!(!format!("{spec:?}").contains("top-secret"));
    assert!(spec.args.iter().any(|arg| arg == "PubkeyAuthentication=no"));
}
```

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::tests::password -- --nocapture`

Expected: FAIL，原因是凭据事务和命令构建 API 尚未实现。

- [x] **Step 3: 最小实现**

新增 macOS `security-framework`、`zeroize`、`fs2`、`sha2` 和随机 token 依赖；实现 endpoint/revision 绑定的 Keychain record、跨进程锁、无秘密恢复 journal、交互和测试两种 SSH spec。ASKPASS 改为一次性 UDS broker：helper 不读 Keychain/Profile，broker 通过 `LOCAL_PEERPID`、真实 SSH PID、进程启动时间和应用身份验证 registry 后返回启动时密码快照。`main.rs` 在启动 Tauri 前处理纯 broker 客户端模式。

```rust
fn main() {
    if tauri_app_lib::run_ssh_askpass_if_requested() {
        return;
    }
    tauri_app_lib::run();
}
```

- [x] **Step 4: 验证 GREEN**

Run: `cd src-tauri && cargo test --locked ssh::tests -- --nocapture`

Expected: Profile 与命令/凭据测试全部 PASS，测试输出不包含密码样例。

### Task 3: Tauri 命令与 PTY 生命周期

**Files:**
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/ssh.rs`

- [x] **Step 1: 写失败测试**

先为测试连接 stderr 清洗/截断、输出字节保持、已退出会话关闭幂等行为编写单元测试。

```rust
#[test]
fn truncates_connection_error_without_breaking_utf8() {
    let source = "连接失败".repeat(1000);
    let result = sanitize_ssh_error(source.as_bytes());
    assert!(result.len() <= SSH_ERROR_LIMIT_CHARS + 1);
    assert!(result.ends_with('…'));
}
```

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::tests::truncates_connection_error -- --nocapture`

Expected: FAIL，原因是错误清洗 API 尚不存在。

- [x] **Step 3: 最小实现**

增加 `list_ssh_profiles`、`save_ssh_profile`、`delete_ssh_profile`、`test_ssh_profile`、`start_ssh_session` 命令。将 PTY 创建抽成接收 `CommandBuilder` 的函数，事件输出改为 `Vec<u8>`，登记 Session 后再启动 reader；EOF/错误发送 `terminal-exit`/`terminal-error`。

```rust
#[derive(Clone, serde::Serialize)]
struct TerminalOutput {
    session_id: String,
    data: Vec<u8>,
}
```

- [x] **Step 4: 验证 GREEN 与回归**

Run: `cd src-tauri && cargo test --locked`

Expected: 全部 Rust 测试 PASS，本地 Shell 相关测试无回归。

### Task 4: 前端纯函数与 LaunchSpec

**Files:**
- Create: `src/ssh-connections.mjs`
- Create: `src/ssh-connections.test.mjs`
- Modify: `src/main.js`

- [x] **Step 1: 写失败测试**

用 Node 内置测试先覆盖 Profile 搜索、endpoint 显示、旧 cwd 状态迁移、SSH LaunchSpec 序列化和终端字节转换。

```javascript
test("migrates legacy cwd into a local launch spec", () => {
  assert.deepEqual(normalizeLaunchSpec(null, "/tmp/demo"), {
    kind: "local",
    cwd: "/tmp/demo",
  });
});
```

- [x] **Step 2: 验证 RED**

Run: `node --test src/ssh-connections.test.mjs`

Expected: FAIL `ERR_MODULE_NOT_FOUND`，因为纯函数模块尚不存在。

- [x] **Step 3: 最小实现**

实现 `filterSshProfiles`、`formatSshEndpoint`、`normalizeLaunchSpec`、`serializeLaunchSpec`、`terminalBytes`。在 `main.js` 导入并用 LaunchSpec 替代仅 cwd 的窗格启动状态，同时保持旧 localStorage 格式兼容。

- [x] **Step 4: 验证 GREEN**

Run: `node --test src/ssh-connections.test.mjs && node --check src/main.js`

Expected: Node 测试全部 PASS，主脚本语法检查 exit 0。

### Task 5: Command+E 连接中心

**Files:**
- Modify: `src/main.js`
- Modify: `src/styles.css`

- [x] **Step 1: 先扩展可测状态行为**

在纯函数测试中补充认证切换时字段清理和保存 payload 规则，运行确认失败，再实现最小函数并确认通过。

Run: `node --test src/ssh-connections.test.mjs`

Expected RED: 新断言找不到 `buildProfilePayload`；Expected GREEN: 全部 PASS。

- [x] **Step 2: 构建连接中心 DOM**

按现有 modal 模式创建搜索、列表、空态、表单、Agent/私钥/密码分段控件、状态区和删除/测试/保存/保存并连接操作。密码 input 永不回填，关闭和保存后清空。

- [x] **Step 3: 接入快捷键与键盘行为**

在 `DEFAULT_HOTKEYS` 增加：

```javascript
{ id: "openSshConnections", label: "SSH 连接", defaultKey: "⌘-E" }
```

`runHotkeyAction` 打开连接中心；弹窗内 `Escape` 关闭，列表焦点下 `Enter` 连接，空列表直接新建。主界面不添加按钮或菜单项。

- [x] **Step 4: 静态验证**

Run: `node --test src/ssh-connections.test.mjs && node --check src/main.js`

Expected: 全部 PASS / exit 0。

### Task 6: SSH 标签、分屏、恢复与重连

**Files:**
- Modify: `src/main.js`
- Modify: `src/styles.css`

- [x] **Step 1: 写失败测试**

补充 `cloneLaunchSpec`、缺失 Profile 的错误保持和 SSH 不带 cwd 的序列化测试，确认 RED 后实现并确认 GREEN。

- [x] **Step 2: 接入启动链路**

`startTerminal` 根据 LaunchSpec 调用 `start_session`、`clone_session` 或 `start_ssh_session`；Session 记录 `kind/profileId`。SSH 跳过 cwd 刷新、Finder 和 `o`/`cx` 拦截。

- [x] **Step 3: 接入生命周期事件**

监听字节输出、退出和错误事件；未知 session 的首屏输出进入有界 pending buffer。SSH 退出后在窗格显示重连操作，同一窗格重启后更新 `leftSessionId/rightSessionId/activeSessionId`。

- [x] **Step 4: 接入状态恢复**

标签持久化保存左右 LaunchSpec；恢复旧状态时迁移 cwd；Profile 缺失时保留 SSH LaunchSpec 和错误视图，不启动本地 Shell。

- [x] **Step 5: 前端回归验证**

Run: `node --test src/ssh-connections.test.mjs && node --check src/main.js`

Expected: 全部 PASS / exit 0。

### Task 7: 文档、完整构建和交互验收

**Files:**
- Modify: `AGENTS.md`
- Modify: `README.md`

- [x] **Step 1: 更新中文文档**

记录 `docs/superpowers`、`src/ssh-connections.mjs`、SSH Profile/Keychain、`Command+E`、测试命令和首版限制。

- [x] **Step 2: 全量自动验证**

依次运行：

```bash
node --test src/ssh-connections.test.mjs
node --check src/main.js
cd src-tauri && cargo fmt --check
cd src-tauri && cargo clippy --locked --all-targets -- -D warnings
cd src-tauri && cargo test --locked
cd src-tauri && cargo build --locked
```

Expected: 全部 exit 0，无 warning、失败或忽略的新增测试。

- [x] **Step 3: 凭据安全验收**

用临时测试 Profile 保存密码，确认 `ssh-profiles.json`、localStorage 和 SSH 进程环境不含密码；确认 Keychain account 使用 Profile UUID；删除测试 Profile 后凭据不存在。

- [x] **Step 4: 应用交互验收**

启动 Tauri 应用并验证 `Command+E`、CRUD、搜索、测试、Agent/Key/Password 至少一种真实连接、标签克隆、分屏、恢复、断线重连，以及本地终端回归。记录无法在本机环境执行的外部主机场景，不用模拟结果替代真实结果。

- [x] **Step 5: 独立审查**

对照设计规格逐项检查实现，再做代码质量和安全审查；修复所有 Critical/Important 问题后重新运行 Step 2。
