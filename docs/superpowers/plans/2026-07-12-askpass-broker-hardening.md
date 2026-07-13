# ASKPASS Broker 复审加固实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 ASKPASS broker 复审发现的运行映像身份、票据生命周期、并发服务、运行期健康和 token 清理问题，同时保持 Task3 边界不变。

**Architecture:** `broker.rs` 继续拥有进程身份、一次性 registry 和 UDS 服务，但把运行映像 CDHash 纳入所有身份快照，把票据过期改为按 Profile 超时计算的绝对 deadline，并以固定 worker pool 服务连接。broker 的 fatal health 通过共享回调写入 `SshRecoveryState`；`process.rs` 和 `askpass.rs` 负责 token 的最小化复制与销毁。

**Tech Stack:** Rust、macOS `csops`/`LOCAL_PEERPID`、Unix Domain Socket、`zeroize`、Rust 单元测试。

---

### Task A：运行映像 CDHash 身份

**Files:**
- Modify: `src-tauri/src/ssh/broker.rs`

- [x] **Step 1: 写失败测试**

新增 `helper_cdhash_mismatch_fails_before_token_lookup`、`changed_helper_cdhash_does_not_consume_token` 和 macOS `real_process_inspector_returns_nonzero_current_process_cdhash`。前两项只改变 `ProcessFacts.code_identity`，分别断言 capture 在 token lookup 前失败，以及 consume 失败后恢复身份仍可消费。

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests::helper_cdhash_mismatch_fails_before_token_lookup -- --nocapture`

Expected: 编译失败，原因是 `ProcessFacts` 尚无 `code_identity` 或 inspector 尚未读取 CDHash。

- [x] **Step 3: 最小实现**

为 `ProcessFacts` 增加 `[u8; 20]` 运行映像身份；macOS 通过 `csops(pid, CS_OPS_CDHASH, ...)` 读取并拒绝失败或全零结果。`AppIdentity`、`PeerIdentitySnapshot`、`SshBinding` 和 `verify_peer` 全量比较该值，不读取磁盘文件重新散列。

- [x] **Step 4: 验证 GREEN**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests:: -- --nocapture`

Expected: broker 全部测试通过。

### Task B：动态 TTL 与主动清理

**Files:**
- Modify: `src-tauri/src/ssh/broker.rs`

- [x] **Step 1: 写失败测试**

新增 `connect_timeout_extends_ticket_deadline_to_150_seconds`，断言 `connect_timeout=120` 时 31 秒和 120 秒仍可 bind/consume，150 秒后拒绝；新增 `prune_removes_expired_bound_snapshot_without_ticket_drop`，推进假时钟后调用清理并断言 `entry_count()==0`。

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests::connect_timeout_extends_ticket_deadline_to_150_seconds -- --nocapture`

Expected: 31 秒时票据被固定 30 秒 TTL 错误拒绝。

- [x] **Step 3: 最小实现**

`RegisteredLaunch` 保存 `deadline`；注册时计算 `max(30s, connect_timeout + 30s)`，受 Profile 的 120 秒校验上限约束。registry 操作和 server 轮询调用 `prune_expired`，按绝对 deadline 删除 entry 并通知等待者。

- [x] **Step 4: 验证 GREEN**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests:: -- --nocapture`

Expected: 动态 TTL、主动清理和原有测试全部通过。

### Task C：固定 worker pool 与有界队列

**Files:**
- Modify: `src-tauri/src/ssh/broker.rs`

- [x] **Step 1: 写失败测试**

新增 `bound_request_is_not_blocked_by_two_unbound_clients`：两个真实 socket 请求占用 bind 等待后，第三个已绑定请求必须在客户端 3 秒超时内返回密码；保留并复验 broker Drop 小于 1 秒。

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests::bound_request_is_not_blocked_by_two_unbound_clients -- --nocapture`

Expected: 单 accept/handle 线程使第三个请求超时。

- [x] **Step 3: 最小实现**

启动 4 个固定 worker，以容量 16 的 `sync_channel` 分发 `UnixStream`。accept 线程不执行连接处理；队列满立即写失败 frame 或关闭。Drop 先 shutdown registry，再停止 accept、关闭 sender并 join accept 和全部 worker。

- [x] **Step 4: 验证 GREEN**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests:: -- --nocapture`

Expected: 并发响应、队列边界和 Drop 测试全部通过。

### Task D：运行期 health 与 fatal 传播

**Files:**
- Modify: `src-tauri/src/ssh/broker.rs`
- Modify: `src-tauri/src/lib.rs`

- [x] **Step 1: 写失败测试**

新增注入式 accept 测试：`Interrupted`/`ConnectionAborted` 继续，`WouldBlock` 轮询，资源错误重试；fatal 错误断言 registry 清空、register fail-fast、等待者被唤醒。增加 health callback 更新 `SshRecoveryState` broker blocker 且 recovery retry 不清除的测试，并覆盖 server panic fail-closed。

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests::fatal_accept_error_shuts_down_registry_and_reports_health -- --nocapture`

Expected: 编译失败，原因是 acceptor、health state 和 failure callback API 尚不存在。

- [x] **Step 3: 最小实现**

抽取可注入 accept loop 和错误分类；资源错误采用有界退避，其余 fatal 原子写 unhealthy、shutdown registry 并调用一次 failure callback。worker/accept panic 由 join 监控路径转换为相同 fatal；`AppState` 以 `Arc<SshRecoveryState>` 启动 broker callback，只更新 broker blocker。

- [x] **Step 4: 验证 GREEN**

Run: `cd src-tauri && cargo test --locked ssh::broker::tests:: && cargo test --locked ssh::tests::broker_start_failure -- --nocapture`

Expected: health、blocker 和既有启动隔离测试全部通过。

### Task E：token 副本与销毁

**Files:**
- Modify: `src-tauri/src/ssh/process.rs`
- Modify: `src-tauri/src/ssh/askpass.rs`

- [x] **Step 1: 写失败测试**

新增可观察清理测试，证明 `SshProcessSpec` 显式清理或 Drop 会 zeroize `ASKPASS_TOKEN_ENV`；生产 helper 环境解析直接构造 `Zeroizing<String>`，不先保留第二个普通 `String`。

- [x] **Step 2: 验证 RED**

Run: `cd src-tauri && cargo test --locked ssh::process::tests::clearing_process_spec_zeroizes_askpass_token -- --nocapture`

Expected: 编译失败，原因是清理 API 尚不存在。

- [x] **Step 3: 最小实现**

为 `SshProcessSpec` 增加显式 `clear_secrets` 并在 Drop 调用，移除 token 后 zeroize 原值。helper 的生产环境收集返回包含 `Zeroizing<String>` 的请求结构，避免普通字符串的额外克隆。

- [x] **Step 4: 验证 GREEN 与全量验证**

Run: `cd src-tauri && cargo fmt --check && cargo check --locked --all-targets && cargo test --locked`

Expected: 格式、全部 target 检查和全部测试通过；不新增 `allow`。
