# SSH 连接功能设计

## 目标

在不增加主界面按钮的前提下，为当前 Tauri 终端增加可保存的 SSH 连接。用户通过可配置快捷键 `Command+E` 打开连接中心，管理连接并在现有标签页、分屏和克隆链路中使用远程终端。

## 首版范围

首版支持：

- 搜索、新建、编辑、删除和保存 SSH Profile。
- Agent、指定私钥、密码三种认证方式。
- 测试连接、保存并连接、断线重连。
- SSH 标签的恢复、克隆和左右分屏。
- 系统 `known_hosts`、首次主机指纹自动接受并记录。

首版不支持跳板机、SFTP、端口转发、ControlMaster、自定义 Host Key 弹窗、keyboard-interactive、2FA 和跨平台凭据存储。密码认证仅覆盖 SSH `password` 流程。

## 架构

沿用 Octovalve 已验证的 `portable-pty + /usr/bin/ssh -tt` 链路，不引入 Tabby 的完整 SSH 协议栈，也不增加 sidecar 或 WebSocket。

```text
Command+E 连接中心
  -> Tauri SSH Profile 命令
  -> app_config_dir/ssh-profiles.json
  -> macOS Keychain（仅密码）
  -> start_ssh_session(profileId)
  -> /usr/bin/ssh + portable-pty
  -> terminal-output / terminal-exit / terminal-error
  -> xterm.js 标签或分屏
```

新增 `src-tauri/src/ssh.rs` 作为独立领域模块，负责 Profile 校验、JSON 持久化、SSH 参数构建和 Keychain 访问。`src-tauri/src/lib.rs` 只保留 Tauri 命令包装、PTY 生命周期和事件桥接。前端新增 `src/ssh-connections.mjs` 保存可独立测试的 Profile/LaunchSpec 纯函数，连接中心 DOM 继续按项目现有模式由 `src/main.js` 构建。

## Profile 与持久化

Profile 对外使用 camelCase：

```text
id, name, host, port, username,
authType(agent|key|password),
identityFile, connectTimeout, hasPassword
```

`hasPassword` 只出现在返回给前端的视图模型中，不写入 Profile 文件。文件格式为带版本号的 JSON 文档：

```json
{
  "version": 1,
  "profiles": []
}
```

Profile 文件位于 Tauri `app_config_dir/ssh-profiles.json`。写入使用同目录临时文件、`sync_all` 和原子重命名；Unix 文件权限为 `0600`。读取时拒绝未知版本和损坏 JSON，不用空列表静默覆盖损坏文件。

校验规则：名称、主机和用户名不能为空；端口为 `1..=65535`；超时为 `1..=120` 秒；私钥认证必须提供展开 `~` 后存在的普通文件；字符串拒绝 NUL、回车和换行。Profile ID 由后端生成 UUID，更新时只允许覆盖同 ID 记录。

## 凭据与 ASKPASS

密码永不进入 JSON、localStorage、日志、SSH 参数或 SSH 子进程的普通环境变量。macOS 使用 `security-framework` 直接访问 Keychain：

- service：`com.levi.codex-terminal.ssh`
- index account：Profile UUID，只保存无秘密 credential revision 指针
- credential account：`Profile UUID:credential revision`，revision 在写入前随机生成
- value：带版本、endpoint fingerprint、credential revision 和密码的二进制记录

保存已有密码 Profile 时，密码输入留空表示保留原凭据；新建密码 Profile 必须提供密码。切换认证方式或删除 Profile 时同步删除旧 Keychain 项。

密码认证时设置 `SSH_ASKPASS` 为当前应用可执行文件，但 helper 不允许直接读取 Profile 或 Keychain。主应用启动一个 `0600` Unix Domain Socket broker，并在每次启动 SSH 前把 endpoint、credential revision 和密码快照登记到仅存在于应用内存的一次性 launch registry。SSH 环境只含随机 token、socket 路径和内部标记，不含 Profile ID、配置路径、PID 或密码。

SSH 进程创建后，主应用把 token 绑定到实际 SSH PID 及进程启动时间。helper 连接 broker 后，broker 用 macOS `LOCAL_PEERPID` 获取真实 helper PID，并验证 helper 可执行文件、helper 的父 SSH PID、SSH 的路径/父应用/启动时间和主应用身份都与 registry 完全一致，随后原子消费 token 并返回密码快照。token 过期、重放、PID 复用、未登记的 `exec /usr/bin/ssh` 和任一身份不匹配都不返回密码。helper 只把 broker 响应写到 stdout 后退出，不启动 Tauri。

`SSH_ASKPASS_REQUIRE=force` 和占位 `DISPLAY` 保证 PTY 中也走 ASKPASS。spawn 早于 registry 绑定的竞态由有界等待解决；spawn/bind 失败会杀死 SSH 并取消 token。

Agent 和私钥认证不启用强制 ASKPASS。加密私钥的口令由系统 ssh-agent 或终端交互处理，首版不保存私钥口令。

## SSH 命令

所有参数通过参数数组交给进程，不拼接 Shell 字符串。通用参数为：

```text
/usr/bin/ssh -tt
-F none
-p <port>
-l <username>
-o ClearAllForwardings=yes
-o ForwardAgent=no
-o PermitLocalCommand=no
-o ConnectionAttempts=1
-o ConnectTimeout=<seconds>
-o ServerAliveInterval=30
-o ServerAliveCountMax=3
-o StrictHostKeyChecking=accept-new
-- <host>
```

`-F none` 防止用户 SSH 配置中的 ProxyCommand、RemoteCommand 或转发隐式改变 Profile 行为，但仍使用标准 `~/.ssh/known_hosts`。私钥认证增加 `-i <identityFile>` 和 `IdentitiesOnly=yes`。密码认证增加 `PreferredAuthentications=password`、`PubkeyAuthentication=no`、`KbdInteractiveAuthentication=no` 和 `NumberOfPasswordPrompts=1`。

测试连接复用相同 Profile 和认证环境，但使用 `-T`、远端命令 `true`，并限制返回的 stderr 长度。Agent/私钥测试启用 `BatchMode=yes`，密码测试走同一个 broker。测试按钮先保存当前表单，再执行测试，因此测试成功的内容一定与后续连接一致。

## 凭据绑定与事务

Keychain 值不是裸密码，而是带版本、credential revision、endpoint fingerprint 和密码的二进制记录。fingerprint 由长度前缀编码的 host、port、username 计算，密码只有在当前 Profile 的 endpoint/revision 完全匹配时才能形成 launch snapshot。修改 host、port 或 username 时不允许“保留密码”，必须重新输入；直接篡改 Profile JSON 会因 fingerprint 不匹配而拒绝连接。

Profile 与 Keychain 操作使用进程内互斥和 `ssh-profiles.lock` 跨进程排他锁。无秘密 journal 在 Keychain 变更前持久化 previous/target revision，Profile 临时文件重命名后同步父目录；启动和每次操作前恢复未完成 journal。恢复状态不明确时保持 journal 并拒绝连接，不猜测新旧密码。Profile UUID account 只作为无秘密索引；新密码先 add-only 写入随机 revision account，再更新索引，避免固定 account 预占导致秘密写入既有 ACL。删除和认证切换同样通过 journal 清理索引及其指向的 credential account，避免并发丢更新、回滚覆盖以及崩溃后把新密码发送给旧 endpoint。

## 会话模型

前端为每个窗格保存独立 LaunchSpec：

```text
{ kind: "local", cwd }
{ kind: "ssh", profileId }
```

运行 Session 继续由后端生成临时 session ID；Profile 与运行 Session 不绑定生命周期。删除 Profile 不结束已经运行的 SSH 进程，但该窗格下次重连会提示 Profile 不存在。

本地 Session 仍调用 `start_session`/`clone_session`。SSH Session 调用 `start_ssh_session`。克隆 SSH 标签或增加 SSH 分屏表示用同一 Profile 建立一条新连接，不复制现有进程。SSH Session 跳过本地 cwd 轮询、Finder 打开和 `o`/`cx` 快命令拦截。

标签状态继续存 localStorage，但只保存 Profile ID，不保存 Profile 内容或密码。旧版 `leftCwd/rightCwd` 状态在读取时迁移为 local LaunchSpec。恢复时 Profile 缺失不会退回本地 Shell，而是在对应窗格展示明确错误和打开连接中心的操作。

## 输出、退出与错误

PTY 输出事件改为原始字节数组，前端以 `Uint8Array` 写入 xterm，避免分块 UTF-8 被 `from_utf8_lossy` 破坏。前端为 invoke 返回前到达的输出维护有界暂存区，Session 登记后立即冲刷，修复首屏输出竞态。

后端在 EOF 和读取错误时分别发送 `terminal-exit` / `terminal-error`。SSH 窗格断开后保留终端内容并展示“重新连接”；重连会关闭旧 Session、在同一窗格启动同一 LaunchSpec，并更新标签中的 session ID。

错误信息保持中文，前端表单区显示校验、保存、测试和连接错误。密码字段每次保存或关闭弹窗后清空。

## 连接中心交互

- `Command+E` 为默认快捷键，并进入现有快捷键设置和持久化系统。
- 弹窗左侧是搜索框和保存连接列表，右侧是编辑表单。
- 没有 Profile 时直接进入新建表单。
- `Enter` 在列表焦点下连接选中项，`Escape` 关闭弹窗。
- 新建使用 `+` 图标按钮；认证方式使用 Agent/私钥/密码分段控件。
- 操作包括删除、测试连接、保存、保存并连接。
- 主标签栏和右键菜单不新增设置或连接入口。

## 验证

Rust 单元测试覆盖 Profile 校验、版本化 JSON、原子保存、命令参数、认证差异、凭据事务和错误输出截断。Node 内置测试覆盖 Profile 搜索、LaunchSpec 迁移/序列化和字节转换。集成验证覆盖：

- Agent 或私钥连接到可达 SSH 主机。
- 密码保存后 JSON/localStorage/进程环境均无明文，ASKPASS 可从 Keychain 登录。
- Profile CRUD 和测试连接。
- SSH 标签克隆、分屏、恢复、断线重连。
- 本地标签、快捷键、cwd 刷新和 `o`/`cx` 行为无回归。
- Rust 测试、格式检查、Clippy、前端语法检查、Node 测试和 Tauri 构建全部通过。
