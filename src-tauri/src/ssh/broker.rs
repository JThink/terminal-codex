use super::{
    credentials::{endpoint_fingerprint, LaunchCredentialSnapshot},
    process::AskpassLaunchEnv,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt, fs,
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt, fs::PermissionsExt},
    panic::{self, AssertUnwindSafe},
    path::Path,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const ASKPASS_TICKET_TTL: Duration = Duration::from_secs(30);
const ASKPASS_TICKET_GRACE: Duration = Duration::from_secs(30);
const ASKPASS_MAX_TICKET_TTL: Duration = Duration::from_secs(150);
pub(crate) const ASKPASS_BIND_WAIT: Duration = Duration::from_secs(2);
pub(super) const ASKPASS_IO_TIMEOUT: Duration = Duration::from_secs(3);
const ASKPASS_SERVER_READ_TIMEOUT: Duration = Duration::from_millis(250);
const ASKPASS_MAX_PASSWORD_BYTES: usize = 1024 * 1024;
pub(super) const ASKPASS_MAX_RESPONSE_BYTES: usize = ASKPASS_MAX_PASSWORD_BYTES + 1;
pub(super) const ASKPASS_SUCCESS: u8 = 0;
pub(super) const ASKPASS_FAILURE: u8 = 1;
const ASKPASS_MAX_REQUEST_BYTES: usize = 512;
const ASKPASS_SOCKET_PATH_LIMIT: usize = 100;
const ASKPASS_WORKER_COUNT: usize = 4;
const ASKPASS_MAX_BIND_WAITERS: usize = ASKPASS_WORKER_COUNT - 1;
const ASKPASS_MAX_PENDING_TICKETS: usize = 8;
const ASKPASS_MAX_BOUND_TICKETS: usize = ASKPASS_MAX_PENDING_TICKETS;
const ASKPASS_CONNECTION_QUEUE_CAPACITY: usize = 16;
const ASKPASS_WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const ASKPASS_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const ASKPASS_RESOURCE_BACKOFF_MAX: Duration = Duration::from_millis(250);
const ASKPASS_SSH_BIND_RETRY_INTERVAL: Duration = Duration::from_millis(10);

type TokenDigest = [u8; 32];
type CodeIdentity = [u8; 20];

#[cfg(target_os = "macos")]
const CS_OPS_CDHASH: libc::c_uint = 5;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        ops: libc::c_uint,
        useraddr: *mut libc::c_void,
        usersize: libc::size_t,
    ) -> libc::c_int;
}

trait RegistryClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl RegistryClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessFacts {
    executable: PathBuf,
    parent_pid: u32,
    start_time: u64,
    code_identity: CodeIdentity,
}

#[derive(Clone, Eq, PartialEq)]
struct ProcessIdentitySnapshot {
    pid: u32,
    facts: ProcessFacts,
}

#[derive(Clone, Eq, PartialEq)]
struct PeerIdentitySnapshot {
    app: ProcessIdentitySnapshot,
    helper: ProcessIdentitySnapshot,
    ssh: ProcessIdentitySnapshot,
}

trait ProcessInspector: Send + Sync {
    fn process_facts(&self, pid: u32) -> Result<ProcessFacts, String>;
}

struct RealProcessInspector;

#[cfg(target_os = "macos")]
fn checked_pid(pid: u32) -> Result<libc::c_int, String> {
    if pid == 0 {
        return Err("进程 ID 无效。".to_string());
    }
    libc::c_int::try_from(pid).map_err(|_| "进程 ID 超出 macOS API 支持范围。".to_string())
}

#[cfg(target_os = "macos")]
fn process_code_identity(pid: libc::pid_t) -> Result<CodeIdentity, String> {
    let mut code_identity = [0_u8; 20];
    let result = unsafe {
        csops(
            pid,
            CS_OPS_CDHASH,
            code_identity.as_mut_ptr().cast(),
            code_identity.len(),
        )
    };
    if result != 0 || code_identity.iter().all(|byte| *byte == 0) {
        return Err("无法读取进程运行映像代码身份。".to_string());
    }
    Ok(code_identity)
}

#[cfg(target_os = "macos")]
impl ProcessInspector for RealProcessInspector {
    fn process_facts(&self, pid: u32) -> Result<ProcessFacts, String> {
        use std::{ffi::OsString, mem::MaybeUninit, os::unix::ffi::OsStringExt};

        let pid = checked_pid(pid)?;
        let mut path_buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let path_length = unsafe {
            libc::proc_pidpath(
                pid,
                path_buffer.as_mut_ptr().cast(),
                path_buffer.len() as u32,
            )
        };
        if path_length <= 0 || path_length as usize >= path_buffer.len() {
            return Err("无法完整读取进程可执行文件路径。".to_string());
        }
        path_buffer.truncate(path_length as usize);
        if path_buffer.last() == Some(&0) {
            path_buffer.pop();
        }
        if path_buffer.is_empty() || path_buffer.contains(&0) {
            return Err("进程可执行文件路径返回了无效长度。".to_string());
        }
        let executable = fs::canonicalize(PathBuf::from(OsString::from_vec(path_buffer)))
            .map_err(|_| "无法规范化进程可执行文件路径。".to_string())?;

        let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let expected = std::mem::size_of::<libc::proc_bsdinfo>();
        let returned = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                expected as libc::c_int,
            )
        };
        if returned != expected as libc::c_int {
            return Err("无法完整读取进程身份信息。".to_string());
        }
        let info = unsafe { info.assume_init() };
        let start_time = info
            .pbi_start_tvsec
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
            .ok_or_else(|| "进程启动时间超出支持范围。".to_string())?;
        if start_time == 0 {
            return Err("进程启动时间无效。".to_string());
        }
        let code_identity = process_code_identity(pid)?;
        Ok(ProcessFacts {
            executable,
            parent_pid: info.pbi_ppid,
            start_time,
            code_identity,
        })
    }
}

#[cfg(not(target_os = "macos"))]
impl ProcessInspector for RealProcessInspector {
    fn process_facts(&self, _pid: u32) -> Result<ProcessFacts, String> {
        Err("当前平台不支持 macOS ASKPASS 进程身份校验。".to_string())
    }
}

#[derive(Clone)]
struct AppIdentity {
    pid: u32,
    executable: PathBuf,
    start_time: u64,
    code_identity: CodeIdentity,
}

struct ProcessIdentityVerifier {
    inspector: Arc<dyn ProcessInspector>,
    app: AppIdentity,
    ssh_executable: PathBuf,
}

impl ProcessIdentityVerifier {
    fn new(
        inspector: Arc<dyn ProcessInspector>,
        app_pid: u32,
        expected_app_executable: PathBuf,
    ) -> Result<Self, String> {
        let facts = inspector.process_facts(app_pid)?;
        if facts.executable != expected_app_executable {
            return Err("ASKPASS broker 主应用可执行文件身份不匹配。".to_string());
        }
        Ok(Self {
            inspector,
            app: AppIdentity {
                pid: app_pid,
                executable: facts.executable,
                start_time: facts.start_time,
                code_identity: facts.code_identity,
            },
            ssh_executable: PathBuf::from("/usr/bin/ssh"),
        })
    }

    fn production() -> Result<Self, String> {
        let executable = std::env::current_exe()
            .map_err(|error| format!("无法获取主应用可执行文件路径：{error}"))?;
        let executable = fs::canonicalize(executable)
            .map_err(|_| "无法规范化主应用可执行文件路径。".to_string())?;
        let mut verifier = Self::new(
            Arc::new(RealProcessInspector),
            std::process::id(),
            executable,
        )?;
        verifier.ssh_executable = fs::canonicalize("/usr/bin/ssh")
            .map_err(|_| "无法规范化系统 SSH 可执行文件路径。".to_string())?;
        Ok(verifier)
    }

    fn inspect_app(&self) -> Result<ProcessIdentitySnapshot, String> {
        let facts = self.inspector.process_facts(self.app.pid)?;
        if facts.executable != self.app.executable
            || facts.start_time != self.app.start_time
            || facts.code_identity != self.app.code_identity
        {
            return Err("ASKPASS broker 主应用进程身份已变化。".to_string());
        }
        Ok(ProcessIdentitySnapshot {
            pid: self.app.pid,
            facts,
        })
    }

    fn inspect_ssh(&self, ssh_pid: u32) -> Result<ProcessFacts, String> {
        let facts = self.inspector.process_facts(ssh_pid)?;
        if facts.executable != self.ssh_executable || facts.parent_pid != self.app.pid {
            return Err("ASKPASS SSH 进程路径或父进程不匹配。".to_string());
        }
        Ok(facts)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SshBinding {
    ssh_pid: u32,
    ssh_start_time: u64,
    ssh_code_identity: CodeIdentity,
}

trait IdentityVerifier: Send + Sync {
    fn capture_peer(&self, helper_pid: u32) -> Result<PeerIdentitySnapshot, String>;
    fn bind_ssh(&self, ssh_pid: u32) -> Result<SshBinding, String>;
    fn verify_peer(&self, peer: &PeerIdentitySnapshot, binding: &SshBinding) -> Result<(), String>;
}

impl IdentityVerifier for ProcessIdentityVerifier {
    fn capture_peer(&self, helper_pid: u32) -> Result<PeerIdentitySnapshot, String> {
        let app = self.inspect_app()?;
        let helper_facts = self.inspector.process_facts(helper_pid)?;
        if helper_facts.executable != self.app.executable
            || helper_facts.code_identity != self.app.code_identity
        {
            return Err("ASKPASS helper 可执行文件路径不匹配。".to_string());
        }
        let ssh_pid = helper_facts.parent_pid;
        let ssh_facts = self.inspect_ssh(ssh_pid)?;
        Ok(PeerIdentitySnapshot {
            app,
            helper: ProcessIdentitySnapshot {
                pid: helper_pid,
                facts: helper_facts,
            },
            ssh: ProcessIdentitySnapshot {
                pid: ssh_pid,
                facts: ssh_facts,
            },
        })
    }

    fn bind_ssh(&self, ssh_pid: u32) -> Result<SshBinding, String> {
        self.inspect_app()?;
        let ssh = self.inspect_ssh(ssh_pid)?;
        Ok(SshBinding {
            ssh_pid,
            ssh_start_time: ssh.start_time,
            ssh_code_identity: ssh.code_identity,
        })
    }

    fn verify_peer(&self, peer: &PeerIdentitySnapshot, binding: &SshBinding) -> Result<(), String> {
        if peer.ssh.pid != binding.ssh_pid
            || peer.ssh.facts.start_time != binding.ssh_start_time
            || peer.ssh.facts.code_identity != binding.ssh_code_identity
        {
            return Err("ASKPASS peer 与 SSH 进程绑定不匹配。".to_string());
        }
        let app = self.inspect_app()?;
        if app != peer.app {
            return Err("ASKPASS 主应用进程身份快照已变化。".to_string());
        }
        let helper = self.inspector.process_facts(peer.helper.pid)?;
        if helper != peer.helper.facts
            || helper.executable != self.app.executable
            || helper.code_identity != self.app.code_identity
            || helper.parent_pid != peer.ssh.pid
        {
            return Err("ASKPASS helper 进程身份快照已变化。".to_string());
        }
        let ssh = self.inspect_ssh(peer.ssh.pid)?;
        if ssh != peer.ssh.facts {
            return Err("ASKPASS SSH 进程身份快照已变化。".to_string());
        }
        Ok(())
    }
}

struct RegisteredLaunch {
    snapshot: LaunchCredentialSnapshot,
    deadline: Instant,
    binding: Option<SshBinding>,
}

struct RegistryState {
    entries: HashMap<TokenDigest, RegisteredLaunch>,
    shutdown: bool,
}

struct RegistryInner {
    state: Mutex<RegistryState>,
    binding_changed: Condvar,
    verifier: Arc<dyn IdentityVerifier>,
    clock: Arc<dyn RegistryClock>,
    ticket_ttl: Duration,
    bind_wait: Duration,
    active_bind_waits: AtomicUsize,
    #[cfg(test)]
    token_lookups: std::sync::atomic::AtomicUsize,
}

#[derive(Clone)]
pub(crate) struct AskpassRegistry {
    inner: Arc<RegistryInner>,
}

impl AskpassRegistry {
    fn production() -> Result<Self, String> {
        Ok(Self::with_dependencies(
            Arc::new(ProcessIdentityVerifier::production()?),
            Arc::new(SystemClock),
            ASKPASS_TICKET_TTL,
            ASKPASS_BIND_WAIT,
        ))
    }

    fn with_dependencies(
        verifier: Arc<dyn IdentityVerifier>,
        clock: Arc<dyn RegistryClock>,
        ticket_ttl: Duration,
        bind_wait: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                state: Mutex::new(RegistryState {
                    entries: HashMap::new(),
                    shutdown: false,
                }),
                binding_changed: Condvar::new(),
                verifier,
                clock,
                ticket_ttl,
                bind_wait,
                active_bind_waits: AtomicUsize::new(0),
                #[cfg(test)]
                token_lookups: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    pub(crate) fn register(
        &self,
        snapshot: LaunchCredentialSnapshot,
    ) -> Result<PendingAskpassTicket, String> {
        let profile_revision = snapshot
            .profile
            .credential_revision
            .as_deref()
            .ok_or_else(|| "SSH 密码快照缺少凭据版本绑定。".to_string())
            .and_then(|revision| {
                uuid::Uuid::parse_str(revision)
                    .map_err(|_| "SSH 密码快照的凭据版本无效。".to_string())
            })?;
        if profile_revision != snapshot.revision {
            return Err("SSH 密码快照的凭据版本绑定不匹配。".to_string());
        }
        let profile_endpoint = endpoint_fingerprint(
            &snapshot.profile.host,
            snapshot.profile.port,
            &snapshot.profile.username,
        );
        if profile_endpoint != snapshot.endpoint {
            return Err("SSH 密码快照的 endpoint 绑定不匹配。".to_string());
        }
        if snapshot.password.len() > ASKPASS_MAX_PASSWORD_BYTES {
            return Err("SSH 密码凭据长度超出 ASKPASS broker 支持范围。".to_string());
        }
        if !(1..=120).contains(&snapshot.profile.connect_timeout) {
            return Err("SSH 连接超时超出 ASKPASS broker 支持范围。".to_string());
        }
        let profile_ttl = Duration::from_secs(u64::from(snapshot.profile.connect_timeout))
            .checked_add(ASKPASS_TICKET_GRACE)
            .ok_or_else(|| "ASKPASS capability 有效期超出支持范围。".to_string())?;
        let ticket_ttl = self.inner.ticket_ttl.max(profile_ttl);
        if ticket_ttl > ASKPASS_MAX_TICKET_TTL {
            return Err("ASKPASS capability 有效期超出支持范围。".to_string());
        }
        let now = self.inner.clock.now();
        let deadline = now
            .checked_add(ticket_ttl)
            .ok_or_else(|| "ASKPASS capability 截止时间超出支持范围。".to_string())?;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutdown {
            return Err("ASKPASS broker 已关闭。".to_string());
        }
        let pruned = prune_expired_entries(&mut state, now);
        if pruned {
            self.inner.binding_changed.notify_all();
        }
        let pending_tickets = state
            .entries
            .values()
            .filter(|entry| entry.binding.is_none())
            .count();
        if pending_tickets >= ASKPASS_MAX_PENDING_TICKETS {
            return Err("ASKPASS 待绑定 capability 数量已达到上限。".to_string());
        }
        let (token, digest) = loop {
            let token = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            let digest = token_digest(&token);
            if !state.entries.contains_key(&digest) {
                break (token, digest);
            }
        };
        state.entries.insert(
            digest,
            RegisteredLaunch {
                snapshot,
                deadline,
                binding: None,
            },
        );
        Ok(PendingAskpassTicket {
            registry: Arc::clone(&self.inner),
            digest,
            token: Zeroizing::new(token),
            active: true,
        })
    }

    fn consume(
        &self,
        capability_token: &str,
        peer: &PeerIdentitySnapshot,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let digest = token_digest(capability_token);
        let binding = self.wait_for_binding(digest)?;
        if peer.ssh.pid != binding.ssh_pid
            || peer.ssh.facts.start_time != binding.ssh_start_time
            || peer.ssh.facts.code_identity != binding.ssh_code_identity
        {
            return Err("ASKPASS peer 与已绑定 SSH 进程不匹配。".to_string());
        }
        self.inner
            .verifier
            .verify_peer(peer, &binding)
            .map_err(|_| "ASKPASS 请求进程身份校验失败。".to_string())?;

        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutdown {
            return Err("ASKPASS broker 已关闭。".to_string());
        }
        let entry = state
            .entries
            .get(&digest)
            .ok_or_else(|| "ASKPASS capability 不存在或已消费。".to_string())?;
        if self.is_expired(entry) {
            state.entries.remove(&digest);
            return Err("ASKPASS capability 已过期。".to_string());
        }
        if entry.binding.as_ref() != Some(&binding) {
            return Err("ASKPASS SSH 进程绑定已变化。".to_string());
        }
        let entry = state
            .entries
            .remove(&digest)
            .ok_or_else(|| "ASKPASS capability 不存在或已消费。".to_string())?;
        Ok(entry.snapshot.password)
    }

    fn wait_for_binding(&self, digest: TokenDigest) -> Result<SshBinding, String> {
        #[cfg(test)]
        self.inner
            .token_lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let started = Instant::now();
        let mut wait_slot = None;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.shutdown {
                return Err("ASKPASS broker 已关闭。".to_string());
            }
            let entry = state
                .entries
                .get(&digest)
                .ok_or_else(|| "ASKPASS capability 不存在或已取消。".to_string())?;
            if self.is_expired(entry) {
                state.entries.remove(&digest);
                return Err("ASKPASS capability 已过期。".to_string());
            }
            if let Some(binding) = &entry.binding {
                return Ok(binding.clone());
            }
            if wait_slot.is_none() {
                wait_slot = Some(self.try_acquire_bind_wait_slot()?);
            }

            let elapsed = started.elapsed();
            let remaining = self
                .inner
                .bind_wait
                .checked_sub(elapsed)
                .ok_or_else(|| "ASKPASS 等待 SSH 进程绑定超时。".to_string())?;
            let (next_state, wait_result) = self
                .inner
                .binding_changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next_state;
            if wait_result.timed_out() {
                return Err("ASKPASS 等待 SSH 进程绑定超时。".to_string());
            }
        }
    }

    fn try_acquire_bind_wait_slot(&self) -> Result<BindWaitSlot<'_>, String> {
        self.inner
            .active_bind_waits
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < ASKPASS_MAX_BIND_WAITERS).then_some(active + 1)
            })
            .map_err(|_| "ASKPASS 等待 SSH 进程绑定的请求过多。".to_string())?;
        Ok(BindWaitSlot {
            active_bind_waits: &self.inner.active_bind_waits,
        })
    }

    fn is_expired(&self, entry: &RegisteredLaunch) -> bool {
        self.inner.clock.now() >= entry.deadline
    }

    fn prune_expired(&self) {
        let now = self.inner.clock.now();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if prune_expired_entries(&mut state, now) {
            self.inner.binding_changed.notify_all();
        }
    }

    fn shutdown(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.shutdown = true;
        state.entries.clear();
        self.inner.binding_changed.notify_all();
    }

    fn capture_peer_identity(&self, helper_pid: u32) -> Result<PeerIdentitySnapshot, String> {
        self.inner
            .verifier
            .capture_peer(helper_pid)
            .map_err(|_| "ASKPASS socket 对端进程身份校验失败。".to_string())
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len()
    }

    #[cfg(test)]
    fn token_lookup_count(&self) -> usize {
        self.inner
            .token_lookups
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    fn active_bind_wait_count(&self) -> usize {
        self.inner.active_bind_waits.load(Ordering::SeqCst)
    }
}

struct BindWaitSlot<'a> {
    active_bind_waits: &'a AtomicUsize,
}

impl Drop for BindWaitSlot<'_> {
    fn drop(&mut self) {
        let previous = self.active_bind_waits.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

fn prune_expired_entries(state: &mut RegistryState, now: Instant) -> bool {
    let before = state.entries.len();
    state.entries.retain(|_, entry| now < entry.deadline);
    state.entries.len() != before
}

fn token_digest(token: &str) -> TokenDigest {
    Sha256::digest(token.as_bytes()).into()
}

fn cancel(inner: &RegistryInner, digest: TokenDigest) {
    let mut state = inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.entries.remove(&digest);
    inner.binding_changed.notify_all();
}

fn bind_ssh_with_retry(
    verifier: &Arc<dyn IdentityVerifier>,
    ssh_pid: u32,
    timeout: Duration,
) -> Result<SshBinding, String> {
    let started = Instant::now();
    loop {
        match verifier.bind_ssh(ssh_pid) {
            Ok(binding) => return Ok(binding),
            Err(error) => {
                let elapsed = started.elapsed();
                if elapsed >= timeout {
                    return Err(format!("无法绑定 ASKPASS SSH 进程身份：{error}"));
                }
                thread::sleep(ASKPASS_SSH_BIND_RETRY_INTERVAL.min(timeout - elapsed));
            }
        }
    }
}

pub(crate) struct PendingAskpassTicket {
    registry: Arc<RegistryInner>,
    digest: TokenDigest,
    token: Zeroizing<String>,
    active: bool,
}

impl PendingAskpassTicket {
    pub(crate) fn launch_env(&self, socket_path: &Path) -> Result<AskpassLaunchEnv, String> {
        if !self.active {
            return Err("ASKPASS capability 已取消。".to_string());
        }
        AskpassLaunchEnv::new(socket_path, self.token.as_str())
    }

    pub(crate) fn bind(mut self, ssh_pid: u32) -> Result<BoundAskpassTicket, String> {
        let binding = bind_ssh_with_retry(&self.registry.verifier, ssh_pid, self.registry.bind_wait)?;
        {
            let mut state = self
                .registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = self.registry.clock.now();
            let deadline = state
                .entries
                .get(&self.digest)
                .map(|entry| entry.deadline)
                .ok_or_else(|| "ASKPASS capability 不存在或已取消。".to_string())?;
            if now >= deadline {
                state.entries.remove(&self.digest);
                self.registry.binding_changed.notify_all();
                return Err("ASKPASS capability 已过期。".to_string());
            }
            if prune_expired_entries(&mut state, now) {
                self.registry.binding_changed.notify_all();
            }
            let bound_tickets = state
                .entries
                .values()
                .filter(|entry| entry.binding.is_some())
                .count();
            if bound_tickets >= ASKPASS_MAX_BOUND_TICKETS {
                return Err("ASKPASS 已绑定 capability 数量已达到上限。".to_string());
            }
            let entry = state
                .entries
                .get_mut(&self.digest)
                .ok_or_else(|| "ASKPASS capability 不存在或已取消。".to_string())?;
            if entry.binding.is_some() {
                return Err("ASKPASS capability 已绑定。".to_string());
            }
            entry.binding = Some(binding);
            self.registry.binding_changed.notify_all();
        }
        self.active = false;
        Ok(BoundAskpassTicket {
            registry: Arc::clone(&self.registry),
            digest: self.digest,
            active: true,
        })
    }
}

impl fmt::Debug for PendingAskpassTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAskpassTicket")
            .field("capability_token", &"<redacted>")
            .field("active", &self.active)
            .finish()
    }
}

impl Drop for PendingAskpassTicket {
    fn drop(&mut self) {
        if self.active {
            cancel(&self.registry, self.digest);
        }
    }
}

pub(crate) struct BoundAskpassTicket {
    registry: Arc<RegistryInner>,
    digest: TokenDigest,
    active: bool,
}

impl fmt::Debug for BoundAskpassTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundAskpassTicket")
            .field("capability_token", &"<redacted>")
            .field("active", &self.active)
            .finish()
    }
}

impl Drop for BoundAskpassTicket {
    fn drop(&mut self) {
        if self.active {
            cancel(&self.registry, self.digest);
        }
    }
}

pub(crate) struct AskpassBroker {
    registry: AskpassRegistry,
    socket_path: PathBuf,
    directory: PathBuf,
    shutdown: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
    workers: Vec<JoinHandle<()>>,
    health: BrokerRuntimeHealth,
}

type BrokerFailureCallback = Arc<dyn Fn(String) + Send + Sync>;

struct BrokerRuntimeHealthInner {
    healthy: AtomicBool,
    failure: Mutex<Option<String>>,
    failure_callback: BrokerFailureCallback,
}

#[derive(Clone)]
struct BrokerRuntimeHealth {
    inner: Arc<BrokerRuntimeHealthInner>,
}

impl BrokerRuntimeHealth {
    fn new(failure_callback: BrokerFailureCallback) -> Self {
        Self {
            inner: Arc::new(BrokerRuntimeHealthInner {
                healthy: AtomicBool::new(true),
                failure: Mutex::new(None),
                failure_callback,
            }),
        }
    }

    fn ensure_healthy(&self) -> Result<(), String> {
        if self.inner.healthy.load(Ordering::Acquire) {
            return Ok(());
        }
        Err(self
            .inner
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| "ASKPASS broker 运行状态异常。".to_string()))
    }

    fn fail(&self, registry: &AskpassRegistry, shutdown: &AtomicBool, failure: String) {
        let first_failure = self
            .inner
            .healthy
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        shutdown.store(true, Ordering::Release);
        registry.shutdown();
        if !first_failure {
            return;
        }
        *self
            .inner
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(failure.clone());
        let callback = Arc::clone(&self.inner.failure_callback);
        let _ = panic::catch_unwind(AssertUnwindSafe(move || callback(failure)));
    }
}

trait ConnectionAcceptor: Send + Sync {
    fn accept_connection(&self) -> io::Result<UnixStream>;
}

impl ConnectionAcceptor for UnixListener {
    fn accept_connection(&self) -> io::Result<UnixStream> {
        self.accept().map(|(stream, _)| stream)
    }
}

impl AskpassBroker {
    #[cfg(test)]
    pub(crate) fn start() -> Result<Self, String> {
        Self::start_with_failure_callback(|_| {})
    }

    pub(crate) fn start_with_failure_callback(
        failure_callback: impl Fn(String) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        Self::start_with_registry_and_callback(
            AskpassRegistry::production()?,
            Arc::new(failure_callback),
        )
    }

    #[cfg(test)]
    fn start_with_registry(registry: AskpassRegistry) -> Result<Self, String> {
        Self::start_with_registry_and_callback(registry, Arc::new(|_| {}))
    }

    fn start_with_registry_and_callback(
        registry: AskpassRegistry,
        failure_callback: BrokerFailureCallback,
    ) -> Result<Self, String> {
        let directory = create_private_socket_directory()?;
        let socket_path = directory.join("s");
        if socket_path.as_os_str().as_bytes().len() > ASKPASS_SOCKET_PATH_LIMIT {
            let _ = fs::remove_dir_all(&directory);
            return Err("ASKPASS broker socket 路径超出系统限制。".to_string());
        }
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_dir_all(&directory);
                return Err(format!("无法创建 ASKPASS broker socket：{error}"));
            }
        };
        if let Err(error) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
            drop(listener);
            let _ = fs::remove_dir_all(&directory);
            return Err(format!("无法设置 ASKPASS broker socket 权限：{error}"));
        }
        if let Err(error) = listener.set_nonblocking(true) {
            drop(listener);
            let _ = fs::remove_dir_all(&directory);
            return Err(format!("无法配置 ASKPASS broker socket：{error}"));
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let health = BrokerRuntimeHealth::new(failure_callback);
        let (connection_sender, connection_receiver) =
            std::sync::mpsc::sync_channel(ASKPASS_CONNECTION_QUEUE_CAPACITY);
        let connection_receiver = Arc::new(Mutex::new(connection_receiver));
        let mut workers = Vec::with_capacity(ASKPASS_WORKER_COUNT);
        for index in 0..ASKPASS_WORKER_COUNT {
            let worker_registry = registry.clone();
            let worker_shutdown = Arc::clone(&shutdown);
            let worker_receiver = Arc::clone(&connection_receiver);
            let worker_health = health.clone();
            match thread::Builder::new()
                .name(format!("ssh-askpass-worker-{index}"))
                .spawn(move || {
                    run_connection_worker(
                        worker_receiver,
                        worker_registry,
                        worker_shutdown,
                        worker_health,
                    )
                }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    registry.shutdown();
                    shutdown.store(true, Ordering::Release);
                    drop(connection_sender);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    drop(listener);
                    let _ = fs::remove_dir_all(&directory);
                    return Err(format!("无法启动 ASKPASS broker worker：{error}"));
                }
            }
        }
        let server_shutdown = Arc::clone(&shutdown);
        let server_registry = registry.clone();
        let server_health = health.clone();
        let acceptor: Arc<dyn ConnectionAcceptor> = Arc::new(listener);
        let server = thread::Builder::new()
            .name("ssh-askpass-broker-accept".into())
            .spawn(move || {
                run_accept_server(
                    acceptor,
                    server_registry,
                    server_shutdown,
                    connection_sender,
                    server_health,
                )
            })
            .map_err(|error| {
                registry.shutdown();
                shutdown.store(true, Ordering::Release);
                for worker in workers.drain(..) {
                    let _ = worker.join();
                }
                let _ = fs::remove_dir_all(&directory);
                format!("无法启动 ASKPASS broker 线程：{error}")
            })?;
        Ok(Self {
            registry,
            socket_path,
            directory,
            shutdown,
            server: Some(server),
            workers,
            health,
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn register(
        &self,
        snapshot: LaunchCredentialSnapshot,
    ) -> Result<PendingAskpassTicket, String> {
        self.ensure_healthy()?;
        self.registry.register(snapshot)
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), String> {
        self.health.ensure_healthy()
    }
}

impl fmt::Debug for AskpassBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AskpassBroker")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl Drop for AskpassBroker {
    fn drop(&mut self) {
        self.registry.shutdown();
        self.shutdown.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn create_private_socket_directory() -> Result<PathBuf, String> {
    let mut bases = vec![std::env::temp_dir()];
    if bases.first().map(PathBuf::as_path) != Some(Path::new("/tmp")) {
        bases.push(PathBuf::from("/tmp"));
    }
    for base in bases {
        for _ in 0..32 {
            let random = uuid::Uuid::new_v4().simple().to_string();
            let directory = base.join(format!("lcs-{}", &random[..16]));
            if directory.join("s").as_os_str().as_bytes().len() > ASKPASS_SOCKET_PATH_LIMIT {
                break;
            }
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&directory) {
                Ok(()) => {
                    if let Err(error) =
                        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                    {
                        let _ = fs::remove_dir_all(&directory);
                        return Err(format!("无法设置 ASKPASS broker 目录权限：{error}"));
                    }
                    return Ok(directory);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!("无法创建 ASKPASS broker 临时目录：{error}"));
                }
            }
        }
    }
    Err("无法创建满足 socket 路径长度限制的 ASKPASS broker 目录。".to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptErrorClass {
    Continue,
    Poll,
    ResourcePressure,
    Fatal,
}

fn classify_accept_error(error: &io::Error) -> AcceptErrorClass {
    match error.kind() {
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted => AcceptErrorClass::Continue,
        io::ErrorKind::WouldBlock => AcceptErrorClass::Poll,
        _ if error
            .raw_os_error()
            .is_some_and(|code| matches!(code, libc::EMFILE | libc::ENFILE | libc::ENOMEM)) =>
        {
            AcceptErrorClass::ResourcePressure
        }
        _ => AcceptErrorClass::Fatal,
    }
}

fn run_accept_server(
    acceptor: Arc<dyn ConnectionAcceptor>,
    registry: AskpassRegistry,
    shutdown: Arc<AtomicBool>,
    connection_sender: std::sync::mpsc::SyncSender<UnixStream>,
    health: BrokerRuntimeHealth,
) {
    let server_registry = registry.clone();
    let server_shutdown = Arc::clone(&shutdown);
    let server_health = health.clone();
    let result = panic::catch_unwind(AssertUnwindSafe(move || {
        serve_accept_loop(
            acceptor,
            server_registry,
            server_shutdown,
            connection_sender,
            server_health,
        )
    }));
    if result.is_err() && !shutdown.load(Ordering::Acquire) {
        health.fail(
            &registry,
            &shutdown,
            "ASKPASS broker accept 线程异常退出。".to_string(),
        );
    } else if !shutdown.load(Ordering::Acquire) {
        health.fail(
            &registry,
            &shutdown,
            "ASKPASS broker accept 线程意外停止。".to_string(),
        );
    }
}

fn serve_accept_loop(
    acceptor: Arc<dyn ConnectionAcceptor>,
    registry: AskpassRegistry,
    shutdown: Arc<AtomicBool>,
    connection_sender: std::sync::mpsc::SyncSender<UnixStream>,
    health: BrokerRuntimeHealth,
) {
    let mut resource_backoff = ASKPASS_ACCEPT_POLL_INTERVAL;
    while !shutdown.load(Ordering::Acquire) {
        registry.prune_expired();
        match acceptor.accept_connection() {
            Ok(stream) => {
                resource_backoff = ASKPASS_ACCEPT_POLL_INTERVAL;
                match connection_sender.try_send(stream) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        health.fail(
                            &registry,
                            &shutdown,
                            "ASKPASS broker worker 队列已断开。".to_string(),
                        );
                        break;
                    }
                }
            }
            Err(error) => match classify_accept_error(&error) {
                AcceptErrorClass::Continue => {}
                AcceptErrorClass::Poll => thread::sleep(ASKPASS_ACCEPT_POLL_INTERVAL),
                AcceptErrorClass::ResourcePressure => {
                    thread::sleep(resource_backoff);
                    resource_backoff = resource_backoff
                        .checked_mul(2)
                        .unwrap_or(ASKPASS_RESOURCE_BACKOFF_MAX)
                        .min(ASKPASS_RESOURCE_BACKOFF_MAX);
                }
                AcceptErrorClass::Fatal => {
                    health.fail(
                        &registry,
                        &shutdown,
                        format!("ASKPASS broker accept 失败：{error}"),
                    );
                    break;
                }
            },
        }
    }
}

fn run_connection_worker(
    connection_receiver: Arc<Mutex<std::sync::mpsc::Receiver<UnixStream>>>,
    registry: AskpassRegistry,
    shutdown: Arc<AtomicBool>,
    health: BrokerRuntimeHealth,
) {
    let worker_registry = registry.clone();
    let worker_shutdown = Arc::clone(&shutdown);
    let result = panic::catch_unwind(AssertUnwindSafe(move || {
        serve_connections(connection_receiver, worker_registry, worker_shutdown)
    }));
    if result.is_err() && !shutdown.load(Ordering::Acquire) {
        health.fail(
            &registry,
            &shutdown,
            "ASKPASS broker worker 线程异常退出。".to_string(),
        );
    } else if !shutdown.load(Ordering::Acquire) {
        health.fail(
            &registry,
            &shutdown,
            "ASKPASS broker worker 线程意外停止。".to_string(),
        );
    }
}

fn serve_connections(
    connection_receiver: Arc<Mutex<std::sync::mpsc::Receiver<UnixStream>>>,
    registry: AskpassRegistry,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let received = connection_receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv_timeout(ASKPASS_WORKER_POLL_INTERVAL);
        let mut stream = match received {
            Ok(stream) => stream,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let _ = stream.set_read_timeout(Some(ASKPASS_SERVER_READ_TIMEOUT));
        let _ = stream.set_write_timeout(Some(ASKPASS_IO_TIMEOUT));
        if handle_connection(&mut stream, &registry).is_err() {
            let _ = write_frame(&mut stream, &[ASKPASS_FAILURE]);
        }
    }
}

fn handle_connection(stream: &mut UnixStream, registry: &AskpassRegistry) -> Result<(), String> {
    let helper_pid = peer_pid(stream)?;
    let peer = registry.capture_peer_identity(helper_pid)?;
    let token = read_frame(stream, ASKPASS_MAX_REQUEST_BYTES)
        .map_err(|_| "ASKPASS 请求协议无效。".to_string())?;
    let token = std::str::from_utf8(&token)
        .ok()
        .filter(|token| token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "ASKPASS capability 格式无效。".to_string())?;
    let password = registry.consume(token, &peer)?;
    if password.len() > ASKPASS_MAX_PASSWORD_BYTES {
        return Err("ASKPASS 响应超出协议上限。".to_string());
    }
    let mut response = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    response.push(ASKPASS_SUCCESS);
    response.extend_from_slice(&password);
    write_frame(stream, &response).map_err(|_| "无法写入 ASKPASS 响应。".to_string())
}

pub(super) fn read_frame(reader: &mut impl Read, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ASKPASS frame length is invalid",
        ));
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

pub(super) fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ASKPASS frame is too large"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Result<u32, String> {
    use std::os::fd::AsRawFd;

    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::pid_t>() || pid <= 0 {
        return Err("无法获取 ASKPASS socket 对端进程身份。".to_string());
    }
    u32::try_from(pid).map_err(|_| "ASKPASS socket 对端进程 ID 无效。".to_string())
}

#[cfg(not(target_os = "macos"))]
fn peer_pid(_stream: &UnixStream) -> Result<u32, String> {
    Err("当前平台不支持 macOS LOCAL_PEERPID 校验。".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        handle_connection, peer_pid, read_frame, run_accept_server, write_frame, AskpassBroker,
        AskpassRegistry, BrokerRuntimeHealth, ConnectionAcceptor, PeerIdentitySnapshot,
        ProcessFacts, ProcessIdentityVerifier, ProcessInspector, RegistryClock, SshBinding,
        ASKPASS_BIND_WAIT, ASKPASS_IO_TIMEOUT, ASKPASS_MAX_REQUEST_BYTES,
        ASKPASS_SOCKET_PATH_LIMIT, ASKPASS_TICKET_TTL,
    };
    use crate::ssh::{
        credential_snapshot_for_launch,
        credentials::{endpoint_fingerprint, LaunchCredentialSnapshot},
        process::{ASKPASS_SOCKET_ENV, ASKPASS_TOKEN_ENV},
        upsert_profile_with_credential, CredentialStore, CredentialUpdate, SshAuthType, SshProfile,
    };
    use std::{
        collections::{HashMap, VecDeque},
        io::{self, Cursor, Write},
        os::unix::net::{UnixListener, UnixStream},
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
            Arc, Barrier, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;

    const SSH_PID: u32 = 71_001;
    const HELPER_PID: u32 = 71_002;
    const APP_PID: u32 = 71_003;
    const SHELL_PID: u32 = 71_004;
    const SECRET: &[u8] = b"registry-snapshot-secret";
    const APP_PATH: &str = "/Applications/LeviQian Codex.app/Contents/MacOS/leviqian-codex";
    const APP_CODE_IDENTITY: [u8; 20] = [0x11; 20];
    const SSH_CODE_IDENTITY: [u8; 20] = [0x22; 20];

    fn fake_peer(helper_pid: u32) -> PeerIdentitySnapshot {
        PeerIdentitySnapshot {
            app: super::ProcessIdentitySnapshot {
                pid: APP_PID,
                facts: ProcessFacts {
                    executable: PathBuf::from(APP_PATH),
                    parent_pid: 1,
                    start_time: 1_000,
                    code_identity: APP_CODE_IDENTITY,
                },
            },
            helper: super::ProcessIdentitySnapshot {
                pid: helper_pid,
                facts: ProcessFacts {
                    executable: PathBuf::from(APP_PATH),
                    parent_pid: SSH_PID,
                    start_time: 3_000,
                    code_identity: APP_CODE_IDENTITY,
                },
            },
            ssh: super::ProcessIdentitySnapshot {
                pid: SSH_PID,
                facts: ProcessFacts {
                    executable: PathBuf::from("/usr/bin/ssh"),
                    parent_pid: APP_PID,
                    start_time: 9_001,
                    code_identity: SSH_CODE_IDENTITY,
                },
            },
        }
    }

    struct FakeClock(Mutex<Instant>);

    impl FakeClock {
        fn new() -> Self {
            Self(Mutex::new(Instant::now()))
        }

        fn advance(&self, duration: Duration) {
            *self.0.lock().unwrap() += duration;
        }
    }

    impl RegistryClock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    struct FakeIdentityVerifier;

    impl super::IdentityVerifier for FakeIdentityVerifier {
        fn capture_peer(&self, helper_pid: u32) -> Result<PeerIdentitySnapshot, String> {
            if helper_pid != HELPER_PID {
                return Err("helper identity mismatch".into());
            }
            Ok(fake_peer(helper_pid))
        }

        fn bind_ssh(&self, ssh_pid: u32) -> Result<SshBinding, String> {
            if ssh_pid != SSH_PID {
                return Err("SSH identity mismatch".into());
            }
            Ok(SshBinding {
                ssh_pid,
                ssh_start_time: 9_001,
                ssh_code_identity: SSH_CODE_IDENTITY,
            })
        }

        fn verify_peer(
            &self,
            peer: &PeerIdentitySnapshot,
            binding: &SshBinding,
        ) -> Result<(), String> {
            if peer == &fake_peer(HELPER_PID)
                && binding.ssh_pid == SSH_PID
                && binding.ssh_start_time == 9_001
                && binding.ssh_code_identity == SSH_CODE_IDENTITY
            {
                Ok(())
            } else {
                Err("helper identity mismatch".into())
            }
        }
    }

    struct DelayedBindIdentityVerifier {
        transient_failures: Mutex<usize>,
        attempts: AtomicUsize,
    }

    impl super::IdentityVerifier for DelayedBindIdentityVerifier {
        fn capture_peer(&self, helper_pid: u32) -> Result<PeerIdentitySnapshot, String> {
            if helper_pid != HELPER_PID {
                return Err("helper identity mismatch".into());
            }
            Ok(fake_peer(helper_pid))
        }

        fn bind_ssh(&self, ssh_pid: u32) -> Result<SshBinding, String> {
            self.attempts.fetch_add(1, AtomicOrdering::SeqCst);
            let mut transient_failures = self.transient_failures.lock().unwrap();
            if *transient_failures > 0 {
                *transient_failures -= 1;
                return Err("SSH process has not execed yet".into());
            }
            if ssh_pid != SSH_PID {
                return Err("SSH identity mismatch".into());
            }
            Ok(SshBinding {
                ssh_pid,
                ssh_start_time: 9_001,
                ssh_code_identity: SSH_CODE_IDENTITY,
            })
        }

        fn verify_peer(
            &self,
            peer: &PeerIdentitySnapshot,
            binding: &SshBinding,
        ) -> Result<(), String> {
            if peer == &fake_peer(HELPER_PID) && binding.ssh_pid == SSH_PID {
                Ok(())
            } else {
                Err("helper identity mismatch".into())
            }
        }
    }

    struct CurrentHelperIdentityVerifier;

    impl super::IdentityVerifier for CurrentHelperIdentityVerifier {
        fn capture_peer(&self, helper_pid: u32) -> Result<PeerIdentitySnapshot, String> {
            if helper_pid != std::process::id() {
                return Err("helper identity mismatch".into());
            }
            Ok(fake_peer(helper_pid))
        }

        fn bind_ssh(&self, ssh_pid: u32) -> Result<SshBinding, String> {
            if ssh_pid != SSH_PID {
                return Err("SSH identity mismatch".into());
            }
            Ok(SshBinding {
                ssh_pid,
                ssh_start_time: 9_001,
                ssh_code_identity: SSH_CODE_IDENTITY,
            })
        }

        fn verify_peer(
            &self,
            peer: &PeerIdentitySnapshot,
            binding: &SshBinding,
        ) -> Result<(), String> {
            if peer == &fake_peer(std::process::id()) && binding.ssh_pid == SSH_PID {
                Ok(())
            } else {
                Err("helper identity mismatch".into())
            }
        }
    }

    struct RejectingPeerIdentityVerifier {
        capture_calls: AtomicUsize,
    }

    impl super::IdentityVerifier for RejectingPeerIdentityVerifier {
        fn capture_peer(&self, _helper_pid: u32) -> Result<PeerIdentitySnapshot, String> {
            self.capture_calls.fetch_add(1, AtomicOrdering::SeqCst);
            Err("wrong peer identity".into())
        }

        fn bind_ssh(&self, _ssh_pid: u32) -> Result<SshBinding, String> {
            panic!("wrong peer must fail before binding")
        }

        fn verify_peer(
            &self,
            _peer: &PeerIdentitySnapshot,
            _binding: &SshBinding,
        ) -> Result<(), String> {
            panic!("wrong peer must fail before registry verification")
        }
    }

    struct FakeProcessInspector {
        facts: Mutex<HashMap<u32, ProcessFacts>>,
        original: HashMap<u32, ProcessFacts>,
    }

    enum ScriptedAcceptStep {
        Error(io::Error),
        Stop,
        Panic,
    }

    struct ScriptedAcceptor {
        steps: Mutex<VecDeque<ScriptedAcceptStep>>,
        calls: AtomicUsize,
        shutdown: Arc<AtomicBool>,
    }

    impl ScriptedAcceptor {
        fn new(steps: Vec<ScriptedAcceptStep>, shutdown: Arc<AtomicBool>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
                calls: AtomicUsize::new(0),
                shutdown,
            }
        }
    }

    impl ConnectionAcceptor for ScriptedAcceptor {
        fn accept_connection(&self) -> io::Result<UnixStream> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            match self.steps.lock().unwrap().pop_front().unwrap() {
                ScriptedAcceptStep::Error(error) => Err(error),
                ScriptedAcceptStep::Stop => {
                    self.shutdown.store(true, AtomicOrdering::Release);
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                }
                ScriptedAcceptStep::Panic => panic!("scripted accept panic"),
            }
        }
    }

    #[derive(Default)]
    struct MemoryCredentialStore(Mutex<HashMap<String, Vec<u8>>>);

    impl CredentialStore for MemoryCredentialStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }

        fn set(&self, account: &str, password: &[u8]) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .insert(account.to_string(), password.to_vec());
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(account);
            Ok(())
        }
    }

    impl FakeProcessInspector {
        fn new() -> Self {
            let original = HashMap::from([
                (
                    APP_PID,
                    ProcessFacts {
                        executable: PathBuf::from(APP_PATH),
                        parent_pid: 1,
                        start_time: 1_000,
                        code_identity: APP_CODE_IDENTITY,
                    },
                ),
                (
                    SSH_PID,
                    ProcessFacts {
                        executable: PathBuf::from("/usr/bin/ssh"),
                        parent_pid: APP_PID,
                        start_time: 2_000,
                        code_identity: SSH_CODE_IDENTITY,
                    },
                ),
                (
                    HELPER_PID,
                    ProcessFacts {
                        executable: PathBuf::from(APP_PATH),
                        parent_pid: SSH_PID,
                        start_time: 3_000,
                        code_identity: APP_CODE_IDENTITY,
                    },
                ),
            ]);
            Self {
                facts: Mutex::new(original.clone()),
                original,
            }
        }

        fn mutate(&self, pid: u32, update: impl FnOnce(&mut ProcessFacts)) {
            update(self.facts.lock().unwrap().get_mut(&pid).unwrap());
        }

        fn restore(&self) {
            *self.facts.lock().unwrap() = self.original.clone();
        }
    }

    impl ProcessInspector for FakeProcessInspector {
        fn process_facts(&self, pid: u32) -> Result<ProcessFacts, String> {
            self.facts
                .lock()
                .unwrap()
                .get(&pid)
                .cloned()
                .ok_or_else(|| "missing process facts".into())
        }
    }

    fn snapshot() -> LaunchCredentialSnapshot {
        let revision = uuid::Uuid::new_v4();
        let profile = SshProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Registry fixture".into(),
            host: "example.com".into(),
            port: 22,
            username: "deploy".into(),
            auth_type: SshAuthType::Password,
            identity_file: None,
            connect_timeout: 15,
            credential_revision: Some(revision.to_string()),
        };
        LaunchCredentialSnapshot {
            endpoint: endpoint_fingerprint(&profile.host, profile.port, &profile.username),
            profile,
            revision,
            password: Zeroizing::new(SECRET.to_vec()),
        }
    }

    fn registry(clock: Arc<FakeClock>, bind_wait: Duration) -> AskpassRegistry {
        AskpassRegistry::with_dependencies(
            Arc::new(FakeIdentityVerifier),
            clock,
            ASKPASS_TICKET_TTL,
            bind_wait,
        )
    }

    #[test]
    fn register_rejects_snapshot_with_mismatched_revision() {
        let registry = registry(Arc::new(FakeClock::new()), ASKPASS_BIND_WAIT);
        let mut launch = snapshot();
        launch.revision = uuid::Uuid::new_v4();

        let error = registry.register(launch).unwrap_err();

        assert_eq!(error, "SSH 密码快照的凭据版本绑定不匹配。");
        assert_eq!(registry.entry_count(), 0);
    }

    #[test]
    fn register_rejects_snapshot_with_mismatched_endpoint() {
        let registry = registry(Arc::new(FakeClock::new()), ASKPASS_BIND_WAIT);
        let mut launch = snapshot();
        launch.endpoint = endpoint_fingerprint("other.example.com", 22, "deploy");

        let error = registry.register(launch).unwrap_err();

        assert_eq!(error, "SSH 密码快照的 endpoint 绑定不匹配。");
        assert_eq!(registry.entry_count(), 0);
    }

    fn consume_as_helper(
        registry: &AskpassRegistry,
        token: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let peer = registry.capture_peer_identity(HELPER_PID)?;
        registry.consume(token, &peer)
    }

    fn assert_identity_tamper_does_not_consume(tamper: impl FnOnce(&FakeProcessInspector)) {
        let clock = Arc::new(FakeClock::new());
        let inspector = Arc::new(FakeProcessInspector::new());
        let verifier = ProcessIdentityVerifier::new(
            Arc::clone(&inspector) as Arc<dyn ProcessInspector>,
            APP_PID,
            PathBuf::from(APP_PATH),
        )
        .unwrap();
        let registry = AskpassRegistry::with_dependencies(
            Arc::new(verifier),
            clock,
            ASKPASS_TICKET_TTL,
            ASKPASS_BIND_WAIT,
        );
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let _bound = pending.bind(SSH_PID).unwrap();
        let peer = registry.capture_peer_identity(HELPER_PID).unwrap();
        tamper(&inspector);

        assert!(registry.consume(&token, &peer).is_err());
        inspector.restore();
        assert_eq!(registry.consume(&token, &peer).unwrap().as_slice(), SECRET);
    }

    fn token_of(pending: &super::PendingAskpassTicket) -> String {
        let env = pending
            .launch_env(Path::new("/tmp/codex-askpass/broker.sock"))
            .unwrap();
        assert_eq!(env.socket_path(), "/tmp/codex-askpass/broker.sock");
        assert!(!format!("{env:?}").contains(env.capability_token()));
        env.capability_token().to_string()
    }

    #[test]
    fn exact_identity_consumes_registered_snapshot_once() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(clock, ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let _bound = pending.bind(SSH_PID).unwrap();

        let password = consume_as_helper(&registry, &token).unwrap();

        assert_eq!(password.as_slice(), SECRET);
        assert!(consume_as_helper(&registry, &token).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wrong_peer_identity_fails_before_reading_or_looking_up_token() {
        let verifier = Arc::new(RejectingPeerIdentityVerifier {
            capture_calls: AtomicUsize::new(0),
        });
        let registry = AskpassRegistry::with_dependencies(
            Arc::clone(&verifier) as Arc<dyn super::IdentityVerifier>,
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            Duration::from_secs(1),
        );
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let nonexistent_token = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        write_frame(&mut client, nonexistent_token.as_bytes()).unwrap();

        let error = handle_connection(&mut server, &registry).unwrap_err();

        assert_eq!(verifier.capture_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(registry.token_lookup_count(), 0);
        assert!(!error.contains(nonexistent_token));
    }

    #[test]
    fn reused_helper_pid_with_changed_start_time_does_not_consume_token() {
        let inspector = Arc::new(FakeProcessInspector::new());
        let verifier = ProcessIdentityVerifier::new(
            Arc::clone(&inspector) as Arc<dyn ProcessInspector>,
            APP_PID,
            PathBuf::from(APP_PATH),
        )
        .unwrap();
        let registry = AskpassRegistry::with_dependencies(
            Arc::new(verifier),
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            ASKPASS_BIND_WAIT,
        );
        let peer = registry.capture_peer_identity(HELPER_PID).unwrap();
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let _bound = pending.bind(SSH_PID).unwrap();
        inspector.mutate(HELPER_PID, |facts| facts.start_time += 1);

        assert!(registry.consume(&token, &peer).is_err());
        inspector.restore();
        assert_eq!(registry.consume(&token, &peer).unwrap().as_slice(), SECRET);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn helper_cdhash_mismatch_fails_before_token_lookup_or_frame_read() {
        let inspector = Arc::new(FakeProcessInspector::new());
        inspector.facts.lock().unwrap().insert(
            std::process::id(),
            ProcessFacts {
                executable: PathBuf::from(APP_PATH),
                parent_pid: SSH_PID,
                start_time: 4_000,
                code_identity: [0x44; 20],
            },
        );
        let verifier = ProcessIdentityVerifier::new(
            Arc::clone(&inspector) as Arc<dyn ProcessInspector>,
            APP_PID,
            PathBuf::from(APP_PATH),
        )
        .unwrap();
        let registry = AskpassRegistry::with_dependencies(
            Arc::new(verifier),
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            ASKPASS_BIND_WAIT,
        );
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let token = b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        write_frame(&mut client, token).unwrap();

        assert!(handle_connection(&mut server, &registry).is_err());
        assert_eq!(registry.token_lookup_count(), 0);
        assert_eq!(
            read_frame(&mut server, ASKPASS_MAX_REQUEST_BYTES)
                .unwrap()
                .as_slice(),
            token
        );
    }

    #[test]
    fn changed_helper_cdhash_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(HELPER_PID, |facts| facts.code_identity[0] ^= 0xff);
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_process_inspector_returns_nonzero_current_process_cdhash() {
        let facts = super::RealProcessInspector
            .process_facts(std::process::id())
            .unwrap();

        assert!(facts.code_identity.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn concurrent_requests_allow_at_most_one_success() {
        let clock = Arc::new(FakeClock::new());
        let registry = Arc::new(registry(clock, ASKPASS_BIND_WAIT));
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let _bound = pending.bind(SSH_PID).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let registry = Arc::clone(&registry);
            let token = token.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                consume_as_helper(&registry, &token).is_ok()
            }));
        }
        barrier.wait();

        let successes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|succeeded| *succeeded)
            .count();

        assert_eq!(successes, 1);
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(Arc::clone(&clock), ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let _bound = pending.bind(SSH_PID).unwrap();
        clock.advance(Duration::from_secs(46));

        assert!(consume_as_helper(&registry, &token).is_err());
    }

    #[test]
    fn connect_timeout_extends_ticket_deadline_to_150_seconds() {
        for elapsed in [Duration::from_secs(31), Duration::from_secs(120)] {
            let clock = Arc::new(FakeClock::new());
            let registry = registry(Arc::clone(&clock), ASKPASS_BIND_WAIT);
            let mut launch = snapshot();
            launch.profile.connect_timeout = 120;
            let pending = registry.register(launch).unwrap();
            let token = token_of(&pending);
            clock.advance(elapsed);

            let _bound = pending.bind(SSH_PID).unwrap();
            assert_eq!(
                consume_as_helper(&registry, &token).unwrap().as_slice(),
                SECRET
            );
        }

        let clock = Arc::new(FakeClock::new());
        let registry = registry(Arc::clone(&clock), ASKPASS_BIND_WAIT);
        let mut launch = snapshot();
        launch.profile.connect_timeout = 120;
        let pending = registry.register(launch).unwrap();
        clock.advance(Duration::from_secs(151));

        assert!(pending.bind(SSH_PID).is_err());
        assert_eq!(registry.entry_count(), 0);
    }

    #[test]
    fn server_prunes_expired_bound_snapshot_without_ticket_drop() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(Arc::clone(&clock), ASKPASS_BIND_WAIT);
        let broker = AskpassBroker::start_with_registry(registry.clone()).unwrap();
        let pending = registry.register(snapshot()).unwrap();
        let bound = pending.bind(SSH_PID).unwrap();
        assert_eq!(registry.entry_count(), 1);
        clock.advance(Duration::from_secs(46));
        let deadline = Instant::now() + Duration::from_millis(500);

        while registry.entry_count() != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(registry.entry_count(), 0);
        drop(bound);
        drop(broker);
    }

    #[test]
    fn register_prunes_expired_bound_snapshot_without_ticket_drop() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(Arc::clone(&clock), ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let bound = pending.bind(SSH_PID).unwrap();
        clock.advance(Duration::from_secs(46));

        let next = registry.register(snapshot()).unwrap();

        assert_eq!(registry.entry_count(), 1);
        drop(bound);
        drop(next);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bound_request_is_not_blocked_by_two_unbound_clients() {
        let registry = AskpassRegistry::with_dependencies(
            Arc::new(CurrentHelperIdentityVerifier),
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            ASKPASS_BIND_WAIT,
        );
        let broker = AskpassBroker::start_with_registry(registry.clone()).unwrap();
        let first_pending = registry.register(snapshot()).unwrap();
        let first_token = token_of(&first_pending);
        let second_pending = registry.register(snapshot()).unwrap();
        let second_token = token_of(&second_pending);
        let ready_pending = registry.register(snapshot()).unwrap();
        let ready_token = token_of(&ready_pending);
        let ready_bound = ready_pending.bind(SSH_PID).unwrap();

        let first_socket = broker.socket_path().to_path_buf();
        let first = thread::spawn(move || {
            crate::ssh::askpass::request_password(&first_socket, &first_token)
        });
        let entered_deadline = Instant::now() + Duration::from_millis(500);
        while registry.token_lookup_count() < 1 && Instant::now() < entered_deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(registry.token_lookup_count(), 1);

        let second_socket = broker.socket_path().to_path_buf();
        let second = thread::spawn(move || {
            crate::ssh::askpass::request_password(&second_socket, &second_token)
        });
        thread::sleep(Duration::from_millis(50));
        let started = Instant::now();

        let ready = crate::ssh::askpass::request_password(broker.socket_path(), &ready_token);

        let first_result = first.join().unwrap();
        let second_result = second.join().unwrap();
        assert!(first_result.is_err());
        assert!(second_result.is_err());
        assert_eq!(ready.unwrap().as_slice(), SECRET);
        assert!(started.elapsed() < ASKPASS_IO_TIMEOUT);
        drop(first_pending);
        drop(second_pending);
        drop(ready_bound);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bound_request_is_not_starved_by_seven_unbound_clients() {
        let registry = AskpassRegistry::with_dependencies(
            Arc::new(CurrentHelperIdentityVerifier),
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            ASKPASS_BIND_WAIT,
        );
        let broker = AskpassBroker::start_with_registry(registry.clone()).unwrap();
        let mut pending_tickets = Vec::new();
        let mut unbound_requests = Vec::new();
        for _ in 0..7 {
            let pending = registry.register(snapshot()).unwrap();
            let token = token_of(&pending);
            let socket = broker.socket_path().to_path_buf();
            pending_tickets.push(pending);
            unbound_requests.push(thread::spawn(move || {
                crate::ssh::askpass::request_password(&socket, &token)
            }));
        }
        let lookup_deadline = Instant::now() + Duration::from_millis(500);
        while registry.token_lookup_count() < 4 && Instant::now() < lookup_deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(registry.token_lookup_count() >= 4);
        thread::sleep(Duration::from_millis(50));

        let ready_pending = registry.register(snapshot()).unwrap();
        let ready_token = token_of(&ready_pending);
        let ready_bound = ready_pending.bind(SSH_PID).unwrap();
        let started = Instant::now();
        let ready = crate::ssh::askpass::request_password(broker.socket_path(), &ready_token);
        let ready_elapsed = started.elapsed();

        for request in unbound_requests {
            assert!(request.join().unwrap().is_err());
        }
        assert_eq!(ready.unwrap().as_slice(), SECRET);
        assert!(ready_elapsed < ASKPASS_IO_TIMEOUT);
        drop(pending_tickets);
        drop(ready_bound);
    }

    #[test]
    fn pending_ticket_quota_rejects_ninth_and_releases_after_drop() {
        let registry = registry(Arc::new(FakeClock::new()), ASKPASS_BIND_WAIT);
        let mut pending_tickets = (0..8)
            .map(|_| registry.register(snapshot()).unwrap())
            .collect::<Vec<_>>();

        let error = registry.register(snapshot()).unwrap_err();

        assert_eq!(error, "ASKPASS 待绑定 capability 数量已达到上限。");
        assert_eq!(registry.entry_count(), 8);

        drop(pending_tickets.remove(0));
        let replacement = registry.register(snapshot()).unwrap();

        assert_eq!(registry.entry_count(), 8);
        drop(pending_tickets);
        drop(replacement);
    }

    #[test]
    fn bound_ticket_quota_allows_eight_rejects_ninth_and_releases_after_drop() {
        let registry = registry(Arc::new(FakeClock::new()), ASKPASS_BIND_WAIT);
        let mut bound_tickets = (0..8)
            .map(|_| {
                registry
                    .register(snapshot())
                    .unwrap()
                    .bind(SSH_PID)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let ninth_pending = registry.register(snapshot()).unwrap();

        let error = ninth_pending.bind(SSH_PID).unwrap_err();

        assert_eq!(error, "ASKPASS 已绑定 capability 数量已达到上限。");
        assert_eq!(registry.entry_count(), 8);

        drop(bound_tickets.remove(0));
        let replacement_bound = registry
            .register(snapshot())
            .unwrap()
            .bind(SSH_PID)
            .unwrap();

        assert_eq!(registry.entry_count(), 8);
        drop(bound_tickets);
        drop(replacement_bound);
    }

    #[test]
    fn bind_wait_quota_is_released_after_cancel() {
        let registry = Arc::new(registry(
            Arc::new(FakeClock::new()),
            Duration::from_millis(500),
        ));
        let mut pending_tickets = Vec::new();
        let mut waiters = Vec::new();
        for _ in 0..3 {
            let pending = registry.register(snapshot()).unwrap();
            let token = token_of(&pending);
            let waiter_registry = Arc::clone(&registry);
            pending_tickets.push(pending);
            waiters.push(thread::spawn(move || {
                consume_as_helper(&waiter_registry, &token)
            }));
        }
        let occupied_deadline = Instant::now() + Duration::from_millis(250);
        while registry.active_bind_wait_count() < 3 && Instant::now() < occupied_deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(registry.active_bind_wait_count(), 3);

        let rejected_pending = registry.register(snapshot()).unwrap();
        let rejected_token = token_of(&rejected_pending);
        let rejected_at = Instant::now();
        assert!(consume_as_helper(&registry, &rejected_token).is_err());
        assert!(rejected_at.elapsed() < Duration::from_millis(250));
        assert_eq!(registry.active_bind_wait_count(), 3);

        drop(pending_tickets.remove(0));
        assert!(waiters.remove(0).join().unwrap().is_err());
        let released_deadline = Instant::now() + Duration::from_millis(250);
        while registry.active_bind_wait_count() != 2 && Instant::now() < released_deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(registry.active_bind_wait_count(), 2);

        let next_pending = registry.register(snapshot()).unwrap();
        let next_token = token_of(&next_pending);
        let next_registry = Arc::clone(&registry);
        let next_waiter = thread::spawn(move || consume_as_helper(&next_registry, &next_token));
        let reused_deadline = Instant::now() + Duration::from_millis(250);
        while registry.active_bind_wait_count() < 3 && Instant::now() < reused_deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(registry.active_bind_wait_count(), 3);
        let next_bound = next_pending.bind(SSH_PID).unwrap();
        assert_eq!(next_waiter.join().unwrap().unwrap().as_slice(), SECRET);

        drop(pending_tickets);
        for waiter in waiters {
            assert!(waiter.join().unwrap().is_err());
        }
        drop(rejected_pending);
        drop(next_bound);
        assert_eq!(registry.active_bind_wait_count(), 0);
    }

    #[test]
    fn transient_accept_errors_continue_with_bounded_resource_backoff() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let acceptor = Arc::new(ScriptedAcceptor::new(
            vec![
                ScriptedAcceptStep::Error(io::Error::from(io::ErrorKind::Interrupted)),
                ScriptedAcceptStep::Error(io::Error::from(io::ErrorKind::ConnectionAborted)),
                ScriptedAcceptStep::Error(io::Error::from(io::ErrorKind::WouldBlock)),
                ScriptedAcceptStep::Error(io::Error::from_raw_os_error(libc::EMFILE)),
                ScriptedAcceptStep::Error(io::Error::from_raw_os_error(libc::ENFILE)),
                ScriptedAcceptStep::Error(io::Error::from_raw_os_error(libc::ENOMEM)),
                ScriptedAcceptStep::Stop,
            ],
            Arc::clone(&shutdown),
        ));
        let registry = registry(Arc::new(FakeClock::new()), ASKPASS_BIND_WAIT);
        let health = BrokerRuntimeHealth::new(Arc::new(|_| {}));
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

        run_accept_server(
            Arc::clone(&acceptor) as Arc<dyn ConnectionAcceptor>,
            registry.clone(),
            Arc::clone(&shutdown),
            sender,
            health.clone(),
        );

        assert_eq!(acceptor.calls.load(AtomicOrdering::SeqCst), 7);
        assert!(health.ensure_healthy().is_ok());
        assert!(!registry.inner.state.lock().unwrap().shutdown);
        drop(receiver);
    }

    #[test]
    fn fatal_accept_error_shuts_down_registry_and_reports_health() {
        let directory = std::env::temp_dir().join(format!(
            "lc-runtime-health-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let credentials = MemoryCredentialStore::default();
        let state = crate::AppState::default();
        let recovery = Arc::clone(&state.ssh_recovery);
        let health = BrokerRuntimeHealth::new(Arc::new(move |error| {
            recovery.record_broker_failure(error);
        }));
        let shutdown = Arc::new(AtomicBool::new(false));
        let acceptor = Arc::new(ScriptedAcceptor::new(
            vec![ScriptedAcceptStep::Error(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fatal accept fixture",
            ))],
            Arc::clone(&shutdown),
        ));
        let registry = registry(Arc::new(FakeClock::new()), ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

        run_accept_server(
            acceptor as Arc<dyn ConnectionAcceptor>,
            registry.clone(),
            Arc::clone(&shutdown),
            sender,
            health.clone(),
        );

        assert_eq!(registry.entry_count(), 0);
        assert!(registry.register(snapshot()).is_err());
        assert!(health.ensure_healthy().is_err());
        assert!(state
            .ssh_recovery
            .ensure_ready()
            .unwrap_err()
            .contains("fatal"));
        state.ssh_recovery.retry(&directory, &credentials).unwrap();
        assert!(state
            .ssh_recovery
            .ensure_ready()
            .unwrap_err()
            .contains("fatal"));
        assert!(state.sessions.lock().unwrap().is_empty());
        drop(pending);
        drop(receiver);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn runtime_failure_during_startup_is_not_overwritten_by_start_success() {
        let directory = std::env::temp_dir().join(format!(
            "lc-runtime-start-race-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let credentials = MemoryCredentialStore::default();
        let state = crate::AppState::default();
        let broker = AskpassBroker::start_with_registry(registry(
            Arc::new(FakeClock::new()),
            ASKPASS_BIND_WAIT,
        ))
        .unwrap();

        crate::attempt_ssh_subsystem_startup(
            &state.ssh_recovery,
            &state.ssh_broker,
            Ok(directory.clone()),
            &credentials,
            || {
                state
                    .ssh_recovery
                    .record_broker_failure("runtime-start-race".into());
                Ok(broker)
            },
        );

        assert!(state
            .ssh_recovery
            .ensure_ready()
            .unwrap_err()
            .contains("runtime-start-race"));
        drop(state);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn accept_server_panic_fails_closed() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let acceptor = Arc::new(ScriptedAcceptor::new(
            vec![ScriptedAcceptStep::Panic],
            Arc::clone(&shutdown),
        ));
        let registry = registry(Arc::new(FakeClock::new()), ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let health = BrokerRuntimeHealth::new(Arc::new(|_| {}));
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

        run_accept_server(
            acceptor as Arc<dyn ConnectionAcceptor>,
            registry.clone(),
            Arc::clone(&shutdown),
            sender,
            health.clone(),
        );

        assert!(health.ensure_healthy().is_err());
        assert_eq!(registry.entry_count(), 0);
        assert!(registry.register(snapshot()).is_err());
        drop(pending);
        drop(receiver);
    }

    #[test]
    fn dropping_pending_ticket_cancels_token() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(clock, ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        drop(pending);

        assert!(consume_as_helper(&registry, &token).is_err());
    }

    #[test]
    fn dropping_bound_ticket_cancels_token() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(clock, ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let bound = pending.bind(SSH_PID).unwrap();
        drop(bound);

        assert!(consume_as_helper(&registry, &token).is_err());
    }

    #[test]
    fn unbound_request_waits_for_a_bounded_period_then_rejects() {
        let clock = Arc::new(FakeClock::new());
        let bind_wait = Duration::from_millis(20);
        let registry = registry(clock, bind_wait);
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let started = Instant::now();

        assert!(consume_as_helper(&registry, &token).is_err());
        assert!(started.elapsed() >= bind_wait);
        drop(pending);
    }

    #[test]
    fn helper_can_arrive_before_bind_and_succeed_after_notification() {
        let clock = Arc::new(FakeClock::new());
        let registry = Arc::new(registry(clock, Duration::from_secs(1)));
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let worker_registry = Arc::clone(&registry);
        let worker = thread::spawn(move || consume_as_helper(&worker_registry, &token));
        thread::sleep(Duration::from_millis(20));

        let _bound = pending.bind(SSH_PID).unwrap();

        assert_eq!(worker.join().unwrap().unwrap().as_slice(), SECRET);
    }

    #[test]
    fn bind_retries_until_spawned_child_execs_ssh() {
        let verifier = Arc::new(DelayedBindIdentityVerifier {
            transient_failures: Mutex::new(2),
            attempts: AtomicUsize::new(0),
        });
        let registry = AskpassRegistry::with_dependencies(
            Arc::clone(&verifier) as Arc<dyn super::IdentityVerifier>,
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            Duration::from_millis(100),
        );
        let pending = registry.register(snapshot()).unwrap();

        let bound = pending.bind(SSH_PID).unwrap();

        assert_eq!(verifier.attempts.load(AtomicOrdering::SeqCst), 3);
        drop(bound);
    }

    #[test]
    fn bind_keeps_retrying_for_the_full_bind_wait_window() {
        let verifier = Arc::new(DelayedBindIdentityVerifier {
            transient_failures: Mutex::new(70),
            attempts: AtomicUsize::new(0),
        });
        let registry = AskpassRegistry::with_dependencies(
            Arc::clone(&verifier) as Arc<dyn super::IdentityVerifier>,
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            Duration::from_millis(1_500),
        );
        let pending = registry.register(snapshot()).unwrap();

        let bound = pending.bind(SSH_PID).unwrap();

        assert!(verifier.attempts.load(AtomicOrdering::SeqCst) > 50);
        drop(bound);
    }

    #[test]
    fn launch_environment_contains_only_socket_and_token_capabilities() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(clock, ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot()).unwrap();
        let env = pending
            .launch_env(Path::new("/tmp/codex-askpass/broker.sock"))
            .unwrap();

        assert_eq!(env.socket_path(), "/tmp/codex-askpass/broker.sock");
        assert!(!env.capability_token().is_empty());
        assert_ne!(ASKPASS_SOCKET_ENV, ASKPASS_TOKEN_ENV);
    }

    #[test]
    fn wrong_helper_executable_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(HELPER_PID, |facts| facts.executable = "/tmp/helper".into());
        });
    }

    #[test]
    fn wrong_helper_parent_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(HELPER_PID, |facts| facts.parent_pid += 1);
        });
    }

    #[test]
    fn wrong_ssh_executable_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(SSH_PID, |facts| facts.executable = "/tmp/ssh".into());
        });
    }

    #[test]
    fn wrong_ssh_parent_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(SSH_PID, |facts| facts.parent_pid += 1);
        });
    }

    #[test]
    fn wrong_ssh_start_time_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(SSH_PID, |facts| facts.start_time += 1);
        });
    }

    #[test]
    fn wrong_app_executable_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(APP_PID, |facts| facts.executable = "/tmp/app".into());
        });
    }

    #[test]
    fn wrong_app_start_time_does_not_consume_token() {
        assert_identity_tamper_does_not_consume(|inspector| {
            inspector.mutate(APP_PID, |facts| facts.start_time += 1);
        });
    }

    #[test]
    fn unbound_app_shell_ssh_chain_cannot_consume_token() {
        let clock = Arc::new(FakeClock::new());
        let inspector = Arc::new(FakeProcessInspector::new());
        let verifier = ProcessIdentityVerifier::new(
            Arc::clone(&inspector) as Arc<dyn ProcessInspector>,
            APP_PID,
            PathBuf::from(APP_PATH),
        )
        .unwrap();
        let registry = AskpassRegistry::with_dependencies(
            Arc::new(verifier),
            clock,
            ASKPASS_TICKET_TTL,
            Duration::from_millis(5),
        );
        let peer = registry.capture_peer_identity(HELPER_PID).unwrap();
        inspector.facts.lock().unwrap().insert(
            SHELL_PID,
            ProcessFacts {
                executable: PathBuf::from("/bin/zsh"),
                parent_pid: APP_PID,
                start_time: 1_500,
                code_identity: [0x33; 20],
            },
        );
        inspector.mutate(SSH_PID, |facts| facts.parent_pid = SHELL_PID);
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);

        assert!(pending.bind(SSH_PID).is_err());
        assert!(registry.consume(&token, &peer).is_err());
    }

    #[test]
    fn in_flight_profile_update_does_not_change_registered_snapshot() {
        let directory = std::env::temp_dir().join(format!(
            "lc-snapshot-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let profiles_path = directory.join("ssh-profiles.json");
        let credentials = MemoryCredentialStore::default();
        let mut profile = snapshot().profile;
        profile.id.clear();
        profile.credential_revision = None;
        let persisted = upsert_profile_with_credential(
            &profiles_path,
            &credentials,
            profile,
            CredentialUpdate::set("snapshot-password-a"),
        )
        .unwrap();
        let snapshot_a =
            credential_snapshot_for_launch(&profiles_path, &credentials, &persisted.id).unwrap();
        let clock = Arc::new(FakeClock::new());
        let registry = registry(clock, ASKPASS_BIND_WAIT);
        let pending = registry.register(snapshot_a).unwrap();
        let token = token_of(&pending);
        let _bound = pending.bind(SSH_PID).unwrap();

        let updated = upsert_profile_with_credential(
            &profiles_path,
            &credentials,
            persisted,
            CredentialUpdate::set("snapshot-password-b"),
        )
        .unwrap();
        let snapshot_b =
            credential_snapshot_for_launch(&profiles_path, &credentials, &updated.id).unwrap();
        assert_eq!(snapshot_b.password.as_slice(), b"snapshot-password-b");
        assert_eq!(
            consume_as_helper(&registry, &token).unwrap().as_slice(),
            b"snapshot-password-a"
        );

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn broker_creates_private_short_directory_and_socket() {
        let clock = Arc::new(FakeClock::new());
        let broker =
            AskpassBroker::start_with_registry(registry(clock, ASKPASS_BIND_WAIT)).unwrap();
        let socket_path = broker.socket_path();
        let directory = socket_path.parent().unwrap();

        assert!(socket_path.as_os_str().as_bytes().len() <= ASKPASS_SOCKET_PATH_LIMIT);
        assert_eq!(
            std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(socket_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn broker_drop_stops_active_session_clears_registry_and_removes_directory() {
        let clock = Arc::new(FakeClock::new());
        let registry = registry(clock, ASKPASS_BIND_WAIT);
        let broker = AskpassBroker::start_with_registry(registry.clone()).unwrap();
        let directory = broker.socket_path().parent().unwrap().to_path_buf();
        let pending = registry.register(snapshot()).unwrap();
        let token = token_of(&pending);
        let mut stalled = UnixStream::connect(broker.socket_path()).unwrap();
        stalled.write_all(&[0, 0]).unwrap();
        thread::sleep(Duration::from_millis(20));
        let started = Instant::now();

        drop(broker);

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!directory.exists());
        assert_eq!(registry.entry_count(), 0);
        assert!(consume_as_helper(&registry, &token).is_err());
        drop(stalled);
        drop(pending);
    }

    #[test]
    fn broker_start_failure_blocks_only_ssh_and_survives_recovery_retry() {
        let directory = std::env::temp_dir().join(format!(
            "lc-startup-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let credentials = MemoryCredentialStore::default();
        let state = crate::AppState::default();

        crate::attempt_ssh_subsystem_startup(
            &state.ssh_recovery,
            &state.ssh_broker,
            Ok(directory.clone()),
            &credentials,
            || Err("模拟 ASKPASS broker 启动失败".into()),
        );

        assert!(state.sessions.lock().unwrap().is_empty());
        assert!(state.ssh_broker.lock().unwrap().is_none());
        assert!(state
            .ssh_recovery
            .ensure_ready()
            .unwrap_err()
            .contains("broker"));
        state.ssh_recovery.retry(&directory, &credentials).unwrap();
        assert!(state
            .ssh_recovery
            .ensure_ready()
            .unwrap_err()
            .contains("broker"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn local_peer_pid_reports_real_connecting_process() {
        let directory = std::env::temp_dir().join(format!(
            "lc-peer-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        let (server, _) = listener.accept().unwrap();

        assert_eq!(peer_pid(&server).unwrap(), std::process::id());

        drop(client);
        drop(server);
        drop(listener);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_socket_protocol_consumes_once_after_local_peer_pid_validation() {
        let registry = AskpassRegistry::with_dependencies(
            Arc::new(CurrentHelperIdentityVerifier),
            Arc::new(FakeClock::new()),
            ASKPASS_TICKET_TTL,
            ASKPASS_BIND_WAIT,
        );
        let broker = AskpassBroker::start_with_registry(registry.clone()).unwrap();
        let pending = registry.register(snapshot()).unwrap();
        let env = pending.launch_env(broker.socket_path()).unwrap();
        let token = env.capability_token().to_string();
        let _bound = pending.bind(SSH_PID).unwrap();

        let password = crate::ssh::askpass::request_password(broker.socket_path(), &token).unwrap();

        assert_eq!(password.as_slice(), SECRET);
        assert!(crate::ssh::askpass::request_password(broker.socket_path(), &token).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn production_broker_starts_with_current_app_identity() {
        let broker = AskpassBroker::start().unwrap();

        assert!(broker.socket_path().exists());
    }

    #[test]
    fn length_prefixed_protocol_rejects_oversized_and_malformed_requests() {
        let oversized = ((ASKPASS_MAX_REQUEST_BYTES + 1) as u32)
            .to_be_bytes()
            .to_vec();
        assert!(read_frame(&mut Cursor::new(oversized), ASKPASS_MAX_REQUEST_BYTES).is_err());

        let mut truncated = 4_u32.to_be_bytes().to_vec();
        truncated.extend_from_slice(b"ab");
        assert!(read_frame(&mut Cursor::new(truncated), ASKPASS_MAX_REQUEST_BYTES).is_err());

        assert!(read_frame(
            &mut Cursor::new(0_u32.to_be_bytes()),
            ASKPASS_MAX_REQUEST_BYTES
        )
        .is_err());
    }
}
