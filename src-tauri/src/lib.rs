use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

mod ssh;

pub fn ssh_askpass_exit_code_if_requested() -> Option<i32> {
    ssh::ssh_askpass_exit_code_if_requested()
}

fn recover_ssh_credential_transaction_on_startup(
    app_config_dir: &Path,
    credentials: &dyn ssh::CredentialStore,
) -> Result<(), String> {
    let profiles_path = app_config_dir.join("ssh-profiles.json");
    ssh::recover_credential_transaction(&profiles_path, credentials)
        .map_err(|error| format!("应用启动时无法恢复 SSH 凭据事务：{error}"))
}

#[derive(Default)]
struct SshSubsystemBlockers {
    recovery: Option<String>,
    broker: Option<String>,
}

#[derive(Default)]
pub(crate) struct SshRecoveryState {
    blockers: Mutex<SshSubsystemBlockers>,
}

impl SshRecoveryState {
    fn record_result(&self, result: &Result<(), String>) {
        let mut blockers = self
            .blockers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        blockers.recovery = result.as_ref().err().cloned();
    }

    fn record_broker_result(&self, result: &Result<(), String>) {
        let mut blockers = self
            .blockers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        blockers.broker = result.as_ref().err().cloned();
    }

    pub(crate) fn record_broker_failure(&self, error: String) {
        let mut blockers = self
            .blockers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        blockers.broker = Some(error);
    }

    pub(crate) fn blocked_error(&self) -> Option<String> {
        let blockers = self
            .blockers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match (&blockers.recovery, &blockers.broker) {
            (Some(recovery), Some(broker)) => Some(format!("{recovery}；{broker}")),
            (Some(recovery), None) => Some(recovery.clone()),
            (None, Some(broker)) => Some(broker.clone()),
            (None, None) => None,
        }
    }

    pub(crate) fn ensure_ready(&self) -> Result<(), String> {
        match self.blocked_error() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn retry(
        &self,
        app_config_dir: &Path,
        credentials: &dyn ssh::CredentialStore,
    ) -> Result<(), String> {
        let result = recover_ssh_credential_transaction_on_startup(app_config_dir, credentials);
        self.record_result(&result);
        result
    }
}

pub(crate) fn attempt_ssh_recovery_on_startup(
    state: &SshRecoveryState,
    app_config_dir: Result<PathBuf, String>,
    credentials: &dyn ssh::CredentialStore,
) {
    let result = app_config_dir.and_then(|directory| {
        recover_ssh_credential_transaction_on_startup(&directory, credentials)
    });
    state.record_result(&result);
}

pub(crate) fn attempt_ssh_subsystem_startup(
    state: &SshRecoveryState,
    broker_slot: &Mutex<Option<ssh::AskpassBroker>>,
    app_config_dir: Result<PathBuf, String>,
    credentials: &dyn ssh::CredentialStore,
    start_broker: impl FnOnce() -> Result<ssh::AskpassBroker, String>,
) {
    attempt_ssh_recovery_on_startup(state, app_config_dir, credentials);
    state.record_broker_result(&Ok(()));
    let broker_result =
        start_broker().map_err(|error| format!("应用启动时无法启动 SSH ASKPASS broker：{error}"));
    let readiness = broker_result.as_ref().map(|_| ()).map_err(Clone::clone);
    if readiness.is_err() {
        state.record_broker_result(&readiness);
    }
    if let Ok(broker) = broker_result {
        let mut slot = broker_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Some(broker);
    }
}

#[cfg(target_os = "macos")]
use std::{ffi::CStr, mem};

use portable_pty::{
    ChildKiller, CommandBuilder, ExitStatus as PtyExitStatus, MasterPty, NativePtySystem, PtySize,
    PtySystem,
};
use tauri::{window::Color, AppHandle, Emitter, Manager, State};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionType {
    Local,
    Ssh,
}

struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    process_id: Option<u32>,
    session_type: SessionType,
    killer: Box<dyn ChildKiller + Send + Sync>,
    child_reaper: Option<thread::JoinHandle<Result<PtyExitStatus, String>>>,
    _askpass_ticket: Option<ssh::BoundAskpassTicket>,
}

#[derive(Clone)]
struct CodexSessionParsed {
    session_key: String,
    session_id: String,
    timestamp: String,
    cwd: String,
    first_question: String,
    last_question: String,
    question_count: usize,
    modified_ms: u128,
    file_size: u64,
}

#[derive(Clone, serde::Serialize)]
struct CodexSessionSummary {
    session_key: String,
    session_id: String,
    timestamp: String,
    cwd: String,
    first_question: String,
    last_question: String,
    question_count: usize,
}

#[derive(Clone, serde::Serialize)]
struct CodexSessionHistoryPage {
    sessions: Vec<CodexSessionSummary>,
    total: usize,
    next_offset: usize,
    has_more: bool,
}

#[derive(Clone, serde::Serialize)]
struct CodexSessionQuestionsResult {
    session_key: String,
    session_id: String,
    timestamp: String,
    cwd: String,
    questions: Vec<String>,
}

#[derive(Clone)]
struct CodexSessionQuestionsCacheEntry {
    modified_ms: u128,
    file_size: u64,
    detail: CodexSessionQuestionsResult,
}

#[derive(Default)]
struct CodexSessionHistoryCache {
    root: Option<PathBuf>,
    summaries: HashMap<String, CodexSessionParsed>,
    ordered_keys: Vec<String>,
    question_details: HashMap<String, CodexSessionQuestionsCacheEntry>,
    last_refresh_ms: u128,
}

struct AppState {
    sessions: Mutex<HashMap<String, Session>>,
    counter: AtomicUsize,
    codex_history_cache: Mutex<CodexSessionHistoryCache>,
    ssh_recovery: Arc<SshRecoveryState>,
    ssh_broker: Mutex<Option<ssh::AskpassBroker>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            counter: AtomicUsize::new(0),
            codex_history_cache: Mutex::new(CodexSessionHistoryCache::default()),
            ssh_recovery: Arc::new(SshRecoveryState::default()),
            ssh_broker: Mutex::new(None),
        }
    }
}

#[derive(Clone, serde::Serialize)]
struct TerminalOutput {
    session_id: String,
    data: Vec<u8>,
}

#[derive(Clone, serde::Serialize)]
struct TerminalEvent {
    session_id: String,
}

#[derive(Clone, serde::Serialize)]
struct TerminalError {
    session_id: String,
    message: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshProfileInput {
    id: Option<String>,
    name: String,
    host: String,
    port: u16,
    username: String,
    auth_type: ssh::SshAuthType,
    identity_file: Option<String>,
    connect_timeout: u16,
}

impl From<SshProfileInput> for ssh::SshProfile {
    fn from(input: SshProfileInput) -> Self {
        Self {
            id: input.id.unwrap_or_default(),
            name: input.name,
            host: input.host,
            port: input.port,
            username: input.username,
            auth_type: input.auth_type,
            identity_file: input.identity_file,
            connect_timeout: input.connect_timeout,
            credential_revision: None,
        }
    }
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SshProfileView {
    id: String,
    name: String,
    host: String,
    port: u16,
    username: String,
    auth_type: ssh::SshAuthType,
    identity_file: Option<String>,
    connect_timeout: u16,
    has_password: bool,
}

impl SshProfileView {
    fn new(profile: ssh::SshProfile, has_password: bool) -> Self {
        Self {
            id: profile.id,
            name: profile.name,
            host: profile.host,
            port: profile.port,
            username: profile.username,
            auth_type: profile.auth_type,
            identity_file: profile.identity_file,
            connect_timeout: profile.connect_timeout,
            has_password,
        }
    }
}

fn profile_has_saved_password_hint(profile: &ssh::SshProfile) -> bool {
    profile.auth_type == ssh::SshAuthType::Password
        && profile
            .credential_revision
            .as_deref()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .is_some()
}

const CODEX_HISTORY_REFRESH_INTERVAL_MS: u128 = 1_500;

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn resolve_codex_home() -> Option<PathBuf> {
    if let Ok(path) = env::var("CODEX_HOME") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".codex"))
}

fn codex_sessions_root() -> Result<PathBuf, String> {
    resolve_codex_home()
        .map(|home| home.join("sessions"))
        .ok_or_else(|| "无法定位 CODEX_HOME 目录。".to_string())
}

#[derive(Clone)]
struct RolloutFileInfo {
    path: PathBuf,
    modified_ms: u128,
    file_size: u64,
}

fn read_file_meta(path: &Path) -> (u128, u64) {
    fs::metadata(path)
        .map(|meta| {
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis())
                .unwrap_or(0);
            (modified_ms, meta.len())
        })
        .unwrap_or((0, 0))
}

fn collect_rollout_session_files(root: &Path) -> Vec<RolloutFileInfo> {
    if !root.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_jsonl = path
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.eq_ignore_ascii_case("jsonl"))
                .unwrap_or(false);
            if !is_jsonl {
                continue;
            }
            let is_rollout = path
                .file_name()
                .and_then(|value| value.to_str())
                .map(|value| value.starts_with("rollout-"))
                .unwrap_or(false);
            if !is_rollout {
                continue;
            }
            let (modified_ms, file_size) = read_file_meta(&path);
            files.push(RolloutFileInfo {
                path,
                modified_ms,
                file_size,
            });
        }
    }
    files
}

fn fallback_timestamp_from_path(path: &Path, modified_ms: u128) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .map(|value| value.trim_start_matches("rollout-").to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            if modified_ms > 0 {
                Some(modified_ms.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "未知时间".to_string())
}

fn extract_text_from_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Array(items) => {
            let mut parts = Vec::new();
            for item in items {
                if let Some(text) = extract_text_from_value(item) {
                    parts.push(text);
                }
            }
            if parts.is_empty() {
                None
            } else {
                Some(parts.join("\n"))
            }
        }
        serde_json::Value::Object(map) => map
            .get("text")
            .and_then(extract_text_from_value)
            .or_else(|| map.get("message").and_then(extract_text_from_value))
            .or_else(|| map.get("content").and_then(extract_text_from_value)),
        _ => None,
    }
}

fn strip_marker_block(mut text: String, start_marker: &str, end_marker: &str) -> String {
    while let Some(start) = text.find(start_marker) {
        let search_from = start + start_marker.len();
        let Some(relative_end) = text[search_from..].find(end_marker) else {
            text.truncate(start);
            break;
        };
        let end = search_from + relative_end + end_marker.len();
        text.replace_range(start..end, "");
    }
    text
}

fn cleanup_extracted_question(text: String) -> Option<String> {
    let mut normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    for (start_marker, end_marker) in [
        ("# AGENTS.md instructions for ", "</INSTRUCTIONS>"),
        ("<environment_context>", "</environment_context>"),
        ("<permissions instructions>", "</permissions instructions>"),
        ("<collaboration_mode>", "</collaboration_mode>"),
        ("<skills_instructions>", "</skills_instructions>"),
        ("<plugins_instructions>", "</plugins_instructions>"),
    ] {
        normalized = strip_marker_block(normalized, start_marker, end_marker);
    }

    normalized = normalized
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");

    while normalized.contains("\n\n\n") {
        normalized = normalized.replace("\n\n\n", "\n\n");
    }

    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn extract_user_question(payload: &serde_json::Value) -> Option<String> {
    if payload.get("type").and_then(|value| value.as_str()) != Some("user_message") {
        return None;
    }

    payload
        .get("message")
        .and_then(extract_text_from_value)
        .and_then(cleanup_extracted_question)
        .or_else(|| payload.get("text").and_then(extract_text_from_value))
        .and_then(cleanup_extracted_question)
        .or_else(|| {
            payload
                .get("text_elements")
                .and_then(extract_text_from_value)
                .and_then(cleanup_extracted_question)
        })
}

fn extract_user_question_from_response_item(payload: &serde_json::Value) -> Option<String> {
    if payload.get("role").and_then(|value| value.as_str()) != Some("user") {
        return None;
    }
    payload
        .get("content")
        .and_then(extract_text_from_value)
        .and_then(cleanup_extracted_question)
}

fn push_question(questions: &mut Vec<String>, text: String) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    if questions
        .last()
        .map(|value| value == trimmed)
        .unwrap_or(false)
    {
        return;
    }
    questions.push(trimmed.to_string());
}

fn normalize_session_history_search_text(value: &str) -> String {
    value.chars().flat_map(|ch| ch.to_lowercase()).collect()
}

fn compact_session_history_search_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_whitespace() && !matches!(*ch, '/' | '\\' | '-' | '_' | '.'))
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn session_history_fuzzy_matches(candidate: &str, query: &str) -> bool {
    let trimmed_query = query.trim();
    if trimmed_query.is_empty() {
        return true;
    }

    let normalized_candidate = normalize_session_history_search_text(candidate);
    let normalized_query = normalize_session_history_search_text(trimmed_query);
    if normalized_candidate.contains(&normalized_query) {
        return true;
    }

    let compact_candidate = compact_session_history_search_text(candidate);
    let compact_query = compact_session_history_search_text(trimmed_query);
    if compact_query.is_empty() {
        return false;
    }

    compact_candidate.contains(&compact_query)
}

fn session_history_matches_query(session: &CodexSessionParsed, query: &str) -> bool {
    session_history_fuzzy_matches(&session.cwd, query)
}

fn scan_codex_session_file<F>(
    root: &Path,
    path: &Path,
    modified_ms: u128,
    mut on_question: F,
) -> Option<(String, String, String, String)>
where
    F: FnMut(String),
{
    let relative = path.strip_prefix(root).ok()?;
    let session_key = relative.to_string_lossy().replace('\\', "/");
    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut session_id: Option<String> = None;
    let mut timestamp: Option<String> = None;
    let mut cwd: Option<String> = None;

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let line_type = value
            .get("type")
            .and_then(|line_type| line_type.as_str())
            .unwrap_or_default();
        let payload = value.get("payload").unwrap_or(&serde_json::Value::Null);

        match line_type {
            "session_meta" => {
                if session_id.is_none() {
                    session_id = payload
                        .get("id")
                        .and_then(|value| value.as_str())
                        .map(|value| value.to_string());
                }
                if timestamp.is_none() {
                    timestamp = payload
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .map(|value| value.to_string());
                }
                if cwd.is_none() {
                    cwd = payload
                        .get("cwd")
                        .and_then(|value| value.as_str())
                        .map(|value| value.to_string());
                }
            }
            "event_msg" => {
                if let Some(question) = extract_user_question(payload) {
                    on_question(question);
                }
            }
            "response_item" => {
                if let Some(question) = extract_user_question_from_response_item(payload) {
                    on_question(question);
                }
            }
            _ => {}
        }
    }

    let session_id = session_id.unwrap_or_else(|| {
        path.file_stem()
            .and_then(|value| value.to_str())
            .map(|value| value.trim_start_matches("rollout-").to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| session_key.clone())
    });
    let timestamp = timestamp.unwrap_or_else(|| fallback_timestamp_from_path(path, modified_ms));

    Some((session_key, session_id, timestamp, cwd.unwrap_or_default()))
}

fn parse_codex_session_summary_file(
    root: &Path,
    path: &Path,
    modified_ms: u128,
    file_size: u64,
) -> Option<CodexSessionParsed> {
    let mut previous_question: Option<String> = None;
    let mut first_question: Option<String> = None;
    let mut last_question: Option<String> = None;
    let mut question_count = 0usize;

    let (session_key, session_id, timestamp, cwd) =
        scan_codex_session_file(root, path, modified_ms, |question| {
            let trimmed = question.trim();
            if trimmed.is_empty() {
                return;
            }
            if previous_question.as_deref() == Some(trimmed) {
                return;
            }
            let normalized = trimmed.to_string();
            if first_question.is_none() {
                first_question = Some(normalized.clone());
            }
            last_question = Some(normalized.clone());
            previous_question = Some(normalized);
            question_count += 1;
        })?;

    Some(CodexSessionParsed {
        session_key,
        session_id,
        timestamp,
        cwd,
        first_question: first_question.unwrap_or_else(|| "(暂无提问记录)".to_string()),
        last_question: last_question.unwrap_or_else(|| "(暂无提问记录)".to_string()),
        question_count,
        modified_ms,
        file_size,
    })
}

fn parse_codex_session_questions_file(
    root: &Path,
    path: &Path,
    modified_ms: u128,
) -> Option<CodexSessionQuestionsResult> {
    let mut questions = Vec::new();
    let (session_key, session_id, timestamp, cwd) =
        scan_codex_session_file(root, path, modified_ms, |question| {
            push_question(&mut questions, question);
        })?;

    Some(CodexSessionQuestionsResult {
        session_key,
        session_id,
        timestamp,
        cwd,
        questions,
    })
}

fn build_codex_session_summary(session: &CodexSessionParsed) -> CodexSessionSummary {
    CodexSessionSummary {
        session_key: session.session_key.clone(),
        session_id: session.session_id.clone(),
        timestamp: session.timestamp.clone(),
        cwd: session.cwd.clone(),
        first_question: session.first_question.clone(),
        last_question: session.last_question.clone(),
        question_count: session.question_count,
    }
}

fn should_refresh_codex_history_cache(cache: &CodexSessionHistoryCache) -> bool {
    if cache.last_refresh_ms == 0 {
        return true;
    }
    now_epoch_ms().saturating_sub(cache.last_refresh_ms) >= CODEX_HISTORY_REFRESH_INTERVAL_MS
}

fn refresh_codex_history_cache(
    cache: &mut CodexSessionHistoryCache,
    force: bool,
) -> Result<(), String> {
    let root = codex_sessions_root()?;
    if !root.exists() {
        cache.root = Some(root);
        cache.summaries.clear();
        cache.ordered_keys.clear();
        cache.question_details.clear();
        cache.last_refresh_ms = now_epoch_ms();
        return Ok(());
    }

    let root = root
        .canonicalize()
        .map_err(|error| format!("无法读取会话目录：{error}"))?;

    if cache.root.as_ref() != Some(&root) {
        cache.root = Some(root.clone());
        cache.summaries.clear();
        cache.ordered_keys.clear();
        cache.question_details.clear();
        cache.last_refresh_ms = 0;
    }

    if !force && !cache.summaries.is_empty() && !should_refresh_codex_history_cache(cache) {
        return Ok(());
    }

    let files = collect_rollout_session_files(&root);
    let mut visible_keys = HashSet::with_capacity(files.len());

    for file in files {
        let relative = match file.path.strip_prefix(&root) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        let session_key = relative.to_string_lossy().replace('\\', "/");
        if session_key.is_empty() {
            continue;
        }
        visible_keys.insert(session_key.clone());

        let needs_reparse = cache
            .summaries
            .get(&session_key)
            .map(|cached| {
                cached.modified_ms != file.modified_ms || cached.file_size != file.file_size
            })
            .unwrap_or(true);

        if !needs_reparse {
            continue;
        }

        if let Some(parsed) =
            parse_codex_session_summary_file(&root, &file.path, file.modified_ms, file.file_size)
        {
            cache.summaries.insert(session_key.clone(), parsed);
        } else {
            cache.summaries.remove(&session_key);
        }
        cache.question_details.remove(&session_key);
    }

    cache
        .summaries
        .retain(|session_key, _| visible_keys.contains(session_key));

    let summaries = &cache.summaries;
    cache.question_details.retain(|session_key, detail| {
        summaries
            .get(session_key)
            .map(|summary| {
                summary.modified_ms == detail.modified_ms && summary.file_size == detail.file_size
            })
            .unwrap_or(false)
    });

    let mut ordered_keys = cache.summaries.keys().cloned().collect::<Vec<_>>();
    ordered_keys.sort_by(|left, right| {
        let left_session = &cache.summaries[left];
        let right_session = &cache.summaries[right];
        right_session
            .modified_ms
            .cmp(&left_session.modified_ms)
            .then_with(|| right_session.timestamp.cmp(&left_session.timestamp))
            .then_with(|| right_session.session_key.cmp(&left_session.session_key))
    });

    cache.ordered_keys = ordered_keys;
    cache.last_refresh_ms = now_epoch_ms();
    Ok(())
}

fn get_codex_session_questions_from_cache(
    cache: &mut CodexSessionHistoryCache,
    session_key: &str,
) -> Result<CodexSessionQuestionsResult, String> {
    let summary = cache
        .summaries
        .get(session_key)
        .cloned()
        .ok_or_else(|| "未找到对应会话。".to_string())?;

    if let Some(cached) = cache.question_details.get(session_key) {
        if cached.modified_ms == summary.modified_ms && cached.file_size == summary.file_size {
            return Ok(cached.detail.clone());
        }
    }

    let root = cache
        .root
        .clone()
        .ok_or_else(|| "未找到 Codex 会话目录。".to_string())?;
    let path = root.join(session_key);
    let detail = parse_codex_session_questions_file(&root, &path, summary.modified_ms)
        .ok_or_else(|| "无法解析会话文件。".to_string())?;

    cache.question_details.insert(
        session_key.to_string(),
        CodexSessionQuestionsCacheEntry {
            modified_ms: summary.modified_ms,
            file_size: summary.file_size,
            detail: detail.clone(),
        },
    );

    Ok(detail)
}

fn validate_session_key(session_key: &str) -> Result<(), String> {
    let key_path = Path::new(session_key);
    if key_path.is_absolute() {
        return Err("会话路径不合法。".to_string());
    }
    for component in key_path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err("会话路径不合法。".to_string());
        }
    }
    Ok(())
}

fn build_shell_command(shell_override: Option<&str>, cwd: Option<&str>) -> CommandBuilder {
    let shell = shell_override
        .map(|value| value.to_string())
        .or_else(|| env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/zsh".to_string());
    let mut command = CommandBuilder::new(shell);
    command.arg("-l");
    if let Some(cwd) = cwd {
        command.cwd(cwd);
    } else if let Ok(home) = env::var("HOME") {
        command.cwd(home);
    }
    command
}

#[cfg(target_os = "macos")]
mod macos_process {
    use super::*;
    use libc::{c_int, c_void, pid_t, size_t};

    const PROC_PIDVNODEPATHINFO: c_int = 9;
    const MAXPATHLEN: usize = 1024;

    #[repr(C)]
    struct VinfoStat {
        vst_dev: u32,
        vst_mode: u16,
        vst_nlink: u16,
        vst_ino: u64,
        vst_uid: libc::uid_t,
        vst_gid: libc::gid_t,
        vst_atime: i64,
        vst_atimensec: i64,
        vst_mtime: i64,
        vst_mtimensec: i64,
        vst_ctime: i64,
        vst_ctimensec: i64,
        vst_birthtime: i64,
        vst_birthtimensec: i64,
        vst_size: libc::off_t,
        vst_blocks: i64,
        vst_blksize: i32,
        vst_flags: u32,
        vst_gen: u32,
        vst_rdev: u32,
        vst_qspare: [i64; 2],
    }

    #[repr(C)]
    struct VnodeInfo {
        vi_stat: VinfoStat,
        vi_type: i32,
        vi_pad: i32,
        vi_fsid: libc::fsid_t,
    }

    #[repr(C)]
    struct VnodeInfoPath {
        vip_vi: VnodeInfo,
        vip_path: [libc::c_char; MAXPATHLEN],
    }

    #[repr(C)]
    struct ProcVnodePathInfo {
        pvi_cdir: VnodeInfoPath,
        pvi_rdir: VnodeInfoPath,
    }

    extern "C" {
        fn proc_pidinfo(
            pid: pid_t,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }

    pub(super) fn read_cwd(pid: u32) -> Result<String, String> {
        let mut info: ProcVnodePathInfo = unsafe { mem::zeroed() };
        let result = unsafe {
            proc_pidinfo(
                pid as pid_t,
                PROC_PIDVNODEPATHINFO,
                0,
                &mut info as *mut _ as *mut c_void,
                mem::size_of::<ProcVnodePathInfo>() as c_int,
            )
        };
        if result <= 0 {
            return Err("无法获取会话工作目录。".to_string());
        }
        let path = unsafe { CStr::from_ptr(info.pvi_cdir.vip_path.as_ptr()) };
        Ok(path.to_string_lossy().to_string())
    }

    fn next_cstring(buffer: &[u8], offset: &mut usize) -> Option<String> {
        while *offset < buffer.len() && buffer[*offset] == 0 {
            *offset += 1;
        }
        if *offset >= buffer.len() {
            return None;
        }
        let start = *offset;
        while *offset < buffer.len() && buffer[*offset] != 0 {
            *offset += 1;
        }
        let value = String::from_utf8_lossy(&buffer[start..*offset]).to_string();
        *offset = (*offset + 1).min(buffer.len());
        Some(value)
    }

    pub(super) fn read_env(pid: u32) -> Result<HashMap<String, String>, String> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as c_int];
        let mut size: size_t = 0;
        let sysctl_result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if sysctl_result != 0 {
            return Err(format!(
                "无法读取会话环境：{}",
                std::io::Error::last_os_error()
            ));
        }
        let mut buffer = vec![0u8; size as usize];
        let sysctl_result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if sysctl_result != 0 {
            return Err(format!(
                "无法读取会话环境：{}",
                std::io::Error::last_os_error()
            ));
        }

        let header_size = mem::size_of::<c_int>();
        if buffer.len() < header_size {
            return Err("无法解析会话环境。".to_string());
        }
        let argc = c_int::from_ne_bytes(
            buffer[..header_size]
                .try_into()
                .map_err(|_| "无法解析会话环境。".to_string())?,
        );
        let mut offset = header_size;

        let _exec_path = next_cstring(&buffer, &mut offset);
        for _ in 0..argc.max(0) {
            let _ = next_cstring(&buffer, &mut offset);
        }

        let mut envs = HashMap::new();
        while let Some(entry) = next_cstring(&buffer, &mut offset) {
            if entry.is_empty() {
                continue;
            }
            if let Some((key, value)) = entry.split_once('=') {
                envs.insert(key.to_string(), value.to_string());
            }
        }
        Ok(envs)
    }
}

#[cfg(target_os = "macos")]
fn get_session_cwd(pid: u32) -> Result<String, String> {
    macos_process::read_cwd(pid)
}

#[cfg(not(target_os = "macos"))]
fn get_session_cwd(_pid: u32) -> Result<String, String> {
    Err("当前平台暂不支持克隆工作目录。".to_string())
}

#[cfg(target_os = "macos")]
fn get_session_env(pid: u32) -> Result<HashMap<String, String>, String> {
    macos_process::read_env(pid)
}

#[cfg(not(target_os = "macos"))]
fn get_session_env(_pid: u32) -> Result<HashMap<String, String>, String> {
    Err("当前平台暂不支持克隆环境变量。".to_string())
}

fn finish_child_reaper(
    killer: &mut dyn ChildKiller,
    child_reaper: thread::JoinHandle<Result<PtyExitStatus, String>>,
) -> Result<(), String> {
    let kill_result = if child_reaper.is_finished() {
        Ok(())
    } else {
        killer
            .kill()
            .map_err(|error| format!("无法结束会话进程：{error}"))
    };
    let wait_result = child_reaper
        .join()
        .map_err(|_| "等待会话进程退出时线程异常终止。".to_string())?
        .map(|_| ());
    wait_result.and(kill_result)
}

fn close_session_record(mut session: Session) -> Result<(), String> {
    let child_reaper = session
        .child_reaper
        .take()
        .ok_or_else(|| "会话进程已被回收。".to_string())?;
    let result = finish_child_reaper(session.killer.as_mut(), child_reaper);
    drop(session.writer);
    drop(session.master);
    result
}

fn close_map_entry<T>(
    entries: &mut HashMap<String, T>,
    key: &str,
    close: impl FnOnce(T) -> Result<(), String>,
) -> Result<(), String> {
    match entries.remove(key) {
        Some(entry) => close(entry),
        None => Ok(()),
    }
}

fn spawn_pty_command(
    app: AppHandle,
    state: &AppState,
    cols: u16,
    rows: u16,
    command: CommandBuilder,
    session_type: SessionType,
    pending_askpass_ticket: Option<ssh::PendingAskpassTicket>,
) -> Result<String, String> {
    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| error.to_string())?;

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| error.to_string())?;
    let process_id = child.process_id();
    let killer = child.clone_killer();
    let askpass_ticket = match pending_askpass_ticket {
        Some(ticket) => {
            let pid = match process_id {
                Some(pid) => pid,
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("无法获取 SSH 进程信息，已取消 ASKPASS capability。".to_string());
                }
            };
            match ticket.bind(pid) {
                Ok(ticket) => Some(ticket),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            }
        }
        None => None,
    };

    let master = pair.master;
    let mut reader = match master.try_clone_reader() {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.to_string());
        }
    };
    let writer = match master.take_writer() {
        Ok(writer) => writer,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.to_string());
        }
    };

    let session_id = format!(
        "session-{}",
        state.counter.fetch_add(1, Ordering::SeqCst) + 1
    );

    let child_reaper = thread::spawn(move || child.wait().map_err(|error| error.to_string()));
    let session = Session {
        master,
        writer,
        process_id,
        session_type,
        killer,
        child_reaper: Some(child_reaper),
        _askpass_ticket: askpass_ticket,
    };

    {
        let mut sessions = match state.sessions.lock() {
            Ok(sessions) => sessions,
            Err(_) => {
                let _ = close_session_record(session);
                return Err("无法获取会话锁。".to_string());
            }
        };
        sessions.insert(session_id.clone(), session);
    }

    let app_handle = app.clone();
    let output_session_id = session_id.clone();
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = app_handle.emit(
                        "terminal-exit",
                        TerminalEvent {
                            session_id: output_session_id.clone(),
                        },
                    );
                    break;
                }
                Ok(size) => {
                    let _ = app_handle.emit(
                        "terminal-output",
                        TerminalOutput {
                            session_id: output_session_id.clone(),
                            data: buffer[..size].to_vec(),
                        },
                    );
                }
                Err(error) => {
                    let _ = app_handle.emit(
                        "terminal-error",
                        TerminalError {
                            session_id: output_session_id.clone(),
                            message: format!("读取终端输出失败：{error}"),
                        },
                    );
                    break;
                }
            }
        }
    });

    Ok(session_id)
}

fn spawn_session(
    app: AppHandle,
    state: &AppState,
    cols: u16,
    rows: u16,
    cwd: Option<String>,
    envs: Option<HashMap<String, String>>,
) -> Result<String, String> {
    let mut envs = envs.unwrap_or_default();

    // Finder/Launchpad 启动的发行版环境通常缺少终端和 UTF-8 locale 设置。
    envs.entry("TERM".to_string())
        .or_insert_with(|| env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()));
    envs.entry("COLORTERM".to_string())
        .or_insert_with(|| env::var("COLORTERM").unwrap_or_else(|_| "truecolor".to_string()));
    if !envs.contains_key("LANG") && !envs.contains_key("LC_ALL") && !envs.contains_key("LC_CTYPE")
    {
        let locale = env::var("LC_ALL")
            .ok()
            .or_else(|| env::var("LC_CTYPE").ok())
            .or_else(|| env::var("LANG").ok())
            .filter(|value| {
                let lower = value.to_ascii_lowercase();
                lower.contains("utf-8") || lower.contains("utf8")
            })
            .unwrap_or_else(|| "en_US.UTF-8".to_string());
        envs.insert("LANG".to_string(), locale.clone());
        envs.insert("LC_CTYPE".to_string(), locale);
    }

    let shell_override = envs.get("SHELL").map(String::as_str);
    let mut command = build_shell_command(shell_override, cwd.as_deref());
    if let Some(cwd) = cwd.as_deref() {
        command.env("PWD", cwd);
    }
    for (key, value) in envs {
        if key != "PWD" && !value.contains(['\0', '\n', '\r']) {
            command.env(key, value);
        }
    }
    spawn_pty_command(app, state, cols, rows, command, SessionType::Local, None)
}

fn ssh_profiles_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("ssh-profiles.json"))
        .map_err(|error| format!("无法定位 SSH 配置目录：{error}"))
}

fn find_ssh_profile(path: &Path, profile_id: &str) -> Result<ssh::SshProfile, String> {
    uuid::Uuid::parse_str(profile_id).map_err(|_| "连接 ID 必须是有效的 UUID。".to_string())?;
    ssh::load_profiles(path)?
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| "找不到要连接的 SSH Profile。".to_string())
}

fn prepare_ssh_process(
    state: &AppState,
    profiles_path: &Path,
    profile_id: &str,
    mode: ssh::SshMode,
) -> Result<
    (
        ssh::SshProfile,
        ssh::SshProcessSpec,
        Option<ssh::PendingAskpassTicket>,
    ),
    String,
> {
    state.ssh_recovery.ensure_ready()?;
    let credentials = ssh::KeychainCredentialStore::production();
    let profile = find_ssh_profile(profiles_path, profile_id)?;
    let (profile, pending_ticket, askpass_env) = if profile.auth_type == ssh::SshAuthType::Password
    {
        let snapshot =
            ssh::credential_snapshot_for_launch(profiles_path, &credentials, profile_id)?;
        let profile = snapshot.profile.clone();
        let (pending_ticket, askpass_env) = {
            let broker_slot = state
                .ssh_broker
                .lock()
                .map_err(|_| "无法获取 SSH ASKPASS broker 锁。")?;
            let broker = broker_slot
                .as_ref()
                .ok_or_else(|| "SSH ASKPASS broker 未运行。".to_string())?;
            broker.ensure_healthy()?;
            let pending_ticket = broker.register(snapshot)?;
            let askpass_env = pending_ticket.launch_env(broker.socket_path())?;
            (pending_ticket, askpass_env)
        };
        (profile, Some(pending_ticket), Some(askpass_env))
    } else {
        (profile, None, None)
    };
    let process_spec = ssh::build_ssh_process_spec(&profile, askpass_env.as_ref(), mode)?;
    Ok((profile, process_spec, pending_ticket))
}

fn pty_command_from_ssh_spec(spec: &ssh::SshProcessSpec) -> CommandBuilder {
    let mut command = CommandBuilder::new(&spec.program);
    command.args(&spec.args);
    for key in &spec.env_remove {
        command.env_remove(key);
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    command
}

fn std_command_from_ssh_spec(spec: &ssh::SshProcessSpec) -> Command {
    let mut command = Command::new(&spec.program);
    command.args(&spec.args);
    for key in &spec.env_remove {
        command.env_remove(key);
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    command
}

fn run_ssh_test_process(
    mut command: Command,
    timeout: Duration,
    pending_askpass_ticket: Option<ssh::PendingAskpassTicket>,
) -> Result<(), String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("无法启动 SSH 连接测试：{error}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "无法读取 SSH 连接测试错误输出。".to_string())?;
    let stderr_reader = thread::spawn(move || {
        let mut stderr = stderr;
        let mut captured = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => return Ok::<Vec<u8>, String>(captured),
                Ok(size) => {
                    let remaining = (ssh::SSH_ERROR_LIMIT_CHARS * 8).saturating_sub(captured.len());
                    captured.extend_from_slice(&buffer[..size.min(remaining)]);
                }
                Err(error) => return Err(format!("读取 SSH 连接测试错误输出失败：{error}")),
            }
        }
    });

    let _askpass_ticket = match pending_askpass_ticket {
        Some(ticket) => match ticket.bind(child.id()) {
            Ok(ticket) => Some(ticket),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stderr_reader.join();
                return Err(error);
            }
        },
        None => None,
    };

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let kill_result = child.kill();
                let wait_result = child.wait();
                let _ = stderr_reader.join();
                kill_result.map_err(|error| format!("SSH 连接测试超时且无法结束进程：{error}"))?;
                wait_result.map_err(|error| format!("SSH 连接测试超时且无法回收进程：{error}"))?;
                return Err("SSH 连接测试超时。".to_string());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stderr_reader.join();
                return Err(format!("无法获取 SSH 连接测试退出状态：{error}"));
            }
        }
    };
    let stderr = stderr_reader
        .join()
        .map_err(|_| "SSH 连接测试错误输出线程异常终止。".to_string())??;
    if status.success() {
        return Ok(());
    }

    let status_description = status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "被信号终止".to_string());
    let stderr = ssh::sanitize_ssh_error(&stderr);
    if stderr.is_empty() {
        Err(format!(
            "SSH 连接测试失败（退出状态 {status_description}）。"
        ))
    } else {
        Err(format!(
            "SSH 连接测试失败（退出状态 {status_description}）：{stderr}"
        ))
    }
}

async fn run_ssh_test_blocking_task<T>(
    task: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| format!("SSH 连接测试后台任务异常终止：{error}"))?
}

#[tauri::command]
fn list_ssh_profiles(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<SshProfileView>, String> {
    state.ssh_recovery.ensure_ready()?;
    let profiles_path = ssh_profiles_path(&app)?;
    let credentials = ssh::KeychainCredentialStore::production();
    ssh::recover_credential_transaction(&profiles_path, &credentials)?;
    ssh::load_profiles(&profiles_path)?
        .into_iter()
        .map(|profile| {
            let has_password = profile_has_saved_password_hint(&profile);
            Ok(SshProfileView::new(profile, has_password))
        })
        .collect()
}

#[tauri::command]
fn save_ssh_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    profile: SshProfileInput,
    password: Option<String>,
) -> Result<SshProfileView, String> {
    state.ssh_recovery.ensure_ready()?;
    let profiles_path = ssh_profiles_path(&app)?;
    let profile = ssh::SshProfile::from(profile);
    let credential_update = match (profile.auth_type.clone(), password) {
        (ssh::SshAuthType::Password, Some(password)) => ssh::CredentialUpdate::Set {
            password: Zeroizing::new(password),
        },
        (ssh::SshAuthType::Password, None) => ssh::CredentialUpdate::Keep,
        (ssh::SshAuthType::Agent | ssh::SshAuthType::Key, _) => ssh::CredentialUpdate::Clear,
    };
    let profile = ssh::upsert_profile_with_credential(
        &profiles_path,
        &ssh::KeychainCredentialStore::production(),
        profile,
        credential_update,
    )?;
    let has_password = profile.auth_type == ssh::SshAuthType::Password;
    Ok(SshProfileView::new(profile, has_password))
}

#[tauri::command]
fn delete_ssh_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<(), String> {
    state.ssh_recovery.ensure_ready()?;
    ssh::delete_profile_with_credential(
        &ssh_profiles_path(&app)?,
        &ssh::KeychainCredentialStore::production(),
        &profile_id,
    )
}

#[tauri::command]
async fn test_ssh_profile(app: AppHandle, profile_id: String) -> Result<(), String> {
    run_ssh_test_blocking_task(move || {
        let state = app.state::<AppState>();
        let (profile, process_spec, pending_ticket) = prepare_ssh_process(
            state.inner(),
            &ssh_profiles_path(&app)?,
            &profile_id,
            ssh::SshMode::Test,
        )?;
        let command = std_command_from_ssh_spec(&process_spec);
        run_ssh_test_process(
            command,
            Duration::from_secs(u64::from(profile.connect_timeout) + 5),
            pending_ticket,
        )
    })
    .await
}

#[tauri::command]
fn start_ssh_session(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    cols: u16,
    rows: u16,
) -> Result<String, String> {
    let (_profile, process_spec, pending_ticket) = prepare_ssh_process(
        state.inner(),
        &ssh_profiles_path(&app)?,
        &profile_id,
        ssh::SshMode::Interactive,
    )?;
    let command = pty_command_from_ssh_spec(&process_spec);
    spawn_pty_command(
        app,
        state.inner(),
        cols,
        rows,
        command,
        SessionType::Ssh,
        pending_ticket,
    )
}

#[tauri::command]
fn start_session(
    app: AppHandle,
    state: State<'_, AppState>,
    cols: u16,
    rows: u16,
    cwd: Option<String>,
) -> Result<String, String> {
    let cwd = cwd.and_then(|value| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    });
    spawn_session(app, state.inner(), cols, rows, cwd, None)
}

fn local_session_process_id(session: &Session) -> Result<u32, String> {
    if session.session_type != SessionType::Local {
        return Err("SSH 会话不支持读取或克隆本地工作目录。".to_string());
    }
    session
        .process_id
        .ok_or_else(|| "无法获取会话进程信息。".to_string())
}

#[tauri::command]
fn clone_session(
    app: AppHandle,
    state: State<'_, AppState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<String, String> {
    let pid = {
        let sessions = state.sessions.lock().map_err(|_| "无法获取会话锁。")?;
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| "未找到对应的会话。".to_string())?;
        local_session_process_id(session)?
    };
    let cwd = get_session_cwd(pid)?;
    let envs = get_session_env(pid).ok();
    spawn_session(app, state.inner(), cols, rows, Some(cwd), envs)
}

#[tauri::command]
fn get_session_cwd_by_id(state: State<'_, AppState>, session_id: String) -> Result<String, String> {
    let pid = {
        let sessions = state.sessions.lock().map_err(|_| "无法获取会话锁。")?;
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| "未找到对应的会话。".to_string())?;
        local_session_process_id(session)?
    };
    get_session_cwd(pid)
}

#[tauri::command]
fn open_session_cwd_in_finder(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    let pid = {
        let sessions = state.sessions.lock().map_err(|_| "无法获取会话锁。")?;
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| "未找到对应的会话。".to_string())?;
        local_session_process_id(session)?
    };
    let cwd = get_session_cwd(pid)?;
    tauri_plugin_opener::open_path(&cwd, Option::<&str>::None)
        .map_err(|error| format!("无法打开访达：{error}"))?;
    Ok(())
}

#[tauri::command]
fn list_codex_session_history(
    state: State<'_, AppState>,
    offset: Option<usize>,
    limit: Option<usize>,
    query: Option<String>,
) -> Result<CodexSessionHistoryPage, String> {
    let mut cache = state
        .codex_history_cache
        .lock()
        .map_err(|_| "无法获取会话历史锁。")?;
    refresh_codex_history_cache(&mut cache, false)?;

    let query = query.unwrap_or_default();
    let filtered_keys = cache
        .ordered_keys
        .iter()
        .filter(|session_key| {
            cache
                .summaries
                .get(*session_key)
                .map(|session| session_history_matches_query(session, &query))
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();

    let total = filtered_keys.len();
    let offset = offset.unwrap_or(0).min(total);
    let limit = limit.unwrap_or(30).clamp(1, 100);
    let end = (offset + limit).min(total);

    let summaries = filtered_keys[offset..end]
        .iter()
        .filter_map(|session_key| cache.summaries.get(session_key))
        .map(build_codex_session_summary)
        .collect::<Vec<_>>();

    Ok(CodexSessionHistoryPage {
        sessions: summaries,
        total,
        next_offset: end,
        has_more: end < total,
    })
}

#[tauri::command]
fn get_codex_session_questions(
    state: State<'_, AppState>,
    session_key: String,
) -> Result<CodexSessionQuestionsResult, String> {
    validate_session_key(&session_key)?;

    let mut cache = state
        .codex_history_cache
        .lock()
        .map_err(|_| "无法获取会话历史锁。")?;
    refresh_codex_history_cache(&mut cache, false)?;
    get_codex_session_questions_from_cache(&mut cache, &session_key)
}

#[tauri::command]
fn send_input(state: State<'_, AppState>, session_id: String, data: String) -> Result<(), String> {
    let mut sessions = state.sessions.lock().map_err(|_| "无法获取会话锁。")?;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(|| "未找到对应的会话。".to_string())?;
    session
        .writer
        .write_all(data.as_bytes())
        .map_err(|error| error.to_string())?;
    session.writer.flush().map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
fn resize_session(
    state: State<'_, AppState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let sessions = state.sessions.lock().map_err(|_| "无法获取会话锁。")?;
    let session = sessions
        .get(&session_id)
        .ok_or_else(|| "未找到对应的会话。".to_string())?;
    session
        .master
        .resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
fn close_session(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    let mut sessions = state.sessions.lock().map_err(|_| "无法获取会话锁。")?;
    close_map_entry(&mut sessions, &session_id, close_session_record)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            let app_config_dir = app
                .path()
                .app_config_dir()
                .map_err(|error| format!("应用启动时无法定位配置目录：{error}"));
            let state = app.state::<AppState>();
            let broker_recovery = Arc::clone(&state.ssh_recovery);
            attempt_ssh_subsystem_startup(
                &state.ssh_recovery,
                &state.ssh_broker,
                app_config_dir,
                &ssh::KeychainCredentialStore::production(),
                move || {
                    ssh::AskpassBroker::start_with_failure_callback(move |error| {
                        broker_recovery.record_broker_failure(format!(
                            "SSH ASKPASS broker 运行期故障：{error}"
                        ));
                    })
                },
            );

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_background_color(Some(Color(33, 33, 33, 255)));
            }

            // 后台预热会话索引，避免首次输入 cx 时等待全量扫描。
            let app_handle = app.handle().clone();
            thread::spawn(move || {
                let state = app_handle.state::<AppState>();
                if let Ok(mut cache) = state.codex_history_cache.lock() {
                    let _ = refresh_codex_history_cache(&mut cache, true);
                };
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_ssh_profiles,
            save_ssh_profile,
            delete_ssh_profile,
            test_ssh_profile,
            start_ssh_session,
            start_session,
            clone_session,
            get_session_cwd_by_id,
            open_session_cwd_in_finder,
            list_codex_session_history,
            get_codex_session_questions,
            close_session,
            send_input,
            resize_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod task_three_tests {
    use super::{
        close_map_entry, finish_child_reaper, run_ssh_test_blocking_task, run_ssh_test_process,
        ssh, TerminalOutput,
    };
    use portable_pty::{ChildKiller, ExitStatus};
    use std::{
        collections::HashMap,
        fmt,
        process::Command,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn terminal_output_serializes_raw_bytes_without_utf8_conversion() {
        let output = TerminalOutput {
            session_id: "session-1".into(),
            data: vec![0, 0x80, 0xff, b'\n'],
        };

        assert_eq!(
            serde_json::to_value(output).unwrap(),
            serde_json::json!({"session_id": "session-1", "data": [0, 128, 255, 10]})
        );
    }

    #[test]
    fn closing_a_session_is_idempotent() {
        let mut sessions = HashMap::from([("session-1".to_string(), 42)]);
        let close_count = AtomicUsize::new(0);

        close_map_entry(&mut sessions, "session-1", |_| {
            close_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
        close_map_entry(&mut sessions, "session-1", |_| {
            close_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();

        assert_eq!(close_count.load(Ordering::SeqCst), 1);
    }

    #[derive(Clone)]
    struct CountingKiller {
        kills: Arc<AtomicUsize>,
        release: mpsc::Sender<()>,
    }

    impl fmt::Debug for CountingKiller {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct("CountingKiller").finish()
        }
    }

    impl ChildKiller for CountingKiller {
        fn kill(&mut self) -> std::io::Result<()> {
            self.kills.fetch_add(1, Ordering::SeqCst);
            let _ = self.release.send(());
            Ok(())
        }

        fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn closing_an_exited_child_reaps_without_killing_again() {
        let (release, _receiver) = mpsc::channel();
        let kills = Arc::new(AtomicUsize::new(0));
        let mut killer = CountingKiller {
            kills: Arc::clone(&kills),
            release,
        };
        let waiter = thread::spawn(|| Ok(ExitStatus::with_exit_code(0)));
        while !waiter.is_finished() {
            thread::yield_now();
        }

        finish_child_reaper(&mut killer, waiter).unwrap();

        assert_eq!(kills.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn closing_a_running_child_kills_and_reaps_it() {
        let (release, receiver) = mpsc::channel();
        let kills = Arc::new(AtomicUsize::new(0));
        let mut killer = CountingKiller {
            kills: Arc::clone(&kills),
            release,
        };
        let waiter = thread::spawn(move || {
            receiver.recv().unwrap();
            Ok(ExitStatus::with_exit_code(143))
        });

        finish_child_reaper(&mut killer, waiter).unwrap();

        assert_eq!(kills.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ssh_test_blocking_task_runs_off_the_caller_thread() {
        let caller_thread = thread::current().id();

        let worker_thread = tauri::async_runtime::block_on(run_ssh_test_blocking_task(|| {
            Ok(thread::current().id())
        }))
        .unwrap();

        assert_ne!(worker_thread, caller_thread);
    }

    #[test]
    fn ssh_test_process_checks_exit_status_and_sanitizes_stderr() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "printf '\\033[31mPermission denied\\033[0m\\n' >&2; exit 7",
        ]);

        let error = run_ssh_test_process(command, Duration::from_secs(2), None).unwrap_err();

        assert!(error.contains("Permission denied"));
        assert!(error.contains("退出状态 7"));
        assert!(!error.contains('\x1b'));
    }

    #[test]
    fn ssh_test_process_kills_and_reaps_on_timeout() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 5"]);
        let started = Instant::now();

        let error = run_ssh_test_process(command, Duration::from_millis(50), None).unwrap_err();

        assert_eq!(error, "SSH 连接测试超时。");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn password_hint_comes_from_profile_binding_without_keychain_reads() {
        let mut password = ssh::SshProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Password".into(),
            host: "example.com".into(),
            port: 22,
            username: "deploy".into(),
            auth_type: ssh::SshAuthType::Password,
            identity_file: None,
            connect_timeout: 15,
            credential_revision: Some(uuid::Uuid::new_v4().to_string()),
        };
        assert!(super::profile_has_saved_password_hint(&password));

        password.credential_revision = Some("not-a-uuid".into());
        assert!(!super::profile_has_saved_password_hint(&password));

        password.auth_type = ssh::SshAuthType::Agent;
        password.credential_revision = Some(uuid::Uuid::new_v4().to_string());
        assert!(!super::profile_has_saved_password_hint(&password));
    }
}
