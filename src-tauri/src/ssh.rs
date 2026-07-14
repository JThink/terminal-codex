use crate::platform::{self, PlatformKind};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
mod askpass;
mod broker;
mod credentials;
mod process;
mod transaction;
pub(crate) use askpass::ssh_askpass_exit_code_if_requested;
pub(crate) use broker::{AskpassBroker, BoundAskpassTicket, PendingAskpassTicket};
pub(crate) use credentials::{
    credential_snapshot_for_launch, delete_profile_with_credential, upsert_profile_with_credential,
    CredentialStore, CredentialUpdate, LocalVaultCredentialStore,
};
#[cfg(test)]
use credentials::{delete_profile_transaction, upsert_profile_transaction, ProfileRepository};
pub(crate) use process::{
    build_ssh_process_spec, SshMode, SshProcessSpec, ASKPASS_MARKER_ENV, ASKPASS_SOCKET_ENV,
    ASKPASS_TOKEN_ENV,
};
pub(crate) use transaction::recover_credential_transaction;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const SSH_PROFILES_VERSION: u32 = 1;
pub(crate) const SSH_ERROR_LIMIT_CHARS: usize = 1024;

pub(crate) fn sanitize_ssh_error(bytes: &[u8]) -> String {
    let mut cleaned = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\x1b' if bytes.get(index + 1) == Some(&b'[') => {
                index += 2;
                while index < bytes.len() {
                    let byte = bytes[index];
                    index += 1;
                    if (0x40..=0x7e).contains(&byte) {
                        break;
                    }
                }
            }
            b'\x1b' if bytes.get(index + 1) == Some(&b']') => {
                index += 2;
                while index < bytes.len() {
                    if bytes[index] == b'\x07' {
                        index += 1;
                        break;
                    }
                    if bytes[index] == b'\x1b' && bytes.get(index + 1) == Some(&b'\\') {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            b'\x1b' => {
                index += usize::from(index + 1 < bytes.len()) + 1;
            }
            b'\r' => {
                if bytes.get(index + 1) != Some(&b'\n') {
                    cleaned.push(b'\n');
                }
                index += 1;
            }
            byte if byte == b'\n' || byte == b'\t' || byte >= b' ' => {
                cleaned.push(byte);
                index += 1;
            }
            _ => index += 1,
        }
    }

    let decoded = String::from_utf8_lossy(&cleaned);
    let mut characters = decoded.chars();
    let mut result = characters
        .by_ref()
        .take(SSH_ERROR_LIMIT_CHARS)
        .collect::<String>();
    if characters.next().is_some() {
        result.push('…');
    }
    result.trim().to_string()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SshAuthType {
    Agent,
    Key,
    Password,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SshProfile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) auth_type: SshAuthType,
    pub(crate) identity_file: Option<String>,
    pub(crate) connect_timeout: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) credential_revision: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SshProfilesDocument {
    version: u32,
    profiles: Vec<SshProfile>,
}

fn reject_control_characters(field: &str, value: &str) -> Result<(), String> {
    if value.contains(['\0', '\r', '\n']) {
        return Err(format!("{field}不能包含 NUL、回车或换行。"));
    }
    Ok(())
}

fn normalize_required(field: &str, empty_error: &str, value: &str) -> Result<String, String> {
    reject_control_characters(field, value)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(empty_error.to_string());
    }
    Ok(value.to_string())
}

fn normalize_connection_token(
    field: &str,
    empty_error: &str,
    value: &str,
    reject_leading_hyphen: bool,
) -> Result<String, String> {
    reject_control_characters(field, value)?;
    if value.trim().is_empty() {
        return Err(empty_error.to_string());
    }
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(format!("{field}不能包含空白或控制字符。"));
    }
    if reject_leading_hyphen && value.starts_with('-') {
        return Err(format!("{field}不能以连字符开头。"));
    }
    Ok(value.to_string())
}

const HOME_EXPANSION_ERROR: &str = "无法展开私钥路径：无法定位用户主目录。";

fn home_relative_path(path: &str, platform: PlatformKind) -> Option<&str> {
    match platform {
        PlatformKind::MacOs => path.strip_prefix("~/"),
        PlatformKind::Windows => path.strip_prefix("~/").or_else(|| path.strip_prefix(r"~\")),
    }
}

fn expand_home_prefix_with(
    path: &str,
    home: Option<&Path>,
    platform: PlatformKind,
) -> Result<PathBuf, String> {
    let Some(relative_path) = home_relative_path(path, platform) else {
        return Ok(PathBuf::from(path));
    };
    let home = home
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or_else(|| HOME_EXPANSION_ERROR.to_string())?;
    let separator = match platform {
        PlatformKind::MacOs => '/',
        PlatformKind::Windows => '\\',
    };
    let home_ends_with_separator = match platform {
        PlatformKind::MacOs => home.to_string_lossy().ends_with('/'),
        PlatformKind::Windows => home.to_string_lossy().ends_with(['/', '\\']),
    };
    let mut expanded = home.as_os_str().to_os_string();
    if !home_ends_with_separator {
        expanded.push(separator.to_string());
    }
    expanded.push(relative_path);
    Ok(PathBuf::from(expanded))
}

fn expand_home_prefix(path: &str) -> Result<PathBuf, String> {
    let platform = platform::current_platform();
    if home_relative_path(path, platform).is_none() {
        return Ok(PathBuf::from(path));
    }
    let home = platform::user_home().map_err(|_| HOME_EXPANSION_ERROR.to_string())?;
    expand_home_prefix_with(path, Some(&home), platform)
}

pub(crate) fn validate_profile(profile: &SshProfile) -> Result<SshProfile, String> {
    let mut normalized = profile.clone();
    normalized.id = normalize_required("连接 ID", "连接 ID 不能为空。", &profile.id)?;
    normalized.name = normalize_required("连接名称", "连接名称不能为空。", &profile.name)?;
    normalized.host =
        normalize_connection_token("主机地址", "主机地址不能为空。", &profile.host, true)?;
    normalized.username =
        normalize_connection_token("用户名", "用户名不能为空。", &profile.username, false)?;

    if profile.port == 0 {
        return Err("端口必须在 1 到 65535 之间。".to_string());
    }
    if !(1..=120).contains(&profile.connect_timeout) {
        return Err("连接超时必须在 1 到 120 秒之间。".to_string());
    }

    if let Some(identity_file) = profile.identity_file.as_deref() {
        reject_control_characters("私钥文件路径", identity_file)?;
    }

    normalized.identity_file = match (&profile.auth_type, profile.identity_file.as_deref()) {
        (SshAuthType::Key, Some(identity_file)) => {
            let identity_file = identity_file.trim();
            if identity_file.is_empty() {
                None
            } else {
                Some(
                    expand_home_prefix(identity_file)?
                        .into_os_string()
                        .into_string()
                        .map_err(|_| "私钥文件路径不是有效的 UTF-8。".to_string())?,
                )
            }
        }
        _ => None,
    };

    if profile.auth_type == SshAuthType::Key && normalized.identity_file.is_none() {
        return Err("私钥认证必须指定私钥文件。".to_string());
    }

    normalized.credential_revision = match profile.auth_type {
        SshAuthType::Password => profile
            .credential_revision
            .as_deref()
            .map(|revision| {
                uuid::Uuid::parse_str(revision)
                    .map(|value| value.to_string())
                    .map_err(|_| "密码凭据版本必须是有效的 UUID。".to_string())
            })
            .transpose()?,
        SshAuthType::Agent | SshAuthType::Key => None,
    };

    Ok(normalized)
}

pub(crate) fn validate_profile_for_connection(profile: &SshProfile) -> Result<SshProfile, String> {
    let normalized = validate_profile(profile)?;
    if normalized.auth_type == SshAuthType::Key {
        let identity_file = normalized
            .identity_file
            .as_deref()
            .ok_or_else(|| "私钥认证必须指定私钥文件。".to_string())?;
        if !Path::new(identity_file).is_file() {
            return Err(format!("私钥文件不存在或不是普通文件：{identity_file}。"));
        }
    }

    Ok(normalized)
}

fn cleanup_temporary_file_after_save_error(path: &Path, save_error: String) -> String {
    match fs::remove_file(path) {
        Ok(()) => save_error,
        Err(cleanup_error) => format!(
            "{save_error}；清理 SSH 配置临时文件 {} 失败：{cleanup_error}",
            path.display()
        ),
    }
}

#[cfg(unix)]
fn replace_file_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    use std::fs as filesystem;

    filesystem::rename(source, destination).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn replace_file_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    use std::{io, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    fn nul_terminated_path(path: &Path, description: &str) -> Result<Vec<u16>, String> {
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(format!("{description}包含 NUL，无法原子替换文件。"));
        }
        encoded.push(0);
        Ok(encoded)
    }

    let source = nul_terminated_path(source, "原子替换源文件路径")?;
    let destination = nul_terminated_path(destination, "原子替换目标文件路径")?;
    // SAFETY: both UTF-16 buffers are NUL-terminated and remain alive for the call.
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(format!(
            "Windows 原子替换文件失败：{}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn validate_profiles(profiles: &[SshProfile]) -> Result<Vec<SshProfile>, String> {
    let mut ids = HashSet::with_capacity(profiles.len());
    let mut normalized_profiles = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let normalized = validate_profile(profile)?;
        if !ids.insert(normalized.id.clone()) {
            return Err(format!("SSH 连接 ID 重复：{}。", normalized.id));
        }
        normalized_profiles.push(normalized);
    }
    Ok(normalized_profiles)
}

pub(crate) fn load_profiles(path: &Path) -> Result<Vec<SshProfile>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!("无法读取 SSH 配置文件 {}：{error}", path.display()));
        }
    };
    let document: SshProfilesDocument = serde_json::from_slice(&bytes)
        .map_err(|error| format!("无法解析 SSH 配置文件：{error}"))?;
    if document.version != SSH_PROFILES_VERSION {
        return Err(format!("不支持的 SSH 配置文件版本：{}。", document.version));
    }
    validate_profiles(&document.profiles)
}

pub(crate) fn save_profiles(path: &Path, profiles: &[SshProfile]) -> Result<(), String> {
    let profiles = validate_profiles(profiles)?;
    let document = SshProfilesDocument {
        version: SSH_PROFILES_VERSION,
        profiles,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("无法序列化 SSH 配置文件：{error}"))?;
    bytes.push(b'\n');

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("无法创建 SSH 配置目录 {}：{error}", parent.display()))?;

    let temporary_path = parent.join(format!(".ssh-profiles.{}.tmp", uuid::Uuid::new_v4()));
    let mut temporary_file_created = false;
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary_path).map_err(|error| {
            format!(
                "无法创建 SSH 配置临时文件 {}：{error}",
                temporary_path.display()
            )
        })?;
        temporary_file_created = true;

        #[cfg(unix)]
        fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                format!(
                    "无法设置 SSH 配置临时文件权限 {}：{error}",
                    temporary_path.display()
                )
            },
        )?;

        file.write_all(&bytes).map_err(|error| {
            format!(
                "无法写入 SSH 配置临时文件 {}：{error}",
                temporary_path.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "无法同步 SSH 配置临时文件 {}：{error}",
                temporary_path.display()
            )
        })?;
        drop(file);

        replace_file_atomically(&temporary_path, path)
            .map_err(|error| format!("无法替换 SSH 配置文件 {}：{error}", path.display()))?;
        temporary_file_created = false;
        sync_directory(parent)?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) if temporary_file_created => Err(cleanup_temporary_file_after_save_error(
            &temporary_path,
            error,
        )),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("无法同步 SSH 配置目录 {}：{error}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub(crate) fn generate_profile_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::credentials::{endpoint_fingerprint, CredentialRecord};
    use super::{
        cleanup_temporary_file_after_save_error, delete_profile_transaction,
        expand_home_prefix_with, generate_profile_id, load_profiles, replace_file_atomically,
        sanitize_ssh_error, save_profiles, upsert_profile_transaction, validate_profile,
        validate_profile_for_connection, CredentialStore, CredentialUpdate, ProfileRepository,
        SshAuthType, SshProfile, SSH_ERROR_LIMIT_CHARS,
    };
    use crate::platform::PlatformKind;
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };
    use zeroize::Zeroizing;

    static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_test_dir() -> PathBuf {
        let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "terminal-codex-ssh-test-{}-{counter}",
            std::process::id()
        ))
    }

    fn fixture_profile() -> SshProfile {
        SshProfile {
            id: "profile-1".into(),
            name: "Production".into(),
            host: "example.com".into(),
            port: 22,
            username: "deploy".into(),
            auth_type: SshAuthType::Agent,
            identity_file: None,
            connect_timeout: 15,
            credential_revision: None,
        }
    }

    #[test]
    fn truncates_connection_error_without_breaking_utf8() {
        let source = "连接失败".repeat(1000);
        let result = sanitize_ssh_error(source.as_bytes());

        assert!(result.chars().count() <= SSH_ERROR_LIMIT_CHARS + 1);
        assert!(result.ends_with('…'));
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }

    #[test]
    fn sanitizes_terminal_sequences_and_invalid_utf8_in_connection_error() {
        let result = sanitize_ssh_error(b"\x1b[31mPermission denied\x1b[0m\r\n\xff");

        assert_eq!(result, "Permission denied\n�");
        assert!(!result.contains('\x1b'));
    }

    fn transaction_profile() -> SshProfile {
        let mut profile = fixture_profile();
        profile.id = "74c00a0b-a7e5-410c-9aed-7e9f5045507b".into();
        profile
    }

    #[derive(Default)]
    struct FakeCredentialStore {
        values: RefCell<HashMap<String, Vec<u8>>>,
        fail_on_mutation: Cell<Option<usize>>,
        mutation_count: Cell<usize>,
    }

    impl FakeCredentialStore {
        fn insert(&self, account: &str, value: &[u8]) {
            self.values
                .borrow_mut()
                .insert(account.to_string(), value.to_vec());
        }

        fn value(&self, account: &str) -> Option<Vec<u8>> {
            self.values.borrow().get(account).cloned()
        }

        fn insert_bound_password(&self, profile: &mut SshProfile, password: &[u8]) {
            let revision = uuid::Uuid::new_v4();
            profile.credential_revision = Some(revision.to_string());
            let record = CredentialRecord::new(
                revision,
                endpoint_fingerprint(&profile.host, profile.port, &profile.username),
                Zeroizing::new(password.to_vec()),
            )
            .unwrap();
            self.insert(&profile.id, &record.encode());
        }

        fn fail_next_restore(&self) {
            self.fail_on_mutation
                .set(Some(self.mutation_count.get() + 2));
        }

        fn before_mutation(&self) -> Result<(), String> {
            let count = self.mutation_count.get() + 1;
            self.mutation_count.set(count);
            if self.fail_on_mutation.get() == Some(count) {
                self.fail_on_mutation.set(None);
                return Err("模拟凭据回滚失败".into());
            }
            Ok(())
        }
    }

    impl CredentialStore for FakeCredentialStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self.value(account).map(Zeroizing::new))
        }

        fn set(&self, account: &str, password: &[u8]) -> Result<(), String> {
            self.before_mutation()?;
            self.insert(account, password);
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), String> {
            self.before_mutation()?;
            self.values.borrow_mut().remove(account);
            Ok(())
        }
    }

    struct FakeProfileRepository {
        profiles: RefCell<Vec<SshProfile>>,
        save_error: RefCell<Option<String>>,
        save_count: Cell<usize>,
    }

    impl FakeProfileRepository {
        fn new(profiles: Vec<SshProfile>) -> Self {
            Self {
                profiles: RefCell::new(profiles),
                save_error: RefCell::new(None),
                save_count: Cell::new(0),
            }
        }

        fn failing(profiles: Vec<SshProfile>, message: &str) -> Self {
            let repository = Self::new(profiles);
            *repository.save_error.borrow_mut() = Some(message.into());
            repository
        }
    }

    impl ProfileRepository for FakeProfileRepository {
        fn load(&self) -> Result<Vec<SshProfile>, String> {
            Ok(self.profiles.borrow().clone())
        }

        fn save(&self, profiles: &[SshProfile]) -> Result<(), String> {
            self.save_count.set(self.save_count.get() + 1);
            if let Some(error) = self.save_error.borrow().as_ref() {
                return Err(error.clone());
            }
            *self.profiles.borrow_mut() = profiles.to_vec();
            Ok(())
        }
    }

    #[test]
    fn credential_update_deserializes_keep_set_and_clear() {
        let keep: CredentialUpdate = serde_json::from_str(r#"{"action":"keep"}"#).unwrap();
        let set: CredentialUpdate =
            serde_json::from_str(r#"{"action":"set","password":"s3cret"}"#).unwrap();
        let clear: CredentialUpdate = serde_json::from_str(r#"{"action":"clear"}"#).unwrap();

        assert!(matches!(keep, CredentialUpdate::Keep));
        assert!(matches!(set, CredentialUpdate::Set { .. }));
        assert!(matches!(clear, CredentialUpdate::Clear));
    }

    #[test]
    fn password_profile_set_stores_new_credential() {
        let repository = FakeProfileRepository::new(Vec::new());
        let credentials = FakeCredentialStore::default();
        let mut profile = transaction_profile();
        profile.id.clear();
        profile.auth_type = SshAuthType::Password;

        let saved = upsert_profile_transaction(
            &repository,
            &credentials,
            profile.clone(),
            CredentialUpdate::set("new-password"),
        )
        .unwrap();

        assert!(uuid::Uuid::parse_str(&saved.id).is_ok());
        profile.id = saved.id.clone();
        profile.credential_revision = saved.credential_revision.clone();
        assert_eq!(saved, profile);
        let record = CredentialRecord::decode(&credentials.value(&profile.id).unwrap()).unwrap();
        assert_eq!(record.password(), b"new-password");
        assert_eq!(repository.profiles.borrow().as_slice(), &[profile]);
    }

    #[test]
    fn password_profile_keep_preserves_existing_credential() {
        let mut profile = transaction_profile();
        profile.auth_type = SshAuthType::Password;
        let credentials = FakeCredentialStore::default();
        credentials.insert_bound_password(&mut profile, b"existing-password");
        let original_record = credentials.value(&profile.id).unwrap();
        let repository = FakeProfileRepository::new(vec![profile.clone()]);
        profile.name = "Renamed".into();

        upsert_profile_transaction(
            &repository,
            &credentials,
            profile.clone(),
            CredentialUpdate::Keep,
        )
        .unwrap();

        assert_eq!(credentials.value(&profile.id).unwrap(), original_record);
        assert_eq!(repository.profiles.borrow().as_slice(), &[profile]);
    }

    #[test]
    fn new_password_profile_without_credential_is_rejected() {
        let repository = FakeProfileRepository::new(Vec::new());
        let credentials = FakeCredentialStore::default();
        let mut profile = transaction_profile();
        profile.id.clear();
        profile.auth_type = SshAuthType::Password;

        let error =
            upsert_profile_transaction(&repository, &credentials, profile, CredentialUpdate::Keep)
                .unwrap_err();

        assert_eq!(error, "密码认证必须提供密码。");
        assert_eq!(repository.save_count.get(), 0);
    }

    #[test]
    fn switching_to_non_password_authentication_clears_credential() {
        let mut old_profile = transaction_profile();
        old_profile.auth_type = SshAuthType::Password;
        let repository = FakeProfileRepository::new(vec![old_profile.clone()]);
        let credentials = FakeCredentialStore::default();
        credentials.insert(&old_profile.id, b"old-password");
        let mut updated = old_profile;
        updated.auth_type = SshAuthType::Agent;

        upsert_profile_transaction(&repository, &credentials, updated, CredentialUpdate::Clear)
            .unwrap();

        assert_eq!(credentials.value(&transaction_profile().id), None);
    }

    #[test]
    fn password_profile_clear_is_rejected_without_deleting_existing_credential() {
        let mut profile = transaction_profile();
        profile.auth_type = SshAuthType::Password;
        let repository = FakeProfileRepository::new(vec![profile.clone()]);
        let credentials = FakeCredentialStore::default();
        credentials.insert(&profile.id, b"old-password");

        let error = upsert_profile_transaction(
            &repository,
            &credentials,
            profile.clone(),
            CredentialUpdate::Clear,
        )
        .unwrap_err();

        assert_eq!(error, "密码认证必须提供密码。");
        assert_eq!(
            credentials.value(&profile.id).as_deref(),
            Some(b"old-password".as_slice())
        );
    }

    #[test]
    fn rejects_empty_or_line_breaking_passwords_without_leaking_them() {
        for password in ["", "has\0nul", "has\rcarriage", "has\nnewline"] {
            let repository = FakeProfileRepository::new(Vec::new());
            let credentials = FakeCredentialStore::default();
            let mut profile = transaction_profile();
            profile.auth_type = SshAuthType::Password;

            let error = upsert_profile_transaction(
                &repository,
                &credentials,
                profile,
                CredentialUpdate::set(password),
            )
            .unwrap_err();

            if !password.is_empty() {
                assert!(!error.contains(password), "error leaked rejected password");
            }
            assert_eq!(repository.save_count.get(), 0);
        }
    }

    #[test]
    fn profile_save_failure_restores_previous_credential_without_secret_in_error() {
        let mut profile = transaction_profile();
        profile.auth_type = SshAuthType::Password;
        let credentials = FakeCredentialStore::default();
        credentials.insert_bound_password(&mut profile, b"old-password");
        let original_record = credentials.value(&profile.id).unwrap();
        let repository =
            FakeProfileRepository::failing(vec![profile.clone()], "模拟 JSON 保存失败");
        profile.name = "Renamed".into();

        let error = upsert_profile_transaction(
            &repository,
            &credentials,
            profile.clone(),
            CredentialUpdate::set("never-log-this-secret"),
        )
        .unwrap_err();

        assert!(error.contains("模拟 JSON 保存失败"));
        assert!(!error.contains("never-log-this-secret"));
        assert_eq!(credentials.value(&profile.id).unwrap(), original_record);
    }

    #[test]
    fn keep_save_failure_does_not_rewrite_unchanged_credential() {
        let mut profile = transaction_profile();
        profile.auth_type = SshAuthType::Password;
        let credentials = FakeCredentialStore::default();
        credentials.insert_bound_password(&mut profile, b"old-password");
        let original_record = credentials.value(&profile.id).unwrap();
        let repository =
            FakeProfileRepository::failing(vec![profile.clone()], "模拟 JSON 保存失败");
        profile.name = "Renamed".into();

        let error = upsert_profile_transaction(
            &repository,
            &credentials,
            profile.clone(),
            CredentialUpdate::Keep,
        )
        .unwrap_err();

        assert!(error.contains("模拟 JSON 保存失败"));
        assert_eq!(credentials.mutation_count.get(), 0);
        assert_eq!(credentials.value(&profile.id).unwrap(), original_record);
    }

    #[test]
    fn delete_save_failure_restores_previous_credential() {
        let mut profile = transaction_profile();
        profile.auth_type = SshAuthType::Password;
        let repository = FakeProfileRepository::failing(vec![profile.clone()], "模拟删除保存失败");
        let credentials = FakeCredentialStore::default();
        credentials.insert(&profile.id, b"old-password");

        let error = delete_profile_transaction(&repository, &credentials, &profile.id).unwrap_err();

        assert!(error.contains("模拟删除保存失败"));
        assert_eq!(
            credentials.value(&profile.id).as_deref(),
            Some(b"old-password".as_slice())
        );
        assert_eq!(repository.profiles.borrow().as_slice(), &[profile]);
    }

    #[test]
    fn rollback_failure_reports_primary_and_rollback_errors_without_secret() {
        let mut profile = transaction_profile();
        profile.auth_type = SshAuthType::Password;
        let repository =
            FakeProfileRepository::failing(vec![profile.clone()], "主要 JSON 保存失败");
        let credentials = FakeCredentialStore::default();
        credentials.insert(&profile.id, b"old-password");
        credentials.fail_next_restore();

        let error = upsert_profile_transaction(
            &repository,
            &credentials,
            profile,
            CredentialUpdate::set("rollback-secret"),
        )
        .unwrap_err();

        assert!(error.contains("主要 JSON 保存失败"));
        assert!(error.contains("模拟凭据回滚失败"));
        assert!(!error.contains("rollback-secret"));
    }

    #[test]
    fn new_profile_with_empty_id_gets_backend_uuid() {
        let repository = FakeProfileRepository::new(Vec::new());
        let credentials = FakeCredentialStore::default();
        let mut profile = transaction_profile();
        profile.id.clear();

        let saved =
            upsert_profile_transaction(&repository, &credentials, profile, CredentialUpdate::Keep)
                .unwrap();

        assert!(uuid::Uuid::parse_str(&saved.id).is_ok());
    }

    #[test]
    fn current_key_profile_requires_existing_file_but_historical_key_is_preserved() {
        let dir = unique_test_dir();
        let missing = dir.join("missing-key");
        let mut historical = transaction_profile();
        historical.id = "348a0961-31f0-4672-b73e-03afc84eb46e".into();
        historical.auth_type = SshAuthType::Key;
        historical.identity_file = Some(missing.to_string_lossy().into_owned());
        let mut current = transaction_profile();
        let repository = FakeProfileRepository::new(vec![historical.clone(), current.clone()]);
        let credentials = FakeCredentialStore::default();
        current.name = "Updated agent".into();

        upsert_profile_transaction(
            &repository,
            &credentials,
            current.clone(),
            CredentialUpdate::Keep,
        )
        .unwrap();

        assert_eq!(
            repository.profiles.borrow().as_slice(),
            &[historical, current]
        );

        let mut invalid_current = transaction_profile();
        invalid_current.id.clear();
        invalid_current.auth_type = SshAuthType::Key;
        invalid_current.identity_file = Some(missing.to_string_lossy().into_owned());
        assert!(upsert_profile_transaction(
            &repository,
            &credentials,
            invalid_current,
            CredentialUpdate::Keep,
        )
        .unwrap_err()
        .starts_with("私钥文件不存在或不是普通文件："));
    }

    fn write_test_key(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join("id_test");
        fs::write(&path, "test-key").unwrap();
        path
    }

    #[test]
    fn accepts_and_normalizes_valid_profile() {
        let mut profile = fixture_profile();
        profile.id = " profile-1 ".into();
        profile.name = " Production ".into();

        let normalized = validate_profile(&profile).unwrap();

        assert_eq!(normalized, fixture_profile());
    }

    #[test]
    fn serializes_profile_fields_as_camel_case_and_auth_as_lowercase() {
        let dir = unique_test_dir();
        let key = write_test_key(&dir);
        let mut profile = fixture_profile();
        profile.auth_type = SshAuthType::Key;
        profile.identity_file = Some(key.to_string_lossy().into_owned());

        let value = serde_json::to_value(&profile).unwrap();

        assert_eq!(value["authType"], "key");
        assert_eq!(value["identityFile"], profile.identity_file.unwrap());
        assert_eq!(value["connectTimeout"], 15);
        assert!(value.get("auth_type").is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn supports_all_auth_type_values() {
        for (auth_type, expected) in [
            (SshAuthType::Agent, "agent"),
            (SshAuthType::Key, "key"),
            (SshAuthType::Password, "password"),
        ] {
            assert_eq!(
                serde_json::to_string(&auth_type).unwrap(),
                format!("\"{expected}\"")
            );
        }
    }

    #[test]
    fn clears_identity_file_for_non_key_authentication() {
        for auth_type in [SshAuthType::Agent, SshAuthType::Password] {
            let mut profile = fixture_profile();
            profile.auth_type = auth_type;
            profile.identity_file = Some(" ~/.ssh/ignored-key ".into());

            assert_eq!(validate_profile(&profile).unwrap().identity_file, None);
        }
    }

    #[test]
    fn rejects_control_characters_in_ignored_identity_file() {
        for auth_type in [SshAuthType::Agent, SshAuthType::Password] {
            for control in ['\0', '\r', '\n'] {
                let mut profile = fixture_profile();
                profile.auth_type = auth_type.clone();
                profile.identity_file = Some(format!("ignored{control}key"));

                assert!(validate_profile(&profile)
                    .unwrap_err()
                    .contains("不能包含 NUL、回车或换行"));
            }
        }
    }

    #[test]
    fn rejects_empty_required_strings() {
        for (field, expected) in [
            ("id", "连接 ID 不能为空。"),
            ("name", "连接名称不能为空。"),
            ("host", "主机地址不能为空。"),
            ("username", "用户名不能为空。"),
        ] {
            let mut profile = fixture_profile();
            match field {
                "id" => profile.id = " \t ".into(),
                "name" => profile.name = " \t ".into(),
                "host" => profile.host = " \t ".into(),
                "username" => profile.username = " \t ".into(),
                _ => unreachable!(),
            }
            assert_eq!(validate_profile(&profile).unwrap_err(), expected);
        }
    }

    #[test]
    fn rejects_zero_port() {
        let mut profile = fixture_profile();
        profile.port = 0;

        assert_eq!(
            validate_profile(&profile).unwrap_err(),
            "端口必须在 1 到 65535 之间。"
        );
    }

    #[test]
    fn rejects_timeout_outside_supported_range() {
        for timeout in [0, 121] {
            let mut profile = fixture_profile();
            profile.connect_timeout = timeout;
            assert_eq!(
                validate_profile(&profile).unwrap_err(),
                "连接超时必须在 1 到 120 秒之间。"
            );
        }
    }

    #[test]
    fn rejects_nul_carriage_return_and_line_feed_in_strings() {
        for control in ['\0', '\r', '\n'] {
            for field in ["id", "name", "host", "username", "identityFile"] {
                let mut profile = fixture_profile();
                let value = format!("before{control}after");
                match field {
                    "id" => profile.id = value,
                    "name" => profile.name = value,
                    "host" => profile.host = value,
                    "username" => profile.username = value,
                    "identityFile" => {
                        profile.auth_type = SshAuthType::Key;
                        profile.identity_file = Some(value);
                    }
                    _ => unreachable!(),
                }
                assert!(
                    validate_profile(&profile)
                        .unwrap_err()
                        .contains("不能包含 NUL、回车或换行"),
                    "field={field}, control={control:?}"
                );
            }
        }
    }

    #[test]
    fn key_authentication_requires_identity_file() {
        let mut profile = fixture_profile();
        profile.auth_type = SshAuthType::Key;

        assert_eq!(
            validate_profile(&profile).unwrap_err(),
            "私钥认证必须指定私钥文件。"
        );

        profile.identity_file = Some(" \t ".into());
        assert_eq!(
            validate_profile(&profile).unwrap_err(),
            "私钥认证必须指定私钥文件。"
        );
    }

    #[test]
    fn connection_validation_requires_existing_regular_key_file() {
        let dir = unique_test_dir();
        fs::create_dir_all(&dir).unwrap();
        let mut profile = fixture_profile();
        profile.auth_type = SshAuthType::Key;

        profile.identity_file = Some(dir.join("missing-key").to_string_lossy().into_owned());
        assert!(validate_profile_for_connection(&profile)
            .unwrap_err()
            .starts_with("私钥文件不存在或不是普通文件："));

        profile.identity_file = Some(dir.to_string_lossy().into_owned());
        assert!(validate_profile_for_connection(&profile)
            .unwrap_err()
            .starts_with("私钥文件不存在或不是普通文件："));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expands_windows_home_prefix_for_key_identity() {
        let home = Path::new(r"C:\Users\levi");

        assert_eq!(
            expand_home_prefix_with(r"~\.ssh\id_ed25519", Some(home), PlatformKind::Windows)
                .unwrap(),
            PathBuf::from(r"C:\Users\levi\.ssh\id_ed25519")
        );
        assert_eq!(
            expand_home_prefix_with("~/.ssh/id_ed25519", Some(home), PlatformKind::Windows)
                .unwrap(),
            PathBuf::from(r"C:\Users\levi\.ssh/id_ed25519")
        );
    }

    #[test]
    fn expands_macos_home_prefix_for_key_identity() {
        assert_eq!(
            expand_home_prefix_with(
                "~/.ssh/id_ed25519",
                Some(Path::new("/Users/levi")),
                PlatformKind::MacOs,
            )
            .unwrap(),
            PathBuf::from("/Users/levi/.ssh/id_ed25519")
        );
    }

    #[test]
    fn leaves_non_home_prefix_paths_unchanged() {
        for path in ["~", "~other/.ssh/id_ed25519", r"~other\.ssh\id_ed25519"] {
            assert_eq!(
                expand_home_prefix_with(path, None, PlatformKind::Windows).unwrap(),
                PathBuf::from(path)
            );
        }
        assert_eq!(
            expand_home_prefix_with(r"~\.ssh\id_ed25519", None, PlatformKind::MacOs).unwrap(),
            PathBuf::from(r"~\.ssh\id_ed25519")
        );
    }

    #[test]
    fn home_prefix_without_home_returns_chinese_error() {
        let error =
            expand_home_prefix_with("~/.ssh/id_ed25519", None, PlatformKind::Windows).unwrap_err();

        assert_eq!(error, "无法展开私钥路径：无法定位用户主目录。");
        assert!(!error.contains(r"C:\Users\secret-user"));
    }

    #[test]
    fn expands_home_prefix_for_key_identity() {
        let home = PathBuf::from(std::env::var_os("HOME").expect("测试需要 HOME"));
        let file_name = format!(
            ".terminal-codex-ssh-key-test-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = home.join(&file_name);
        fs::write(&path, "test-key").unwrap();

        let mut profile = fixture_profile();
        profile.auth_type = SshAuthType::Key;
        profile.identity_file = Some(format!("~/{file_name}"));
        let normalized = validate_profile(&profile).unwrap();

        assert_eq!(
            normalized.identity_file.as_deref(),
            Some(path.to_string_lossy().as_ref())
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_profile_file_loads_as_empty() {
        let dir = unique_test_dir();
        let path = dir.join("ssh-profiles.json");

        assert_eq!(load_profiles(&path).unwrap(), Vec::<SshProfile>::new());
    }

    #[test]
    fn rejects_unsupported_document_version() {
        let dir = unique_test_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ssh-profiles.json");
        fs::write(&path, r#"{"version":2,"profiles":[]}"#).unwrap();

        assert_eq!(
            load_profiles(&path).unwrap_err(),
            "不支持的 SSH 配置文件版本：2。"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_corrupt_json_in_chinese() {
        let dir = unique_test_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ssh-profiles.json");
        fs::write(&path, "{not-json").unwrap();

        let error = load_profiles(&path).unwrap_err();

        assert!(error.starts_with("无法解析 SSH 配置文件："));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn round_trips_profile_document() {
        let dir = unique_test_dir();
        let path = dir.join("nested/ssh-profiles.json");

        save_profiles(&path, &[fixture_profile()]).unwrap();

        assert_eq!(load_profiles(&path).unwrap(), vec![fixture_profile()]);
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(document["version"], 1);
        assert_eq!(document["profiles"].as_array().unwrap().len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replace_file_atomically_overwrites_existing_destination() {
        let dir = unique_test_dir();
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.tmp");
        let destination = dir.join("destination.json");
        fs::write(&source, b"new contents").unwrap();
        fs::write(&destination, b"old contents").unwrap();

        replace_file_atomically(&source, &destination).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new contents");
        assert!(!source.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persistence_allows_loading_profile_after_key_file_is_removed() {
        let dir = unique_test_dir();
        let path = dir.join("ssh-profiles.json");
        let key = write_test_key(&dir);
        let mut profile = fixture_profile();
        profile.auth_type = SshAuthType::Key;
        profile.identity_file = Some(key.to_string_lossy().into_owned());
        save_profiles(&path, &[profile.clone()]).unwrap();
        fs::remove_file(key).unwrap();

        assert_eq!(load_profiles(&path).unwrap(), vec![profile]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persistence_allows_saving_other_profile_when_key_file_is_missing() {
        let dir = unique_test_dir();
        let path = dir.join("ssh-profiles.json");
        let key = write_test_key(&dir);
        let mut key_profile = fixture_profile();
        key_profile.id = "key-profile".into();
        key_profile.auth_type = SshAuthType::Key;
        key_profile.identity_file = Some(key.to_string_lossy().into_owned());
        let mut agent_profile = fixture_profile();
        agent_profile.id = "agent-profile".into();
        save_profiles(&path, &[key_profile.clone(), agent_profile.clone()]).unwrap();
        fs::remove_file(key).unwrap();
        agent_profile.name = "Updated agent".into();

        save_profiles(&path, &[key_profile.clone(), agent_profile.clone()]).unwrap();

        assert_eq!(
            load_profiles(&path).unwrap(),
            vec![key_profile, agent_profile]
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_duplicate_profile_ids_without_overwriting_existing_file() {
        let dir = unique_test_dir();
        let path = dir.join("ssh-profiles.json");
        save_profiles(&path, &[fixture_profile()]).unwrap();
        let original = fs::read(&path).unwrap();
        let duplicate = fixture_profile();

        assert_eq!(
            save_profiles(&path, &[fixture_profile(), duplicate]).unwrap_err(),
            "SSH 连接 ID 重复：profile-1。"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn removes_temporary_file_when_atomic_rename_fails() {
        let dir = unique_test_dir();
        let path = dir.join("ssh-profiles.json");
        fs::create_dir_all(&path).unwrap();

        assert!(save_profiles(&path, &[fixture_profile()]).is_err());

        let entries = fs::read_dir(&dir)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path(), path);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_temporary_file_cleanup_failure() {
        let dir = unique_test_dir();
        let temporary_path = dir.join("temporary-directory");
        fs::create_dir_all(&temporary_path).unwrap();

        let error =
            cleanup_temporary_file_after_save_error(&temporary_path, "主要保存失败".to_string());

        assert!(error.starts_with("主要保存失败"));
        assert!(error.contains("清理 SSH 配置临时文件"));
        assert!(error.contains(temporary_path.to_string_lossy().as_ref()));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn saves_profile_file_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_test_dir();
        let path = dir.join("ssh-profiles.json");

        save_profiles(&path, &[fixture_profile()]).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn generates_distinct_version_four_profile_ids() {
        let first = generate_profile_id();
        let second = generate_profile_id();

        assert_ne!(first, second);
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4');
        assert!(matches!(first.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }
}
