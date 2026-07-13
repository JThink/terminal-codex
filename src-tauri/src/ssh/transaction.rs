use super::{
    credentials::{
        endpoint_fingerprint, CredentialRecord, CredentialStore, CredentialTransactionLock,
        CredentialUpdate, EndpointFingerprint, LaunchCredentialSnapshot,
    },
    generate_profile_id, load_profiles, save_profiles, validate_profile,
    validate_profile_for_connection, SshAuthType, SshProfile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const JOURNAL_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum CredentialMarker {
    Missing,
    Record {
        revision: uuid::Uuid,
        endpoint: EndpointFingerprint,
    },
    Opaque,
}

impl CredentialMarker {
    fn observe(value: Option<&Zeroizing<Vec<u8>>>) -> Self {
        let Some(value) = value else {
            return Self::Missing;
        };
        match CredentialRecord::decode(value) {
            Ok(record) => Self::Record {
                revision: record.revision(),
                endpoint: record.endpoint(),
            },
            Err(_) => Self::Opaque,
        }
    }

    fn from_record(record: &CredentialRecord) -> Self {
        Self::Record {
            revision: record.revision(),
            endpoint: record.endpoint(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum JournalOperation {
    Set,
    Clear,
    Delete,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialJournal {
    version: u8,
    operation: JournalOperation,
    profile_id: String,
    previous_profiles: Vec<SshProfile>,
    target_profiles: Vec<SshProfile>,
    previous_credential: CredentialMarker,
    target_credential: CredentialMarker,
}

enum CredentialMutation {
    Unchanged,
    Set(Zeroizing<Vec<u8>>),
    Delete,
}

struct CredentialPlan {
    profile_id: String,
    previous_profiles: Vec<SshProfile>,
    target_profiles: Vec<SshProfile>,
    previous_value: Option<Zeroizing<Vec<u8>>>,
    previous_marker: CredentialMarker,
    target_marker: CredentialMarker,
    mutation: CredentialMutation,
    journal_operation: Option<JournalOperation>,
    result_profile: Option<SshProfile>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransactionCrashPoint {
    Journal,
    Credential,
    Profiles,
}

impl TransactionCrashPoint {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 3] = [Self::Journal, Self::Credential, Self::Profiles];
}

pub(crate) fn credential_journal_path(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("ssh-profiles.txn.json")
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("无法同步 SSH 凭据事务目录 {}：{error}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn save_journal(path: &Path, journal: &CredentialJournal) -> Result<(), String> {
    validate_journal(journal)?;
    let journal_path = credential_journal_path(path);
    let parent = journal_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("无法创建 SSH 凭据事务目录 {}：{error}", parent.display()))?;
    let mut bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| format!("无法序列化 SSH 凭据事务：{error}"))?;
    bytes.push(b'\n');
    let temporary = parent.join(format!(".ssh-profiles.txn.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary).map_err(|error| {
            format!(
                "无法创建 SSH 凭据事务临时文件 {}：{error}",
                temporary.display()
            )
        })?;
        file.write_all(&bytes).map_err(|error| {
            format!(
                "无法写入 SSH 凭据事务临时文件 {}：{error}",
                temporary.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "无法同步 SSH 凭据事务临时文件 {}：{error}",
                temporary.display()
            )
        })?;
        drop(file);
        fs::rename(&temporary, &journal_path).map_err(|error| {
            format!(
                "无法提交 SSH 凭据事务文件 {}：{error}",
                journal_path.display()
            )
        })?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn load_journal(path: &Path) -> Result<Option<CredentialJournal>, String> {
    let journal_path = credential_journal_path(path);
    let bytes = match fs::read(&journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "无法读取 SSH 凭据事务文件 {}：{error}",
                journal_path.display()
            ));
        }
    };
    let journal: CredentialJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("无法解析 SSH 凭据事务文件：{error}"))?;
    if journal.version != JOURNAL_VERSION {
        return Err(format!("不支持的 SSH 凭据事务版本：{}。", journal.version));
    }
    validate_journal(&journal)?;
    Ok(Some(journal))
}

fn invalid_journal(reason: impl AsRef<str>) -> String {
    format!("SSH 凭据事务内容无效：{}。", reason.as_ref())
}

fn validate_journal_profiles(profiles: &[SshProfile], label: &str) -> Result<(), String> {
    let mut ids = HashSet::with_capacity(profiles.len());
    for profile in profiles {
        let normalized = validate_profile(profile)
            .map_err(|_| invalid_journal(format!("{label} Profile 无法通过结构校验")))?;
        if normalized != *profile {
            return Err(invalid_journal(format!("{label} Profile 不是规范格式")));
        }
        uuid::Uuid::parse_str(&profile.id)
            .map_err(|_| invalid_journal(format!("{label} Profile ID 不是有效 UUID")))?;
        if !ids.insert(profile.id.as_str()) {
            return Err(invalid_journal(format!("{label} Profile ID 重复")));
        }
    }
    Ok(())
}

fn record_marker_matches_profile(marker: CredentialMarker, profile: &SshProfile) -> bool {
    let CredentialMarker::Record { revision, endpoint } = marker else {
        return false;
    };
    profile.auth_type == SshAuthType::Password
        && profile
            .credential_revision
            .as_deref()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            == Some(revision)
        && endpoint == endpoint_fingerprint(&profile.host, profile.port, &profile.username)
}

fn validate_other_profiles_unchanged(journal: &CredentialJournal) -> Result<(), String> {
    let previous_others = journal
        .previous_profiles
        .iter()
        .filter(|profile| profile.id != journal.profile_id)
        .collect::<Vec<_>>();
    let target_others = journal
        .target_profiles
        .iter()
        .filter(|profile| profile.id != journal.profile_id)
        .collect::<Vec<_>>();
    if previous_others.len() != target_others.len()
        || previous_others
            .iter()
            .any(|previous| !target_others.contains(previous))
    {
        return Err(invalid_journal("事务修改了目标 ID 之外的 Profile"));
    }
    Ok(())
}

fn validate_journal(journal: &CredentialJournal) -> Result<(), String> {
    if journal.version != JOURNAL_VERSION {
        return Err(invalid_journal("版本与当前格式不匹配"));
    }
    uuid::Uuid::parse_str(&journal.profile_id)
        .map_err(|_| invalid_journal("Profile ID 不是有效 UUID"))?;
    validate_journal_profiles(&journal.previous_profiles, "previous")?;
    validate_journal_profiles(&journal.target_profiles, "target")?;
    if matches!(journal.target_credential, CredentialMarker::Opaque) {
        return Err(invalid_journal("target 凭据标记不能是 Opaque"));
    }
    if journal.previous_credential == journal.target_credential {
        return Err(invalid_journal("凭据状态没有发生变化"));
    }
    validate_other_profiles_unchanged(journal)?;

    let previous = journal
        .previous_profiles
        .iter()
        .find(|profile| profile.id == journal.profile_id);
    let target = journal
        .target_profiles
        .iter()
        .find(|profile| profile.id == journal.profile_id);
    if matches!(journal.previous_credential, CredentialMarker::Record { .. })
        && !previous
            .map(|profile| record_marker_matches_profile(journal.previous_credential, profile))
            .unwrap_or(false)
    {
        return Err(invalid_journal(
            "previous Record 未绑定对应的 Password Profile",
        ));
    }

    match journal.operation {
        JournalOperation::Set => {
            let target =
                target.ok_or_else(|| invalid_journal("Set 操作缺少目标 Password Profile"))?;
            let expected_len = journal.previous_profiles.len() + usize::from(previous.is_none());
            if journal.target_profiles.len() != expected_len
                || !record_marker_matches_profile(journal.target_credential, target)
            {
                return Err(invalid_journal(
                    "Set 目标 Profile 与 revision/endpoint Record 不匹配",
                ));
            }
        }
        JournalOperation::Clear => {
            let previous = previous
                .ok_or_else(|| invalid_journal("Clear 操作缺少 previous Password Profile"))?;
            let target =
                target.ok_or_else(|| invalid_journal("Clear 操作缺少目标非密码 Profile"))?;
            if journal.previous_profiles.len() != journal.target_profiles.len()
                || (journal.previous_credential != CredentialMarker::Opaque
                    && !record_marker_matches_profile(journal.previous_credential, previous))
                || target.auth_type == SshAuthType::Password
                || journal.target_credential != CredentialMarker::Missing
            {
                return Err(invalid_journal("Clear 操作的 Profile 或凭据标记关系不可能"));
            }
        }
        JournalOperation::Delete => {
            let previous = previous
                .ok_or_else(|| invalid_journal("Delete 操作缺少 previous Password Profile"))?;
            if target.is_some()
                || journal.previous_profiles.len() != journal.target_profiles.len() + 1
                || (journal.previous_credential != CredentialMarker::Opaque
                    && !record_marker_matches_profile(journal.previous_credential, previous))
                || journal.target_credential != CredentialMarker::Missing
            {
                return Err(invalid_journal(
                    "Delete 操作的 Profile 或凭据标记关系不可能",
                ));
            }
        }
    }
    Ok(())
}

fn clear_journal(path: &Path) -> Result<(), String> {
    let journal_path = credential_journal_path(path);
    match fs::remove_file(&journal_path) {
        Ok(()) => {
            let parent = journal_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            sync_directory(parent)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "无法清理 SSH 凭据事务文件 {}：{error}",
            journal_path.display()
        )),
    }
}

fn read_credential(
    credentials: &dyn CredentialStore,
    profile_id: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    credentials
        .get(profile_id)
        .map_err(|error| format!("无法读取 SSH 密码凭据：{error}"))
}

fn validate_keep_binding(
    existing: &SshProfile,
    requested: &SshProfile,
    value: Option<&Zeroizing<Vec<u8>>>,
) -> Result<uuid::Uuid, String> {
    let record = value
        .ok_or_else(|| "密码认证必须提供密码。".to_string())
        .and_then(|value| CredentialRecord::decode(value))?;
    let revision = existing
        .credential_revision
        .as_deref()
        .ok_or_else(|| "SSH 密码凭据缺少版本绑定，请重新输入密码。".to_string())
        .and_then(|value| {
            uuid::Uuid::parse_str(value)
                .map_err(|_| "SSH 密码凭据版本无效，请重新输入密码。".to_string())
        })?;
    let existing_endpoint = endpoint_fingerprint(&existing.host, existing.port, &existing.username);
    let requested_endpoint =
        endpoint_fingerprint(&requested.host, requested.port, &requested.username);
    if record.revision() != revision
        || record.endpoint() != existing_endpoint
        || record.endpoint() != requested_endpoint
    {
        return Err("主机、端口或用户名发生变化时必须重新输入密码。".to_string());
    }
    Ok(revision)
}

fn prepare_upsert(
    path: &Path,
    credentials: &dyn CredentialStore,
    mut profile: SshProfile,
    credential_update: CredentialUpdate,
) -> Result<CredentialPlan, String> {
    let is_new = profile.id.trim().is_empty();
    if is_new {
        profile.id = generate_profile_id();
    }
    let mut profile = validate_profile(&profile)?;
    uuid::Uuid::parse_str(&profile.id).map_err(|_| "连接 ID 必须是有效的 UUID。".to_string())?;
    let previous_profiles = load_profiles(path)?;
    let existing_index = previous_profiles
        .iter()
        .position(|existing| existing.id == profile.id);
    if !is_new && existing_index.is_none() {
        return Err("找不到要更新的 SSH 连接。".to_string());
    }
    if profile.auth_type == SshAuthType::Key {
        let unchanged_existing_key = existing_index
            .and_then(|index| previous_profiles.get(index))
            .map(|existing| {
                existing.auth_type == SshAuthType::Key
                    && existing.identity_file == profile.identity_file
            })
            .unwrap_or(false);
        if !unchanged_existing_key {
            profile = validate_profile_for_connection(&profile)?;
        }
    }
    let previous_value = read_credential(credentials, &profile.id)?;
    let previous_marker = CredentialMarker::observe(previous_value.as_ref());

    let (mutation, target_marker, journal_operation) = match (&profile.auth_type, credential_update)
    {
        (SshAuthType::Password, CredentialUpdate::Keep) => {
            let existing = existing_index
                .and_then(|index| previous_profiles.get(index))
                .ok_or_else(|| "密码认证必须提供密码。".to_string())?;
            let revision = validate_keep_binding(existing, &profile, previous_value.as_ref())?;
            profile.credential_revision = Some(revision.to_string());
            (CredentialMutation::Unchanged, previous_marker, None)
        }
        (SshAuthType::Password, CredentialUpdate::Set { password }) => {
            let revision = uuid::Uuid::new_v4();
            let record = CredentialRecord::new(
                revision,
                endpoint_fingerprint(&profile.host, profile.port, &profile.username),
                Zeroizing::new(password.as_bytes().to_vec()),
            )?;
            profile.credential_revision = Some(revision.to_string());
            let marker = CredentialMarker::from_record(&record);
            (
                CredentialMutation::Set(record.encode()),
                marker,
                Some(JournalOperation::Set),
            )
        }
        (SshAuthType::Password, CredentialUpdate::Clear) => {
            return Err("密码认证必须提供密码。".to_string());
        }
        (_, _) => {
            profile.credential_revision = None;
            if previous_value.is_some() {
                (
                    CredentialMutation::Delete,
                    CredentialMarker::Missing,
                    Some(JournalOperation::Clear),
                )
            } else {
                (
                    CredentialMutation::Unchanged,
                    CredentialMarker::Missing,
                    None,
                )
            }
        }
    };

    let mut target_profiles = previous_profiles.clone();
    if let Some(index) = existing_index {
        target_profiles[index] = profile.clone();
    } else {
        target_profiles.push(profile.clone());
    }
    Ok(CredentialPlan {
        profile_id: profile.id.clone(),
        previous_profiles,
        target_profiles,
        previous_value,
        previous_marker,
        target_marker,
        mutation,
        journal_operation,
        result_profile: Some(profile),
    })
}

fn prepare_delete(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile_id: &str,
) -> Result<CredentialPlan, String> {
    uuid::Uuid::parse_str(profile_id).map_err(|_| "连接 ID 必须是有效的 UUID。".to_string())?;
    let previous_profiles = load_profiles(path)?;
    let index = previous_profiles
        .iter()
        .position(|profile| profile.id == profile_id)
        .ok_or_else(|| "找不到要删除的 SSH 连接。".to_string())?;
    let previous_value = read_credential(credentials, profile_id)?;
    let previous_marker = CredentialMarker::observe(previous_value.as_ref());
    let mut target_profiles = previous_profiles.clone();
    target_profiles.remove(index);
    let mutation = if previous_value.is_some() {
        CredentialMutation::Delete
    } else {
        CredentialMutation::Unchanged
    };
    let journal_operation = previous_value.as_ref().map(|_| JournalOperation::Delete);
    Ok(CredentialPlan {
        profile_id: profile_id.to_string(),
        previous_profiles,
        target_profiles,
        previous_value,
        previous_marker,
        target_marker: CredentialMarker::Missing,
        mutation,
        journal_operation,
        result_profile: None,
    })
}

fn restore_previous_credential(
    credentials: &dyn CredentialStore,
    plan: &CredentialPlan,
) -> Result<(), String> {
    let current_value = read_credential(credentials, &plan.profile_id)?;
    let current_marker = CredentialMarker::observe(current_value.as_ref());
    if current_marker == plan.previous_marker {
        return Ok(());
    }
    if current_marker != plan.target_marker {
        return Err("SSH 密码凭据已被其他写入者修改，已拒绝覆盖并保留事务记录。".to_string());
    }
    match plan.previous_value.as_ref() {
        Some(value) => credentials.set(&plan.profile_id, value),
        None => credentials.delete(&plan.profile_id),
    }
}

fn rollback_after_error(
    path: &Path,
    credentials: &dyn CredentialStore,
    plan: &CredentialPlan,
    primary: String,
) -> String {
    let credential_result = restore_previous_credential(credentials, plan);
    if let Err(error) = credential_result {
        return format!("{primary}；恢复 SSH 密码凭据失败：{error}");
    }
    let profiles_result = save_profiles(path, &plan.previous_profiles);
    if profiles_result.is_ok() {
        return match clear_journal(path) {
            Ok(()) => primary,
            Err(error) => format!("{primary}；清理回滚事务失败：{error}"),
        };
    }
    let mut details = Vec::new();
    if let Err(error) = profiles_result {
        details.push(format!("恢复 SSH Profile 失败：{error}"));
    }
    format!("{primary}；{}", details.join("；"))
}

fn execute_plan(
    path: &Path,
    credentials: &dyn CredentialStore,
    plan: &CredentialPlan,
    crash_at: Option<TransactionCrashPoint>,
) -> Result<(), String> {
    if matches!(plan.mutation, CredentialMutation::Unchanged) {
        return save_profiles(path, &plan.target_profiles);
    }
    let journal = CredentialJournal {
        version: JOURNAL_VERSION,
        operation: plan
            .journal_operation
            .ok_or_else(|| "SSH Profile 事务操作类型无效。".to_string())?,
        profile_id: plan.profile_id.clone(),
        previous_profiles: plan.previous_profiles.clone(),
        target_profiles: plan.target_profiles.clone(),
        previous_credential: plan.previous_marker,
        target_credential: plan.target_marker,
    };
    save_journal(path, &journal)?;
    if crash_at == Some(TransactionCrashPoint::Journal) {
        return Err("模拟在 journal 提交后崩溃。".to_string());
    }

    let credential_result = match &plan.mutation {
        CredentialMutation::Set(value) => credentials.set(&plan.profile_id, value),
        CredentialMutation::Delete => credentials.delete(&plan.profile_id),
        CredentialMutation::Unchanged => Ok(()),
    };
    if let Err(error) = credential_result {
        let primary = format!("无法提交 SSH 密码凭据变更：{error}");
        return Err(rollback_after_error(path, credentials, plan, primary));
    }
    if crash_at == Some(TransactionCrashPoint::Credential) {
        return Err("模拟在 Keychain 提交后崩溃。".to_string());
    }

    if let Err(error) = save_profiles(path, &plan.target_profiles) {
        return Err(rollback_after_error(path, credentials, plan, error));
    }
    if crash_at == Some(TransactionCrashPoint::Profiles) {
        return Err("模拟在 Profile 提交后崩溃。".to_string());
    }
    clear_journal(path)
}

fn recover_locked(path: &Path, credentials: &dyn CredentialStore) -> Result<(), String> {
    let Some(journal) = load_journal(path)? else {
        return Ok(());
    };
    let current_profiles = load_profiles(path)?;
    if current_profiles != journal.previous_profiles && current_profiles != journal.target_profiles
    {
        return Err("当前 SSH Profile 已与事务快照分叉，已保留恢复记录并拒绝写盘。".to_string());
    }
    let current_value = read_credential(credentials, &journal.profile_id)?;
    let current_marker = CredentialMarker::observe(current_value.as_ref());
    let profiles = if current_marker == journal.target_credential {
        &journal.target_profiles
    } else {
        match journal.previous_credential {
            CredentialMarker::Opaque if current_marker == CredentialMarker::Opaque => {
                &journal.previous_profiles
            }
            CredentialMarker::Record { .. } | CredentialMarker::Missing
                if current_marker == journal.previous_credential =>
            {
                &journal.previous_profiles
            }
            _ => {
                return Err("SSH 凭据事务处于未知状态，已保留恢复记录并拒绝继续操作。".to_string());
            }
        }
    };
    save_profiles(path, profiles)?;
    clear_journal(path)
}

pub(crate) fn recover_credential_transaction(
    path: &Path,
    credentials: &dyn CredentialStore,
) -> Result<(), String> {
    let _lock = CredentialTransactionLock::acquire(path)?;
    recover_locked(path, credentials)
}

pub(crate) fn upsert_profile_with_credential(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile: SshProfile,
    credential_update: CredentialUpdate,
) -> Result<SshProfile, String> {
    let _lock = CredentialTransactionLock::acquire(path)?;
    recover_locked(path, credentials)?;
    let plan = prepare_upsert(path, credentials, profile, credential_update)?;
    execute_plan(path, credentials, &plan, None)?;
    plan.result_profile
        .ok_or_else(|| "SSH Profile 事务结果无效。".to_string())
}

pub(crate) fn delete_profile_with_credential(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile_id: &str,
) -> Result<(), String> {
    let _lock = CredentialTransactionLock::acquire(path)?;
    recover_locked(path, credentials)?;
    let plan = prepare_delete(path, credentials, profile_id)?;
    execute_plan(path, credentials, &plan, None)
}

pub(crate) fn credential_snapshot_for_launch(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile_id: &str,
) -> Result<LaunchCredentialSnapshot, String> {
    let _lock = CredentialTransactionLock::acquire(path)?;
    recover_locked(path, credentials)?;
    uuid::Uuid::parse_str(profile_id).map_err(|_| "连接 ID 必须是有效的 UUID。".to_string())?;
    let profile = load_profiles(path)?
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| "找不到要连接的 SSH Profile。".to_string())?;
    if profile.auth_type != SshAuthType::Password {
        return Err("SSH Profile 未使用密码认证。".to_string());
    }
    let revision = profile
        .credential_revision
        .as_deref()
        .ok_or_else(|| "SSH 密码凭据缺少版本绑定。".to_string())
        .and_then(|value| {
            uuid::Uuid::parse_str(value).map_err(|_| "SSH 密码凭据版本无效。".to_string())
        })?;
    let value = read_credential(credentials, profile_id)?
        .ok_or_else(|| "找不到 SSH 密码凭据。".to_string())?;
    let record = CredentialRecord::decode(&value)?;
    let endpoint = endpoint_fingerprint(&profile.host, profile.port, &profile.username);
    if record.revision() != revision || record.endpoint() != endpoint {
        return Err("SSH Profile 与密码凭据绑定不匹配，已拒绝连接。".to_string());
    }
    Ok(LaunchCredentialSnapshot {
        profile,
        revision,
        endpoint,
        password: record.into_password(),
    })
}

#[cfg(test)]
pub(crate) fn upsert_profile_with_credential_at_crash(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile: SshProfile,
    credential_update: CredentialUpdate,
    crash_at: TransactionCrashPoint,
) -> Result<SshProfile, String> {
    let _lock = CredentialTransactionLock::acquire(path)?;
    recover_locked(path, credentials)?;
    let plan = prepare_upsert(path, credentials, profile, credential_update)?;
    execute_plan(path, credentials, &plan, Some(crash_at))?;
    plan.result_profile
        .ok_or_else(|| "SSH Profile 事务结果无效。".to_string())
}

#[cfg(test)]
pub(crate) fn delete_profile_with_credential_at_crash(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile_id: &str,
    crash_at: TransactionCrashPoint,
) -> Result<(), String> {
    let _lock = CredentialTransactionLock::acquire(path)?;
    recover_locked(path, credentials)?;
    let plan = prepare_delete(path, credentials, profile_id)?;
    execute_plan(path, credentials, &plan, Some(crash_at))
}
