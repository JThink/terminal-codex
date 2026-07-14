#[cfg(test)]
use super::{generate_profile_id, validate_profile, validate_profile_for_connection, SshAuthType};
use super::{replace_file_atomically, SshProfile};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroizing;

use fs2::FileExt;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const CREDENTIAL_RECORD_MAGIC: &[u8; 8] = b"LCSSHCR\0";
const CREDENTIAL_RECORD_VERSION: u8 = 1;
const CREDENTIAL_RECORD_HEADER_LEN: usize = 8 + 1 + 16 + 32 + 4;
const LOCAL_VAULT_KEY_LEN: usize = 32;
const LOCAL_VAULT_NONCE_LEN: usize = 12;
const LOCAL_VAULT_VERSION: u32 = 1;
static PROCESS_CREDENTIAL_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn credential_lock_path(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("ssh-profiles.lock")
}

pub(crate) struct CredentialTransactionLock {
    _process_guard: MutexGuard<'static, ()>,
    _file: File,
}

impl CredentialTransactionLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, String> {
        let process_guard = PROCESS_CREDENTIAL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let lock_path = credential_lock_path(path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("无法创建 SSH 凭据锁目录 {}：{error}", parent.display())
            })?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&lock_path)
            .map_err(|error| format!("无法打开 SSH 凭据锁文件 {}：{error}", lock_path.display()))?;
        file.lock_exclusive()
            .map_err(|error| format!("无法锁定 SSH 凭据文件 {}：{error}", lock_path.display()))?;
        Ok(Self {
            _process_guard: process_guard,
            _file: file,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
pub(crate) struct EndpointFingerprint([u8; 32]);

pub(crate) fn endpoint_fingerprint(host: &str, port: u16, username: &str) -> EndpointFingerprint {
    fn update_field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u32).to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"codex-terminal-ssh-endpoint-v1\0");
    update_field(&mut hasher, host.as_bytes());
    update_field(&mut hasher, &port.to_be_bytes());
    update_field(&mut hasher, username.as_bytes());
    EndpointFingerprint(hasher.finalize().into())
}

pub(crate) struct CredentialRecord {
    revision: uuid::Uuid,
    endpoint: EndpointFingerprint,
    password: Zeroizing<Vec<u8>>,
}

pub(crate) struct LaunchCredentialSnapshot {
    pub(crate) profile: SshProfile,
    pub(crate) revision: uuid::Uuid,
    pub(crate) endpoint: EndpointFingerprint,
    pub(crate) password: Zeroizing<Vec<u8>>,
}

impl CredentialRecord {
    pub(crate) fn new(
        revision: uuid::Uuid,
        endpoint: EndpointFingerprint,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<Self, String> {
        validate_record_password(&password)?;
        u32::try_from(password.len()).map_err(|_| "SSH 密码凭据长度超出支持范围。".to_string())?;
        Ok(Self {
            revision,
            endpoint,
            password,
        })
    }

    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        if value.len() < CREDENTIAL_RECORD_HEADER_LEN
            || &value[..CREDENTIAL_RECORD_MAGIC.len()] != CREDENTIAL_RECORD_MAGIC
            || value[CREDENTIAL_RECORD_MAGIC.len()] != CREDENTIAL_RECORD_VERSION
        {
            return Err("SSH 密码凭据记录格式无效或版本不受支持。".to_string());
        }
        let mut offset = CREDENTIAL_RECORD_MAGIC.len() + 1;
        let revision = uuid::Uuid::from_slice(&value[offset..offset + 16])
            .map_err(|_| "SSH 密码凭据记录格式无效。".to_string())?;
        offset += 16;
        let mut endpoint = [0_u8; 32];
        endpoint.copy_from_slice(&value[offset..offset + 32]);
        offset += 32;
        let password_len = u32::from_be_bytes(
            value[offset..offset + 4]
                .try_into()
                .map_err(|_| "SSH 密码凭据记录格式无效。".to_string())?,
        ) as usize;
        offset += 4;
        if password_len == 0 || value.len() != offset.saturating_add(password_len) {
            return Err("SSH 密码凭据记录格式无效。".to_string());
        }
        Self::new(
            revision,
            EndpointFingerprint(endpoint),
            Zeroizing::new(value[offset..].to_vec()),
        )
    }

    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut value = Zeroizing::new(Vec::with_capacity(
            CREDENTIAL_RECORD_HEADER_LEN + self.password.len(),
        ));
        value.extend_from_slice(CREDENTIAL_RECORD_MAGIC);
        value.push(CREDENTIAL_RECORD_VERSION);
        value.extend_from_slice(self.revision.as_bytes());
        value.extend_from_slice(&self.endpoint.0);
        value.extend_from_slice(&(self.password.len() as u32).to_be_bytes());
        value.extend_from_slice(&self.password);
        value
    }

    pub(crate) fn revision(&self) -> uuid::Uuid {
        self.revision
    }

    pub(crate) fn endpoint(&self) -> EndpointFingerprint {
        self.endpoint
    }

    #[cfg(test)]
    pub(crate) fn password(&self) -> &[u8] {
        &self.password
    }

    pub(crate) fn into_password(self) -> Zeroizing<Vec<u8>> {
        self.password
    }
}

fn validate_record_password(password: &[u8]) -> Result<(), String> {
    let password = std::str::from_utf8(password)
        .map_err(|_| "SSH 密码凭据必须是有效的 UTF-8。".to_string())?;
    validate_password(password)
}

pub(crate) trait CredentialStore {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    fn set(&self, account: &str, password: &[u8]) -> Result<(), String>;
    fn delete(&self, account: &str) -> Result<(), String>;
}

#[derive(Clone, Debug)]
pub(crate) struct LocalVaultCredentialStore {
    key_path: PathBuf,
    vault_path: PathBuf,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalVaultDocument {
    version: u32,
    records: BTreeMap<String, LocalVaultEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalVaultEntry {
    nonce: String,
    ciphertext: String,
}

impl LocalVaultDocument {
    fn new() -> Self {
        Self {
            version: LOCAL_VAULT_VERSION,
            records: BTreeMap::new(),
        }
    }
}

impl LocalVaultCredentialStore {
    pub(crate) fn for_app_config_dir(app_config_dir: &Path) -> Self {
        Self {
            key_path: app_config_dir.join("ssh-secrets.key"),
            vault_path: app_config_dir.join("ssh-secrets.vault"),
        }
    }

    pub(crate) fn for_profiles_path(profiles_path: &Path) -> Self {
        let app_config_dir = profiles_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Self::for_app_config_dir(app_config_dir)
    }

    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let key = fs::read(&self.key_path).map_err(|error| {
            format!(
                "无法读取 SSH 本地凭据密钥 {}：{error}",
                self.key_path.display()
            )
        })?;
        if key.len() != LOCAL_VAULT_KEY_LEN {
            return Err("SSH 本地凭据密钥长度无效。".to_string());
        }
        Ok(Zeroizing::new(key))
    }

    fn load_or_create_key(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        match self.load_key() {
            Ok(key) => Ok(key),
            Err(_) if !self.key_path.exists() => {
                let mut key = Zeroizing::new(vec![0_u8; LOCAL_VAULT_KEY_LEN]);
                getrandom::getrandom(&mut key)
                    .map_err(|error| format!("无法生成 SSH 本地凭据密钥：{error}"))?;
                write_secret_file(&self.key_path, &key)?;
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }

    fn load_vault(&self) -> Result<LocalVaultDocument, String> {
        match fs::read(&self.vault_path) {
            Ok(bytes) => {
                let document: LocalVaultDocument =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        format!(
                            "SSH 本地凭据库格式无效 {}：{error}",
                            self.vault_path.display()
                        )
                    })?;
                if document.version != LOCAL_VAULT_VERSION {
                    return Err("SSH 本地凭据库版本不受支持。".to_string());
                }
                Ok(document)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(LocalVaultDocument::new())
            }
            Err(error) => Err(format!(
                "无法读取 SSH 本地凭据库 {}：{error}",
                self.vault_path.display()
            )),
        }
    }

    fn save_vault(&self, document: &LocalVaultDocument) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(document)
            .map_err(|error| format!("无法序列化 SSH 本地凭据库：{error}"))?;
        write_secret_file(&self.vault_path, &bytes)
    }
}

impl CredentialStore for LocalVaultCredentialStore {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        if !self.vault_path.exists() {
            return Ok(None);
        }
        let vault = self.load_vault()?;
        let Some(entry) = vault.records.get(account) else {
            return Ok(None);
        };
        let key = self.load_key()?;
        let nonce = hex_decode_exact(&entry.nonce, LOCAL_VAULT_NONCE_LEN)?;
        let ciphertext = hex_decode(&entry.ciphertext)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| "SSH 本地凭据密钥无效。".to_string())?;
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: account.as_bytes(),
                },
            )
            .map(|value| Some(Zeroizing::new(value)))
            .map_err(|_| "无法解密 SSH 本地凭据。".to_string())
    }

    fn set(&self, account: &str, password: &[u8]) -> Result<(), String> {
        CredentialRecord::decode(password)
            .map_err(|_| "拒绝保存格式无效的 SSH 密码凭据。".to_string())?;
        let key = self.load_or_create_key()?;
        let mut nonce = [0_u8; LOCAL_VAULT_NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("无法生成 SSH 本地凭据 nonce：{error}"))?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| "SSH 本地凭据密钥无效。".to_string())?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: password,
                    aad: account.as_bytes(),
                },
            )
            .map_err(|_| "无法加密 SSH 本地凭据。".to_string())?;
        let mut vault = self.load_vault()?;
        vault.records.insert(
            account.to_string(),
            LocalVaultEntry {
                nonce: hex_encode(&nonce),
                ciphertext: hex_encode(&ciphertext),
            },
        );
        self.save_vault(&vault)
    }

    fn delete(&self, account: &str) -> Result<(), String> {
        if !self.vault_path.exists() {
            return Ok(());
        }
        let mut vault = self.load_vault()?;
        if vault.records.remove(account).is_some() {
            self.save_vault(&vault)?;
        }
        Ok(())
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("无法创建 SSH 本地凭据目录 {}：{error}", parent.display()))?;
    }
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ssh-secret"),
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).map_err(|error| {
        format!(
            "无法创建 SSH 本地凭据临时文件 {}：{error}",
            temporary.display()
        )
    })?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "无法写入 SSH 本地凭据临时文件 {}：{error}",
            temporary.display()
        ));
    }
    drop(file);
    replace_file_atomically(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!("无法替换 SSH 本地凭据文件 {}：{error}", path.display())
    })?;
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|error| format!("无法设置 SSH 本地凭据文件权限 {}：{error}", path.display()))?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(TABLE[(byte >> 4) as usize] as char);
        encoded.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode_exact(value: &str, len: usize) -> Result<Vec<u8>, String> {
    let decoded = hex_decode(value)?;
    if decoded.len() != len {
        return Err("SSH 本地凭据库编码长度无效。".to_string());
    }
    Ok(decoded)
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("SSH 本地凭据库编码无效。".to_string());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for chunk in raw.chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("SSH 本地凭据库编码无效。".to_string()),
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub(crate) enum CredentialUpdate {
    Keep,
    Set { password: Zeroizing<String> },
    Clear,
}

impl CredentialUpdate {
    #[cfg(test)]
    pub(super) fn set(password: impl Into<String>) -> Self {
        Self::Set {
            password: Zeroizing::new(password.into()),
        }
    }
}

#[cfg(test)]
pub(super) trait ProfileRepository {
    fn load(&self) -> Result<Vec<SshProfile>, String>;
    fn save(&self, profiles: &[SshProfile]) -> Result<(), String>;
}

#[cfg(test)]
pub(crate) fn validate_transaction_profile(profile: &SshProfile) -> Result<SshProfile, String> {
    let normalized = if profile.auth_type == SshAuthType::Key {
        validate_profile_for_connection(profile)?
    } else {
        validate_profile(profile)?
    };
    uuid::Uuid::parse_str(&normalized.id).map_err(|_| "连接 ID 必须是有效的 UUID。".to_string())?;
    Ok(normalized)
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("密码不能为空。".to_string());
    }
    if password.as_bytes().contains(&0)
        || password.as_bytes().contains(&b'\r')
        || password.as_bytes().contains(&b'\n')
    {
        return Err("密码不能包含 NUL、回车或换行。".to_string());
    }
    Ok(())
}

#[cfg(test)]
fn restore_credential(
    credentials: &dyn CredentialStore,
    account: &str,
    previous: Option<&Zeroizing<Vec<u8>>>,
) -> Result<(), String> {
    match previous {
        Some(password) => credentials.set(account, password),
        None => credentials.delete(account),
    }
}

#[cfg(test)]
fn append_rollback_error(primary: String, rollback: Result<(), String>) -> String {
    match rollback {
        Ok(()) => primary,
        Err(error) => format!("{primary}；恢复 SSH 密码凭据失败：{error}"),
    }
}

#[cfg(test)]
pub(super) fn upsert_profile_transaction(
    repository: &dyn ProfileRepository,
    credentials: &dyn CredentialStore,
    mut profile: SshProfile,
    credential_update: CredentialUpdate,
) -> Result<SshProfile, String> {
    let is_new = profile.id.trim().is_empty();
    if is_new {
        profile.id = generate_profile_id();
    }
    let mut profile = validate_transaction_profile(&profile)?;
    let mut profiles = repository.load()?;
    let existing_index = profiles
        .iter()
        .position(|existing| existing.id == profile.id);
    if !is_new && existing_index.is_none() {
        return Err("找不到要更新的 SSH 连接。".to_string());
    }

    let previous_credential = credentials
        .get(&profile.id)
        .map_err(|error| format!("无法读取 SSH 密码凭据：{error}"))?;

    let credential_changed = match (&profile.auth_type, credential_update) {
        (SshAuthType::Password, CredentialUpdate::Keep) => {
            let existing = existing_index
                .and_then(|index| profiles.get(index))
                .ok_or_else(|| "密码认证必须提供密码。".to_string())?;
            let record = previous_credential
                .as_deref()
                .ok_or_else(|| "密码认证必须提供密码。".to_string())
                .and_then(|value| CredentialRecord::decode(value.as_slice()))?;
            let stored_revision = existing
                .credential_revision
                .as_deref()
                .ok_or_else(|| "SSH 密码凭据缺少版本绑定，请重新输入密码。".to_string())
                .and_then(|revision| {
                    uuid::Uuid::parse_str(revision)
                        .map_err(|_| "SSH 密码凭据版本无效，请重新输入密码。".to_string())
                })?;
            let existing_endpoint =
                endpoint_fingerprint(&existing.host, existing.port, &existing.username);
            let requested_endpoint =
                endpoint_fingerprint(&profile.host, profile.port, &profile.username);
            if record.revision() != stored_revision
                || record.endpoint() != existing_endpoint
                || record.endpoint() != requested_endpoint
            {
                return Err("主机、端口或用户名发生变化时必须重新输入密码。".to_string());
            }
            profile.credential_revision = Some(record.revision().to_string());
            false
        }
        (SshAuthType::Password, CredentialUpdate::Set { password }) => {
            validate_password(&password)?;
            let revision = uuid::Uuid::new_v4();
            let record = CredentialRecord::new(
                revision,
                endpoint_fingerprint(&profile.host, profile.port, &profile.username),
                Zeroizing::new(password.as_bytes().to_vec()),
            )?;
            credentials
                .set(&profile.id, &record.encode())
                .map_err(|error| format!("无法保存 SSH 密码凭据：{error}"))?;
            profile.credential_revision = Some(revision.to_string());
            true
        }
        (SshAuthType::Password, CredentialUpdate::Clear) => {
            return Err("密码认证必须提供密码。".to_string());
        }
        (_, _) => {
            credentials
                .delete(&profile.id)
                .map_err(|error| format!("无法删除 SSH 密码凭据：{error}"))?;
            true
        }
    };

    if let Some(index) = existing_index {
        profiles[index] = profile.clone();
    } else {
        profiles.push(profile.clone());
    }

    if let Err(error) = repository.save(&profiles) {
        let rollback = if credential_changed {
            restore_credential(credentials, &profile.id, previous_credential.as_ref())
        } else {
            Ok(())
        };
        return Err(append_rollback_error(error, rollback));
    }
    Ok(profile)
}

#[cfg(test)]
pub(super) fn delete_profile_transaction(
    repository: &dyn ProfileRepository,
    credentials: &dyn CredentialStore,
    profile_id: &str,
) -> Result<(), String> {
    uuid::Uuid::parse_str(profile_id).map_err(|_| "连接 ID 必须是有效的 UUID。".to_string())?;
    let mut profiles = repository.load()?;
    let index = profiles
        .iter()
        .position(|profile| profile.id == profile_id)
        .ok_or_else(|| "找不到要删除的 SSH 连接。".to_string())?;
    let previous_credential = credentials
        .get(profile_id)
        .map_err(|error| format!("无法读取 SSH 密码凭据：{error}"))?;
    credentials
        .delete(profile_id)
        .map_err(|error| format!("无法删除 SSH 密码凭据：{error}"))?;
    profiles.remove(index);

    if let Err(error) = repository.save(&profiles) {
        let rollback = restore_credential(credentials, profile_id, previous_credential.as_ref());
        return Err(append_rollback_error(error, rollback));
    }
    Ok(())
}

pub(crate) fn upsert_profile_with_credential(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile: SshProfile,
    credential_update: CredentialUpdate,
) -> Result<SshProfile, String> {
    super::transaction::upsert_profile_with_credential(
        path,
        credentials,
        profile,
        credential_update,
    )
}

pub(crate) fn delete_profile_with_credential(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile_id: &str,
) -> Result<(), String> {
    super::transaction::delete_profile_with_credential(path, credentials, profile_id)
}

pub(crate) fn credential_snapshot_for_launch(
    path: &Path,
    credentials: &dyn CredentialStore,
    profile_id: &str,
) -> Result<LaunchCredentialSnapshot, String> {
    super::transaction::credential_snapshot_for_launch(path, credentials, profile_id)
}

#[cfg(test)]
use super::transaction::{
    credential_journal_path, delete_profile_with_credential_at_crash,
    recover_credential_transaction, upsert_profile_with_credential_at_crash, TransactionCrashPoint,
};

#[cfg(test)]
mod local_vault_tests {
    use super::{
        endpoint_fingerprint, CredentialRecord, CredentialStore, LocalVaultCredentialStore,
    };
    use std::{fs, path::PathBuf};
    use zeroize::Zeroizing;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "terminal-codex-local-vault-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn local_vault_store_encrypts_updates_and_deletes_without_plaintext() {
        let dir = TestDir::new();
        let profiles_path = dir.0.join("ssh-profiles.json");
        let store = LocalVaultCredentialStore::for_profiles_path(&profiles_path);
        let account = "74c00a0b-a7e5-410c-9aed-7e9f5045507b";
        let endpoint = endpoint_fingerprint("example.com", 22, "deploy");
        let first = CredentialRecord::new(
            uuid::Uuid::new_v4(),
            endpoint,
            Zeroizing::new(b"first-local-vault-password".to_vec()),
        )
        .unwrap();
        let second = CredentialRecord::new(
            uuid::Uuid::new_v4(),
            endpoint,
            Zeroizing::new(b"second-local-vault-password".to_vec()),
        )
        .unwrap();

        store.set(account, &first.encode()).unwrap();
        assert_eq!(
            CredentialRecord::decode(&store.get(account).unwrap().unwrap())
                .unwrap()
                .password(),
            b"first-local-vault-password"
        );
        let first_vault = fs::read(dir.0.join("ssh-secrets.vault")).unwrap();
        assert!(!first_vault
            .windows(b"first-local-vault-password".len())
            .any(|window| window == b"first-local-vault-password"));
        assert!(fs::metadata(dir.0.join("ssh-secrets.key"))
            .unwrap()
            .is_file());

        store.set(account, &second.encode()).unwrap();
        assert_eq!(
            CredentialRecord::decode(&store.get(account).unwrap().unwrap())
                .unwrap()
                .password(),
            b"second-local-vault-password"
        );
        assert!(!fs::read(dir.0.join("ssh-secrets.vault"))
            .unwrap()
            .windows(b"second-local-vault-password".len())
            .any(|window| window == b"second-local-vault-password"));

        store.delete(account).unwrap();
        assert!(store.get(account).unwrap().is_none());
    }
}

#[cfg(test)]
mod record_tests {
    use super::{endpoint_fingerprint, CredentialRecord};
    use crate::ssh::{SshAuthType, SshProfile};
    use zeroize::Zeroizing;

    const SECRET: &[u8] = b"record-test-secret";

    fn profile() -> SshProfile {
        SshProfile {
            id: "74c00a0b-a7e5-410c-9aed-7e9f5045507b".into(),
            name: "Production".into(),
            host: "example.com".into(),
            port: 2222,
            username: "deploy".into(),
            auth_type: SshAuthType::Password,
            identity_file: None,
            connect_timeout: 15,
            credential_revision: None,
        }
    }

    #[test]
    fn credential_record_round_trips_versioned_binary_instead_of_raw_password() {
        let revision = uuid::Uuid::new_v4();
        let endpoint = endpoint_fingerprint("example.com", 2222, "deploy");
        let record =
            CredentialRecord::new(revision, endpoint, Zeroizing::new(SECRET.to_vec())).unwrap();

        let encoded = record.encode();

        assert_ne!(encoded.as_slice(), SECRET);
        assert!(encoded.starts_with(b"LCSSHCR\0"));
        let decoded = CredentialRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.revision(), revision);
        assert_eq!(decoded.endpoint(), endpoint);
        assert_eq!(decoded.password(), SECRET);
    }

    #[test]
    fn malformed_and_legacy_raw_credential_values_are_rejected_without_secret_in_error() {
        for value in [
            SECRET.to_vec(),
            b"LCSSHCR\0".to_vec(),
            [b"LCSSHCR\0".as_slice(), &[99], SECRET].concat(),
        ] {
            let error = match CredentialRecord::decode(&value) {
                Ok(_) => panic!("expected malformed record rejection"),
                Err(error) => error,
            };
            assert!(!error.contains(std::str::from_utf8(SECRET).unwrap()));
        }
    }

    #[test]
    fn endpoint_fingerprint_uses_unambiguous_field_boundaries() {
        assert_ne!(
            endpoint_fingerprint("ab", 22, "c"),
            endpoint_fingerprint("a", 22, "bc")
        );
        assert_ne!(
            endpoint_fingerprint("example.com", 22, "deploy"),
            endpoint_fingerprint("example.com", 2222, "deploy")
        );
        assert_ne!(
            endpoint_fingerprint("example.com", 22, "deploy"),
            endpoint_fingerprint("example.com", 22, "deploy2")
        );
    }

    #[test]
    fn profile_credential_revision_is_backward_compatible_and_persisted() {
        let mut value = serde_json::to_value(profile()).unwrap();
        value.as_object_mut().unwrap().remove("credentialRevision");

        let legacy: SshProfile = serde_json::from_value(value).unwrap();
        assert_eq!(legacy.credential_revision, None);

        let mut current = profile();
        current.credential_revision = Some("12d8876d-e9d7-4821-9a77-58db718147c2".into());
        let value = serde_json::to_value(current).unwrap();
        assert_eq!(
            value["credentialRevision"],
            "12d8876d-e9d7-4821-9a77-58db718147c2"
        );
    }
}

#[cfg(test)]
mod transaction_v2_tests {
    use super::{
        credential_snapshot_for_launch, endpoint_fingerprint, upsert_profile_transaction,
        upsert_profile_with_credential, CredentialRecord, CredentialStore, CredentialUpdate,
        ProfileRepository,
    };
    use crate::ssh::{save_profiles, SshAuthType, SshProfile};
    use std::{collections::HashMap, fs, path::PathBuf, sync::Mutex};
    use zeroize::Zeroizing;

    const PROFILE_ID: &str = "74c00a0b-a7e5-410c-9aed-7e9f5045507b";
    const SECRET: &[u8] = b"transaction-v2-secret";

    #[derive(Default)]
    struct MemoryCredentialStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryCredentialStore {
        fn bytes(&self, account: &str) -> Option<Vec<u8>> {
            self.values.lock().unwrap().get(account).cloned()
        }

        fn put_raw(&self, account: &str, value: &[u8]) {
            self.values
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_vec());
        }
    }

    impl CredentialStore for MemoryCredentialStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self.bytes(account).map(Zeroizing::new))
        }

        fn set(&self, account: &str, password: &[u8]) -> Result<(), String> {
            self.put_raw(account, password);
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), String> {
            self.values.lock().unwrap().remove(account);
            Ok(())
        }
    }

    struct MemoryProfileRepository(Mutex<Vec<SshProfile>>);

    impl MemoryProfileRepository {
        fn new(profiles: Vec<SshProfile>) -> Self {
            Self(Mutex::new(profiles))
        }

        fn profiles(&self) -> Vec<SshProfile> {
            self.0.lock().unwrap().clone()
        }
    }

    impl ProfileRepository for MemoryProfileRepository {
        fn load(&self) -> Result<Vec<SshProfile>, String> {
            Ok(self.profiles())
        }

        fn save(&self, profiles: &[SshProfile]) -> Result<(), String> {
            *self.0.lock().unwrap() = profiles.to_vec();
            Ok(())
        }
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "terminal-codex-credential-v2-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn profile() -> SshProfile {
        SshProfile {
            id: PROFILE_ID.into(),
            name: "Production".into(),
            host: "example.com".into(),
            port: 2222,
            username: "deploy".into(),
            auth_type: SshAuthType::Password,
            identity_file: None,
            connect_timeout: 15,
            credential_revision: None,
        }
    }

    fn install_record(store: &MemoryCredentialStore, profile: &mut SshProfile) -> uuid::Uuid {
        let revision = uuid::Uuid::new_v4();
        profile.credential_revision = Some(revision.to_string());
        let record = CredentialRecord::new(
            revision,
            endpoint_fingerprint(&profile.host, profile.port, &profile.username),
            Zeroizing::new(SECRET.to_vec()),
        )
        .unwrap();
        store.put_raw(&profile.id, &record.encode());
        revision
    }

    #[test]
    fn password_set_generates_revision_and_stores_bound_record() {
        let repository = MemoryProfileRepository::new(Vec::new());
        let store = MemoryCredentialStore::default();
        let mut new_profile = profile();
        new_profile.id.clear();

        let saved = upsert_profile_transaction(
            &repository,
            &store,
            new_profile,
            CredentialUpdate::set(std::str::from_utf8(SECRET).unwrap()),
        )
        .unwrap();

        let revision =
            uuid::Uuid::parse_str(saved.credential_revision.as_deref().unwrap()).unwrap();
        let record = CredentialRecord::decode(&store.bytes(&saved.id).unwrap()).unwrap();
        assert_eq!(record.revision(), revision);
        assert_eq!(
            record.endpoint(),
            endpoint_fingerprint(&saved.host, saved.port, &saved.username)
        );
        assert_eq!(record.password(), SECRET);
    }

    #[test]
    fn password_keep_allows_name_and_timeout_changes_without_rewriting_record() {
        let store = MemoryCredentialStore::default();
        let mut existing = profile();
        let revision = install_record(&store, &mut existing);
        let original_record = store.bytes(&existing.id).unwrap();
        let repository = MemoryProfileRepository::new(vec![existing.clone()]);
        existing.name = "Renamed".into();
        existing.connect_timeout = 30;

        let saved =
            upsert_profile_transaction(&repository, &store, existing, CredentialUpdate::Keep)
                .unwrap();

        assert_eq!(saved.credential_revision, Some(revision.to_string()));
        assert_eq!(store.bytes(&saved.id).unwrap(), original_record);
    }

    #[test]
    fn password_keep_rejects_host_port_or_username_changes_and_requires_set() {
        for field in ["host", "port", "username"] {
            let store = MemoryCredentialStore::default();
            let mut existing = profile();
            install_record(&store, &mut existing);
            let repository = MemoryProfileRepository::new(vec![existing.clone()]);
            match field {
                "host" => existing.host = "other.example.com".into(),
                "port" => existing.port = 2200,
                "username" => existing.username = "root".into(),
                _ => unreachable!(),
            }

            let error =
                upsert_profile_transaction(&repository, &store, existing, CredentialUpdate::Keep)
                    .unwrap_err();

            assert!(
                error.contains("重新输入密码"),
                "field={field}, error={error}"
            );
        }
    }

    #[test]
    fn switching_away_from_password_clears_revision_and_record() {
        let store = MemoryCredentialStore::default();
        let mut existing = profile();
        install_record(&store, &mut existing);
        let repository = MemoryProfileRepository::new(vec![existing.clone()]);
        existing.auth_type = SshAuthType::Agent;

        let saved =
            upsert_profile_transaction(&repository, &store, existing, CredentialUpdate::Keep)
                .unwrap();

        assert_eq!(saved.credential_revision, None);
        assert_eq!(store.bytes(&saved.id), None);
    }

    #[test]
    fn launch_snapshot_returns_atomically_bound_password_record() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        let mut saved = profile();
        let revision = install_record(&store, &mut saved);
        save_profiles(&path, &[saved.clone()]).unwrap();

        let snapshot = credential_snapshot_for_launch(&path, &store, &saved.id).unwrap();

        assert_eq!(snapshot.profile, saved);
        assert_eq!(snapshot.revision, revision);
        assert_eq!(
            snapshot.endpoint,
            endpoint_fingerprint("example.com", 2222, "deploy")
        );
        assert_eq!(snapshot.password.as_slice(), SECRET);
    }

    #[test]
    fn launch_snapshot_rejects_endpoint_or_revision_tampering_and_legacy_values() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        for scenario in ["endpoint", "revision", "legacy"] {
            let store = MemoryCredentialStore::default();
            let mut saved = profile();
            install_record(&store, &mut saved);
            match scenario {
                "endpoint" => saved.host = "attacker.example.com".into(),
                "revision" => saved.credential_revision = Some(uuid::Uuid::new_v4().to_string()),
                "legacy" => store.put_raw(&saved.id, SECRET),
                _ => unreachable!(),
            }
            save_profiles(&path, &[saved.clone()]).unwrap();

            let error = match credential_snapshot_for_launch(&path, &store, &saved.id) {
                Ok(_) => panic!("expected launch snapshot rejection"),
                Err(error) => error,
            };
            assert!(!error.contains(std::str::from_utf8(SECRET).unwrap()));
        }
    }

    #[test]
    fn key_profile_can_be_renamed_after_its_identity_file_is_moved() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let identity_file = dir.0.join("id_moved_after_save");
        fs::write(&identity_file, "test-key").unwrap();
        let store = MemoryCredentialStore::default();
        let mut saved = profile();
        saved.auth_type = SshAuthType::Key;
        saved.identity_file = Some(identity_file.to_string_lossy().into_owned());
        saved.credential_revision = None;
        save_profiles(&path, &[saved.clone()]).unwrap();
        fs::remove_file(&identity_file).unwrap();
        saved.name = "Renamed after key move".into();
        saved.connect_timeout = 30;

        let updated =
            upsert_profile_with_credential(&path, &store, saved.clone(), CredentialUpdate::Keep)
                .unwrap();

        assert_eq!(updated, saved);
        assert_eq!(crate::ssh::load_profiles(&path).unwrap(), vec![saved]);
    }

    #[test]
    fn new_key_profile_requires_an_existing_identity_file() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        let mut profile = profile();
        profile.id.clear();
        profile.auth_type = SshAuthType::Key;
        profile.identity_file = Some(dir.0.join("missing-new-key").to_string_lossy().into_owned());

        let error = upsert_profile_with_credential(&path, &store, profile, CredentialUpdate::Keep)
            .unwrap_err();

        assert!(error.starts_with("私钥文件不存在或不是普通文件："));
        assert!(crate::ssh::load_profiles(&path).unwrap().is_empty());
    }

    #[test]
    fn switching_agent_or_password_profile_to_key_requires_an_existing_identity_file() {
        for auth_type in [SshAuthType::Agent, SshAuthType::Password] {
            let dir = TestDir::new();
            let path = dir.0.join("ssh-profiles.json");
            let store = MemoryCredentialStore::default();
            let mut existing = profile();
            existing.auth_type = auth_type;
            existing.credential_revision = None;
            save_profiles(&path, &[existing.clone()]).unwrap();
            existing.auth_type = SshAuthType::Key;
            existing.identity_file = Some(
                dir.0
                    .join("missing-transition-key")
                    .to_string_lossy()
                    .into_owned(),
            );

            let error =
                upsert_profile_with_credential(&path, &store, existing, CredentialUpdate::Keep)
                    .unwrap_err();

            assert!(error.starts_with("私钥文件不存在或不是普通文件："));
        }
    }

    #[test]
    fn changing_key_identity_path_requires_the_new_file_to_exist() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let old_identity = dir.0.join("old-key");
        fs::write(&old_identity, "test-key").unwrap();
        let store = MemoryCredentialStore::default();
        let mut existing = profile();
        existing.auth_type = SshAuthType::Key;
        existing.identity_file = Some(old_identity.to_string_lossy().into_owned());
        existing.credential_revision = None;
        save_profiles(&path, &[existing.clone()]).unwrap();
        existing.identity_file = Some(
            dir.0
                .join("missing-replacement-key")
                .to_string_lossy()
                .into_owned(),
        );

        let error = upsert_profile_with_credential(&path, &store, existing, CredentialUpdate::Keep)
            .unwrap_err();

        assert!(error.starts_with("私钥文件不存在或不是普通文件："));
    }
}

#[cfg(test)]
mod locking_tests {
    use super::{
        credential_journal_path, credential_lock_path, credential_snapshot_for_launch,
        delete_profile_with_credential, endpoint_fingerprint, upsert_profile_with_credential,
        CredentialRecord, CredentialStore, CredentialTransactionLock, CredentialUpdate,
        PROCESS_CREDENTIAL_LOCK,
    };
    use crate::ssh::{load_profiles, save_profiles, SshAuthType, SshProfile};
    use fs2::FileExt;
    use std::{
        fs::{self, OpenOptions},
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Condvar, Mutex,
        },
        thread,
        time::Duration,
    };
    use zeroize::Zeroizing;

    const OLD_SECRET: &[u8] = b"concurrency-old-secret";
    const FAILED_SECRET: &[u8] = b"concurrency-failed-secret";
    const SUCCESS_SECRET: &[u8] = b"concurrency-success-secret";
    const EXTERNAL_SECRET: &[u8] = b"concurrency-external-secret";

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "terminal-codex-locking-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct CoordinatedStore {
        reads: AtomicUsize,
        gate: (Mutex<()>, Condvar),
    }

    struct FailingSetStore {
        values: Mutex<std::collections::HashMap<String, Vec<u8>>>,
        failed_set_started: (Mutex<bool>, Condvar),
        release_failed_set: (Mutex<bool>, Condvar),
    }

    struct ExternalWriteBeforeSaveFailureStore {
        value: Mutex<Vec<u8>>,
        profiles_path: PathBuf,
        third_record: Vec<u8>,
        third_revision: uuid::Uuid,
        injected: Mutex<bool>,
    }

    impl ExternalWriteBeforeSaveFailureStore {
        fn new(profile: &mut SshProfile, profiles_path: PathBuf) -> Self {
            let endpoint = endpoint_fingerprint(&profile.host, profile.port, &profile.username);
            let previous_revision = uuid::Uuid::new_v4();
            profile.credential_revision = Some(previous_revision.to_string());
            let previous = CredentialRecord::new(
                previous_revision,
                endpoint,
                Zeroizing::new(OLD_SECRET.to_vec()),
            )
            .unwrap();
            let third_revision = uuid::Uuid::new_v4();
            let third_record = CredentialRecord::new(
                third_revision,
                endpoint,
                Zeroizing::new(EXTERNAL_SECRET.to_vec()),
            )
            .unwrap()
            .encode()
            .to_vec();
            Self {
                value: Mutex::new(previous.encode().to_vec()),
                profiles_path,
                third_record,
                third_revision,
                injected: Mutex::new(false),
            }
        }

        fn record(&self) -> CredentialRecord {
            CredentialRecord::decode(&self.value.lock().unwrap()).unwrap()
        }
    }

    impl CredentialStore for ExternalWriteBeforeSaveFailureStore {
        fn get(&self, _account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(Some(Zeroizing::new(self.value.lock().unwrap().clone())))
        }

        fn set(&self, _account: &str, password: &[u8]) -> Result<(), String> {
            let is_target = CredentialRecord::decode(password)
                .map(|record| record.password() == FAILED_SECRET)
                .unwrap_or(false);
            let mut injected = self.injected.lock().unwrap();
            if is_target && !*injected {
                *self.value.lock().unwrap() = password.to_vec();
                fs::remove_file(&self.profiles_path).unwrap();
                fs::create_dir(&self.profiles_path).unwrap();
                *self.value.lock().unwrap() = self.third_record.clone();
                *injected = true;
            } else {
                *self.value.lock().unwrap() = password.to_vec();
            }
            Ok(())
        }

        fn delete(&self, _account: &str) -> Result<(), String> {
            self.value.lock().unwrap().clear();
            Ok(())
        }
    }

    impl FailingSetStore {
        fn new(profile: &mut SshProfile) -> Self {
            let revision = uuid::Uuid::new_v4();
            profile.credential_revision = Some(revision.to_string());
            let record = CredentialRecord::new(
                revision,
                endpoint_fingerprint(&profile.host, profile.port, &profile.username),
                Zeroizing::new(OLD_SECRET.to_vec()),
            )
            .unwrap();
            Self {
                values: Mutex::new(std::collections::HashMap::from([(
                    profile.id.clone(),
                    record.encode().to_vec(),
                )])),
                failed_set_started: (Mutex::new(false), Condvar::new()),
                release_failed_set: (Mutex::new(false), Condvar::new()),
            }
        }

        fn wait_for_failed_set(&self) {
            let mut started = self.failed_set_started.0.lock().unwrap();
            while !*started {
                started = self.failed_set_started.1.wait(started).unwrap();
            }
        }

        fn release_failed_set(&self) {
            *self.release_failed_set.0.lock().unwrap() = true;
            self.release_failed_set.1.notify_all();
        }
    }

    impl CredentialStore for FailingSetStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }

        fn set(&self, account: &str, password: &[u8]) -> Result<(), String> {
            self.values
                .lock()
                .unwrap()
                .insert(account.to_string(), password.to_vec());
            let is_failed_value = CredentialRecord::decode(password)
                .map(|record| record.password() == FAILED_SECRET)
                .unwrap_or(false);
            if is_failed_value {
                *self.failed_set_started.0.lock().unwrap() = true;
                self.failed_set_started.1.notify_all();
                let mut released = self.release_failed_set.0.lock().unwrap();
                while !*released {
                    released = self.release_failed_set.1.wait(released).unwrap();
                }
                return Err("模拟目标凭据写入失败".into());
            }
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), String> {
            self.values.lock().unwrap().remove(account);
            Ok(())
        }
    }

    impl CoordinatedStore {
        fn new() -> Self {
            Self {
                reads: AtomicUsize::new(0),
                gate: (Mutex::new(()), Condvar::new()),
            }
        }
    }

    impl CredentialStore for CoordinatedStore {
        fn get(&self, _account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            if read == 1 {
                let guard = self.gate.0.lock().unwrap();
                let _ = self
                    .gate
                    .1
                    .wait_timeout(guard, Duration::from_millis(250))
                    .unwrap();
            } else if read == 2 {
                self.gate.1.notify_all();
            }
            Ok(None)
        }

        fn set(&self, _account: &str, _password: &[u8]) -> Result<(), String> {
            Ok(())
        }

        fn delete(&self, _account: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn agent_profile(id: &str, name: &str) -> SshProfile {
        SshProfile {
            id: id.into(),
            name: name.into(),
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
    fn concurrent_upserts_do_not_lose_each_others_profile_changes() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let first_id = "74c00a0b-a7e5-410c-9aed-7e9f5045507b";
        let second_id = "348a0961-31f0-4672-b73e-03afc84eb46e";
        save_profiles(
            &path,
            &[
                agent_profile(first_id, "First"),
                agent_profile(second_id, "Second"),
            ],
        )
        .unwrap();
        let store = Arc::new(CoordinatedStore::new());

        let handles = [(first_id, "First updated"), (second_id, "Second updated")]
            .into_iter()
            .map(|(id, name)| {
                let path = path.clone();
                let store = store.clone();
                thread::spawn(move || {
                    upsert_profile_with_credential(
                        &path,
                        store.as_ref(),
                        agent_profile(id, name),
                        CredentialUpdate::Keep,
                    )
                    .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        let profiles = load_profiles(&path).unwrap();
        assert_eq!(
            profiles
                .iter()
                .find(|profile| profile.id == first_id)
                .unwrap()
                .name,
            "First updated"
        );
        assert_eq!(
            profiles
                .iter()
                .find(|profile| profile.id == second_id)
                .unwrap()
                .name,
            "Second updated"
        );
    }

    #[test]
    fn concurrent_upsert_and_delete_do_not_resurrect_or_overwrite_profiles() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let keep_id = "74c00a0b-a7e5-410c-9aed-7e9f5045507b";
        let delete_id = "348a0961-31f0-4672-b73e-03afc84eb46e";
        save_profiles(
            &path,
            &[
                agent_profile(keep_id, "Keep"),
                agent_profile(delete_id, "Delete"),
            ],
        )
        .unwrap();
        let store = Arc::new(CoordinatedStore::new());

        let update = {
            let path = path.clone();
            let store = store.clone();
            thread::spawn(move || {
                upsert_profile_with_credential(
                    &path,
                    store.as_ref(),
                    agent_profile(keep_id, "Updated"),
                    CredentialUpdate::Keep,
                )
                .unwrap();
            })
        };
        let delete = {
            let path = path.clone();
            let store = store.clone();
            thread::spawn(move || {
                delete_profile_with_credential(&path, store.as_ref(), delete_id).unwrap();
            })
        };
        update.join().unwrap();
        delete.join().unwrap();

        let profiles = load_profiles(&path).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, keep_id);
        assert_eq!(profiles[0].name, "Updated");
    }

    #[test]
    fn credential_lock_uses_os_level_exclusive_file_lock() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let _guard = CredentialTransactionLock::acquire(&path).unwrap();
        let competing = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(credential_lock_path(&path))
            .unwrap();

        assert!(competing.try_lock_exclusive().is_err());
    }

    #[test]
    fn credential_transaction_lock_recovers_from_poisoned_process_mutex() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let poisoned = thread::spawn(|| {
            let _guard = PROCESS_CREDENTIAL_LOCK.lock().unwrap();
            panic!("poison the pure serialization lock");
        });
        assert!(poisoned.join().is_err());

        let _guard = CredentialTransactionLock::acquire(&path).unwrap();
    }

    #[test]
    fn failed_rollback_cannot_overwrite_a_concurrent_successful_password_update() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let mut profile = agent_profile("74c00a0b-a7e5-410c-9aed-7e9f5045507b", "Password profile");
        profile.auth_type = SshAuthType::Password;
        let store = Arc::new(FailingSetStore::new(&mut profile));
        save_profiles(&path, &[profile.clone()]).unwrap();

        let failed = {
            let path = path.clone();
            let store = store.clone();
            let profile = profile.clone();
            thread::spawn(move || {
                upsert_profile_with_credential(
                    &path,
                    store.as_ref(),
                    profile,
                    CredentialUpdate::set(std::str::from_utf8(FAILED_SECRET).unwrap()),
                )
            })
        };
        store.wait_for_failed_set();
        let succeeded = {
            let path = path.clone();
            let store = store.clone();
            let profile = profile.clone();
            thread::spawn(move || {
                upsert_profile_with_credential(
                    &path,
                    store.as_ref(),
                    profile,
                    CredentialUpdate::set(std::str::from_utf8(SUCCESS_SECRET).unwrap()),
                )
            })
        };
        store.release_failed_set();

        assert!(failed.join().unwrap().is_err());
        succeeded.join().unwrap().unwrap();
        let snapshot = credential_snapshot_for_launch(&path, store.as_ref(), &profile.id).unwrap();
        assert_eq!(snapshot.password.as_slice(), SUCCESS_SECRET);
    }

    #[test]
    fn rollback_cannot_overwrite_a_lock_bypassing_third_revision() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let mut profile = agent_profile("74c00a0b-a7e5-410c-9aed-7e9f5045507b", "Password profile");
        profile.auth_type = SshAuthType::Password;
        let store = ExternalWriteBeforeSaveFailureStore::new(&mut profile, path.clone());
        save_profiles(&path, &[profile.clone()]).unwrap();
        profile.name = "Target update".into();

        let error = upsert_profile_with_credential(
            &path,
            &store,
            profile,
            CredentialUpdate::set(std::str::from_utf8(FAILED_SECRET).unwrap()),
        )
        .unwrap_err();

        assert!(error.contains("凭据已被其他写入者修改"));
        assert_eq!(store.record().revision(), store.third_revision);
        assert_eq!(store.record().password(), EXTERNAL_SECRET);
        assert!(credential_journal_path(&path).exists());
    }
}

#[cfg(test)]
mod journal_tests {
    use super::{
        credential_journal_path, credential_snapshot_for_launch, delete_profile_with_credential,
        delete_profile_with_credential_at_crash, endpoint_fingerprint,
        recover_credential_transaction, upsert_profile_with_credential,
        upsert_profile_with_credential_at_crash, CredentialRecord, CredentialStore,
        CredentialUpdate, TransactionCrashPoint,
    };
    use crate::ssh::{load_profiles, save_profiles, SshAuthType, SshProfile};
    use std::{collections::HashMap, fs, path::PathBuf, sync::Mutex};
    use zeroize::Zeroizing;

    const PROFILE_ID: &str = "74c00a0b-a7e5-410c-9aed-7e9f5045507b";
    const OLD_SECRET: &[u8] = b"journal-old-secret";
    const NEW_SECRET: &[u8] = b"journal-new-secret";
    const OPAQUE_VALUE: &[u8] = b"legacy-opaque-credential-value";

    #[derive(Default)]
    struct MemoryCredentialStore(Mutex<HashMap<String, Vec<u8>>>);

    impl MemoryCredentialStore {
        fn put(&self, account: &str, value: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_vec());
        }

        fn bytes(&self, account: &str) -> Option<Vec<u8>> {
            self.0.lock().unwrap().get(account).cloned()
        }
    }

    impl CredentialStore for MemoryCredentialStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self.bytes(account).map(Zeroizing::new))
        }

        fn set(&self, account: &str, password: &[u8]) -> Result<(), String> {
            self.put(account, password);
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(account);
            Ok(())
        }
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "terminal-codex-journal-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn password_profile(name: &str) -> SshProfile {
        SshProfile {
            id: PROFILE_ID.into(),
            name: name.into(),
            host: "example.com".into(),
            port: 2222,
            username: "deploy".into(),
            auth_type: SshAuthType::Password,
            identity_file: None,
            connect_timeout: 15,
            credential_revision: None,
        }
    }

    fn agent_profile(id: &str, name: &str) -> SshProfile {
        SshProfile {
            id: id.into(),
            name: name.into(),
            host: "agent.example.com".into(),
            port: 22,
            username: "deploy".into(),
            auth_type: SshAuthType::Agent,
            identity_file: None,
            connect_timeout: 15,
            credential_revision: None,
        }
    }

    fn install_old_state(path: &std::path::Path, store: &MemoryCredentialStore) -> SshProfile {
        let mut profile = password_profile("Old");
        let revision = uuid::Uuid::new_v4();
        profile.credential_revision = Some(revision.to_string());
        let record = CredentialRecord::new(
            revision,
            endpoint_fingerprint(&profile.host, profile.port, &profile.username),
            Zeroizing::new(OLD_SECRET.to_vec()),
        )
        .unwrap();
        store.put(PROFILE_ID, &record.encode());
        save_profiles(path, &[profile.clone()]).unwrap();
        profile
    }

    fn install_opaque_state(path: &std::path::Path, store: &MemoryCredentialStore) -> SshProfile {
        let mut profile = password_profile("Opaque old");
        profile.credential_revision = Some(uuid::Uuid::new_v4().to_string());
        store.put(PROFILE_ID, OPAQUE_VALUE);
        save_profiles(path, &[profile.clone()]).unwrap();
        profile
    }

    fn assert_journal_has_no_secret(path: &std::path::Path) {
        let bytes = fs::read(credential_journal_path(path)).unwrap();
        assert!(!bytes
            .windows(OLD_SECRET.len())
            .any(|window| window == OLD_SECRET));
        assert!(!bytes
            .windows(NEW_SECRET.len())
            .any(|window| window == NEW_SECRET));
    }

    fn read_journal_value(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(credential_journal_path(path)).unwrap()).unwrap()
    }

    fn write_journal_value(path: &std::path::Path, value: &serde_json::Value) {
        fs::write(
            credential_journal_path(path),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
    }

    fn create_set_journal(path: &std::path::Path, store: &MemoryCredentialStore) -> SshProfile {
        let mut target = install_old_state(path, store);
        target.name = "New".into();
        assert!(upsert_profile_with_credential_at_crash(
            path,
            store,
            target.clone(),
            CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
            TransactionCrashPoint::Journal,
        )
        .is_err());
        target
    }

    fn assert_invalid_journal_is_preserved(path: &std::path::Path, store: &MemoryCredentialStore) {
        let profiles_before = fs::read(path).unwrap();
        let error = recover_credential_transaction(path, store).unwrap_err();
        assert!(
            error.contains("SSH 凭据事务内容无效"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(path).unwrap(), profiles_before);
        assert!(credential_journal_path(path).exists());
    }

    #[test]
    fn set_crash_points_recover_by_observed_credential_revision() {
        for point in TransactionCrashPoint::ALL {
            let dir = TestDir::new();
            let path = dir.0.join("ssh-profiles.json");
            let store = MemoryCredentialStore::default();
            let mut target = install_old_state(&path, &store);
            target.name = "New".into();

            assert!(upsert_profile_with_credential_at_crash(
                &path,
                &store,
                target,
                CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
                point,
            )
            .is_err());
            assert_journal_has_no_secret(&path);

            recover_credential_transaction(&path, &store).unwrap();

            let snapshot = credential_snapshot_for_launch(&path, &store, PROFILE_ID).unwrap();
            match point {
                TransactionCrashPoint::Journal => {
                    assert_eq!(snapshot.profile.name, "Old");
                    assert_eq!(snapshot.password.as_slice(), OLD_SECRET);
                }
                TransactionCrashPoint::Credential | TransactionCrashPoint::Profiles => {
                    assert_eq!(snapshot.profile.name, "New");
                    assert_eq!(snapshot.password.as_slice(), NEW_SECRET);
                }
            }
            assert!(!credential_journal_path(&path).exists());
        }
    }

    #[test]
    fn clear_crash_points_recover_to_password_or_agent_state() {
        for point in TransactionCrashPoint::ALL {
            let dir = TestDir::new();
            let path = dir.0.join("ssh-profiles.json");
            let store = MemoryCredentialStore::default();
            let mut target = install_old_state(&path, &store);
            target.auth_type = SshAuthType::Agent;

            assert!(upsert_profile_with_credential_at_crash(
                &path,
                &store,
                target,
                CredentialUpdate::Clear,
                point,
            )
            .is_err());
            assert_journal_has_no_secret(&path);

            recover_credential_transaction(&path, &store).unwrap();

            let profiles = load_profiles(&path).unwrap();
            if point == TransactionCrashPoint::Journal {
                assert_eq!(profiles[0].auth_type, SshAuthType::Password);
                assert!(store.bytes(PROFILE_ID).is_some());
            } else {
                assert_eq!(profiles[0].auth_type, SshAuthType::Agent);
                assert_eq!(profiles[0].credential_revision, None);
                assert!(store.bytes(PROFILE_ID).is_none());
            }
            assert!(!credential_journal_path(&path).exists());
        }
    }

    #[test]
    fn delete_crash_points_recover_without_unenumerable_account() {
        for point in TransactionCrashPoint::ALL {
            let dir = TestDir::new();
            let path = dir.0.join("ssh-profiles.json");
            let store = MemoryCredentialStore::default();
            install_old_state(&path, &store);

            assert!(
                delete_profile_with_credential_at_crash(&path, &store, PROFILE_ID, point,).is_err()
            );
            assert_journal_has_no_secret(&path);

            recover_credential_transaction(&path, &store).unwrap();

            if point == TransactionCrashPoint::Journal {
                assert_eq!(load_profiles(&path).unwrap().len(), 1);
                assert!(store.bytes(PROFILE_ID).is_some());
            } else {
                assert!(load_profiles(&path).unwrap().is_empty());
                assert!(store.bytes(PROFILE_ID).is_none());
            }
            assert!(!credential_journal_path(&path).exists());
        }
    }

    #[test]
    fn unknown_credential_state_keeps_journal_and_blocks_launch_snapshot() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        let target = install_old_state(&path, &store);
        assert!(upsert_profile_with_credential_at_crash(
            &path,
            &store,
            target,
            CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
            TransactionCrashPoint::Journal,
        )
        .is_err());
        let unrelated_revision = uuid::Uuid::new_v4();
        let unrelated = CredentialRecord::new(
            unrelated_revision,
            endpoint_fingerprint("unrelated.example.com", 22, "other"),
            Zeroizing::new(b"unrelated-password".to_vec()),
        )
        .unwrap();
        store.put(PROFILE_ID, &unrelated.encode());

        assert!(recover_credential_transaction(&path, &store).is_err());
        assert!(credential_journal_path(&path).exists());
        assert!(credential_snapshot_for_launch(&path, &store, PROFILE_ID).is_err());
        assert!(credential_journal_path(&path).exists());
    }

    #[test]
    fn replayed_old_journal_cannot_overwrite_a_later_profile_edit() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        let mut target = install_old_state(&path, &store);
        target.name = "Transaction target".into();
        assert!(upsert_profile_with_credential_at_crash(
            &path,
            &store,
            target,
            CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
            TransactionCrashPoint::Credential,
        )
        .is_err());
        let replayed_journal = fs::read(credential_journal_path(&path)).unwrap();
        recover_credential_transaction(&path, &store).unwrap();
        let mut later = load_profiles(&path).unwrap()[0].clone();
        later.name = "Later independent edit".into();
        save_profiles(&path, &[later]).unwrap();
        fs::write(credential_journal_path(&path), replayed_journal).unwrap();
        let profiles_before = fs::read(&path).unwrap();

        let error = recover_credential_transaction(&path, &store).unwrap_err();

        assert!(error.contains("当前 SSH Profile 已与事务快照分叉"));
        assert_eq!(fs::read(&path).unwrap(), profiles_before);
        assert!(credential_journal_path(&path).exists());
    }

    #[test]
    fn recovery_cannot_drop_an_unrelated_profile_added_after_the_journal() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        create_set_journal(&path, &store);
        let mut forked = load_profiles(&path).unwrap();
        forked.push(agent_profile(
            "348a0961-31f0-4672-b73e-03afc84eb46e",
            "Added after crash",
        ));
        save_profiles(&path, &forked).unwrap();
        let profiles_before = fs::read(&path).unwrap();

        let error = recover_credential_transaction(&path, &store).unwrap_err();

        assert!(error.contains("当前 SSH Profile 已与事务快照分叉"));
        assert_eq!(fs::read(&path).unwrap(), profiles_before);
        assert!(credential_journal_path(&path).exists());
    }

    #[test]
    fn semantically_invalid_journals_are_preserved_without_writing_profile_snapshots() {
        for scenario in [
            "duplicate_previous_id",
            "invalid_target_id",
            "changes_multiple_profiles",
            "target_revision_mismatch",
            "target_endpoint_mismatch",
            "target_non_password_with_record",
            "previous_record_for_non_password",
            "delete_target_not_missing",
        ] {
            let dir = TestDir::new();
            let path = dir.0.join("ssh-profiles.json");
            let store = MemoryCredentialStore::default();

            if scenario == "delete_target_not_missing" {
                install_old_state(&path, &store);
                assert!(delete_profile_with_credential_at_crash(
                    &path,
                    &store,
                    PROFILE_ID,
                    TransactionCrashPoint::Journal,
                )
                .is_err());
            } else {
                create_set_journal(&path, &store);
            }

            let mut journal = read_journal_value(&path);
            match scenario {
                "duplicate_previous_id" => {
                    let duplicate = journal["previousProfiles"][0].clone();
                    journal["previousProfiles"]
                        .as_array_mut()
                        .unwrap()
                        .push(duplicate);
                }
                "invalid_target_id" => {
                    journal["targetProfiles"][0]["id"] = serde_json::json!("not-a-uuid");
                }
                "changes_multiple_profiles" => {
                    let mut extra = journal["targetProfiles"][0].clone();
                    extra["id"] = serde_json::json!("348a0961-31f0-4672-b73e-03afc84eb46e");
                    extra["name"] = serde_json::json!("Unexpected second change");
                    journal["targetProfiles"]
                        .as_array_mut()
                        .unwrap()
                        .push(extra);
                }
                "target_revision_mismatch" => {
                    journal["targetProfiles"][0]["credentialRevision"] =
                        serde_json::json!(uuid::Uuid::new_v4().to_string());
                }
                "target_endpoint_mismatch" => {
                    journal["targetProfiles"][0]["host"] =
                        serde_json::json!("attacker.example.com");
                }
                "target_non_password_with_record" => {
                    journal["targetProfiles"][0]["authType"] = serde_json::json!("agent");
                    journal["targetProfiles"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("credentialRevision");
                }
                "previous_record_for_non_password" => {
                    journal["previousProfiles"][0]["authType"] = serde_json::json!("agent");
                    journal["previousProfiles"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("credentialRevision");
                }
                "delete_target_not_missing" => {
                    journal["targetCredential"] = journal["previousCredential"].clone();
                }
                _ => unreachable!(),
            }
            write_journal_value(&path, &journal);

            assert_invalid_journal_is_preserved(&path, &store);
        }
    }

    #[test]
    fn malformed_existing_credential_is_rejected_by_keep_and_snapshot() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        let target = install_old_state(&path, &store);
        let malformed = b"legacy-unbound-password";
        store.put(PROFILE_ID, malformed);
        let profiles_before = fs::read(&path).unwrap();

        let error =
            upsert_profile_with_credential(&path, &store, target.clone(), CredentialUpdate::Keep)
                .unwrap_err();

        assert!(error.contains("SSH 密码凭据"));
        assert!(!error.contains(std::str::from_utf8(malformed).unwrap()));
        let snapshot_error = match credential_snapshot_for_launch(&path, &store, &target.id) {
            Ok(_) => panic!("expected malformed snapshot rejection"),
            Err(error) => error,
        };
        assert!(!snapshot_error.contains(std::str::from_utf8(malformed).unwrap()));
        assert_eq!(
            store.bytes(PROFILE_ID).as_deref(),
            Some(malformed.as_slice())
        );
        assert_eq!(fs::read(&path).unwrap(), profiles_before);
        assert!(!credential_journal_path(&path).exists());
    }

    #[test]
    fn explicit_set_clear_and_delete_repair_an_opaque_credential() {
        for operation in ["set", "clear", "delete"] {
            let dir = TestDir::new();
            let path = dir.0.join("ssh-profiles.json");
            let store = MemoryCredentialStore::default();
            let mut target = install_opaque_state(&path, &store);

            match operation {
                "set" => {
                    upsert_profile_with_credential(
                        &path,
                        &store,
                        target,
                        CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
                    )
                    .unwrap();
                    let snapshot =
                        credential_snapshot_for_launch(&path, &store, PROFILE_ID).unwrap();
                    assert_eq!(snapshot.password.as_slice(), NEW_SECRET);
                }
                "clear" => {
                    target.auth_type = SshAuthType::Agent;
                    upsert_profile_with_credential(&path, &store, target, CredentialUpdate::Clear)
                        .unwrap();
                    assert_eq!(
                        load_profiles(&path).unwrap()[0].auth_type,
                        SshAuthType::Agent
                    );
                    assert!(store.bytes(PROFILE_ID).is_none());
                }
                "delete" => {
                    delete_profile_with_credential(&path, &store, PROFILE_ID).unwrap();
                    assert!(load_profiles(&path).unwrap().is_empty());
                    assert!(store.bytes(PROFILE_ID).is_none());
                }
                _ => unreachable!(),
            }
            assert!(!credential_journal_path(&path).exists());
        }
    }

    #[test]
    fn opaque_repair_transactions_recover_at_every_crash_point_without_journaling_raw_value() {
        for operation in ["set", "clear", "delete"] {
            for point in TransactionCrashPoint::ALL {
                let dir = TestDir::new();
                let path = dir.0.join("ssh-profiles.json");
                let store = MemoryCredentialStore::default();
                let mut target = install_opaque_state(&path, &store);
                target.name = "Opaque repair target".into();

                let result = match operation {
                    "set" => upsert_profile_with_credential_at_crash(
                        &path,
                        &store,
                        target,
                        CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
                        point,
                    )
                    .map(|_| ()),
                    "clear" => {
                        target.auth_type = SshAuthType::Agent;
                        upsert_profile_with_credential_at_crash(
                            &path,
                            &store,
                            target,
                            CredentialUpdate::Clear,
                            point,
                        )
                        .map(|_| ())
                    }
                    "delete" => {
                        delete_profile_with_credential_at_crash(&path, &store, PROFILE_ID, point)
                    }
                    _ => unreachable!(),
                };
                assert!(result.is_err());
                let journal_path = credential_journal_path(&path);
                assert!(
                    journal_path.exists(),
                    "operation={operation}, point={point:?}"
                );
                let journal_bytes = fs::read(&journal_path).unwrap();
                assert!(!journal_bytes
                    .windows(OPAQUE_VALUE.len())
                    .any(|window| window == OPAQUE_VALUE));

                recover_credential_transaction(&path, &store).unwrap();

                if point == TransactionCrashPoint::Journal {
                    assert_eq!(load_profiles(&path).unwrap()[0].name, "Opaque old");
                    assert_eq!(store.bytes(PROFILE_ID).as_deref(), Some(OPAQUE_VALUE));
                } else {
                    match operation {
                        "set" => {
                            let snapshot =
                                credential_snapshot_for_launch(&path, &store, PROFILE_ID).unwrap();
                            assert_eq!(snapshot.profile.name, "Opaque repair target");
                            assert_eq!(snapshot.password.as_slice(), NEW_SECRET);
                        }
                        "clear" => {
                            assert_eq!(
                                load_profiles(&path).unwrap()[0].auth_type,
                                SshAuthType::Agent
                            );
                            assert!(store.bytes(PROFILE_ID).is_none());
                        }
                        "delete" => {
                            assert!(load_profiles(&path).unwrap().is_empty());
                            assert!(store.bytes(PROFILE_ID).is_none());
                        }
                        _ => unreachable!(),
                    }
                }
                assert!(!journal_path.exists());
            }
        }
    }

    #[test]
    fn unexpected_current_opaque_or_target_opaque_fail_closed_and_preserve_journal() {
        for scenario in ["current_opaque", "target_opaque"] {
            let dir = TestDir::new();
            let path = dir.0.join("ssh-profiles.json");
            let store = MemoryCredentialStore::default();
            create_set_journal(&path, &store);
            let profiles_before = fs::read(&path).unwrap();
            let mut journal = read_journal_value(&path);

            match scenario {
                "current_opaque" => store.put(PROFILE_ID, b"malformed-current-value"),
                "target_opaque" => {
                    journal["targetCredential"] = serde_json::json!("Opaque");
                    store.put(PROFILE_ID, b"different-malformed-target-value");
                    write_journal_value(&path, &journal);
                }
                _ => unreachable!(),
            }

            assert!(recover_credential_transaction(&path, &store).is_err());
            assert_eq!(fs::read(&path).unwrap(), profiles_before);
            assert!(credential_journal_path(&path).exists());
        }
    }

    #[test]
    fn startup_recovery_helper_forwards_a_crashed_transaction() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        let mut target = install_old_state(&path, &store);
        target.name = "Recovered on startup".into();
        assert!(upsert_profile_with_credential_at_crash(
            &path,
            &store,
            target,
            CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
            TransactionCrashPoint::Credential,
        )
        .is_err());
        assert!(credential_journal_path(&path).exists());

        crate::recover_ssh_credential_transaction_on_startup(&dir.0, &store).unwrap();

        assert!(!credential_journal_path(&path).exists());
        assert_eq!(
            load_profiles(&path).unwrap()[0].name,
            "Recovered on startup"
        );
        let snapshot = credential_snapshot_for_launch(&path, &store, PROFILE_ID).unwrap();
        assert_eq!(snapshot.profile.name, "Recovered on startup");
        assert_eq!(snapshot.password.as_slice(), NEW_SECRET);
    }

    #[test]
    fn startup_recovery_helper_returns_chinese_error_and_preserves_unknown_journal() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        create_set_journal(&path, &store);
        store.put(PROFILE_ID, b"unknown-startup-credential");

        let error =
            crate::recover_ssh_credential_transaction_on_startup(&dir.0, &store).unwrap_err();

        assert!(error.starts_with("应用启动时无法恢复 SSH 凭据事务："));
        assert!(credential_journal_path(&path).exists());
    }

    #[test]
    fn startup_recovery_error_is_recorded_without_propagating_from_setup_helper() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        create_set_journal(&path, &store);
        store.put(PROFILE_ID, b"unknown-startup-credential");
        let state = crate::SshRecoveryState::default();

        crate::attempt_ssh_recovery_on_startup(&state, Ok(dir.0.clone()), &store);

        let error = state.ensure_ready().unwrap_err();
        assert!(error.starts_with("应用启动时无法恢复 SSH 凭据事务："));
        assert_eq!(state.blocked_error().as_deref(), Some(error.as_str()));
        assert!(credential_journal_path(&path).exists());
    }

    #[test]
    fn config_path_failure_only_blocks_ssh_and_retry_can_clear_the_state() {
        let dir = TestDir::new();
        let path = dir.0.join("ssh-profiles.json");
        let store = MemoryCredentialStore::default();
        let mut target = install_old_state(&path, &store);
        target.name = "Retry target".into();
        assert!(upsert_profile_with_credential_at_crash(
            &path,
            &store,
            target,
            CredentialUpdate::set(std::str::from_utf8(NEW_SECRET).unwrap()),
            TransactionCrashPoint::Credential,
        )
        .is_err());
        let state = crate::SshRecoveryState::default();

        crate::attempt_ssh_recovery_on_startup(
            &state,
            Err("应用启动时无法定位配置目录：模拟失败".into()),
            &store,
        );

        assert!(state
            .ensure_ready()
            .unwrap_err()
            .contains("无法定位配置目录"));
        assert!(credential_journal_path(&path).exists());

        state.retry(&dir.0, &store).unwrap();

        assert!(state.ensure_ready().is_ok());
        assert_eq!(state.blocked_error(), None);
        assert!(!credential_journal_path(&path).exists());
        assert_eq!(load_profiles(&path).unwrap()[0].name, "Retry target");
    }
}
