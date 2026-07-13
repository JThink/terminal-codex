use super::{validate_profile_for_connection, SshAuthType, SshProfile};
use std::{collections::BTreeMap, collections::BTreeSet, env, ffi::OsStr, fmt, path::Path};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const ASKPASS_MARKER_ENV: &str = "CODEX_TERMINAL_SSH_ASKPASS";
const ASKPASS_PROFILE_ENV: &str = "CODEX_TERMINAL_SSH_PROFILE_ID";
const ASKPASS_APP_PID_ENV: &str = "CODEX_TERMINAL_SSH_APP_PID";
const ASKPASS_PROFILES_PATH_ENV: &str = "CODEX_TERMINAL_SSH_PROFILES_PATH";
pub(crate) const ASKPASS_SOCKET_ENV: &str = "CODEX_TERMINAL_SSH_ASKPASS_SOCKET";
pub(crate) const ASKPASS_TOKEN_ENV: &str = "CODEX_TERMINAL_SSH_ASKPASS_TOKEN";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SshMode {
    Interactive,
    Test,
}

#[derive(Eq, PartialEq)]
pub(crate) struct SshProcessSpec {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) env_remove: BTreeSet<String>,
}

impl SshProcessSpec {
    pub(crate) fn clear_secrets(&mut self) {
        if let Some(capability_token) = self.env.get_mut(ASKPASS_TOKEN_ENV) {
            capability_token.zeroize();
        }
        self.env.remove(ASKPASS_TOKEN_ENV);
    }
}

impl Drop for SshProcessSpec {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

struct RedactedEnvironment<'a>(&'a BTreeMap<String, String>);

impl fmt::Debug for RedactedEnvironment<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = formatter.debug_map();
        for (key, value) in self.0 {
            if key == ASKPASS_TOKEN_ENV {
                map.entry(key, &"<redacted>");
            } else {
                map.entry(key, value);
            }
        }
        map.finish()
    }
}

impl fmt::Debug for SshProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshProcessSpec")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &RedactedEnvironment(&self.env))
            .field("env_remove", &self.env_remove)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AskpassLaunchEnv {
    socket_path: String,
    capability_token: Zeroizing<String>,
}

impl AskpassLaunchEnv {
    pub(crate) fn new(
        socket_path: &Path,
        capability_token: impl Into<String>,
    ) -> Result<Self, String> {
        let socket_path = path_to_utf8(socket_path, "ASKPASS socket 路径")?;
        if socket_path.is_empty() {
            return Err("ASKPASS socket 路径不能为空。".to_string());
        }
        let capability_token = capability_token.into();
        if capability_token.len() != 64
            || !capability_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("ASKPASS capability token 格式无效。".to_string());
        }
        Ok(Self {
            socket_path,
            capability_token: Zeroizing::new(capability_token),
        })
    }

    pub(crate) fn socket_path(&self) -> &str {
        &self.socket_path
    }

    pub(crate) fn capability_token(&self) -> &str {
        &self.capability_token
    }
}

impl fmt::Debug for AskpassLaunchEnv {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AskpassLaunchEnv")
            .field("socket_path", &self.socket_path)
            .field("capability_token", &"<redacted>")
            .finish()
    }
}

fn path_to_utf8(path: &Path, description: &str) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{description}不是有效的 UTF-8 路径。"))
}

fn push_option(args: &mut Vec<String>, option: impl Into<String>) {
    args.push("-o".to_string());
    args.push(option.into());
}

pub(crate) fn build_ssh_process_spec(
    profile: &SshProfile,
    askpass: Option<&AskpassLaunchEnv>,
    mode: SshMode,
) -> Result<SshProcessSpec, String> {
    let executable =
        env::current_exe().map_err(|error| format!("无法获取当前应用可执行文件路径：{error}"))?;
    build_ssh_process_spec_for_runtime(profile, &executable, askpass, mode)
}

fn build_ssh_process_spec_for_runtime(
    profile: &SshProfile,
    executable: &Path,
    askpass: Option<&AskpassLaunchEnv>,
    mode: SshMode,
) -> Result<SshProcessSpec, String> {
    let parent_term = env::var_os("TERM");
    build_ssh_process_spec_for_runtime_with_term(
        profile,
        executable,
        askpass,
        mode,
        parent_term.as_deref(),
    )
}

fn build_ssh_process_spec_for_runtime_with_term(
    profile: &SshProfile,
    executable: &Path,
    askpass: Option<&AskpassLaunchEnv>,
    mode: SshMode,
    parent_term: Option<&OsStr>,
) -> Result<SshProcessSpec, String> {
    let profile = validate_profile_for_connection(profile)?;
    uuid::Uuid::parse_str(&profile.id).map_err(|_| "连接 ID 必须是有效的 UUID。".to_string())?;

    let mut args = vec![match mode {
        SshMode::Interactive => "-tt".to_string(),
        SshMode::Test => "-T".to_string(),
    }];
    args.extend(["-F".to_string(), "none".to_string()]);
    for option in [
        "StrictHostKeyChecking=accept-new".to_string(),
        "UpdateHostKeys=no".to_string(),
        "HashKnownHosts=yes".to_string(),
        "ClearAllForwardings=yes".to_string(),
        "ForwardAgent=no".to_string(),
        "PermitLocalCommand=no".to_string(),
        "ConnectionAttempts=1".to_string(),
        format!("ConnectTimeout={}", profile.connect_timeout),
        "ServerAliveInterval=30".to_string(),
        "ServerAliveCountMax=3".to_string(),
    ] {
        push_option(&mut args, option);
    }

    let mut env = BTreeMap::new();
    if parent_term.is_none_or(OsStr::is_empty) {
        env.insert("TERM".to_string(), "xterm-256color".to_string());
    }
    let env_remove = [
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        ASKPASS_MARKER_ENV,
        ASKPASS_PROFILE_ENV,
        ASKPASS_APP_PID_ENV,
        ASKPASS_PROFILES_PATH_ENV,
        ASKPASS_SOCKET_ENV,
        ASKPASS_TOKEN_ENV,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    match profile.auth_type {
        SshAuthType::Agent => {
            push_option(&mut args, "IdentityFile=none");
            push_option(&mut args, "PreferredAuthentications=publickey");
            push_option(&mut args, "BatchMode=yes");
        }
        SshAuthType::Key => {
            let identity_file = profile
                .identity_file
                .as_ref()
                .ok_or_else(|| "私钥认证必须指定私钥文件。".to_string())?;
            args.extend(["-i".to_string(), identity_file.clone()]);
            push_option(&mut args, "IdentitiesOnly=yes");
            push_option(&mut args, "PreferredAuthentications=publickey");
            if mode == SshMode::Test {
                push_option(&mut args, "BatchMode=yes");
            }
        }
        SshAuthType::Password => {
            let askpass =
                askpass.ok_or_else(|| "密码认证缺少 ASKPASS broker 启动凭据。".to_string())?;
            push_option(&mut args, "PreferredAuthentications=password");
            push_option(&mut args, "PubkeyAuthentication=no");
            push_option(&mut args, "KbdInteractiveAuthentication=no");
            push_option(&mut args, "NumberOfPasswordPrompts=1");
            env.insert(
                "SSH_ASKPASS".to_string(),
                path_to_utf8(executable, "应用可执行文件")?,
            );
            env.insert("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string());
            env.insert("DISPLAY".to_string(), ":0".to_string());
            env.insert(ASKPASS_MARKER_ENV.to_string(), "1".to_string());
            env.insert(
                ASKPASS_SOCKET_ENV.to_string(),
                askpass.socket_path().to_string(),
            );
            env.insert(
                ASKPASS_TOKEN_ENV.to_string(),
                askpass.capability_token().to_string(),
            );
        }
    }

    args.extend([
        "-p".to_string(),
        profile.port.to_string(),
        "-l".to_string(),
        profile.username,
        "--".to_string(),
        profile.host,
    ]);
    if mode == SshMode::Test {
        args.push("true".to_string());
    }

    Ok(SshProcessSpec {
        program: "/usr/bin/ssh".to_string(),
        args,
        env,
        env_remove,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_ssh_process_spec, build_ssh_process_spec_for_runtime,
        build_ssh_process_spec_for_runtime_with_term, AskpassLaunchEnv, SshMode, SshProcessSpec,
        ASKPASS_MARKER_ENV, ASKPASS_SOCKET_ENV, ASKPASS_TOKEN_ENV,
    };
    use crate::ssh::{SshAuthType, SshProfile};
    use std::{collections::BTreeSet, fs, path::Path, path::PathBuf};

    const PROFILE_ID: &str = "74c00a0b-a7e5-410c-9aed-7e9f5045507b";
    const ASKPASS_SOCKET: &str = "/tmp/codex-ssh/askpass.sock";
    const ASKPASS_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const PASSWORD: &str = "top-secret-password";

    fn fixture_profile(auth_type: SshAuthType) -> SshProfile {
        SshProfile {
            id: PROFILE_ID.into(),
            name: "Production".into(),
            host: "example.com".into(),
            port: 2222,
            username: "deploy".into(),
            auth_type,
            identity_file: None,
            connect_timeout: 17,
            credential_revision: None,
        }
    }

    fn unique_key_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "terminal-codex-process-key-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, "test-key").unwrap();
        path
    }

    fn build_for_runtime(profile: &SshProfile, mode: SshMode) -> SshProcessSpec {
        let launch = (profile.auth_type == SshAuthType::Password)
            .then(|| AskpassLaunchEnv::new(Path::new(ASKPASS_SOCKET), ASKPASS_TOKEN).unwrap());
        build_ssh_process_spec_for_runtime_with_term(
            profile,
            Path::new("/Applications/LeviQian Codex.app/Contents/MacOS/leviqian-codex"),
            launch.as_ref(),
            mode,
            Some(std::ffi::OsStr::new("test-parent-term")),
        )
        .unwrap()
    }

    fn build_for_runtime_with_term(
        profile: &SshProfile,
        mode: SshMode,
        parent_term: Option<&str>,
    ) -> SshProcessSpec {
        let launch = (profile.auth_type == SshAuthType::Password)
            .then(|| AskpassLaunchEnv::new(Path::new(ASKPASS_SOCKET), ASKPASS_TOKEN).unwrap());
        build_ssh_process_spec_for_runtime_with_term(
            profile,
            Path::new("/Applications/LeviQian Codex.app/Contents/MacOS/leviqian-codex"),
            launch.as_ref(),
            mode,
            parent_term.map(std::ffi::OsStr::new),
        )
        .unwrap()
    }

    fn common_args(mode_flag: &str) -> Vec<String> {
        [
            mode_flag,
            "-F",
            "none",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "HashKnownHosts=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ConnectTimeout=17",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    fn connection_tail(test_command: bool) -> Vec<String> {
        let mut tail = ["-p", "2222", "-l", "deploy", "--", "example.com"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if test_command {
            tail.push("true".into());
        }
        tail
    }

    fn inherited_env_removals() -> BTreeSet<String> {
        [
            "SSH_ASKPASS",
            "SSH_ASKPASS_REQUIRE",
            ASKPASS_MARKER_ENV,
            ASKPASS_SOCKET_ENV,
            ASKPASS_TOKEN_ENV,
            "CODEX_TERMINAL_SSH_PROFILE_ID",
            "CODEX_TERMINAL_SSH_APP_PID",
            "CODEX_TERMINAL_SSH_PROFILES_PATH",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn agent_interactive_spec_has_exact_arguments_and_clean_environment() {
        let profile = fixture_profile(SshAuthType::Agent);
        let spec = build_for_runtime(&profile, SshMode::Interactive);
        let mut expected = common_args("-tt");
        expected.extend(
            [
                "-o",
                "IdentityFile=none",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ]
            .into_iter()
            .map(str::to_string),
        );
        expected.extend(connection_tail(false));

        assert_eq!(spec.program, "/usr/bin/ssh");
        assert_eq!(spec.args, expected);
        assert!(spec.env.is_empty());
        assert_eq!(spec.env_remove, inherited_env_removals());
        assert!(!spec.env_remove.contains("DISPLAY"));
    }

    #[test]
    fn missing_or_empty_parent_term_uses_xterm_fallback() {
        let profile = fixture_profile(SshAuthType::Agent);

        for parent_term in [None, Some("")] {
            let spec = build_for_runtime_with_term(&profile, SshMode::Interactive, parent_term);

            assert_eq!(
                spec.env.get("TERM").map(String::as_str),
                Some("xterm-256color")
            );
        }
    }

    #[test]
    fn nonempty_parent_term_is_inherited_without_override() {
        let profile = fixture_profile(SshAuthType::Agent);

        let spec =
            build_for_runtime_with_term(&profile, SshMode::Interactive, Some("custom-terminal"));

        assert!(!spec.env.contains_key("TERM"));
    }

    #[test]
    fn key_interactive_spec_has_exact_arguments_without_batch_mode() {
        let key = unique_key_file();
        let mut profile = fixture_profile(SshAuthType::Key);
        profile.identity_file = Some(key.to_string_lossy().into_owned());
        let spec = build_for_runtime(&profile, SshMode::Interactive);
        let mut expected = common_args("-tt");
        expected.extend(
            [
                "-i",
                key.to_string_lossy().as_ref(),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
            ]
            .into_iter()
            .map(str::to_string),
        );
        expected.extend(connection_tail(false));

        assert_eq!(spec.args, expected);
        assert!(spec.env.is_empty());
        assert_eq!(spec.env_remove, inherited_env_removals());
        assert!(!spec.args.iter().any(|arg| arg == "BatchMode=yes"));
        fs::remove_file(key).unwrap();
    }

    #[test]
    fn password_interactive_spec_has_exact_arguments_and_askpass_environment() {
        let profile = fixture_profile(SshAuthType::Password);
        let spec = build_for_runtime(&profile, SshMode::Interactive);
        let mut expected = common_args("-tt");
        expected.extend(
            [
                "-o",
                "PreferredAuthentications=password",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "NumberOfPasswordPrompts=1",
            ]
            .into_iter()
            .map(str::to_string),
        );
        expected.extend(connection_tail(false));

        assert_eq!(spec.args, expected);
        assert_eq!(spec.env_remove, inherited_env_removals());
        assert_eq!(
            spec.env.get("SSH_ASKPASS").map(String::as_str),
            Some("/Applications/LeviQian Codex.app/Contents/MacOS/leviqian-codex")
        );
        assert_eq!(
            spec.env.get("SSH_ASKPASS_REQUIRE").map(String::as_str),
            Some("force")
        );
        assert_eq!(spec.env.get("DISPLAY").map(String::as_str), Some(":0"));
        assert_eq!(
            spec.env.get(ASKPASS_MARKER_ENV).map(String::as_str),
            Some("1")
        );
        assert_eq!(
            spec.env.get(ASKPASS_SOCKET_ENV).map(String::as_str),
            Some(ASKPASS_SOCKET)
        );
        assert_eq!(
            spec.env.get(ASKPASS_TOKEN_ENV).map(String::as_str),
            Some(ASKPASS_TOKEN)
        );
        for forbidden in [
            PROFILE_ID,
            "/tmp/config/ssh-profiles.json",
            "42424",
            PASSWORD,
        ] {
            assert!(!spec.env.values().any(|value| value.contains(forbidden)));
        }
        assert!(!format!("{spec:?}").contains(ASKPASS_TOKEN));
    }

    #[test]
    fn clearing_process_spec_zeroizes_and_removes_askpass_token() {
        let profile = fixture_profile(SshAuthType::Password);
        let mut spec = build_for_runtime(&profile, SshMode::Interactive);
        assert_eq!(
            spec.env.get(ASKPASS_TOKEN_ENV).map(String::as_str),
            Some(ASKPASS_TOKEN)
        );

        spec.clear_secrets();

        assert!(!spec.env.contains_key(ASKPASS_TOKEN_ENV));
        spec.clear_secrets();
        assert!(!spec.env.contains_key(ASKPASS_TOKEN_ENV));
    }

    #[test]
    fn test_mode_exactly_adjusts_agent_key_and_password_specs() {
        let agent = build_for_runtime(&fixture_profile(SshAuthType::Agent), SshMode::Test);
        let mut expected_agent = common_args("-T");
        expected_agent.extend(
            [
                "-o",
                "IdentityFile=none",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ]
            .into_iter()
            .map(str::to_string),
        );
        expected_agent.extend(connection_tail(true));
        assert_eq!(agent.args, expected_agent);

        let key_path = unique_key_file();
        let mut key_profile = fixture_profile(SshAuthType::Key);
        key_profile.identity_file = Some(key_path.to_string_lossy().into_owned());
        let key = build_for_runtime(&key_profile, SshMode::Test);
        let mut expected_key = common_args("-T");
        expected_key.extend(
            [
                "-i",
                key_path.to_string_lossy().as_ref(),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ]
            .into_iter()
            .map(str::to_string),
        );
        expected_key.extend(connection_tail(true));
        assert_eq!(key.args, expected_key);

        let password = build_for_runtime(&fixture_profile(SshAuthType::Password), SshMode::Test);
        let mut expected_password = common_args("-T");
        expected_password.extend(
            [
                "-o",
                "PreferredAuthentications=password",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "NumberOfPasswordPrompts=1",
            ]
            .into_iter()
            .map(str::to_string),
        );
        expected_password.extend(connection_tail(true));
        assert_eq!(password.args, expected_password);
        assert_eq!(
            password.env.get("SSH_ASKPASS_REQUIRE").map(String::as_str),
            Some("force")
        );
        fs::remove_file(key_path).unwrap();
    }

    #[test]
    fn host_metacharacters_remain_one_argument_without_shell_parsing() {
        let mut profile = fixture_profile(SshAuthType::Agent);
        profile.host = "example.com;touch_/tmp/not-executed".into();

        let spec = build_for_runtime(&profile, SshMode::Interactive);

        assert_eq!(
            spec.args.iter().filter(|arg| *arg == &profile.host).count(),
            1
        );
    }

    #[test]
    fn rejects_invalid_uuid_and_unsafe_host_or_username() {
        let rejects = |profile: &SshProfile| {
            build_ssh_process_spec_for_runtime(
                profile,
                Path::new("/tmp/app"),
                None,
                SshMode::Interactive,
            )
            .is_err()
        };
        let mut invalid_uuid = fixture_profile(SshAuthType::Agent);
        invalid_uuid.id = "not-a-uuid".into();
        assert!(rejects(&invalid_uuid));

        for host in ["-proxy", "bad host", "bad\thost", "bad\u{7f}host"] {
            let mut profile = fixture_profile(SshAuthType::Agent);
            profile.host = host.into();
            assert!(rejects(&profile), "host={host:?}");
        }

        for username in ["bad user", "bad\tuser", "bad\u{7f}user"] {
            let mut profile = fixture_profile(SshAuthType::Agent);
            profile.username = username.into();
            assert!(rejects(&profile), "username={username:?}");
        }
    }

    #[test]
    fn production_builder_uses_current_executable_for_password_askpass() {
        let profile = fixture_profile(SshAuthType::Password);

        let spec = build_ssh_process_spec(
            &profile,
            Some(&AskpassLaunchEnv::new(Path::new(ASKPASS_SOCKET), ASKPASS_TOKEN).unwrap()),
            SshMode::Interactive,
        )
        .unwrap();

        assert_eq!(
            spec.env.get("SSH_ASKPASS"),
            Some(
                &std::env::current_exe()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            )
        );
    }
}
