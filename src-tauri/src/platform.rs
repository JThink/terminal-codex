use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
};

#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("平台模块仅支持 macOS 和 Windows。");

const ENVIRONMENT_KEYS: [&str; 8] = [
    "CODEX_HOME",
    "ComSpec",
    "HOME",
    "PATH",
    "PATHEXT",
    "SHELL",
    "USERPROFILE",
    "WINDIR",
];
const DEFAULT_WINDOWS_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";
const SSH_NOT_FOUND_ERROR: &str = "找不到可用的 SSH 可执行文件。";
const USER_HOME_NOT_FOUND_ERROR: &str = "无法定位用户主目录。";

type EnvVars = HashMap<String, String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformKind {
    // Task 3 consumes the native variant on each target; injected tests need both variants.
    #[cfg_attr(windows, allow(dead_code))]
    MacOs,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Windows,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShellSpec {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) cwd: PathBuf,
}

#[cfg(target_os = "macos")]
pub(crate) fn current_platform() -> PlatformKind {
    PlatformKind::MacOs
}

#[cfg(windows)]
pub(crate) fn current_platform() -> PlatformKind {
    PlatformKind::Windows
}

// Task 3/4 will consume these entries when their existing call sites are migrated.
#[allow(dead_code)]
pub(crate) fn user_home() -> Result<PathBuf, String> {
    home_from_vars(current_platform(), &runtime_vars())
        .ok_or_else(|| USER_HOME_NOT_FOUND_ERROR.to_string())
}

#[allow(dead_code)]
pub(crate) fn codex_home() -> Result<PathBuf, String> {
    codex_home_from_vars(current_platform(), &runtime_vars())
        .ok_or_else(|| "无法定位 CODEX_HOME 目录。".to_string())
}

#[allow(dead_code)]
pub(crate) fn shell_spec(
    shell_override: Option<&str>,
    cwd: Option<&str>,
) -> Result<ShellSpec, String> {
    shell_spec_with(
        current_platform(),
        shell_override,
        cwd,
        &runtime_vars(),
        Path::is_file,
    )
}

#[allow(dead_code)]
pub(crate) fn resolve_ssh_executable() -> Result<PathBuf, String> {
    resolve_ssh_executable_with(current_platform(), &runtime_vars(), Path::is_file)
}

fn runtime_vars() -> EnvVars {
    ENVIRONMENT_KEYS
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_string(), value)))
        .collect()
}

fn non_empty_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn var<'a>(vars: &'a EnvVars, key: &str) -> Option<&'a str> {
    non_empty_value(vars.get(key).map(String::as_str))
}

fn path_value(value: Option<&str>) -> Option<PathBuf> {
    non_empty_value(value).map(PathBuf::from)
}

fn home_from_vars(platform: PlatformKind, vars: &EnvVars) -> Option<PathBuf> {
    match platform {
        PlatformKind::MacOs => var(vars, "HOME").map(PathBuf::from),
        PlatformKind::Windows => var(vars, "USERPROFILE")
            .or_else(|| var(vars, "HOME"))
            .map(PathBuf::from),
    }
}

fn codex_home_from_vars(platform: PlatformKind, vars: &EnvVars) -> Option<PathBuf> {
    var(vars, "CODEX_HOME").map(PathBuf::from).or_else(|| {
        home_from_vars(platform, vars).map(|home| append_path(platform, &home, ".codex"))
    })
}

fn append_path(platform: PlatformKind, base: &Path, component: &str) -> PathBuf {
    let separator = match platform {
        PlatformKind::MacOs => '/',
        PlatformKind::Windows => '\\',
    };
    let mut joined = base.to_string_lossy().into_owned();
    let has_separator = match platform {
        PlatformKind::MacOs => joined.ends_with('/'),
        PlatformKind::Windows => joined.ends_with(['/', '\\']),
    };
    if !joined.is_empty() && !has_separator {
        joined.push(separator);
    }
    joined.push_str(component);
    PathBuf::from(joined)
}

fn windows_program_names(program: &str, vars: &EnvVars) -> Vec<String> {
    let file_name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    if file_name
        .rsplit_once('.')
        .is_some_and(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
    {
        return vec![program.to_string()];
    }

    let extensions = var(vars, "PATHEXT")
        .unwrap_or(DEFAULT_WINDOWS_PATHEXT)
        .split(';')
        .filter_map(|value| non_empty_value(Some(value)))
        .map(|extension| {
            if extension.starts_with('.') {
                extension.to_string()
            } else {
                format!(".{extension}")
            }
        })
        .collect::<Vec<_>>();
    let extensions = if extensions.is_empty() {
        DEFAULT_WINDOWS_PATHEXT
            .split(';')
            .map(str::to_string)
            .collect()
    } else {
        extensions
    };

    extensions
        .into_iter()
        .map(|extension| format!("{program}{extension}"))
        .collect()
}

fn find_program_with<F>(
    platform: PlatformKind,
    program: &str,
    vars: &EnvVars,
    is_file: F,
) -> Option<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    let program = non_empty_value(Some(program))?;
    let search_path = var(vars, "PATH")?;
    let delimiter = match platform {
        PlatformKind::MacOs => ':',
        PlatformKind::Windows => ';',
    };
    let names = match platform {
        PlatformKind::MacOs => vec![program.to_string()],
        PlatformKind::Windows => windows_program_names(program, vars),
    };

    for directory in search_path.split(delimiter) {
        let directory = directory.trim().trim_matches('"');
        if directory.is_empty() {
            continue;
        }
        for name in &names {
            let candidate = append_path(platform, Path::new(directory), name);
            if is_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn shell_spec_with<F>(
    platform: PlatformKind,
    shell_override: Option<&str>,
    cwd: Option<&str>,
    vars: &EnvVars,
    is_file: F,
) -> Result<ShellSpec, String>
where
    F: Fn(&Path) -> bool,
{
    let cwd = path_value(cwd)
        .or_else(|| home_from_vars(platform, vars))
        .ok_or_else(|| USER_HOME_NOT_FOUND_ERROR.to_string())?;
    let shell_override = path_value(shell_override);

    let (program, args) = match platform {
        PlatformKind::MacOs => (
            shell_override
                .or_else(|| var(vars, "SHELL").map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("/bin/zsh")),
            vec!["-l".to_string()],
        ),
        PlatformKind::Windows => (
            shell_override
                .or_else(|| find_program_with(platform, "pwsh.exe", vars, &is_file))
                .or_else(|| find_program_with(platform, "powershell.exe", vars, &is_file))
                .or_else(|| var(vars, "ComSpec").map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("cmd.exe")),
            Vec::new(),
        ),
    };

    Ok(ShellSpec { program, args, cwd })
}

fn resolve_ssh_executable_with<F>(
    platform: PlatformKind,
    vars: &EnvVars,
    is_file: F,
) -> Result<PathBuf, String>
where
    F: Fn(&Path) -> bool,
{
    match platform {
        PlatformKind::MacOs => {
            let ssh = PathBuf::from("/usr/bin/ssh");
            is_file(&ssh)
                .then_some(ssh)
                .ok_or_else(|| SSH_NOT_FOUND_ERROR.to_string())
        }
        PlatformKind::Windows => {
            if let Some(windows_directory) = var(vars, "WINDIR") {
                let system_ssh = ["System32", "OpenSSH", "ssh.exe"]
                    .into_iter()
                    .fold(PathBuf::from(windows_directory), |path, component| {
                        append_path(platform, &path, component)
                    });
                if is_file(&system_ssh) {
                    return Ok(system_ssh);
                }
            }

            find_program_with(platform, "ssh.exe", vars, is_file)
                .ok_or_else(|| SSH_NOT_FOUND_ERROR.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::HashSet,
        path::{Path, PathBuf},
    };

    use super::*;

    fn vars(entries: &[(&str, &str)]) -> EnvVars {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn files(paths: &[&str]) -> HashSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    fn no_files(_: &Path) -> bool {
        false
    }

    #[test]
    fn windows_home_prefers_userprofile_and_falls_back_to_home() {
        let preferred = vars(&[("USERPROFILE", r"C:\Users\levi"), ("HOME", r"C:\fallback")]);
        assert_eq!(
            home_from_vars(PlatformKind::Windows, &preferred),
            Some(PathBuf::from(r"C:\Users\levi"))
        );

        let fallback = vars(&[("USERPROFILE", "  "), ("HOME", r"C:\fallback")]);
        assert_eq!(
            home_from_vars(PlatformKind::Windows, &fallback),
            Some(PathBuf::from(r"C:\fallback"))
        );
    }

    #[test]
    fn codex_home_prefers_non_empty_override_and_otherwise_uses_user_home() {
        let overridden = vars(&[
            ("CODEX_HOME", r"  C:\codex-data  "),
            ("USERPROFILE", r"C:\Users\levi"),
        ]);
        assert_eq!(
            codex_home_from_vars(PlatformKind::Windows, &overridden),
            Some(PathBuf::from(r"C:\codex-data"))
        );

        let defaulted = vars(&[("CODEX_HOME", "\t"), ("USERPROFILE", r"C:\Users\levi")]);
        assert_eq!(
            codex_home_from_vars(PlatformKind::Windows, &defaulted),
            Some(PathBuf::from(r"C:\Users\levi\.codex"))
        );
    }

    #[test]
    fn macos_shell_uses_override_with_login_argument() {
        let environment = vars(&[("HOME", "/Users/levi"), ("SHELL", "/bin/bash")]);

        let spec = shell_spec_with(
            PlatformKind::MacOs,
            Some("  /opt/homebrew/bin/fish  "),
            None,
            &environment,
            no_files,
        )
        .unwrap();

        assert_eq!(spec.program, PathBuf::from("/opt/homebrew/bin/fish"));
        assert_eq!(spec.args, vec!["-l"]);
    }

    #[test]
    fn macos_shell_uses_shell_env_then_zsh_fallback() {
        let from_env = vars(&[("HOME", "/Users/levi"), ("SHELL", "/bin/bash")]);
        let spec = shell_spec_with(PlatformKind::MacOs, None, None, &from_env, no_files).unwrap();
        assert_eq!(spec.program, PathBuf::from("/bin/bash"));
        assert_eq!(spec.args, vec!["-l"]);

        let without_shell = vars(&[("HOME", "/Users/levi")]);
        let spec =
            shell_spec_with(PlatformKind::MacOs, None, None, &without_shell, no_files).unwrap();
        assert_eq!(spec.program, PathBuf::from("/bin/zsh"));
    }

    #[test]
    fn blank_shell_override_continues_with_platform_default_resolution() {
        let environment = vars(&[("HOME", "/Users/levi"), ("SHELL", "/bin/bash")]);

        let spec = shell_spec_with(
            PlatformKind::MacOs,
            Some(" \t "),
            None,
            &environment,
            no_files,
        )
        .unwrap();

        assert_eq!(spec.program, PathBuf::from("/bin/bash"));
    }

    #[test]
    fn shell_cwd_uses_non_empty_explicit_value_then_user_home() {
        let environment = vars(&[("HOME", "/Users/levi")]);

        let explicit = shell_spec_with(
            PlatformKind::MacOs,
            None,
            Some("  /work/project  "),
            &environment,
            no_files,
        )
        .unwrap();
        assert_eq!(explicit.cwd, PathBuf::from("/work/project"));

        let defaulted = shell_spec_with(
            PlatformKind::MacOs,
            None,
            Some(" \t "),
            &environment,
            no_files,
        )
        .unwrap();
        assert_eq!(defaulted.cwd, PathBuf::from("/Users/levi"));
    }

    #[test]
    fn windows_shell_order_is_pwsh_powershell_then_comspec_or_cmd() {
        let environment = vars(&[
            ("USERPROFILE", r"C:\Users\levi"),
            (
                "PATH",
                r"C:\PowerShell\7;C:\Windows\System32\WindowsPowerShell\v1.0",
            ),
            ("ComSpec", r"C:\Windows\System32\cmd.exe"),
        ]);
        let both = files(&[
            r"C:\PowerShell\7\pwsh.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ]);
        let spec = shell_spec_with(PlatformKind::Windows, None, None, &environment, |path| {
            both.contains(path)
        })
        .unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\PowerShell\7\pwsh.exe"));
        assert!(spec.args.is_empty());

        let legacy = files(&[r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]);
        let spec = shell_spec_with(PlatformKind::Windows, None, None, &environment, |path| {
            legacy.contains(path)
        })
        .unwrap();
        assert_eq!(
            spec.program,
            PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );

        let spec =
            shell_spec_with(PlatformKind::Windows, None, None, &environment, no_files).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\Windows\System32\cmd.exe"));

        let without_comspec = vars(&[("USERPROFILE", r"C:\Users\levi")]);
        let spec = shell_spec_with(
            PlatformKind::Windows,
            None,
            None,
            &without_comspec,
            no_files,
        )
        .unwrap();
        assert_eq!(spec.program, PathBuf::from("cmd.exe"));
        assert!(spec.args.is_empty());
    }

    #[test]
    fn path_search_skips_non_files_and_applies_windows_pathext() {
        let environment = vars(&[("PATH", r"C:\first;C:\second"), ("PATHEXT", ".COM;.EXE")]);
        let visited = RefCell::new(Vec::new());

        let result = find_program_with(PlatformKind::Windows, "tool", &environment, |path| {
            visited.borrow_mut().push(path.to_path_buf());
            path == Path::new(r"C:\second\tool.EXE")
        });

        assert_eq!(result, Some(PathBuf::from(r"C:\second\tool.EXE")));
        assert_eq!(
            visited.into_inner(),
            vec![
                PathBuf::from(r"C:\first\tool.COM"),
                PathBuf::from(r"C:\first\tool.EXE"),
                PathBuf::from(r"C:\second\tool.COM"),
                PathBuf::from(r"C:\second\tool.EXE"),
            ]
        );
    }

    #[test]
    fn windows_ssh_prefers_system_openssh_then_path() {
        let environment = vars(&[("WINDIR", r"C:\Windows"), ("PATH", r"D:\Tools")]);
        let system_ssh = PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe");
        let path_ssh = PathBuf::from(r"D:\Tools\ssh.exe");
        let both = HashSet::from([system_ssh.clone(), path_ssh.clone()]);

        assert_eq!(
            resolve_ssh_executable_with(PlatformKind::Windows, &environment, |path| {
                both.contains(path)
            })
            .unwrap(),
            system_ssh
        );

        assert_eq!(
            resolve_ssh_executable_with(PlatformKind::Windows, &environment, |path| {
                path == path_ssh
            })
            .unwrap(),
            path_ssh
        );
    }

    #[test]
    fn macos_ssh_requires_usr_bin_ssh_to_be_a_regular_file() {
        assert_eq!(
            resolve_ssh_executable_with(PlatformKind::MacOs, &EnvVars::new(), |path| {
                path == Path::new("/usr/bin/ssh")
            })
            .unwrap(),
            PathBuf::from("/usr/bin/ssh")
        );

        assert_eq!(
            resolve_ssh_executable_with(PlatformKind::MacOs, &EnvVars::new(), no_files),
            Err("找不到可用的 SSH 可执行文件。".to_string())
        );
    }
}
