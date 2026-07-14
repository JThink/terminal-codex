use super::{
    broker::{
        read_frame, write_frame, ASKPASS_FAILURE, ASKPASS_IO_TIMEOUT, ASKPASS_MAX_RESPONSE_BYTES,
        ASKPASS_SUCCESS,
    },
    local_socket::{self, LocalStream},
    ASKPASS_MARKER_ENV, ASKPASS_SOCKET_ENV, ASKPASS_TOKEN_ENV,
};
#[cfg(test)]
use std::collections::BTreeMap;
use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

struct AskpassClientRequest {
    socket_path: PathBuf,
    capability_token: Zeroizing<String>,
}

fn validate_capability_token(token: &str) -> Result<(), String> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ASKPASS capability 格式无效。".to_string());
    }
    Ok(())
}

#[cfg(test)]
fn parse_request(environment: &BTreeMap<String, String>) -> Result<AskpassClientRequest, String> {
    if environment.get(ASKPASS_MARKER_ENV).map(String::as_str) != Some("1") {
        return Err("ASKPASS 内部标记无效。".to_string());
    }
    let socket_path = environment
        .get(ASKPASS_SOCKET_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "ASKPASS 缺少 broker socket 路径。".to_string())?;
    let capability_token = environment
        .get(ASKPASS_TOKEN_ENV)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "ASKPASS 缺少 capability。".to_string())?;
    validate_capability_token(capability_token)?;
    Ok(AskpassClientRequest {
        socket_path,
        capability_token: Zeroizing::new(capability_token.clone()),
    })
}

pub(super) fn request_password(
    socket_path: &Path,
    capability_token: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    validate_capability_token(capability_token)?;
    let mut stream: LocalStream =
        local_socket::connect(socket_path).map_err(|_| "无法连接 ASKPASS broker。".to_string())?;
    stream
        .set_read_timeout(Some(ASKPASS_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(ASKPASS_IO_TIMEOUT)))
        .map_err(|_| "无法配置 ASKPASS broker 连接。".to_string())?;
    write_frame(&mut stream, capability_token.as_bytes())
        .map_err(|_| "无法发送 ASKPASS broker 请求。".to_string())?;
    let mut response = read_frame(&mut stream, ASKPASS_MAX_RESPONSE_BYTES)
        .map_err(|_| "ASKPASS broker 响应协议无效。".to_string())?;
    match response.first().copied() {
        Some(ASKPASS_SUCCESS) => {
            response.remove(0);
            if response.is_empty()
                || std::str::from_utf8(&response).is_err()
                || response.contains(&0)
                || response.contains(&b'\r')
                || response.contains(&b'\n')
            {
                return Err("ASKPASS broker 密码响应无效。".to_string());
            }
            Ok(response)
        }
        Some(ASKPASS_FAILURE) => Err("ASKPASS broker 拒绝请求。".to_string()),
        _ => Err("ASKPASS broker 响应状态无效。".to_string()),
    }
}

fn write_askpass_response(
    request: AskpassClientRequest,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    let password = request_password(&request.socket_path, &request.capability_token)?;
    stdout
        .write_all(&password)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| "无法写入 ASKPASS 输出。".to_string())
}

#[cfg(test)]
fn ssh_askpass_client_exit_code_with(
    environment: &BTreeMap<String, String>,
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> Option<i32> {
    if !environment.contains_key(ASKPASS_MARKER_ENV) {
        return None;
    }
    let result =
        parse_request(environment).and_then(|request| write_askpass_response(request, stdout));
    Some(if result.is_ok() { 0 } else { 1 })
}

fn collect_askpass_request(
    mut read: impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<AskpassClientRequest>, ()> {
    let Some(marker) = read(ASKPASS_MARKER_ENV) else {
        return Ok(None);
    };
    if marker.into_string().map_err(|_| ())? != "1" {
        return Err(());
    }
    let socket_path = read(ASKPASS_SOCKET_ENV)
        .ok_or(())?
        .into_string()
        .map_err(|_| ())?;
    if socket_path.is_empty() {
        return Err(());
    }
    let capability_token = Zeroizing::new(
        read(ASKPASS_TOKEN_ENV)
            .ok_or(())?
            .into_string()
            .map_err(|_| ())?,
    );
    validate_capability_token(&capability_token).map_err(|_| ())?;
    Ok(Some(AskpassClientRequest {
        socket_path: PathBuf::from(socket_path),
        capability_token,
    }))
}

fn ssh_askpass_client_exit_code_with_os_environment(
    read: impl FnMut(&str) -> Option<OsString>,
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> Option<i32> {
    let request = match collect_askpass_request(read) {
        Ok(Some(request)) => request,
        Ok(None) => return None,
        Err(()) => return Some(1),
    };
    Some(if write_askpass_response(request, stdout).is_ok() {
        0
    } else {
        1
    })
}

pub(crate) fn ssh_askpass_exit_code_if_requested() -> Option<i32> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::sink();
    ssh_askpass_client_exit_code_with_os_environment(
        |key| env::var_os(key),
        &mut stdout,
        &mut stderr,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::ssh_askpass_client_exit_code_with_os_environment;
    use super::{collect_askpass_request, request_password, ssh_askpass_client_exit_code_with};
    use crate::ssh::{local_socket, ASKPASS_MARKER_ENV, ASKPASS_SOCKET_ENV, ASKPASS_TOKEN_ENV};
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        fs,
        io::{Read, Write},
        path::PathBuf,
        thread,
        time::Duration,
    };

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SECRET: &[u8] = b"pure-client-secret";

    struct TestServer {
        directory: PathBuf,
        socket: PathBuf,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn success() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "lc-client-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ));
            fs::create_dir(&directory).unwrap();
            let socket = directory.join("s");
            let listener = local_socket::bind(&socket).unwrap();
            let worker = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut length = [0_u8; 4];
                stream.read_exact(&mut length).unwrap();
                let mut token = vec![0_u8; u32::from_be_bytes(length) as usize];
                stream.read_exact(&mut token).unwrap();
                assert_eq!(token, TOKEN.as_bytes());
                let mut response = vec![0];
                response.extend_from_slice(SECRET);
                stream
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            });
            Self {
                directory,
                socket,
                worker: Some(worker),
            }
        }

        fn environment(&self) -> BTreeMap<String, String> {
            BTreeMap::from([
                (ASKPASS_MARKER_ENV.into(), "1".into()),
                (
                    ASKPASS_SOCKET_ENV.into(),
                    self.socket.to_string_lossy().into_owned(),
                ),
                (ASKPASS_TOKEN_ENV.into(), TOKEN.into()),
            ])
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[test]
    fn broker_client_returns_only_success_password_bytes() {
        let server = TestServer::success();

        let password = request_password(&server.socket, TOKEN).unwrap();

        assert_eq!(password.as_slice(), SECRET);
    }

    #[test]
    fn helper_success_writes_only_password_and_newline() {
        let server = TestServer::success();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code =
            ssh_askpass_client_exit_code_with(&server.environment(), &mut stdout, &mut stderr);

        assert_eq!(code, Some(0));
        assert_eq!(stdout, [SECRET, b"\n"].concat());
        assert!(stderr.is_empty());
    }

    #[test]
    fn helper_failure_is_silent_and_nonzero() {
        let mut environment = BTreeMap::from([
            (ASKPASS_MARKER_ENV.into(), "1".into()),
            (ASKPASS_SOCKET_ENV.into(), "/tmp/does-not-exist/s".into()),
            (ASKPASS_TOKEN_ENV.into(), TOKEN.into()),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = ssh_askpass_client_exit_code_with(&environment, &mut stdout, &mut stderr);

        assert_eq!(code, Some(1));
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        environment.remove(ASKPASS_MARKER_ENV);
        assert_eq!(
            ssh_askpass_client_exit_code_with(&environment, &mut stdout, &mut stderr),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_internal_environment_fails_before_tauri_startup() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = OsString::from_vec(vec![0xff]);
        for invalid_key in [ASKPASS_MARKER_ENV, ASKPASS_SOCKET_ENV, ASKPASS_TOKEN_ENV] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = ssh_askpass_client_exit_code_with_os_environment(
                |key| {
                    if key == invalid_key {
                        Some(invalid.clone())
                    } else if key == ASKPASS_MARKER_ENV {
                        Some(OsString::from("1"))
                    } else if key == ASKPASS_SOCKET_ENV {
                        Some(OsString::from("/tmp/broker.sock"))
                    } else if key == ASKPASS_TOKEN_ENV {
                        Some(OsString::from(TOKEN))
                    } else {
                        None
                    }
                },
                &mut stdout,
                &mut stderr,
            );

            assert_eq!(code, Some(1));
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn production_environment_collector_moves_token_into_zeroizing_request() {
        let mut values = BTreeMap::from([
            (ASKPASS_MARKER_ENV.to_string(), OsString::from("1")),
            (
                ASKPASS_SOCKET_ENV.to_string(),
                OsString::from("/tmp/broker.sock"),
            ),
            (ASKPASS_TOKEN_ENV.to_string(), OsString::from(TOKEN)),
        ]);

        let request = collect_askpass_request(|key| values.remove(key))
            .unwrap()
            .unwrap();

        assert_eq!(request.socket_path, PathBuf::from("/tmp/broker.sock"));
        assert_eq!(request.capability_token.as_str(), TOKEN);
        assert!(!values.contains_key(ASKPASS_TOKEN_ENV));
    }
}
