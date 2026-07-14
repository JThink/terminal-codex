use std::{io, path::Path};

#[cfg(unix)]
pub(crate) type LocalListener = std::os::unix::net::UnixListener;
#[cfg(windows)]
pub(crate) type LocalListener = uds_windows::UnixListener;

#[cfg(unix)]
pub(crate) type LocalStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub(crate) type LocalStream = uds_windows::UnixStream;

pub(crate) fn bind(path: &Path) -> io::Result<LocalListener> {
    LocalListener::bind(path)
}

pub(crate) fn connect(path: &Path) -> io::Result<LocalStream> {
    LocalStream::connect(path)
}

#[cfg(unix)]
pub(crate) fn socket_path_len(path: &Path) -> io::Result<usize> {
    use std::os::unix::ffi::OsStrExt;

    Ok(path.as_os_str().as_bytes().len())
}

#[cfg(windows)]
pub(crate) fn socket_path_len(path: &Path) -> io::Result<usize> {
    path.to_str().map(str::len).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ASKPASS socket 路径不是有效的 UTF-8。",
        )
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn peer_pid(stream: &LocalStream) -> Result<u32, String> {
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
    if result != 0 {
        return Err(format!(
            "无法获取 ASKPASS socket 对端进程身份：{}",
            io::Error::last_os_error()
        ));
    }
    if length as usize != std::mem::size_of::<libc::pid_t>() || pid <= 0 {
        return Err("ASKPASS socket 对端进程身份返回无效。".to_string());
    }
    u32::try_from(pid).map_err(|_| "ASKPASS socket 对端进程 ID 无效。".to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn peer_pid(_stream: &LocalStream) -> Result<u32, String> {
    Err("当前平台不支持 ASKPASS socket 对端进程身份校验。".to_string())
}

#[cfg(windows)]
fn winsock_last_error() -> io::Error {
    use windows_sys::Win32::Networking::WinSock::WSAGetLastError;

    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[cfg(windows)]
pub(crate) fn peer_pid(stream: &LocalStream) -> Result<u32, String> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SIO_AF_UNIX_GETPEERPID, SOCKET_ERROR};

    let mut pid = 0_u32;
    let mut bytes_returned = 0_u32;
    let result = unsafe {
        WSAIoctl(
            stream.as_raw_socket() as _,
            SIO_AF_UNIX_GETPEERPID,
            std::ptr::null(),
            0,
            (&mut pid as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        return Err(format!(
            "无法获取 ASKPASS socket 对端进程身份：{}",
            winsock_last_error()
        ));
    }
    // Windows may report zero bytes here even though the fixed-size PID output was written.
    if pid == 0 {
        return Err("ASKPASS socket 对端进程 ID 无效。".to_string());
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::{bind, connect, peer_pid, socket_path_len, LocalListener, LocalStream};

    #[cfg(windows)]
    #[test]
    fn winsock_last_error_reads_winsock_error_channel() {
        use super::winsock_last_error;
        use windows_sys::Win32::Networking::WinSock::{WSASetLastError, WSAEACCES};

        unsafe { WSASetLastError(WSAEACCES) };

        assert_eq!(winsock_last_error().raw_os_error(), Some(WSAEACCES));
    }

    #[test]
    fn path_length_counts_transport_bytes() {
        assert_eq!(
            socket_path_len(std::path::Path::new("local/socket")).unwrap(),
            "local/socket".len()
        );
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn reports_real_connecting_process_pid() {
        #[cfg(target_os = "macos")]
        let base = std::path::PathBuf::from("/tmp");
        #[cfg(windows)]
        let base = std::env::temp_dir();
        let random = uuid::Uuid::new_v4().simple().to_string();
        let directory = base.join(format!("lcp-{}", &random[..16]));
        std::fs::create_dir(&directory).unwrap();
        let socket_path = directory.join("s");
        let listener: LocalListener = bind(&socket_path).unwrap();
        let client: LocalStream = connect(&socket_path).unwrap();
        let (server, _) = listener.accept().unwrap();

        assert_eq!(peer_pid(&server).unwrap(), std::process::id());

        drop(client);
        drop(server);
        drop(listener);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
