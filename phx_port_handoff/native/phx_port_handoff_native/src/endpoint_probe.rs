use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{UnixAddr, connect};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::time::Instant;

pub(crate) fn is_live(socket: OwnedFd, path: &Path, deadline: Instant) -> io::Result<bool> {
    let check_deadline = || {
        if Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Unix socket liveness probe timed out",
            ))
        } else {
            Ok(())
        }
    };
    check_deadline()?;
    let address = UnixAddr::new(path)?;
    let flags = OFlag::from_bits_truncate(fcntl(&socket, FcntlArg::F_GETFL)?);
    fcntl(&socket, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;

    loop {
        check_deadline()?;
        let result = connect(socket.as_raw_fd(), &address);
        check_deadline()?;
        match result {
            Ok(()) | Err(Errno::EISCONN) => return Ok(true),
            Err(Errno::ECONNREFUSED) => return Ok(false),
            Err(Errno::EINTR) => continue,
            // A full queue (EAGAIN), pending connection, or operational error
            // is not proof of staleness. Preserve the endpoint without waiting.
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_live;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};
    use std::{fs, io};
    use tempfile::tempdir;

    fn probe_socket() -> OwnedFd {
        socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn expired_deadline_fails_closed() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("live.sock");
        let _listener = UnixListener::bind(&path).unwrap();

        let error = is_live(probe_socket(), &path, Instant::now()).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(path.exists());
    }

    #[test]
    fn missing_endpoint_is_not_a_confirmed_stale_socket() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("missing.sock");

        let error = is_live(
            probe_socket(),
            &path,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
