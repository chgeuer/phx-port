use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{UnixAddr, connect, getsockopt, sockopt};
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) fn connect_stream_until(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let address = UnixAddr::new(path)?;
    let socket: OwnedFd =
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?.into();
    connect_until(&socket, &address, deadline)?;
    Ok(UnixStream::from(socket))
}

pub(crate) fn connect_until(
    socket: &OwnedFd,
    address: &UnixAddr,
    deadline: Instant,
) -> io::Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFL)?);
    fcntl(socket, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "Unix socket connection timed out")
            })
    };
    loop {
        remaining()?;
        match connect(socket.as_raw_fd(), address) {
            Ok(()) | Err(Errno::EISCONN) => break,
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => {
                // A full AF_UNIX accept queue has not initiated a connection. POLLOUT
                // can be immediately ready here; retry connect instead of busy-polling.
                std::thread::sleep(remaining()?.min(Duration::from_millis(5)));
            }
            Err(Errno::EINPROGRESS | Errno::EALREADY) => {
                loop {
                    let timeout_ms = remaining()?.as_millis().clamp(1, u16::MAX as u128) as u16;
                    let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLOUT)];
                    match poll(&mut fds, timeout_ms) {
                        Ok(0) | Err(Errno::EINTR) => continue,
                        Err(error) => return Err(error.into()),
                        Ok(_) => {}
                    }
                    let error = getsockopt(socket, sockopt::SocketError)?;
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error));
                    }
                    break;
                }
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    remaining()?;
    fcntl(socket, FcntlArg::F_SETFL(flags))?;
    Ok(())
}
