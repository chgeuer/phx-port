use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, TcpListener};

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_os = "linux")]
const IPV4_DESCRIPTOR_NAME: &str = "tls-ipv4";
#[cfg(target_os = "linux")]
const IPV6_DESCRIPTOR_NAME: &str = "tls-ipv6";

#[derive(Debug, Eq, PartialEq)]
pub enum ListenerOrigin {
    Direct,
    #[cfg(target_os = "linux")]
    Systemd(String),
}

pub struct IngressListener {
    pub listener: TcpListener,
    pub origin: ListenerOrigin,
}

struct ExpectedListener {
    configured: String,
    address: SocketAddr,
    #[cfg(target_os = "linux")]
    descriptor_name: &'static str,
}

pub fn acquire(configured_addresses: &[String]) -> Result<Vec<IngressListener>, String> {
    let expected = configured_addresses
        .iter()
        .map(|configured| {
            let address = configured.parse::<SocketAddr>().map_err(|error| {
                format!("invalid ingress listener address {configured:?}: {error}")
            })?;
            Ok(ExpectedListener {
                configured: configured.clone(),
                address,
                #[cfg(target_os = "linux")]
                descriptor_name: if address.is_ipv4() {
                    IPV4_DESCRIPTOR_NAME
                } else {
                    IPV6_DESCRIPTOR_NAME
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    #[cfg(target_os = "linux")]
    if let Some(descriptors) = systemd_descriptors(expected.len())? {
        return acquire_systemd(&expected, descriptors);
    }

    expected
        .into_iter()
        .map(|expected| {
            let listener = bind_listener(expected.address)
                .map_err(|error| format!("cannot listen on {}: {error}", expected.configured))?;
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("cannot configure listener: {error}"))?;
            Ok(IngressListener {
                listener,
                origin: ListenerOrigin::Direct,
            })
        })
        .collect()
}

fn bind_listener(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

#[cfg(target_os = "linux")]
struct SystemdDescriptor {
    fd: RawFd,
    name: String,
}

#[cfg(target_os = "linux")]
fn systemd_descriptors(expected_count: usize) -> Result<Option<Vec<SystemdDescriptor>>, String> {
    let listen_pid = env::var_os("LISTEN_PID");
    let listen_fds = env::var_os("LISTEN_FDS");
    let listen_fdnames = env::var_os("LISTEN_FDNAMES");
    let listen_pidfdid = env::var_os("LISTEN_PIDFDID");
    if listen_pid.is_none()
        && listen_fds.is_none()
        && listen_fdnames.is_none()
        && listen_pidfdid.is_none()
    {
        return Ok(None);
    }

    // Listener acquisition happens before this process starts any threads.
    unsafe {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
        env::remove_var("LISTEN_FDNAMES");
        env::remove_var("LISTEN_PIDFDID");
    }

    let Some(listen_pid) = listen_pid else {
        return Ok(None);
    };
    let listen_pid = listen_pid
        .into_string()
        .map_err(|_| "systemd LISTEN_PID must be valid UTF-8".to_string())?;
    let pid = listen_pid
        .parse::<u32>()
        .map_err(|_| format!("invalid systemd LISTEN_PID {listen_pid:?}"))?;
    if pid != std::process::id() {
        return Ok(None);
    }
    if let Some(pidfd_id) = listen_pidfdid {
        let pidfd_id = pidfd_id
            .into_string()
            .map_err(|_| "systemd LISTEN_PIDFDID must be valid UTF-8".to_string())?;
        let expected = pidfd_id
            .parse::<u64>()
            .map_err(|_| format!("invalid systemd LISTEN_PIDFDID {pidfd_id:?}"))?;
        if process_pidfd_id()? != expected {
            return Ok(None);
        }
    }

    let listen_fds = listen_fds
        .ok_or_else(|| "systemd activation set LISTEN_PID without LISTEN_FDS".to_string())?
        .into_string()
        .map_err(|_| "systemd LISTEN_FDS must be valid UTF-8".to_string())?;
    let count = listen_fds
        .parse::<usize>()
        .map_err(|_| format!("invalid systemd LISTEN_FDS {listen_fds:?}"))?;
    if count != expected_count {
        return Err(format!(
            "systemd supplied {count} listener descriptor(s), but {expected_count} were configured"
        ));
    }

    let listen_fdnames = listen_fdnames
        .ok_or_else(|| {
            "systemd activation requires LISTEN_FDNAMES with named TLS descriptors".to_string()
        })?
        .into_string()
        .map_err(|_| "systemd LISTEN_FDNAMES must be valid UTF-8".to_string())?;
    let names = if listen_fdnames.is_empty() {
        Vec::new()
    } else {
        listen_fdnames.split(':').map(str::to_string).collect()
    };
    if names.len() != count {
        return Err(format!(
            "systemd supplied {count} listener descriptor(s), but LISTEN_FDNAMES contains {} name(s)",
            names.len()
        ));
    }

    names
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            let offset = RawFd::try_from(index)
                .map_err(|_| "systemd listener descriptor index overflowed".to_string())?;
            let fd = 3_i32
                .checked_add(offset)
                .ok_or_else(|| "systemd listener descriptor number overflowed".to_string())?;
            Ok(SystemdDescriptor { fd, name })
        })
        .collect::<Result<Vec<_>, String>>()
        .map(Some)
}

#[cfg(target_os = "linux")]
fn acquire_systemd(
    expected: &[ExpectedListener],
    descriptors: Vec<SystemdDescriptor>,
) -> Result<Vec<IngressListener>, String> {
    let mut expected_by_name = BTreeMap::new();
    for (index, listener) in expected.iter().enumerate() {
        if expected_by_name
            .insert(listener.descriptor_name, index)
            .is_some()
        {
            return Err(format!(
                "systemd activation requires at most one configured {} listener",
                if listener.address.is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                }
            ));
        }
    }

    let mut acquired = std::iter::repeat_with(|| None)
        .take(expected.len())
        .collect::<Vec<Option<IngressListener>>>();
    for descriptor in descriptors {
        let Some(index) = expected_by_name.get(descriptor.name.as_str()).copied() else {
            return Err(format!(
                "systemd supplied unexpected listener descriptor name {:?}; expected {}",
                descriptor.name,
                expected_by_name
                    .keys()
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        };
        if acquired[index].is_some() {
            return Err(format!(
                "systemd supplied duplicate listener descriptor name {:?}",
                descriptor.name
            ));
        }

        let listener = unsafe { TcpListener::from_raw_fd(descriptor.fd) };
        validate_systemd_listener(&listener, &expected[index]).map_err(|error| {
            format!(
                "invalid systemd listener {} on fd {}: {error}",
                descriptor.name, descriptor.fd
            )
        })?;
        acquired[index] = Some(IngressListener {
            listener,
            origin: ListenerOrigin::Systemd(descriptor.name),
        });
    }

    acquired
        .into_iter()
        .enumerate()
        .map(|(index, listener)| {
            listener.ok_or_else(|| {
                format!(
                    "systemd did not supply required listener descriptor {}",
                    expected[index].descriptor_name
                )
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn validate_systemd_listener(
    listener: &TcpListener,
    expected: &ExpectedListener,
) -> Result<(), String> {
    let fd = listener.as_raw_fd();
    if socket_option(fd, nix::libc::SOL_SOCKET, nix::libc::SO_TYPE)? != nix::libc::SOCK_STREAM {
        return Err("descriptor is not a TCP stream socket".to_string());
    }
    if socket_option(fd, nix::libc::SOL_SOCKET, nix::libc::SO_PROTOCOL)? != nix::libc::IPPROTO_TCP {
        return Err("descriptor does not use the TCP protocol".to_string());
    }
    if socket_option(fd, nix::libc::SOL_SOCKET, nix::libc::SO_ACCEPTCONN)? != 1 {
        return Err("descriptor is not a listening socket".to_string());
    }

    let actual = listener
        .local_addr()
        .map_err(|error| format!("cannot read listener address: {error}"))?;
    if !listener_address_matches(actual, expected.address) {
        return Err(format!(
            "descriptor listens on {actual}, expected {}",
            expected.address
        ));
    }
    if expected.address.is_ipv6()
        && socket_option(fd, nix::libc::IPPROTO_IPV6, nix::libc::IPV6_V6ONLY)? != 1
    {
        return Err("IPv6 descriptor must be configured IPv6-only".to_string());
    }

    listener
        .set_nonblocking(true)
        .map_err(|error| format!("cannot enable nonblocking mode: {error}"))?;
    set_close_on_exec(fd)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn listener_address_matches(mut actual: SocketAddr, expected: SocketAddr) -> bool {
    if expected.port() == 0 {
        actual.set_port(0);
    }
    actual == expected
}

#[cfg(target_os = "linux")]
fn process_pidfd_id() -> Result<u64, String> {
    let raw_fd =
        unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, std::process::id(), 0_u32) };
    if raw_fd == -1 {
        return Err(format!(
            "cannot open a pidfd to validate systemd LISTEN_PIDFDID: {}",
            std::io::Error::last_os_error()
        ));
    }
    let raw_fd = RawFd::try_from(raw_fd)
        .map_err(|_| "pidfd number does not fit the platform RawFd type".to_string())?;
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut metadata = std::mem::MaybeUninit::<nix::libc::stat>::uninit();
    if unsafe { nix::libc::fstat(pidfd.as_raw_fd(), metadata.as_mut_ptr()) } == -1 {
        return Err(format!(
            "cannot inspect the pidfd used to validate systemd LISTEN_PIDFDID: {}",
            std::io::Error::last_os_error()
        ));
    }
    let metadata = unsafe { metadata.assume_init() };
    Ok(metadata.st_ino)
}

#[cfg(target_os = "linux")]
fn socket_option(fd: RawFd, level: i32, option: i32) -> Result<i32, String> {
    let mut value = 0_i32;
    let mut length = std::mem::size_of::<i32>() as nix::libc::socklen_t;
    let result = unsafe {
        nix::libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if length as usize != std::mem::size_of::<i32>() {
        return Err(format!(
            "socket option {option} returned an unexpected size {length}"
        ));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn set_close_on_exec(fd: RawFd) -> Result<(), String> {
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
    if flags == -1 {
        return Err(format!(
            "cannot read descriptor flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC) } == -1 {
        return Err(format!(
            "cannot set close-on-exec: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{ExpectedListener, acquire, listener_address_matches, validate_systemd_listener};
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::unix::net::UnixListener;
    use tempfile::tempdir;

    fn expected(address: SocketAddr) -> ExpectedListener {
        ExpectedListener {
            configured: address.to_string(),
            address,
            descriptor_name: "tls-ipv4",
        }
    }

    #[test]
    fn descriptor_validation_rejects_non_listening_and_non_tcp_sockets() {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let stream = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        stream.bind(&address.into()).unwrap();
        let stream = unsafe { TcpListener::from_raw_fd(stream.into_raw_fd()) };
        assert!(
            validate_systemd_listener(&stream, &expected(address))
                .unwrap_err()
                .contains("not a listening socket")
        );

        let datagram = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        datagram.bind(&address.into()).unwrap();
        let datagram = unsafe { TcpListener::from_raw_fd(datagram.into_raw_fd()) };
        assert!(
            validate_systemd_listener(&datagram, &expected(address))
                .unwrap_err()
                .contains("not a TCP stream socket")
        );

        let directory = tempdir().unwrap();
        let unix = UnixListener::bind(directory.path().join("listener.sock")).unwrap();
        let unix = unsafe { TcpListener::from_raw_fd(unix.into_raw_fd()) };
        assert!(
            validate_systemd_listener(&unix, &expected(address))
                .unwrap_err()
                .contains("does not use the TCP protocol")
        );
    }

    #[test]
    fn descriptor_validation_requires_the_configured_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let actual = listener.local_addr().unwrap();
        let wrong = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, actual.port()));
        let error = validate_systemd_listener(&listener, &expected(wrong)).unwrap_err();
        assert!(error.contains(&format!("listens on {actual}, expected {wrong}")));
    }

    #[test]
    fn ipv6_scope_is_part_of_the_configured_listener_identity() {
        let first_scope = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 1));
        let second_scope = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 2));
        assert!(!listener_address_matches(first_scope, second_scope));

        let dynamic_port = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 1));
        assert!(listener_address_matches(first_scope, dynamic_port));
    }

    #[test]
    fn direct_ipv6_listener_is_v6_only_so_ipv4_can_share_its_port() {
        let Ok(mut ipv6) = acquire(&["[::]:0".to_string()]) else {
            return;
        };
        let ipv6 = ipv6.pop().unwrap().listener;
        let port = ipv6.local_addr().unwrap().port();
        let mut ipv4 = acquire(&[format!("0.0.0.0:{port}")]).unwrap();
        let ipv4 = ipv4.pop().unwrap().listener;

        assert!(ipv6.local_addr().unwrap().is_ipv6());
        assert!(ipv4.local_addr().unwrap().is_ipv4());
    }
}
