use sha2::{Digest, Sha256};
use std::env;
use std::net::TcpStream;
use std::path::{Path, PathBuf};

pub enum Outcome {
    Unavailable(TcpStream),
    Transferred,
    Delivered(String),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn try_transfer(
    client: TcpStream,
    project: &str,
    role: &str,
    hostname: &str,
    peeked_length: usize,
    connection_id: [u8; 16],
    accepted_at_ns: u64,
) -> Outcome {
    let path = match endpoint_path(project, role) {
        Ok(path) => path,
        Err(_) => return Outcome::Unavailable(client),
    };
    platform::try_transfer_to_endpoint(
        client,
        &path,
        hostname,
        peeked_length,
        connection_id,
        accepted_at_ns,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn try_transfer(
    client: TcpStream,
    _project: &str,
    _role: &str,
    _hostname: &str,
    _peeked_length: usize,
    _connection_id: [u8; 16],
    _accepted_at_ns: u64,
) -> Outcome {
    Outcome::Unavailable(client)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn endpoint_path(project: &str, role: &str) -> Result<PathBuf, String> {
    let hash = endpoint_hash(project, role);
    let path = match nonempty_env("PHX_PORT_RUNTIME_DIR") {
        Some(runtime) => endpoint_path_in(Path::new(&runtime), false, &hash),
        None => platform_default_endpoint(&hash)?,
    };
    nix::sys::socket::UnixAddr::new(&path).map_err(|error| {
        format!(
            "handoff endpoint path {} is too long: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn nonempty_env(name: &str) -> Option<std::ffi::OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn endpoint_hash(project: &str, role: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(project.as_bytes());
    digest.update([0]);
    digest.update(role.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn endpoint_path_in(runtime: &Path, include_product_directory: bool, hash: &str) -> PathBuf {
    let root = if include_product_directory {
        runtime.join("phx-port")
    } else {
        runtime.to_path_buf()
    };
    root.join("handoff").join(format!("{hash}.sock"))
}

#[cfg(target_os = "linux")]
fn platform_default_endpoint(hash: &str) -> Result<PathBuf, String> {
    let runtime = nonempty_env("XDG_RUNTIME_DIR")
        .ok_or_else(|| "XDG_RUNTIME_DIR is unavailable".to_string())?;
    Ok(endpoint_path_in(Path::new(&runtime), true, hash))
}

#[cfg(target_os = "macos")]
fn platform_default_endpoint(hash: &str) -> Result<PathBuf, String> {
    let runtime = PathBuf::from(format!("/tmp/phx-port-{}", nix::unistd::geteuid().as_raw()));
    Ok(endpoint_path_in(&runtime, false, hash))
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Outcome, TcpStream};
    use crate::handoff_protocol::{self, Handoff, MAX_PACKET_LENGTH, Message};
    use nix::sys::socket::{
        AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr, connect, getsockopt,
        recv, send, sendmsg, socket, sockopt,
    };
    use std::io::IoSlice;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::Path;
    use std::time::Duration;

    const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);

    pub(super) fn try_transfer_to_endpoint(
        client: TcpStream,
        path: &Path,
        hostname: &str,
        peeked_length: usize,
        connection_id: [u8; 16],
        accepted_at_ns: u64,
    ) -> Outcome {
        let socket = match connect_endpoint(path) {
            Ok(socket) => socket,
            Err(_) => return Outcome::Unavailable(client),
        };
        if capability_handshake(&socket).is_err() {
            return Outcome::Unavailable(client);
        }

        let Ok(peeked_length) = u32::try_from(peeked_length) else {
            return Outcome::Unavailable(client);
        };
        let Ok(packet) = handoff_protocol::encode(&Message::Handoff(Handoff {
            connection_id,
            peeked_length,
            accepted_at_ns,
            requested_sni: hostname.to_string(),
        })) else {
            return Outcome::Unavailable(client);
        };
        let descriptor = [client.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&descriptor)];
        let sent = match sendmsg::<UnixAddr>(
            socket.as_raw_fd(),
            &[IoSlice::new(&packet)],
            &control,
            MsgFlags::empty(),
            None,
        ) {
            Ok(0) | Err(_) => return Outcome::Unavailable(client),
            Ok(sent) => sent,
        };

        drop(client);
        if sent != packet.len() {
            return Outcome::Delivered(
                "client descriptor was transferred with a partial PHXP packet".to_string(),
            );
        }

        let mut response = [0_u8; MAX_PACKET_LENGTH + 1];
        let received = match recv(socket.as_raw_fd(), &mut response, MsgFlags::empty()) {
            Ok(received) => received,
            Err(error) => {
                return Outcome::Delivered(format!(
                    "client descriptor was transferred but acknowledgement failed: {error}"
                ));
            }
        };
        validate_response(&response[..received], connection_id)
    }

    fn connect_endpoint(path: &Path) -> Result<OwnedFd, String> {
        let address = UnixAddr::new(path)
            .map_err(|error| format!("invalid handoff endpoint {}: {error}", path.display()))?;
        let socket = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|error| format!("cannot create handoff socket: {error}"))?;
        connect(socket.as_raw_fd(), &address)
            .map_err(|error| format!("cannot connect to handoff endpoint: {error}"))?;
        let timeout = nix::sys::time::TimeVal::new(
            CONTROL_TIMEOUT.as_secs() as i64,
            i64::from(CONTROL_TIMEOUT.subsec_micros()),
        );
        nix::sys::socket::setsockopt(&socket, sockopt::ReceiveTimeout, &timeout)
            .map_err(|error| format!("cannot configure handoff receive timeout: {error}"))?;
        nix::sys::socket::setsockopt(&socket, sockopt::SendTimeout, &timeout)
            .map_err(|error| format!("cannot configure handoff send timeout: {error}"))?;

        let credentials = getsockopt(&socket, sockopt::PeerCredentials)
            .map_err(|error| format!("cannot inspect handoff peer credentials: {error}"))?;
        if credentials.uid() != nix::unistd::geteuid().as_raw() {
            return Err("handoff endpoint belongs to a different user".to_string());
        }
        Ok(socket)
    }

    fn capability_handshake(socket: &OwnedFd) -> Result<(), String> {
        let hello = handoff_protocol::encode(&Message::Hello)?;
        let sent = send(socket.as_raw_fd(), &hello, MsgFlags::empty())
            .map_err(|error| format!("cannot send handoff capability request: {error}"))?;
        if sent != hello.len() {
            return Err("handoff capability request was only partially sent".to_string());
        }
        let mut response = [0_u8; MAX_PACKET_LENGTH + 1];
        let received = recv(socket.as_raw_fd(), &mut response, MsgFlags::empty())
            .map_err(|error| format!("cannot read handoff capability response: {error}"))?;
        if handoff_protocol::decode(&response[..received]) == Ok(Message::Ready) {
            Ok(())
        } else {
            Err("handoff endpoint does not support protocol version 1".to_string())
        }
    }

    fn validate_response(packet: &[u8], connection_id: [u8; 16]) -> Outcome {
        match handoff_protocol::decode(packet) {
            Ok(Message::Adopted {
                connection_id: response_id,
            }) if response_id == connection_id => Outcome::Transferred,
            Ok(Message::Rejected {
                connection_id: response_id,
                reason_code,
            }) if response_id == connection_id => Outcome::Delivered(format!(
                "backend rejected transferred descriptor with reason {reason_code}"
            )),
            Ok(_) | Err(_) => Outcome::Delivered(
                "backend returned an invalid acknowledgement after descriptor transfer".to_string(),
            ),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Outcome, try_transfer_to_endpoint};
        use crate::handoff::{endpoint_hash, endpoint_path_in};
        use crate::handoff_protocol::{MAX_PACKET_LENGTH, Message, decode, encode};
        use nix::sys::socket::{
            AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
            accept, bind, listen, recv, recvmsg, send, socket,
        };
        use std::io::{IoSliceMut, Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::path::Path;
        use std::thread;
        use tempfile::tempdir;

        #[test]
        fn endpoint_name_hashes_canonical_project_and_role() {
            let hash = endpoint_hash("/srv/contoso", "https");
            let path = endpoint_path_in(Path::new("/run/user/1000"), true, &hash);
            let expected = format!("/run/user/1000/phx-port/handoff/{hash}.sock");
            assert_eq!(path.to_string_lossy(), expected);
        }

        #[test]
        fn transfers_one_untouched_connected_stream_descriptor() {
            let directory = tempdir().unwrap();
            let endpoint = directory.path().join("handoff.sock");
            let listener = socket(
                AddressFamily::Unix,
                SockType::SeqPacket,
                SockFlag::SOCK_CLOEXEC,
                None,
            )
            .unwrap();
            bind(
                listener.as_raw_fd(),
                &UnixAddr::new(endpoint.as_path()).unwrap(),
            )
            .unwrap();
            listen(&listener, Backlog::new(1).unwrap()).unwrap();

            let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let destination = tcp_listener.local_addr().unwrap();
            let mut client = TcpStream::connect(destination).unwrap();
            let source = client.local_addr().unwrap();
            let (accepted, _) = tcp_listener.accept().unwrap();
            let connection_id = [0x5A; 16];
            let backend = thread::spawn(move || {
                let accepted = accept(listener.as_raw_fd()).unwrap();
                let accepted = unsafe { OwnedFd::from_raw_fd(accepted) };
                let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];

                let length = recv(accepted.as_raw_fd(), &mut packet, MsgFlags::empty()).unwrap();
                assert_eq!(decode(&packet[..length]).unwrap(), Message::Hello);
                send(
                    accepted.as_raw_fd(),
                    &encode(&Message::Ready).unwrap(),
                    MsgFlags::empty(),
                )
                .unwrap();

                let (packet_length, descriptor) = {
                    let mut ancillary = nix::cmsg_space!([i32; 1]);
                    let mut iov = [IoSliceMut::new(&mut packet)];
                    let message = recvmsg::<UnixAddr>(
                        accepted.as_raw_fd(),
                        &mut iov,
                        Some(&mut ancillary),
                        MsgFlags::empty(),
                    )
                    .unwrap();
                    let descriptors = message
                        .cmsgs()
                        .unwrap()
                        .flat_map(|control| match control {
                            ControlMessageOwned::ScmRights(descriptors) => descriptors,
                            _ => Vec::new(),
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(descriptors.len(), 1);
                    (message.bytes, descriptors[0])
                };
                let request = decode(&packet[..packet_length]).unwrap();
                assert!(matches!(
                    request,
                    Message::Handoff(ref handoff)
                        if handoff.connection_id == connection_id
                            && handoff.requested_sni == "www.contoso.com"
                ));
                let mut handed_off = unsafe { TcpStream::from_raw_fd(descriptor) };
                assert_eq!(handed_off.peer_addr().unwrap(), source);
                assert_eq!(handed_off.local_addr().unwrap(), destination);
                let mut payload = [0_u8; 12];
                handed_off.read_exact(&mut payload).unwrap();
                assert_eq!(&payload, b"client hello");

                send(
                    accepted.as_raw_fd(),
                    &encode(&Message::Adopted { connection_id }).unwrap(),
                    MsgFlags::empty(),
                )
                .unwrap();
            });

            client.write_all(b"client hello").unwrap();

            assert!(matches!(
                try_transfer_to_endpoint(
                    accepted,
                    &endpoint,
                    "www.contoso.com",
                    12,
                    connection_id,
                    42,
                ),
                Outcome::Transferred
            ));
            backend.join().unwrap();
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Outcome, TcpStream};
    use crate::handoff_protocol::{self, Handoff, Message};
    use crate::handoff_stream::read_frame;
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::sys::socket::{
        AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr, connect, sendmsg,
        socket,
    };
    use std::io::{IoSlice, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);

    pub(super) fn try_transfer_to_endpoint(
        client: TcpStream,
        path: &Path,
        hostname: &str,
        peeked_length: usize,
        connection_id: [u8; 16],
        accepted_at_ns: u64,
    ) -> Outcome {
        let mut control = match connect_endpoint(path) {
            Ok(control) => control,
            Err(_) => return Outcome::Unavailable(client),
        };
        if capability_handshake(&mut control).is_err() {
            return Outcome::Unavailable(client);
        }

        let Ok(peeked_length) = u32::try_from(peeked_length) else {
            return Outcome::Unavailable(client);
        };
        let Ok(packet) = handoff_protocol::encode(&Message::Handoff(Handoff {
            connection_id,
            peeked_length,
            accepted_at_ns,
            requested_sni: hostname.to_string(),
        })) else {
            return Outcome::Unavailable(client);
        };

        let descriptor = [client.as_raw_fd()];
        let ancillary = [ControlMessage::ScmRights(&descriptor)];
        let sent = match classify_initial_send(
            sendmsg::<UnixAddr>(
                control.as_raw_fd(),
                &[IoSlice::new(&packet)],
                &ancillary,
                MsgFlags::empty(),
                None,
            )
            .map_err(|error| format!("cannot send client descriptor: {error}")),
        ) {
            Ok(sent) => sent,
            Err(_) => return Outcome::Unavailable(client),
        };

        if sent < packet.len()
            && let Err(error) = control.write_all(&packet[sent..])
        {
            return Outcome::Delivered(format!(
                "client descriptor was transferred but the remaining PHXP frame failed: {error}"
            ));
        }

        let response = match read_frame(&mut control) {
            Ok(response) => response,
            Err(error) => {
                return Outcome::Delivered(format!(
                    "client descriptor was transferred but acknowledgement failed: {error}"
                ));
            }
        };
        drop(client);
        validate_response(&response, connection_id)
    }

    fn connect_endpoint(path: &Path) -> Result<UnixStream, String> {
        let address = UnixAddr::new(path)
            .map_err(|error| format!("invalid handoff endpoint {}: {error}", path.display()))?;
        let socket = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(|error| format!("cannot create handoff socket: {error}"))?;
        set_cloexec(&socket)?;
        set_no_sigpipe(&socket)?;
        connect(socket.as_raw_fd(), &address)
            .map_err(|error| format!("cannot connect to handoff endpoint: {error}"))?;

        let stream = UnixStream::from(socket);
        stream
            .set_read_timeout(Some(CONTROL_TIMEOUT))
            .map_err(|error| format!("cannot configure handoff receive timeout: {error}"))?;
        stream
            .set_write_timeout(Some(CONTROL_TIMEOUT))
            .map_err(|error| format!("cannot configure handoff send timeout: {error}"))?;
        let (peer_euid, _) = nix::unistd::getpeereid(&stream)
            .map_err(|error| format!("cannot inspect handoff peer credentials: {error}"))?;
        if peer_euid != nix::unistd::geteuid() {
            return Err("handoff endpoint belongs to a different user".to_string());
        }
        Ok(stream)
    }

    fn capability_handshake(control: &mut UnixStream) -> Result<(), String> {
        let hello = handoff_protocol::encode(&Message::Hello)?;
        control
            .write_all(&hello)
            .map_err(|error| format!("cannot send handoff capability request: {error}"))?;
        let response = read_frame(control)
            .map_err(|error| format!("cannot read handoff capability response: {error}"))?;
        if handoff_protocol::decode(&response) == Ok(Message::Ready) {
            Ok(())
        } else {
            Err("handoff endpoint does not support protocol version 1".to_string())
        }
    }

    fn classify_initial_send(result: Result<usize, String>) -> Result<usize, String> {
        match result {
            Ok(0) => Err("descriptor-bearing sendmsg wrote no bytes".to_string()),
            other => other,
        }
    }

    fn validate_response(packet: &[u8], connection_id: [u8; 16]) -> Outcome {
        match handoff_protocol::decode(packet) {
            Ok(Message::Adopted {
                connection_id: response_id,
            }) if response_id == connection_id => Outcome::Transferred,
            Ok(Message::Rejected {
                connection_id: response_id,
                reason_code,
            }) if response_id == connection_id => Outcome::Delivered(format!(
                "backend rejected transferred descriptor with reason {reason_code}"
            )),
            Ok(_) | Err(_) => Outcome::Delivered(
                "backend returned an invalid acknowledgement after descriptor transfer".to_string(),
            ),
        }
    }

    fn set_cloexec(fd: &impl AsFd) -> Result<(), String> {
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|error| format!("cannot set close-on-exec: {error}"))?;
        Ok(())
    }

    fn set_no_sigpipe(fd: &impl AsFd) -> Result<(), String> {
        let enabled: nix::libc::c_int = 1;
        let result = unsafe {
            nix::libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                nix::libc::SOL_SOCKET,
                nix::libc::SO_NOSIGPIPE,
                (&raw const enabled).cast(),
                std::mem::size_of_val(&enabled) as nix::libc::socklen_t,
            )
        };
        if result == -1 {
            return Err(format!(
                "cannot disable SIGPIPE on handoff socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{
            Outcome, classify_initial_send, set_cloexec, set_no_sigpipe, try_transfer_to_endpoint,
        };
        use crate::handoff::{endpoint_hash, endpoint_path_in};
        use crate::handoff_protocol::{MAX_PACKET_LENGTH, Message, decode, encode};
        use crate::handoff_stream::{complete_frame, read_frame};
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        use nix::sys::socket::{
            AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
            accept, bind, listen, recvmsg, socket,
        };
        use std::io::{IoSliceMut, Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::net::UnixStream;
        use std::path::Path;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;
        use tempfile::tempdir_in;

        #[test]
        fn endpoint_name_uses_short_macos_runtime_root() {
            let hash = endpoint_hash("/srv/contoso", "https");
            let path = endpoint_path_in(Path::new("/tmp/phx-port-501"), false, &hash);
            assert_eq!(
                path.to_string_lossy(),
                format!("/tmp/phx-port-501/handoff/{hash}.sock")
            );
        }

        #[test]
        fn positive_sendmsg_result_crosses_delivery_boundary() {
            assert!(classify_initial_send(Err("failed".to_string())).is_err());
            assert!(classify_initial_send(Ok(0)).is_err());
            assert_eq!(classify_initial_send(Ok(1)).unwrap(), 1);
        }

        #[test]
        fn transfers_one_untouched_connected_stream_descriptor() {
            let directory = tempdir_in("/tmp").unwrap();
            let endpoint = directory.path().join("handoff.sock");
            let listener = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            set_cloexec(&listener).unwrap();
            set_no_sigpipe(&listener).unwrap();
            bind(
                listener.as_raw_fd(),
                &UnixAddr::new(endpoint.as_path()).unwrap(),
            )
            .unwrap();
            listen(&listener, Backlog::new(1).unwrap()).unwrap();

            let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let destination = tcp_listener.local_addr().unwrap();
            let mut client = TcpStream::connect(destination).unwrap();
            let source = client.local_addr().unwrap();
            let (accepted, _) = tcp_listener.accept().unwrap();
            let mut peeked = [0_u8; 12];
            client.write_all(b"client hello").unwrap();
            assert_eq!(accepted.peek(&mut peeked).unwrap(), peeked.len());
            assert_eq!(&peeked, b"client hello");

            let connection_id = [0x5A; 16];
            let backend = thread::spawn(move || {
                let control = accept(listener.as_raw_fd()).unwrap();
                let control = unsafe { OwnedFd::from_raw_fd(control) };
                set_cloexec(&control).unwrap();
                set_no_sigpipe(&control).unwrap();
                assert!(has_cloexec(&control));
                let (peer_euid, _) = nix::unistd::getpeereid(&control).unwrap();
                assert_eq!(peer_euid, nix::unistd::geteuid());
                let mut control = UnixStream::from(control);

                let hello = read_frame(&mut control).unwrap();
                assert_eq!(decode(&hello).unwrap(), Message::Hello);
                control
                    .write_all(&encode(&Message::Ready).unwrap())
                    .unwrap();

                let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
                let (packet_length, descriptors, flags) = {
                    let mut ancillary = nix::cmsg_space!([i32; 2]);
                    let mut iov = [IoSliceMut::new(&mut packet)];
                    let message = recvmsg::<UnixAddr>(
                        control.as_raw_fd(),
                        &mut iov,
                        Some(&mut ancillary),
                        MsgFlags::empty(),
                    )
                    .unwrap();
                    let descriptors = message
                        .cmsgs()
                        .unwrap()
                        .flat_map(|control| match control {
                            ControlMessageOwned::ScmRights(descriptors) => descriptors,
                            _ => Vec::new(),
                        })
                        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
                        .collect::<Vec<_>>();
                    (message.bytes, descriptors, message.flags)
                };
                assert!(!flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC));
                assert_eq!(descriptors.len(), 1);
                let descriptor = descriptors.into_iter().next().unwrap();
                set_cloexec(&descriptor).unwrap();
                assert!(has_cloexec(&descriptor));

                let request =
                    complete_frame(&mut control, packet[..packet_length].to_vec()).unwrap();
                assert!(matches!(
                    decode(&request).unwrap(),
                    Message::Handoff(ref handoff)
                        if handoff.connection_id == connection_id
                            && handoff.requested_sni == "www.contoso.com"
                ));

                let mut handed_off = TcpStream::from(descriptor);
                assert_eq!(handed_off.peer_addr().unwrap(), source);
                assert_eq!(handed_off.local_addr().unwrap(), destination);
                let mut payload = [0_u8; 12];
                handed_off.read_exact(&mut payload).unwrap();
                assert_eq!(&payload, b"client hello");
                handed_off.write_all(b"server reply").unwrap();

                for byte in encode(&Message::Adopted { connection_id }).unwrap() {
                    control.write_all(&[byte]).unwrap();
                }
            });

            assert!(matches!(
                try_transfer_to_endpoint(
                    accepted,
                    &endpoint,
                    "www.contoso.com",
                    12,
                    connection_id,
                    42,
                ),
                Outcome::Transferred
            ));
            let mut response = [0_u8; 12];
            client.read_exact(&mut response).unwrap();
            assert_eq!(&response, b"server reply");
            backend.join().unwrap();
        }

        #[test]
        fn retains_inert_sender_descriptor_until_response() {
            let directory = tempdir_in("/tmp").unwrap();
            let endpoint = directory.path().join("handoff.sock");
            let listener = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            set_cloexec(&listener).unwrap();
            set_no_sigpipe(&listener).unwrap();
            bind(
                listener.as_raw_fd(),
                &UnixAddr::new(endpoint.as_path()).unwrap(),
            )
            .unwrap();
            listen(&listener, Backlog::new(1).unwrap()).unwrap();

            let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(tcp_listener.local_addr().unwrap()).unwrap();
            let (accepted, _) = tcp_listener.accept().unwrap();
            let connection_id = [0x6B; 16];
            let (dropped_tx, dropped_rx) = mpsc::channel();
            let (respond_tx, respond_rx) = mpsc::channel();

            let backend = thread::spawn(move || {
                let control = accept(listener.as_raw_fd()).unwrap();
                let control = unsafe { OwnedFd::from_raw_fd(control) };
                let mut control = UnixStream::from(control);

                assert_eq!(
                    decode(&read_frame(&mut control).unwrap()).unwrap(),
                    Message::Hello
                );
                control
                    .write_all(&encode(&Message::Ready).unwrap())
                    .unwrap();

                let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
                let (packet_length, descriptors) = {
                    let mut ancillary = nix::cmsg_space!([i32; 2]);
                    let mut iov = [IoSliceMut::new(&mut packet)];
                    let message = recvmsg::<UnixAddr>(
                        control.as_raw_fd(),
                        &mut iov,
                        Some(&mut ancillary),
                        MsgFlags::empty(),
                    )
                    .unwrap();
                    let descriptors = message
                        .cmsgs()
                        .unwrap()
                        .flat_map(|control| match control {
                            ControlMessageOwned::ScmRights(descriptors) => descriptors,
                            _ => Vec::new(),
                        })
                        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
                        .collect::<Vec<_>>();
                    (message.bytes, descriptors)
                };
                assert_eq!(descriptors.len(), 1);
                let request =
                    complete_frame(&mut control, packet[..packet_length].to_vec()).unwrap();
                assert!(matches!(
                    decode(&request).unwrap(),
                    Message::Handoff(ref handoff) if handoff.connection_id == connection_id
                ));

                drop(descriptors);
                dropped_tx.send(()).unwrap();
                respond_rx.recv().unwrap();
                control
                    .write_all(&encode(&Message::Adopted { connection_id }).unwrap())
                    .unwrap();
            });

            let endpoint_for_sender = endpoint.clone();
            let sender = thread::spawn(move || {
                try_transfer_to_endpoint(
                    accepted,
                    &endpoint_for_sender,
                    "www.contoso.com",
                    0,
                    connection_id,
                    42,
                )
            });

            dropped_rx.recv().unwrap();
            client
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut byte = [0_u8; 1];
            let error = client.read(&mut byte).unwrap_err();
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ));

            respond_tx.send(()).unwrap();
            assert!(matches!(sender.join().unwrap(), Outcome::Transferred));
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_eq!(client.read(&mut byte).unwrap(), 0);
            backend.join().unwrap();
        }

        fn has_cloexec(fd: &impl AsFd) -> bool {
            let flags = fcntl(fd, FcntlArg::F_GETFD).unwrap();
            FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC)
        }
    }
}
