#[cfg(target_os = "linux")]
mod linux {
    use crate::handoff_protocol::{self, Handoff, MAX_PACKET_LENGTH, Message};
    use nix::sys::socket::{
        AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr, connect, getsockopt,
        send, sendmsg, socket, sockopt,
    };
    use sha2::{Digest, Sha256};
    use std::env;
    use std::io::IoSlice;
    use std::net::TcpStream;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const CONTROL_TIMEOUT: Duration = Duration::from_millis(200);

    pub enum Outcome {
        Unavailable(TcpStream),
        Transferred,
        Delivered(String),
    }

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
        try_transfer_to_endpoint(
            client,
            &path,
            hostname,
            peeked_length,
            connection_id,
            accepted_at_ns,
        )
    }

    fn try_transfer_to_endpoint(
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
        if sendmsg::<UnixAddr>(
            socket.as_raw_fd(),
            &[IoSlice::new(&packet)],
            &control,
            MsgFlags::empty(),
            None,
        )
        .is_err()
        {
            return Outcome::Unavailable(client);
        }

        drop(client);
        let mut response = [0_u8; MAX_PACKET_LENGTH + 1];
        let received =
            match nix::sys::socket::recv(socket.as_raw_fd(), &mut response, MsgFlags::empty()) {
                Ok(received) => received,
                Err(error) => {
                    return Outcome::Delivered(format!(
                        "client descriptor was transferred but acknowledgement failed: {error}"
                    ));
                }
            };
        match handoff_protocol::decode(&response[..received]) {
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

    pub fn endpoint_path(project: &str, role: &str) -> Result<PathBuf, String> {
        let runtime = env::var_os("XDG_RUNTIME_DIR")
            .ok_or_else(|| "XDG_RUNTIME_DIR is unavailable".to_string())?;
        let mut digest = Sha256::new();
        digest.update(project.as_bytes());
        digest.update([0]);
        digest.update(role.as_bytes());
        let hash = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(endpoint_path_in(Path::new(&runtime), &hash))
    }

    fn endpoint_path_in(runtime: &Path, hash: &str) -> PathBuf {
        runtime
            .join("phx-port/handoff")
            .join(format!("{hash}.sock"))
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
            .map_err(|error| format!("cannot configure handoff timeout: {error}"))?;

        let credentials = getsockopt(&socket, sockopt::PeerCredentials)
            .map_err(|error| format!("cannot inspect handoff peer credentials: {error}"))?;
        if credentials.uid() != nix::unistd::getuid().as_raw() {
            return Err("handoff endpoint belongs to a different user".to_string());
        }
        Ok(socket)
    }

    fn capability_handshake(socket: &OwnedFd) -> Result<(), String> {
        let hello = handoff_protocol::encode(&Message::Hello)?;
        send(socket.as_raw_fd(), &hello, MsgFlags::empty())
            .map_err(|error| format!("cannot send handoff capability request: {error}"))?;
        let mut response = [0_u8; MAX_PACKET_LENGTH + 1];
        let received = nix::sys::socket::recv(socket.as_raw_fd(), &mut response, MsgFlags::empty())
            .map_err(|error| format!("cannot read handoff capability response: {error}"))?;
        if handoff_protocol::decode(&response[..received]) == Ok(Message::Ready) {
            Ok(())
        } else {
            Err("handoff endpoint does not support protocol version 1".to_string())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Outcome, endpoint_path_in, try_transfer_to_endpoint};
        use crate::handoff_protocol::{MAX_PACKET_LENGTH, Message, decode, encode};
        use nix::sys::socket::{
            AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
            accept, bind, listen, recv, recvmsg, send, socket,
        };
        use sha2::{Digest, Sha256};
        use std::io::{IoSliceMut, Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::path::Path;
        use std::thread;
        use tempfile::tempdir;

        #[test]
        fn endpoint_name_hashes_canonical_project_and_role() {
            let mut digest = Sha256::new();
            digest.update(b"/srv/contoso\0https");
            let hash = digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = endpoint_path_in(Path::new("/run/user/1000"), &hash);
            let expected = format!("/run/user/1000/phx-port/handoff/{hash}.sock",);
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
                    let descriptor = descriptors[0];
                    (message.bytes, descriptor)
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

#[cfg(target_os = "linux")]
pub use linux::{Outcome, try_transfer};

#[cfg(not(target_os = "linux"))]
pub enum Outcome {
    Unavailable(std::net::TcpStream),
    Transferred,
    Delivered(String),
}

#[cfg(not(target_os = "linux"))]
pub fn try_transfer(
    client: std::net::TcpStream,
    _project: &str,
    _role: &str,
    _hostname: &str,
    _peeked_length: usize,
    _connection_id: [u8; 16],
    _accepted_at_ns: u64,
) -> Outcome {
    Outcome::Unavailable(client)
}
