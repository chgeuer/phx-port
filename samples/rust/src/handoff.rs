use crate::handoff_protocol::{self, MAX_PACKET_LENGTH, Message};
use crate::{ResponseInfo, serve_tls};
use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrStorage,
    UnixAddr, accept4, bind, connect, getpeername, getsockopt, listen, recv, recvmsg, send, socket,
    sockopt,
};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::IoSliceMut;
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

const REJECT_INVALID_DESCRIPTOR: u16 = 1;
const REJECT_DUPLICATE_ID: u16 = 2;
const REJECT_ADOPTION_FAILED: u16 = 3;

pub(crate) struct HandoffListener {
    listener: OwnedFd,
    path: PathBuf,
    active_ids: Arc<Mutex<HashSet<[u8; 16]>>>,
}

impl HandoffListener {
    pub(crate) fn bind(path: &Path) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "handoff socket has no parent directory".to_string())?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "cannot create handoff directory {}: {error}",
                parent.display()
            )
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "cannot secure handoff directory {}: {error}",
                parent.display()
            )
        })?;
        remove_stale_endpoint(path)?;

        let listener = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|error| format!("cannot create handoff socket: {error}"))?;
        let address = UnixAddr::new(path)
            .map_err(|error| format!("invalid handoff path {}: {error}", path.display()))?;
        bind(listener.as_raw_fd(), &address)
            .map_err(|error| format!("cannot bind handoff socket {}: {error}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot secure handoff socket {}: {error}", path.display()))?;
        listen(
            &listener,
            Backlog::new(128).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("cannot listen on handoff socket: {error}"))?;

        Ok(Self {
            listener,
            path: path.to_path_buf(),
            active_ids: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub(crate) fn run(self, tls: Arc<ServerConfig>) -> Result<(), String> {
        loop {
            let control = match accept4(self.listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC) {
                Ok(descriptor) => unsafe { OwnedFd::from_raw_fd(descriptor) },
                Err(error) => {
                    eprintln!("PHXP accept failed: {error}");
                    continue;
                }
            };
            let tls = Arc::clone(&tls);
            let active_ids = Arc::clone(&self.active_ids);
            thread::spawn(move || {
                if let Err(error) = receive_handoff(control, tls, active_ids) {
                    eprintln!("PHXP handoff failed: {error}");
                }
            });
        }
    }
}

impl Drop for HandoffListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn endpoint_path(project: &str, role: &str) -> Result<PathBuf, String> {
    let runtime = env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| "XDG_RUNTIME_DIR is unavailable; set it or --handoff-socket".to_string())?;
    Ok(endpoint_path_in(Path::new(&runtime), project, role))
}

fn endpoint_path_in(runtime: &Path, project: &str, role: &str) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(project.as_bytes());
    digest.update([0]);
    digest.update(role.as_bytes());
    let hash = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    runtime
        .join("phx-port/handoff")
        .join(format!("{hash}.sock"))
}

fn remove_stale_endpoint(path: &Path) -> Result<(), String> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "refusing to replace non-socket handoff path {}",
            path.display()
        ));
    }
    if endpoint_is_live(path) {
        return Err(format!(
            "another handoff receiver is already listening at {}",
            path.display()
        ));
    }
    fs::remove_file(path)
        .map_err(|error| format!("cannot remove stale endpoint {}: {error}", path.display()))
}

fn endpoint_is_live(path: &Path) -> bool {
    let Ok(address) = UnixAddr::new(path) else {
        return false;
    };
    let Ok(socket) = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) else {
        return false;
    };
    connect(socket.as_raw_fd(), &address).is_ok()
}

fn receive_handoff(
    control: OwnedFd,
    tls: Arc<ServerConfig>,
    active_ids: Arc<Mutex<HashSet<[u8; 16]>>>,
) -> Result<(), String> {
    let credentials = getsockopt(&control, sockopt::PeerCredentials)
        .map_err(|error| format!("cannot inspect PHXP peer credentials: {error}"))?;
    if credentials.uid() != nix::unistd::getuid().as_raw() {
        return Err("PHXP peer belongs to a different user".into());
    }
    let timeout = nix::sys::time::TimeVal::new(2, 0);
    nix::sys::socket::setsockopt(&control, sockopt::ReceiveTimeout, &timeout)
        .map_err(|error| format!("cannot configure PHXP receive timeout: {error}"))?;

    let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
    let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty())
        .map_err(|error| format!("cannot receive PHXP hello: {error}"))?;
    if handoff_protocol::decode(&packet[..length]) != Ok(Message::Hello) {
        return Err("invalid PHXP hello".into());
    }
    send_packet(&control, &Message::Ready)?;

    let (packet_length, descriptors) = receive_descriptor(&control, &mut packet)?;
    let request = handoff_protocol::decode(&packet[..packet_length])
        .map_err(|error| format!("invalid PHXP handoff packet: {error}"))?;
    let Message::Handoff(handoff) = request else {
        return Err("expected PHXP handoff request".into());
    };

    if descriptors.len() != 1 {
        send_rejected(&control, handoff.connection_id, REJECT_INVALID_DESCRIPTOR)?;
        return Err(format!(
            "handoff contained {} descriptors instead of one",
            descriptors.len()
        ));
    }
    let client = descriptors.into_iter().next().expect("length checked");
    let is_connected_stream = getsockopt(&client, sockopt::SockType)
        .is_ok_and(|socket_type| socket_type == SockType::Stream)
        && getpeername::<SockaddrStorage>(client.as_raw_fd()).is_ok();
    if !is_connected_stream {
        send_rejected(&control, handoff.connection_id, REJECT_INVALID_DESCRIPTOR)?;
        return Err("handed-off descriptor is not a connected stream socket".into());
    }

    {
        let mut ids = active_ids
            .lock()
            .map_err(|_| "active connection ID lock is poisoned".to_string())?;
        if !ids.insert(handoff.connection_id) {
            send_rejected(&control, handoff.connection_id, REJECT_DUPLICATE_ID)?;
            return Err("duplicate handoff connection identifier".into());
        }
    }

    let stream = TcpStream::from(client);
    let peer = stream.peer_addr().ok();
    let local = stream.local_addr().ok();
    let connection_id = handoff.connection_id;
    let info = ResponseInfo::handed_off(
        peer,
        local,
        handoff.requested_sni.clone(),
        handoff.peeked_length,
    );
    let ids_for_connection = Arc::clone(&active_ids);
    let worker = thread::Builder::new()
        .name("phxp-tls-connection".into())
        .spawn(move || {
            if let Err(error) = serve_tls(stream, tls, info) {
                eprintln!("handed-off TLS connection failed: {error}");
            }
            if let Ok(mut ids) = ids_for_connection.lock() {
                ids.remove(&connection_id);
            }
        });

    match worker {
        Ok(_) => {
            send_packet(
                &control,
                &Message::Adopted {
                    connection_id: handoff.connection_id,
                },
            )?;
            println!(
                "adopted PHXP connection for {} from {} (peeked {} bytes, accepted_at_ns={})",
                handoff.requested_sni,
                peer.map(|address| address.to_string())
                    .unwrap_or_else(|| "unknown peer".into()),
                handoff.peeked_length,
                handoff.accepted_at_ns
            );
            Ok(())
        }
        Err(error) => {
            if let Ok(mut ids) = active_ids.lock() {
                ids.remove(&handoff.connection_id);
            }
            send_rejected(&control, handoff.connection_id, REJECT_ADOPTION_FAILED)?;
            Err(format!("cannot start handed-off connection: {error}"))
        }
    }
}

fn receive_descriptor(
    control: &OwnedFd,
    packet: &mut [u8],
) -> Result<(usize, Vec<OwnedFd>), String> {
    let mut ancillary = nix::cmsg_space!([i32; 2]);
    let mut iov = [IoSliceMut::new(packet)];
    let message = recvmsg::<UnixAddr>(
        control.as_raw_fd(),
        &mut iov,
        Some(&mut ancillary),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(|error| format!("cannot receive PHXP descriptor: {error}"))?;
    let packet_length = message.bytes;
    let flags = message.flags;
    let descriptors = message
        .cmsgs()
        .map_err(|error| format!("invalid PHXP ancillary message: {error}"))?
        .flat_map(|control| match control {
            ControlMessageOwned::ScmRights(descriptors) => descriptors,
            _ => Vec::new(),
        })
        .map(|descriptor| unsafe { OwnedFd::from_raw_fd(descriptor) })
        .collect::<Vec<_>>();
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err("truncated PHXP packet or ancillary data".into());
    }
    Ok((packet_length, descriptors))
}

fn send_rejected(
    control: &OwnedFd,
    connection_id: [u8; 16],
    reason_code: u16,
) -> Result<(), String> {
    send_packet(
        control,
        &Message::Rejected {
            connection_id,
            reason_code,
        },
    )
}

fn send_packet(control: &OwnedFd, message: &Message) -> Result<(), String> {
    let packet = handoff_protocol::encode(message)?;
    send(control.as_raw_fd(), &packet, MsgFlags::empty())
        .map_err(|error| format!("cannot send PHXP response: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::endpoint_path_in;
    use sha2::{Digest, Sha256};
    use std::path::Path;

    #[test]
    fn endpoint_name_matches_the_daemon_algorithm() {
        let mut digest = Sha256::new();
        digest.update(b"/srv/contoso\0https");
        let expected_hash = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let path = endpoint_path_in(Path::new("/run/user/1000"), "/srv/contoso", "https");

        assert_eq!(
            path.to_string_lossy(),
            format!("/run/user/1000/phx-port/handoff/{expected_hash}.sock")
        );
    }
}
