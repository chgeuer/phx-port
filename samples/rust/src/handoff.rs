use crate::handoff_protocol::{self, MAX_PACKET_LENGTH, Message};
#[cfg(target_os = "macos")]
use crate::handoff_stream::{complete_frame, read_frame};
#[cfg(target_os = "macos")]
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
#[cfg(target_os = "macos")]
use nix::sys::socket::accept;
use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrLike,
    SockaddrStorage, UnixAddr, bind, connect, getpeername, getsockopt, listen, recvmsg, socket,
    sockopt,
};
#[cfg(target_os = "linux")]
use nix::sys::socket::{accept4, recv, send};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::IoSliceMut;
#[cfg(target_os = "macos")]
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
#[cfg(target_os = "macos")]
use std::os::fd::AsFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::{Sender, error::TrySendError};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const REJECT_INVALID_DESCRIPTOR: u16 = 1;
const REJECT_DUPLICATE_ID: u16 = 2;
const REJECT_ADOPTION_FAILED: u16 = 3;

#[cfg(target_os = "linux")]
type Control = OwnedFd;
#[cfg(target_os = "macos")]
type Control = UnixStream;

pub(crate) struct AdoptedConn {
    pub(crate) stream: TcpStream,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) sni: String,
    pub(crate) peeked: u32,
    pub(crate) connection_id: [u8; 16],
    pub(crate) active_ids: Arc<Mutex<HashSet<[u8; 16]>>>,
}

pub(crate) struct ActiveIdGuard {
    id: [u8; 16],
    active_ids: Arc<Mutex<HashSet<[u8; 16]>>>,
}

impl ActiveIdGuard {
    pub(crate) fn new(id: [u8; 16], active_ids: Arc<Mutex<HashSet<[u8; 16]>>>) -> Self {
        Self { id, active_ids }
    }
}

impl Drop for ActiveIdGuard {
    fn drop(&mut self) {
        if let Ok(mut ids) = self.active_ids.lock() {
            ids.remove(&self.id);
        }
    }
}

pub(crate) struct HandoffListener {
    listener: OwnedFd,
    path: PathBuf,
    endpoint_identity: EndpointIdentity,
    active_ids: Arc<Mutex<HashSet<[u8; 16]>>>,
}

#[derive(Clone, Copy)]
struct EndpointIdentity {
    device: u64,
    inode: u64,
}

impl HandoffListener {
    pub(crate) fn bind(path: &Path, validate_runtime_root: bool) -> Result<Self, String> {
        ensure_endpoint_directory(path, validate_runtime_root)?;
        remove_stale_endpoint(path)?;

        let listener = create_control_socket()?;
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

        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!("cannot inspect handoff socket {}: {error}", path.display())
        })?;
        let endpoint_identity = EndpointIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };

        Ok(Self {
            listener,
            path: path.to_path_buf(),
            endpoint_identity,
            active_ids: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub(crate) fn spawn(self, adopted_tx: Sender<AdoptedConn>) {
        thread::Builder::new()
            .name("phxp-listener".into())
            .spawn(move || self.run_loop(adopted_tx))
            .expect("failed to start PHXP listener thread");
    }

    fn run_loop(self, adopted_tx: Sender<AdoptedConn>) {
        loop {
            let control = match accept_control(&self.listener) {
                Ok(control) => control,
                Err(error) => {
                    eprintln!("PHXP accept failed: {error}");
                    continue;
                }
            };
            let tx = adopted_tx.clone();
            let active_ids = Arc::clone(&self.active_ids);
            thread::spawn(move || {
                if let Err(error) = receive_handoff(control, tx, active_ids) {
                    eprintln!("PHXP handoff failed: {error}");
                }
            });
        }
    }
}

impl Drop for HandoffListener {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.endpoint_identity.device
            && metadata.ino() == self.endpoint_identity.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn endpoint_path(project: &str, role: &str) -> Result<PathBuf, String> {
    let hash = endpoint_hash(project, role);
    let path = match nonempty_env("PHX_PORT_RUNTIME_DIR") {
        Some(runtime) => endpoint_path_in(Path::new(&runtime), false, &hash),
        None => platform_default_endpoint(&hash)?,
    };
    UnixAddr::new(&path).map_err(|error| {
        format!(
            "handoff endpoint path {} is too long: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

fn nonempty_env(name: &str) -> Option<std::ffi::OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

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
        .ok_or_else(|| "XDG_RUNTIME_DIR is unavailable; set it or --handoff-socket".to_string())?;
    Ok(endpoint_path_in(Path::new(&runtime), true, hash))
}

#[cfg(target_os = "macos")]
fn platform_default_endpoint(hash: &str) -> Result<PathBuf, String> {
    let runtime = PathBuf::from(format!("/tmp/phx-port-{}", nix::unistd::geteuid().as_raw()));
    Ok(endpoint_path_in(&runtime, false, hash))
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)?;
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect handoff directory {}: {error}",
                path.display()
            ));
        }
    }

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect handoff directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "handoff directory {} is not a directory",
            path.display()
        ));
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(format!(
            "handoff directory {} belongs to a different user",
            path.display()
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "handoff directory {} must not grant group or other permissions",
            path.display()
        ));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "cannot create handoff directory {}: {error}",
            path.display()
        )),
    }
}

fn ensure_endpoint_directory(path: &Path, validate_runtime_root: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "handoff socket has no parent directory".to_string())?;
    if validate_runtime_root {
        let runtime_root = parent
            .parent()
            .ok_or_else(|| "handoff directory has no runtime root".to_string())?;
        ensure_private_directory(runtime_root)?;
    }
    ensure_private_directory(parent)
}

fn remove_stale_endpoint(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect handoff endpoint {}: {error}",
                path.display()
            ));
        }
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
    let Ok(socket) = create_control_socket() else {
        return false;
    };
    connect(socket.as_raw_fd(), &address).is_ok()
}

fn receive_handoff(
    mut control: Control,
    adopted_tx: Sender<AdoptedConn>,
    active_ids: Arc<Mutex<HashSet<[u8; 16]>>>,
) -> Result<(), String> {
    authenticate_peer(&control)?;
    configure_control(&control)?;

    let hello = read_control_frame(&mut control)?;
    if handoff_protocol::decode(&hello) != Ok(Message::Hello) {
        return Err("invalid PHXP hello".into());
    }
    send_packet(&mut control, &Message::Ready)?;

    let (packet, descriptors) = receive_descriptor(&mut control)?;
    let request = handoff_protocol::decode(&packet)
        .map_err(|error| format!("invalid PHXP handoff packet: {error}"))?;
    let Message::Handoff(handoff) = request else {
        return Err("expected PHXP handoff request".into());
    };

    if descriptors.len() != 1 {
        send_rejected(
            &mut control,
            handoff.connection_id,
            REJECT_INVALID_DESCRIPTOR,
        )?;
        return Err(format!(
            "handoff contained {} descriptors instead of one",
            descriptors.len()
        ));
    }
    let client = descriptors
        .into_iter()
        .next()
        .expect("length checked above");
    let peer_address = getpeername::<SockaddrStorage>(client.as_raw_fd());
    let is_connected_stream = getsockopt(&client, sockopt::SockType)
        .is_ok_and(|socket_type| socket_type == SockType::Stream)
        && peer_address.is_ok_and(|address| {
            matches!(
                address.family(),
                Some(AddressFamily::Inet | AddressFamily::Inet6)
            )
        });
    if !is_connected_stream {
        send_rejected(
            &mut control,
            handoff.connection_id,
            REJECT_INVALID_DESCRIPTOR,
        )?;
        return Err("handed-off descriptor is not a connected TCP stream socket".into());
    }

    let stream = TcpStream::from(client);
    let peer = stream.peer_addr().ok();
    let local = stream.local_addr().ok();

    stream.set_nonblocking(true).map_err(|error| {
        let _ = send_rejected(&mut control, handoff.connection_id, REJECT_ADOPTION_FAILED);
        format!("cannot set adopted fd to nonblocking mode: {error}")
    })?;

    {
        let mut ids = active_ids
            .lock()
            .map_err(|_| "active connection ID lock is poisoned".to_string())?;
        if !ids.insert(handoff.connection_id) {
            send_rejected(&mut control, handoff.connection_id, REJECT_DUPLICATE_ID)?;
            return Err("duplicate handoff connection identifier".into());
        }
    }

    let conn = AdoptedConn {
        stream,
        peer,
        local,
        sni: handoff.requested_sni.clone(),
        peeked: handoff.peeked_length,
        connection_id: handoff.connection_id,
        active_ids: Arc::clone(&active_ids),
    };

    if let Err(error) = adopted_tx.try_send(conn) {
        let (conn, reason) = match error {
            TrySendError::Full(conn) => (conn, "handoff queue is full"),
            TrySendError::Closed(conn) => (conn, "async runtime shut down"),
        };
        drop(conn);
        if let Ok(mut ids) = active_ids.lock() {
            ids.remove(&handoff.connection_id);
        }
        send_rejected(&mut control, handoff.connection_id, REJECT_ADOPTION_FAILED)?;
        return Err(format!("{reason}; rejected adoption"));
    }

    if let Err(error) = send_packet(
        &mut control,
        &Message::Adopted {
            connection_id: handoff.connection_id,
        },
    ) {
        eprintln!(
            "PHXP connection {} was adopted, but its acknowledgement was lost: {error}",
            hex_id(&handoff.connection_id)
        );
    }
    println!(
        "adopted PHXP connection for {} from {} (peeked {} bytes, accepted_at_ns={})",
        handoff.requested_sni,
        peer.map(|address| address.to_string())
            .unwrap_or_else(|| "unknown peer".into()),
        handoff.peeked_length,
        handoff.accepted_at_ns,
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_control_socket() -> Result<OwnedFd, String> {
    socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|error| format!("cannot create handoff socket: {error}"))
}

#[cfg(target_os = "macos")]
fn create_control_socket() -> Result<OwnedFd, String> {
    let socket = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|error| format!("cannot create handoff socket: {error}"))?;
    set_cloexec(&socket)?;
    set_no_sigpipe(&socket)?;
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn accept_control(listener: &OwnedFd) -> Result<Control, String> {
    let fd = accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC)
        .map_err(|error| format!("cannot accept PHXP connection: {error}"))?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "macos")]
fn accept_control(listener: &OwnedFd) -> Result<Control, String> {
    let fd = accept(listener.as_raw_fd())
        .map_err(|error| format!("cannot accept PHXP connection: {error}"))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(&fd)?;
    set_no_sigpipe(&fd)?;
    Ok(UnixStream::from(fd))
}

#[cfg(target_os = "linux")]
fn authenticate_peer(control: &Control) -> Result<(), String> {
    let credentials = getsockopt(control, sockopt::PeerCredentials)
        .map_err(|error| format!("cannot inspect PHXP peer credentials: {error}"))?;
    if credentials.uid() != nix::unistd::geteuid().as_raw() {
        return Err("PHXP peer belongs to a different user".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn authenticate_peer(control: &Control) -> Result<(), String> {
    let (peer_euid, _) = nix::unistd::getpeereid(control)
        .map_err(|error| format!("cannot inspect PHXP peer credentials: {error}"))?;
    if peer_euid != nix::unistd::geteuid() {
        return Err("PHXP peer belongs to a different user".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_control(control: &Control) -> Result<(), String> {
    let timeout = nix::sys::time::TimeVal::new(
        CONTROL_TIMEOUT.as_secs() as i64,
        i64::from(CONTROL_TIMEOUT.subsec_micros()),
    );
    nix::sys::socket::setsockopt(control, sockopt::ReceiveTimeout, &timeout)
        .map_err(|error| format!("cannot configure PHXP receive timeout: {error}"))?;
    nix::sys::socket::setsockopt(control, sockopt::SendTimeout, &timeout)
        .map_err(|error| format!("cannot configure PHXP send timeout: {error}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_control(control: &Control) -> Result<(), String> {
    control
        .set_read_timeout(Some(CONTROL_TIMEOUT))
        .map_err(|error| format!("cannot configure PHXP receive timeout: {error}"))?;
    control
        .set_write_timeout(Some(CONTROL_TIMEOUT))
        .map_err(|error| format!("cannot configure PHXP send timeout: {error}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_control_frame(control: &mut Control) -> Result<Vec<u8>, String> {
    let mut packet = vec![0_u8; MAX_PACKET_LENGTH + 1];
    let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty())
        .map_err(|error| format!("cannot receive PHXP frame: {error}"))?;
    packet.truncate(length);
    Ok(packet)
}

#[cfg(target_os = "macos")]
fn read_control_frame(control: &mut Control) -> Result<Vec<u8>, String> {
    read_frame(control)
}

#[cfg(target_os = "linux")]
fn receive_descriptor(control: &mut Control) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
    let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
    let mut ancillary = nix::cmsg_space!([i32; 2]);
    let mut iov = [IoSliceMut::new(&mut packet)];
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
        .flat_map(|cmsg| match cmsg {
            ControlMessageOwned::ScmRights(fds) => fds,
            _ => Vec::new(),
        })
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect::<Vec<_>>();
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err("truncated PHXP packet or ancillary data".into());
    }
    Ok((packet[..packet_length].to_vec(), descriptors))
}

#[cfg(target_os = "macos")]
fn receive_descriptor(control: &mut Control) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
    let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
    let (packet_length, flags, descriptors) = {
        let mut ancillary = nix::cmsg_space!([i32; 2]);
        let mut iov = [IoSliceMut::new(&mut packet)];
        let message = recvmsg::<UnixAddr>(
            control.as_raw_fd(),
            &mut iov,
            Some(&mut ancillary),
            MsgFlags::empty(),
        )
        .map_err(|error| format!("cannot receive PHXP descriptor: {error}"))?;
        let descriptors = message
            .cmsgs()
            .map_err(|error| format!("invalid PHXP ancillary message: {error}"))?
            .flat_map(|cmsg| match cmsg {
                ControlMessageOwned::ScmRights(fds) => fds,
                _ => Vec::new(),
            })
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
            .collect::<Vec<_>>();
        (message.bytes, message.flags, descriptors)
    };
    for descriptor in &descriptors {
        set_cloexec(descriptor)?;
    }
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err("truncated PHXP packet or ancillary data".into());
    }
    let packet = complete_frame(control, packet[..packet_length].to_vec())?;
    Ok((packet, descriptors))
}

fn send_rejected(
    control: &mut Control,
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

#[cfg(target_os = "linux")]
fn send_packet(control: &mut Control, message: &Message) -> Result<(), String> {
    let packet = handoff_protocol::encode(message)?;
    let sent = send(control.as_raw_fd(), &packet, MsgFlags::empty())
        .map_err(|error| format!("cannot send PHXP response: {error}"))?;
    if sent != packet.len() {
        return Err("PHXP response was only partially sent".to_string());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn send_packet(control: &mut Control, message: &Message) -> Result<(), String> {
    let packet = handoff_protocol::encode(message)?;
    control
        .write_all(&packet)
        .map_err(|error| format!("cannot send PHXP response: {error}"))
}

#[cfg(target_os = "macos")]
fn set_cloexec(fd: &impl AsFd) -> Result<(), String> {
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .map_err(|error| format!("cannot set close-on-exec: {error}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
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

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        HandoffListener, create_private_directory, endpoint_hash, endpoint_path_in,
        ensure_endpoint_directory, ensure_private_directory, remove_stale_endpoint,
    };
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn endpoint_name_matches_the_daemon_algorithm() {
        let hash = endpoint_hash("/srv/contoso", "https");

        #[cfg(target_os = "linux")]
        let path = endpoint_path_in(Path::new("/run/user/1000"), true, &hash);
        #[cfg(target_os = "linux")]
        let expected = format!("/run/user/1000/phx-port/handoff/{hash}.sock");

        #[cfg(target_os = "macos")]
        let path = endpoint_path_in(Path::new("/tmp/phx-port-501"), false, &hash);
        #[cfg(target_os = "macos")]
        let expected = format!("/tmp/phx-port-501/handoff/{hash}.sock");

        assert_eq!(path.to_string_lossy(), expected);
    }

    #[test]
    fn listener_creates_private_socket_and_removes_its_endpoint() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint_directory = directory.path().join("handoff");
        let endpoint = endpoint_directory.join("receiver.sock");
        let listener = HandoffListener::bind(&endpoint, true).unwrap();

        assert!(
            fs::symlink_metadata(&endpoint)
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert_eq!(
            fs::symlink_metadata(&endpoint)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(listener);
        assert!(!endpoint.exists());
    }

    #[test]
    fn private_directory_validation_refuses_open_permissions() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("handoff");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(ensure_private_directory(&path).is_err());
    }

    #[test]
    fn private_directory_creation_tolerates_a_concurrent_creator() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("handoff");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

        create_private_directory(&path).unwrap();
        ensure_private_directory(&path).unwrap();
    }

    #[test]
    fn endpoint_directory_rejects_symlinked_runtime_root() {
        let directory = tempdir().unwrap();
        let actual = directory.path().join("actual");
        fs::create_dir(&actual).unwrap();
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = directory.path().join("runtime");
        symlink(&actual, &runtime).unwrap();
        let endpoint = runtime.join("handoff").join("receiver.sock");

        assert!(ensure_endpoint_directory(&endpoint, true).is_err());
        assert!(!actual.join("handoff").exists());
    }

    #[test]
    fn explicit_endpoint_validates_only_its_private_parent() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let handoff = directory.path().join("handoff");
        fs::create_dir(&handoff).unwrap();
        fs::set_permissions(&handoff, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = handoff.join("receiver.sock");

        ensure_endpoint_directory(&endpoint, false).unwrap();
    }

    #[test]
    fn stale_endpoint_validation_refuses_regular_files() {
        let directory = tempdir().unwrap();
        let endpoint = directory.path().join("handoff.sock");
        fs::write(&endpoint, b"not a socket").unwrap();

        assert!(remove_stale_endpoint(&endpoint).is_err());
    }
}
