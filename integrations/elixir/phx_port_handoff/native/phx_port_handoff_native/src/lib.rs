#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("phx_port_handoff_native requires Linux or macOS");

#[cfg(target_os = "macos")]
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
#[cfg(target_os = "macos")]
use nix::sys::socket::accept as socket_accept;
use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrLike,
    SockaddrStorage, UnixAddr, bind, connect, getpeername, getsockopt, listen as socket_listen,
    recv, recvmsg, socket, sockopt,
};
#[cfg(target_os = "linux")]
use nix::sys::socket::{accept4, send};
use rustler::{Atom, Env, Error, LocalPid, Monitor, NifResult, ResourceArc};
use std::collections::HashSet;
use std::fs;
use std::io::IoSliceMut;
#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::fd::AsFd;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const MAGIC: &[u8; 4] = b"PHXP";
const VERSION: u8 = 1;
const HEADER_LENGTH: usize = 40;
const MAX_PACKET_LENGTH: usize = 512;
const MAX_SNI_LENGTH: usize = 253;
const TYPE_HELLO: u8 = 1;
const TYPE_READY: u8 = 2;
const TYPE_HANDOFF: u8 = 3;
const TYPE_ADOPTED: u8 = 4;
const TYPE_REJECTED: u8 = 5;
const REJECT_INVALID_DESCRIPTOR: u16 = 1;
const REJECT_DUPLICATE_ID: u16 = 2;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(target_os = "linux")]
type Control = OwnedFd;
#[cfg(target_os = "macos")]
type Control = UnixStream;

mod atoms {
    rustler::atoms! {
        ok,
        closed,
        error,
        econnaborted,
    }
}

#[derive(Clone, Copy)]
struct EndpointIdentity {
    device: u64,
    inode: u64,
}

struct Broker {
    listener: OwnedFd,
    path: PathBuf,
    endpoint_identity: EndpointIdentity,
    closed: AtomicBool,
    connection_ids: Mutex<HashSet<[u8; 16]>>,
}

#[rustler::resource_impl]
impl rustler::Resource for Broker {
    const IMPLEMENTS_DOWN: bool = true;

    fn down(&self, _env: Env<'_>, _pid: LocalPid, _monitor: Monitor) {
        self.close();
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.close();
    }
}

impl Broker {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            remove_owned_endpoint(&self.path, self.endpoint_identity);
        }
    }
}

struct Receipt {
    client: Mutex<Option<OwnedFd>>,
    control: Mutex<Option<Control>>,
    connection_id: [u8; 16],
    broker: ResourceArc<Broker>,
}

#[rustler::resource_impl]
impl rustler::Resource for Receipt {}

impl Drop for Receipt {
    fn drop(&mut self) {
        if let Ok(mut ids) = self.broker.connection_ids.lock() {
            ids.remove(&self.connection_id);
        }
    }
}

#[rustler::nif]
fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

#[rustler::nif]
fn listen(env: Env<'_>, path: String) -> NifResult<(Atom, ResourceArc<Broker>)> {
    let path = PathBuf::from(path);
    let parent = path
        .parent()
        .ok_or_else(|| failure("handoff path has no parent directory"))?;
    ensure_private_directory(parent).map_err(failure)?;
    remove_stale_endpoint(&path).map_err(failure)?;

    let listener = create_listener_socket().map_err(failure)?;
    let address = UnixAddr::new(&path)
        .map_err(|error| failure(format!("invalid handoff socket path: {error}")))?;
    bind(listener.as_raw_fd(), &address)
        .map_err(|error| failure(format!("cannot bind handoff socket: {error}")))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|error| failure(format!("cannot secure handoff socket: {error}")))?;
    socket_listen(
        &listener,
        Backlog::new(128).map_err(|error| failure(error.to_string()))?,
    )
    .map_err(|error| failure(format!("cannot listen on handoff socket: {error}")))?;

    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| failure(format!("cannot inspect handoff socket: {error}")))?;
    let endpoint_identity = EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let broker = ResourceArc::new(Broker {
        listener,
        path,
        endpoint_identity,
        closed: AtomicBool::new(false),
        connection_ids: Mutex::new(HashSet::new()),
    });
    env.monitor(&broker, &env.pid())
        .ok_or_else(|| failure("cannot monitor handoff listener owner"))?;
    Ok((atoms::ok(), broker))
}

#[rustler::nif]
fn close_listener(broker: ResourceArc<Broker>) -> NifResult<Atom> {
    broker.close();
    Ok(atoms::ok())
}

#[rustler::nif(schedule = "DirtyIo")]
fn accept(
    broker: ResourceArc<Broker>,
) -> NifResult<(Atom, ResourceArc<Receipt>, i32, String, u32)> {
    let mut control = loop {
        if broker.closed.load(Ordering::Acquire) {
            return Err(Error::Term(Box::new(atoms::closed())));
        }
        match accept_control(&broker.listener) {
            Ok(Some(control)) => break control,
            Ok(None) => thread::sleep(ACCEPT_RETRY_DELAY),
            Err(_error) if broker.closed.load(Ordering::Acquire) => {
                return Err(Error::Term(Box::new(atoms::closed())));
            }
            Err(error) => {
                return Err(failure(format!(
                    "cannot accept handoff connection: {error}"
                )));
            }
        }
    };
    if broker.closed.load(Ordering::Acquire) {
        return Err(Error::Term(Box::new(atoms::closed())));
    }

    authenticate_peer(&control).map_err(failure)?;
    if peer_closed(&control) {
        return Err(Error::Term(Box::new(atoms::econnaborted())));
    }
    if let Err(error) = configure_control(&control) {
        if peer_closed(&control) {
            return Err(Error::Term(Box::new(atoms::econnaborted())));
        }
        return Err(failure(error));
    }

    let packet = match read_control_frame(&mut control).map_err(failure)? {
        Some(packet) => packet,
        None => return Err(Error::Term(Box::new(atoms::econnaborted()))),
    };
    parse_empty_message(&packet, TYPE_HELLO)?;
    send_message(&mut control, &empty_message(TYPE_READY, [0; 16], 0)).map_err(failure)?;

    let (packet, descriptors) = receive_descriptor(&mut control).map_err(failure)?;
    if descriptors.is_empty() && packet.is_empty() {
        return Err(Error::Term(Box::new(atoms::econnaborted())));
    }

    let (connection_id, peeked_length, sni) = parse_handoff(&packet)?;
    if descriptors.len() != 1 {
        send_response(
            &mut control,
            connection_id,
            TYPE_REJECTED,
            REJECT_INVALID_DESCRIPTOR,
        )
        .map_err(failure)?;
        return Err(failure(
            "handoff request must contain exactly one descriptor",
        ));
    }

    let client = descriptors
        .into_iter()
        .next()
        .expect("descriptor count checked above");
    let peer_address = getpeername::<SockaddrStorage>(client.as_raw_fd());
    let is_connected_ip_stream = getsockopt(&client, sockopt::SockType)
        .is_ok_and(|socket_type| socket_type == SockType::Stream)
        && peer_address.is_ok_and(|address| {
            matches!(
                address.family(),
                Some(AddressFamily::Inet | AddressFamily::Inet6)
            )
        });
    if !is_connected_ip_stream {
        send_response(
            &mut control,
            connection_id,
            TYPE_REJECTED,
            REJECT_INVALID_DESCRIPTOR,
        )
        .map_err(failure)?;
        return Err(failure(
            "handed-off descriptor is not a connected TCP stream socket",
        ));
    }

    {
        let mut ids = broker
            .connection_ids
            .lock()
            .map_err(|_| failure("connection ID lock poisoned"))?;
        if !ids.insert(connection_id) {
            drop(ids);
            send_response(
                &mut control,
                connection_id,
                TYPE_REJECTED,
                REJECT_DUPLICATE_ID,
            )
            .map_err(failure)?;
            return Err(failure("duplicate handoff connection identifier"));
        }
    }

    let fd = client.as_raw_fd();
    let receipt = ResourceArc::new(Receipt {
        client: Mutex::new(Some(client)),
        control: Mutex::new(Some(control)),
        connection_id,
        broker,
    });
    Ok((atoms::ok(), receipt, fd, sni, peeked_length))
}

#[rustler::nif]
fn take_fd(receipt: ResourceArc<Receipt>) -> NifResult<(Atom, i32)> {
    let mut client = receipt
        .client
        .lock()
        .map_err(|_| failure("handoff client lock poisoned"))?;
    let fd = client
        .take()
        .ok_or_else(|| failure("handoff descriptor was already taken"))?
        .into_raw_fd();
    Ok((atoms::ok(), fd))
}

#[rustler::nif]
fn adopted(receipt: ResourceArc<Receipt>) -> NifResult<Atom> {
    respond(&receipt, TYPE_ADOPTED, 0)?;
    Ok(atoms::ok())
}

#[rustler::nif]
fn rejected(receipt: ResourceArc<Receipt>, reason_code: u16) -> NifResult<Atom> {
    if reason_code == 0 {
        return Err(failure("rejection reason must be nonzero"));
    }
    respond(&receipt, TYPE_REJECTED, reason_code)?;
    Ok(atoms::ok())
}

#[rustler::nif]
fn close_fd(fd: i32) -> NifResult<Atom> {
    if fd < 0 {
        return Err(failure("invalid descriptor"));
    }
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(atoms::ok())
}

fn respond(receipt: &Receipt, message_type: u8, reason_code: u16) -> NifResult<()> {
    let mut control = receipt
        .control
        .lock()
        .map_err(|_| failure("handoff control lock poisoned"))?;
    let Some(mut socket) = control.take() else {
        return Ok(());
    };
    send_response(
        &mut socket,
        receipt.connection_id,
        message_type,
        reason_code,
    )
    .map_err(failure)?;
    if let Ok(mut ids) = receipt.broker.connection_ids.lock() {
        ids.remove(&receipt.connection_id);
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(path).map_err(|create_error| {
                format!(
                    "cannot create handoff directory {}: {create_error}",
                    path.display()
                )
            })?;
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

fn remove_owned_endpoint(path: &Path, identity: EndpointIdentity) {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_socket()
        && metadata.dev() == identity.device
        && metadata.ino() == identity.inode
    {
        let _ = fs::remove_file(path);
    }
}

fn endpoint_is_live(path: &Path) -> bool {
    let Ok(address) = UnixAddr::new(path) else {
        return false;
    };
    let Ok(socket) = create_client_socket() else {
        return false;
    };
    connect(socket.as_raw_fd(), &address).is_ok()
}

#[cfg(target_os = "linux")]
fn create_listener_socket() -> Result<OwnedFd, String> {
    socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|error| format!("cannot create handoff socket: {error}"))
}

#[cfg(target_os = "macos")]
fn create_listener_socket() -> Result<OwnedFd, String> {
    let socket = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|error| format!("cannot create handoff socket: {error}"))?;
    set_cloexec(&socket)?;
    set_nonblocking(&socket, true)?;
    set_no_sigpipe(&socket)?;
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn create_client_socket() -> Result<OwnedFd, String> {
    socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|error| format!("cannot create handoff socket: {error}"))
}

#[cfg(target_os = "macos")]
fn create_client_socket() -> Result<OwnedFd, String> {
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
fn accept_control(listener: &OwnedFd) -> Result<Option<Control>, String> {
    match accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC) {
        Ok(fd) => Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) })),
        Err(nix::errno::Errno::EAGAIN) => Ok(None),
        Err(nix::errno::Errno::EINTR) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn accept_control(listener: &OwnedFd) -> Result<Option<Control>, String> {
    match socket_accept(listener.as_raw_fd()) {
        Ok(fd) => {
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            set_cloexec(&fd)?;
            set_nonblocking(&fd, false)?;
            Ok(Some(UnixStream::from(fd)))
        }
        Err(nix::errno::Errno::EAGAIN) => Ok(None),
        Err(nix::errno::Errno::EINTR) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn authenticate_peer(control: &Control) -> Result<(), String> {
    let credentials = getsockopt(control, sockopt::PeerCredentials)
        .map_err(|error| format!("cannot inspect handoff peer: {error}"))?;
    if credentials.uid() != nix::unistd::geteuid().as_raw() {
        return Err("handoff peer belongs to a different user".to_string());
    }
    Ok(())
}

fn peer_closed(control: &Control) -> bool {
    let mut byte = [0_u8; 1];
    match recv(
        control.as_raw_fd(),
        &mut byte,
        MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(0) => true,
        Ok(_) | Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => false,
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
fn authenticate_peer(control: &Control) -> Result<(), String> {
    let (peer_euid, _) = nix::unistd::getpeereid(control)
        .map_err(|error| format!("cannot inspect handoff peer: {error}"))?;
    if peer_euid != nix::unistd::geteuid() {
        return Err("handoff peer belongs to a different user".to_string());
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
        .map_err(|error| format!("cannot configure handoff receive timeout: {error}"))?;
    nix::sys::socket::setsockopt(control, sockopt::SendTimeout, &timeout)
        .map_err(|error| format!("cannot configure handoff send timeout: {error}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_control(control: &Control) -> Result<(), String> {
    control
        .set_read_timeout(Some(CONTROL_TIMEOUT))
        .map_err(|error| format!("cannot configure handoff receive timeout: {error}"))?;
    control
        .set_write_timeout(Some(CONTROL_TIMEOUT))
        .map_err(|error| format!("cannot configure handoff send timeout: {error}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_control_frame(control: &mut Control) -> Result<Option<Vec<u8>>, String> {
    let mut packet = vec![0_u8; MAX_PACKET_LENGTH + 1];
    let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty())
        .map_err(|error| format!("cannot receive handoff frame: {error}"))?;
    if length == 0 {
        return Ok(None);
    }
    packet.truncate(length);
    Ok(Some(packet))
}

#[cfg(target_os = "macos")]
fn read_control_frame(control: &mut Control) -> Result<Option<Vec<u8>>, String> {
    let mut initial = vec![0_u8; MAX_PACKET_LENGTH + 1];
    let received = control
        .read(&mut initial)
        .map_err(|error| format!("cannot read handoff frame: {error}"))?;
    if received == 0 {
        return Ok(None);
    }
    initial.truncate(received);
    complete_frame(control, initial).map(Some)
}

fn receive_descriptor(control: &mut Control) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
    let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
    let (packet_length, flags, descriptors) = {
        let mut ancillary = nix::cmsg_space!([i32; 2]);
        let mut iov = [IoSliceMut::new(&mut packet)];
        let message = recvmsg::<UnixAddr>(
            control.as_raw_fd(),
            &mut iov,
            Some(&mut ancillary),
            receive_descriptor_flags(),
        )
        .map_err(|error| format!("cannot receive handed-off descriptor: {error}"))?;
        let descriptors = message
            .cmsgs()
            .map_err(|error| format!("invalid descriptor control message: {error}"))?
            .flat_map(|control| match control {
                ControlMessageOwned::ScmRights(descriptors) => descriptors,
                _ => Vec::new(),
            })
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
            .collect::<Vec<_>>();
        (message.bytes, message.flags, descriptors)
    };

    #[cfg(target_os = "macos")]
    for descriptor in &descriptors {
        set_cloexec(descriptor)?;
    }
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err("truncated handoff frame or ancillary data".to_string());
    }

    #[cfg(target_os = "linux")]
    let packet = packet[..packet_length].to_vec();
    #[cfg(target_os = "macos")]
    let packet = complete_frame(control, packet[..packet_length].to_vec())?;
    Ok((packet, descriptors))
}

#[cfg(target_os = "linux")]
fn receive_descriptor_flags() -> MsgFlags {
    MsgFlags::MSG_CMSG_CLOEXEC
}

#[cfg(target_os = "macos")]
fn receive_descriptor_flags() -> MsgFlags {
    MsgFlags::empty()
}

#[cfg(target_os = "linux")]
fn send_message(control: &mut Control, packet: &[u8]) -> Result<(), String> {
    let sent = send(control.as_raw_fd(), packet, MsgFlags::empty())
        .map_err(|error| format!("cannot send handoff response: {error}"))?;
    if sent != packet.len() {
        return Err("handoff response was only partially sent".to_string());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn send_message(control: &mut Control, packet: &[u8]) -> Result<(), String> {
    control
        .write_all(packet)
        .map_err(|error| format!("cannot send handoff response: {error}"))
}

fn send_response(
    control: &mut Control,
    connection_id: [u8; 16],
    message_type: u8,
    reason_code: u16,
) -> Result<(), String> {
    send_message(
        control,
        &empty_message(message_type, connection_id, reason_code),
    )
}

fn parse_empty_message(packet: &[u8], expected_type: u8) -> NifResult<()> {
    validate_header(packet, expected_type)?;
    if packet.len() != HEADER_LENGTH || packet[6..40].iter().any(|byte| *byte != 0) {
        return Err(failure("invalid handoff capability message"));
    }
    Ok(())
}

fn parse_handoff(packet: &[u8]) -> NifResult<([u8; 16], u32, String)> {
    validate_header(packet, TYPE_HANDOFF)?;
    let payload_length = usize::from(u16::from_be_bytes([packet[36], packet[37]]));
    if payload_length == 0
        || payload_length > MAX_SNI_LENGTH
        || packet.len() != HEADER_LENGTH + payload_length
        || packet[38..40] != [0, 0]
    {
        return Err(failure("invalid handoff request fields"));
    }
    let connection_id = packet[8..24]
        .try_into()
        .map_err(|_| failure("invalid connection identifier"))?;
    let peeked_length = u32::from_be_bytes(
        packet[24..28]
            .try_into()
            .map_err(|_| failure("invalid peeked length"))?,
    );
    let sni = std::str::from_utf8(&packet[HEADER_LENGTH..])
        .map_err(|_| failure("handoff SNI is not UTF-8"))?
        .to_string();
    Ok((connection_id, peeked_length, sni))
}

fn validate_header(packet: &[u8], expected_type: u8) -> NifResult<()> {
    let frame_length = frame_length_from_header(packet).map_err(failure)?;
    if frame_length != packet.len() {
        return Err(failure("handoff payload length does not match frame"));
    }
    if packet[5] != expected_type {
        return Err(failure("handoff packet has unexpected message type"));
    }
    Ok(())
}

fn frame_length_from_header(header: &[u8]) -> Result<usize, String> {
    if header.len() < HEADER_LENGTH {
        return Err("handoff packet is shorter than its fixed header".to_string());
    }
    if &header[0..4] != MAGIC || header[4] != VERSION {
        return Err("handoff packet header is invalid".to_string());
    }
    if !matches!(
        header[5],
        TYPE_HELLO | TYPE_READY | TYPE_HANDOFF | TYPE_ADOPTED | TYPE_REJECTED
    ) {
        return Err("handoff packet has unknown message type".to_string());
    }
    if header[6..8] != [0, 0] {
        return Err("handoff packet uses unsupported flags".to_string());
    }
    let payload_length = usize::from(u16::from_be_bytes([header[36], header[37]]));
    let frame_length = HEADER_LENGTH
        .checked_add(payload_length)
        .ok_or_else(|| "handoff frame length overflow".to_string())?;
    if frame_length > MAX_PACKET_LENGTH {
        return Err("handoff packet exceeds protocol limit".to_string());
    }
    Ok(frame_length)
}

#[cfg(target_os = "macos")]
fn complete_frame(control: &mut Control, mut frame: Vec<u8>) -> Result<Vec<u8>, String> {
    if frame.len() > MAX_PACKET_LENGTH {
        return Err("handoff stream contains bytes beyond the maximum frame".to_string());
    }
    if frame.len() < HEADER_LENGTH {
        read_exact_part(
            control,
            &mut frame,
            HEADER_LENGTH,
            "unexpected EOF in handoff frame header",
        )?;
    }
    let frame_length = frame_length_from_header(&frame[..HEADER_LENGTH])?;
    if frame.len() > frame_length {
        return Err("handoff stream contains bytes beyond the declared frame".to_string());
    }
    if frame.len() < frame_length {
        read_exact_part(
            control,
            &mut frame,
            frame_length,
            "unexpected EOF in handoff frame payload",
        )?;
    }
    Ok(frame)
}

#[cfg(target_os = "macos")]
fn read_exact_part(
    control: &mut Control,
    frame: &mut Vec<u8>,
    target_length: usize,
    eof_message: &str,
) -> Result<(), String> {
    let start = frame.len();
    frame.resize(target_length, 0);
    match control.read_exact(&mut frame[start..]) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(eof_message.to_string())
        }
        Err(error) => Err(format!("cannot read handoff frame: {error}")),
    }
}

fn empty_message(message_type: u8, connection_id: [u8; 16], reason_code: u16) -> [u8; 40] {
    let mut packet = [0_u8; HEADER_LENGTH];
    packet[0..4].copy_from_slice(MAGIC);
    packet[4] = VERSION;
    packet[5] = message_type;
    packet[8..24].copy_from_slice(&connection_id);
    packet[38..40].copy_from_slice(&reason_code.to_be_bytes());
    packet
}

#[cfg(target_os = "macos")]
fn set_cloexec(fd: &impl AsFd) -> Result<(), String> {
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .map_err(|error| format!("cannot set close-on-exec: {error}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_nonblocking(fd: &impl AsFd, enabled: bool) -> Result<(), String> {
    let current = fcntl(fd, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| format!("cannot inspect descriptor flags: {error}"))?;
    let updated = if enabled {
        current | OFlag::O_NONBLOCK
    } else {
        current & !OFlag::O_NONBLOCK
    };
    fcntl(fd, FcntlArg::F_SETFL(updated))
        .map_err(|error| format!("cannot configure descriptor flags: {error}"))?;
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

fn failure(message: impl Into<String>) -> Error {
    Error::Term(Box::new(message.into()))
}

rustler::init!("Elixir.PhxPortHandoff.Native");

#[cfg(test)]
mod tests {
    use super::{
        HEADER_LENGTH, MAX_PACKET_LENGTH, TYPE_HELLO, create_listener_socket, empty_message,
        ensure_private_directory, frame_length_from_header, remove_stale_endpoint,
    };
    use nix::sys::socket::{UnixAddr, bind};
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn rejects_oversized_stream_header_before_payload() {
        let mut header = empty_message(TYPE_HELLO, [0; 16], 0);
        header[36..38].copy_from_slice(
            &u16::try_from(MAX_PACKET_LENGTH - HEADER_LENGTH + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert!(frame_length_from_header(&header).is_err());
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
    fn removes_only_stale_socket_endpoints() {
        let directory = tempdir().unwrap();
        let regular = directory.path().join("regular");
        fs::write(&regular, b"not a socket").unwrap();
        assert!(remove_stale_endpoint(&regular).is_err());

        let stale = directory.path().join("stale.sock");
        let socket = create_listener_socket().unwrap();
        bind(socket.as_raw_fd(), &UnixAddr::new(&stale).unwrap()).unwrap();
        drop(socket);
        remove_stale_endpoint(&stale).unwrap();
        assert!(!stale.exists());
    }
}
