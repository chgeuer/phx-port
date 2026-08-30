use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrStorage,
    UnixAddr, accept4, bind, connect, getpeername, getsockopt, listen as socket_listen, recv,
    recvmsg, send, setsockopt, socket, sockopt,
};
use rustler::{Atom, Error, NifResult, ResourceArc};
use std::collections::HashSet;
use std::fs;
use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

const MAGIC: &[u8; 4] = b"PHXP";
const VERSION: u8 = 1;
const HEADER_LENGTH: usize = 40;
const MAX_PACKET_LENGTH: usize = 512;
const TYPE_HELLO: u8 = 1;
const TYPE_READY: u8 = 2;
const TYPE_HANDOFF: u8 = 3;
const TYPE_ADOPTED: u8 = 4;
const TYPE_REJECTED: u8 = 5;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        econnaborted,
    }
}

struct Broker {
    listener: OwnedFd,
    path: PathBuf,
    connection_ids: Mutex<HashSet<[u8; 16]>>,
}

#[rustler::resource_impl]
impl rustler::Resource for Broker {}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct Receipt {
    client: Mutex<Option<OwnedFd>>,
    control: Mutex<Option<OwnedFd>>,
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
fn listen(path: String) -> NifResult<(Atom, ResourceArc<Broker>)> {
    let path = PathBuf::from(path);
    let parent = path
        .parent()
        .ok_or_else(|| failure("handoff path has no parent directory"))?;
    fs::create_dir_all(parent)
        .map_err(|error| failure(format!("cannot create handoff directory: {error}")))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| failure(format!("cannot secure handoff directory: {error}")))?;
    if path.exists() {
        if endpoint_is_live(&path) {
            return Err(failure("another handoff receiver is already listening"));
        }
        fs::remove_file(&path)
            .map_err(|error| failure(format!("cannot remove stale handoff socket: {error}")))?;
    }

    let listener = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|error| failure(format!("cannot create handoff socket: {error}")))?;
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

    Ok((
        atoms::ok(),
        ResourceArc::new(Broker {
            listener,
            path,
            connection_ids: Mutex::new(HashSet::new()),
        }),
    ))
}

#[rustler::nif(schedule = "DirtyIo")]
fn accept(
    broker: ResourceArc<Broker>,
) -> NifResult<(Atom, ResourceArc<Receipt>, i32, String, u32)> {
    let control = accept4(broker.listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC)
        .map_err(|error| failure(format!("cannot accept handoff connection: {error}")))?;
    let control = unsafe { OwnedFd::from_raw_fd(control) };
    let credentials = getsockopt(&control, sockopt::PeerCredentials)
        .map_err(|error| failure(format!("cannot inspect handoff peer: {error}")))?;
    if credentials.uid() != nix::unistd::getuid().as_raw() {
        return Err(failure("handoff peer belongs to a different user"));
    }
    let timeout = nix::sys::time::TimeVal::new(2, 0);
    setsockopt(&control, sockopt::ReceiveTimeout, &timeout)
        .map_err(|error| failure(format!("cannot configure handoff timeout: {error}")))?;

    let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
    let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty())
        .map_err(|error| failure(format!("cannot receive handoff hello: {error}")))?;
    if length == 0 {
        return Err(Error::Term(Box::new(atoms::econnaborted())));
    }
    parse_empty_message(&packet[..length], TYPE_HELLO)?;
    send(
        control.as_raw_fd(),
        &empty_message(TYPE_READY, [0; 16], 0),
        MsgFlags::empty(),
    )
    .map_err(|error| failure(format!("cannot send handoff readiness: {error}")))?;

    let (packet_length, descriptors) = {
        let mut ancillary = nix::cmsg_space!([i32; 2]);
        let mut iov = [IoSliceMut::new(&mut packet)];
        let message = recvmsg::<UnixAddr>(
            control.as_raw_fd(),
            &mut iov,
            Some(&mut ancillary),
            MsgFlags::empty(),
        )
        .map_err(|error| failure(format!("cannot receive handed-off descriptor: {error}")))?;
        let descriptors = message
            .cmsgs()
            .map_err(|error| failure(format!("invalid descriptor control message: {error}")))?
            .flat_map(|control| match control {
                ControlMessageOwned::ScmRights(descriptors) => descriptors,
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        (message.bytes, descriptors)
    };
    if packet_length == 0 {
        return Err(Error::Term(Box::new(atoms::econnaborted())));
    }
    if descriptors.len() != 1 {
        for descriptor in descriptors {
            drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
        }
        return Err(failure(
            "handoff request must contain exactly one descriptor",
        ));
    }

    let (connection_id, peeked_length, sni) = parse_handoff(&packet[..packet_length])?;
    let client = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    if getsockopt(&client, sockopt::SockType)
        .map_err(|error| failure(format!("cannot inspect handed-off descriptor: {error}")))?
        != SockType::Stream
        || getpeername::<SockaddrStorage>(client.as_raw_fd()).is_err()
    {
        return Err(failure(
            "handed-off descriptor is not a connected stream socket",
        ));
    }
    {
        let mut ids = broker
            .connection_ids
            .lock()
            .map_err(|_| failure("connection ID lock poisoned"))?;
        if !ids.insert(connection_id) {
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
    let Some(socket) = control.take() else {
        return Ok(());
    };
    send(
        socket.as_raw_fd(),
        &empty_message(message_type, receipt.connection_id, reason_code),
        MsgFlags::empty(),
    )
    .map_err(|error| failure(format!("cannot send handoff response: {error}")))?;
    if let Ok(mut ids) = receipt.broker.connection_ids.lock() {
        ids.remove(&receipt.connection_id);
    }
    Ok(())
}

fn endpoint_is_live(path: &PathBuf) -> bool {
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
        || payload_length > 253
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
    if packet.len() < HEADER_LENGTH || packet.len() > MAX_PACKET_LENGTH {
        return Err(failure("handoff packet length is invalid"));
    }
    if &packet[0..4] != MAGIC || packet[4] != VERSION || packet[5] != expected_type {
        return Err(failure("handoff packet header is invalid"));
    }
    if packet[6..8] != [0, 0] {
        return Err(failure("handoff packet uses unsupported flags"));
    }
    Ok(())
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

fn failure(message: impl Into<String>) -> Error {
    Error::Term(Box::new(message.into()))
}

rustler::init!("Elixir.PhxPortHandoff.Native");
