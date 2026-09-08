use super::platform::try_transfer_to_endpoint;
use super::{EndpointIdentity, Outcome, endpoint_path};
use crate::handoff_protocol::{MAX_PACKET_LENGTH, Message, decode, encode};
use crate::handoff_stream::{complete_frame, read_frame};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixAddr, recvmsg};
use std::io::{self, IoSliceMut, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir_in};

pub(crate) const WORKLOAD: &str = "/darwin-deadline-workload";
const CONNECTION_ID: [u8; 16] = [0xD4; 16];
const WATCHDOG: Duration = Duration::from_secs(3);

pub(crate) struct Receiver<T> {
    pub(crate) directory: TempDir,
    pub(crate) endpoint: PathBuf,
    worker: JoinHandle<T>,
}

impl<T: Send + 'static> Receiver<T> {
    pub(crate) fn start(receive: impl FnOnce(UnixStream) -> T + Send + 'static) -> Self {
        let directory = tempdir_in("/tmp").unwrap();
        std::fs::create_dir(directory.path().join("handoff")).unwrap();
        let endpoint = endpoint_path(
            EndpointIdentity::Development(WORKLOAD),
            "https",
            Some(directory.path()),
        )
        .unwrap();
        let listener = UnixListener::bind(&endpoint).unwrap();
        listener.set_nonblocking(true).unwrap();
        eprintln!("Darwin PHXP fixture process={}", std::process::id());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + WATCHDOG;
            let mut control = loop {
                match listener.accept() {
                    Ok((control, _)) => break control,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "PHXP sender did not connect");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("cannot accept fixture PHXP connection: {error}"),
                }
            };
            control.set_nonblocking(false).unwrap();
            control.set_read_timeout(Some(WATCHDOG)).unwrap();
            control.set_write_timeout(Some(WATCHDOG)).unwrap();
            assert_eq!(
                decode(&read_frame(&mut control).unwrap()).unwrap(),
                Message::Hello
            );
            receive(control)
        });
        Self {
            directory,
            endpoint,
            worker,
        }
    }

    pub(crate) fn finish(self) -> T {
        self.worker.join().unwrap()
    }
}

pub(crate) fn receive_descriptor(control: &mut UnixStream) -> (TcpStream, [u8; 16]) {
    let mut packet = [0_u8; MAX_PACKET_LENGTH + 1];
    let (length, mut descriptors, flags) = {
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
    let frame = complete_frame(control, packet[..length].to_vec()).unwrap();
    let connection_id = match decode(&frame).unwrap() {
        Message::Handoff(handoff) => handoff.connection_id,
        message => panic!("expected descriptor-bearing HANDOFF, received {message:?}"),
    };
    let stream = TcpStream::from(descriptors.pop().unwrap());
    stream.set_read_timeout(Some(WATCHDOG)).unwrap();
    stream.set_write_timeout(Some(WATCHDOG)).unwrap();
    (stream, connection_id)
}

pub(crate) fn write_fragmented(control: &mut UnixStream, frame: &[u8], delay: Duration) -> usize {
    let started = Instant::now();
    for (index, byte) in frame.iter().enumerate() {
        if index != 0 {
            let scheduled = started + delay * u32::try_from(index).unwrap();
            thread::sleep(scheduled.saturating_duration_since(Instant::now()));
        }
        match control.write_all(&[*byte]) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) =>
            {
                return index;
            }
            Err(error) => panic!("unexpected fixture write failure: {error}"),
        }
    }
    frame.len()
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(WATCHDOG)).unwrap();
    peer.set_write_timeout(Some(WATCHDOG)).unwrap();
    let (client, _) = listener.accept().unwrap();
    client.set_read_timeout(Some(WATCHDOG)).unwrap();
    (peer, client)
}

fn transfer(client: TcpStream, endpoint: &std::path::Path) -> Outcome {
    try_transfer_to_endpoint(
        client,
        endpoint,
        "deadline.example.test",
        12,
        CONNECTION_ID,
        42,
        &|| false,
    )
}

#[test]
fn fragmented_ready_expires_before_descriptor_delivery() {
    let receiver = Receiver::start(|mut control| {
        let ready = encode(&Message::Ready).unwrap();
        let written = write_fragmented(&mut control, &ready, Duration::from_millis(40));
        if written == ready.len() {
            let (client, connection_id) = receive_descriptor(&mut control);
            control
                .write_all(&encode(&Message::Adopted { connection_id }).unwrap())
                .unwrap();
            (written, Some(client))
        } else {
            (written, None)
        }
    });
    let (mut peer, client) = tcp_pair();
    peer.write_all(b"client hello").unwrap();
    let started = Instant::now();
    let outcome = transfer(client, &receiver.endpoint);
    let elapsed = started.elapsed();
    let (ready_bytes, received) = receiver.finish();
    eprintln!(
        "fragmented READY: elapsed={elapsed:?}, ready_bytes={ready_bytes}, delivered={}",
        received.is_some()
    );
    assert!(
        elapsed < Duration::from_millis(1350),
        "READY exceeded the one-second exchange budget: {elapsed:?}"
    );
    assert!(ready_bytes >= 10, "fixture did not fragment READY");
    assert!(
        received.is_none(),
        "descriptor was delivered after READY expired"
    );
    let Outcome::Unavailable(mut client) = outcome else {
        panic!("READY timeout did not preserve the original client for safe fallback");
    };
    let mut hello = [0_u8; 12];
    client.read_exact(&mut hello).unwrap();
    assert_eq!(&hello, b"client hello");
}

#[test]
fn fragmented_adopted_uses_the_remaining_ready_budget() {
    let receiver = Receiver::start(|mut control| {
        let ready = encode(&Message::Ready).unwrap();
        assert_eq!(
            write_fragmented(&mut control, &ready, Duration::from_millis(20)),
            ready.len()
        );
        let (client, connection_id) = receive_descriptor(&mut control);
        let adopted = encode(&Message::Adopted { connection_id }).unwrap();
        let written = write_fragmented(&mut control, &adopted, Duration::from_millis(20));
        (written, client)
    });
    let (mut peer, client) = tcp_pair();
    let started = Instant::now();
    let outcome = transfer(client, &receiver.endpoint);
    let elapsed = started.elapsed();
    let (response_bytes, mut received) = receiver.finish();
    eprintln!("fragmented ADOPTED: elapsed={elapsed:?}, response_bytes={response_bytes}");
    assert!(
        elapsed < Duration::from_millis(1350),
        "READY and ADOPTED refreshed the exchange budget: {elapsed:?}"
    );
    assert!(
        response_bytes > 0 && response_bytes < 40,
        "fixture did not fragment acknowledgement across the deadline"
    );
    assert!(
        matches!(outcome, Outcome::Delivered(_)),
        "acknowledgement timeout reversed descriptor ownership"
    );
    received.write_all(b"still owned").unwrap();
    let mut reply = [0_u8; 11];
    peer.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"still owned");
}
