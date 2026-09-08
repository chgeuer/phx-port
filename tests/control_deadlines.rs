#![cfg(target_os = "linux")]

use socket2::{Domain, SockAddr, Socket, Type};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir_in};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(3);

struct ControlEndpoint {
    directory: TempDir,
    path: PathBuf,
    listener: Option<Socket>,
}

impl ControlEndpoint {
    fn new(socket_type: Type) -> Self {
        let directory = tempdir_in(Path::new("/tmp").canonicalize().unwrap()).unwrap();
        let runtime = directory.path().join("phx-port");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let path = runtime.join("control.sock");
        let listener = Socket::new(Domain::UNIX, socket_type, None).unwrap();
        listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
        listener.listen(1).unwrap();
        listener.set_nonblocking(true).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            directory,
            path,
            listener: Some(listener),
        }
    }

    fn spawn(&self, args: &[&str]) -> BoundedChild {
        let child = Command::new(env!("CARGO_BIN_EXE_phx-port"))
            .args(args)
            .env("HOME", self.directory.path())
            .env("XDG_RUNTIME_DIR", self.directory.path())
            .env("PHX_PORT_CONFIG", self.directory.path().join("ports.toml"))
            .env_remove("PHX_PORT_INGRESS_CONFIG")
            .env_remove("PHX_PORT_RUNTIME_DIR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        BoundedChild {
            child: Some(child),
            deadline: Instant::now() + PROCESS_TIMEOUT,
        }
    }

    fn spawn_duplicate(&self) -> BoundedChild {
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        self.spawn(&["daemon", "--listen", &address.to_string()])
    }

    fn fill_queue(&self) -> Vec<Socket> {
        let mut queued = Vec::new();
        for _ in 0..8 {
            let socket = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
            socket.set_nonblocking(true).unwrap();
            match socket.connect(&SockAddr::unix(&self.path).unwrap()) {
                Ok(()) => queued.push(socket),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(!queued.is_empty());
                    return queued;
                }
                Err(error) => panic!("cannot fill isolated control accept queue: {error}"),
            }
        }
        panic!("isolated control accept queue did not fill");
    }

    fn accept(&self) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match self.listener.as_ref().unwrap().accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    let stream: UnixStream = socket.into();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    return stream;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "control client did not connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("cannot accept isolated control connection: {error}"),
            }
        }
    }

    fn assert_same_endpoint(&self, before: &fs::Metadata) {
        let after = fs::symlink_metadata(&self.path).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
    }
}

struct BoundedChild {
    child: Option<Child>,
    deadline: Instant,
}

impl BoundedChild {
    fn wait(mut self) -> (Output, bool) {
        let child = self.child.as_mut().unwrap();
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() {
                break false;
            }
            if Instant::now() >= self.deadline {
                child.kill().unwrap();
                break true;
            }
            thread::sleep(Duration::from_millis(5));
        };
        (
            self.child.take().unwrap().wait_with_output().unwrap(),
            timed_out,
        )
    }
}

impl Drop for BoundedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn assert_unavailable(result: (Output, bool), expected: &str) {
    let (output, timed_out) = result;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out,
        "control operation exceeded its external {PROCESS_TIMEOUT:?} watchdog: {stderr}"
    );
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains(expected), "{stderr}");
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
}

fn read_request(stream: &mut UnixStream, expected: &str) {
    let mut request = Vec::new();
    stream.take(1025).read_to_end(&mut request).unwrap();
    assert_eq!(request, expected.as_bytes());
}

#[test]
fn control_queries_time_out_when_accept_queue_is_full() {
    let endpoint = ControlEndpoint::new(Type::STREAM);
    let _queued = endpoint.fill_queue();
    for args in [&["proxy", "status"][..], &["proxy", "check", "--ready"][..]] {
        assert_unavailable(endpoint.spawn(args).wait(), "timed out");
    }
}

#[test]
fn duplicate_startup_times_out_without_unlinking_a_full_control_socket() {
    let endpoint = ControlEndpoint::new(Type::STREAM);
    let _queued = endpoint.fill_queue();
    let before = fs::symlink_metadata(&endpoint.path).unwrap();
    let result = endpoint.spawn_duplicate().wait();
    endpoint.assert_same_endpoint(&before);
    assert_unavailable(result, "timed out");
}

#[test]
fn duplicate_startup_preserves_endpoint_on_operational_connect_error() {
    let endpoint = ControlEndpoint::new(Type::from(nix::libc::SOCK_SEQPACKET));
    let before = fs::symlink_metadata(&endpoint.path).unwrap();
    let result = endpoint.spawn_duplicate().wait();
    endpoint.assert_same_endpoint(&before);
    assert_unavailable(result, "cannot check existing control socket");
}

#[test]
fn stale_control_socket_is_replaced_but_a_live_daemon_is_preserved() {
    let mut endpoint = ControlEndpoint::new(Type::STREAM);
    drop(endpoint.listener.take());
    let daemon = endpoint.spawn_duplicate();
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let (output, timed_out) = endpoint.spawn(&["proxy", "check", "--live"]).wait();
        assert!(!timed_out, "daemon health query exceeded its watchdog");
        if output.status.success() {
            let health: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(health["live"], true);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not replace its stale endpoint: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(5));
    }
    let before = fs::symlink_metadata(&endpoint.path).unwrap();
    assert_unavailable(
        endpoint.spawn_duplicate().wait(),
        "another TLS proxy daemon is already using",
    );
    endpoint.assert_same_endpoint(&before);
    let (stop, timed_out) = endpoint.spawn(&["proxy", "stop"]).wait();
    assert!(!timed_out);
    assert!(stop.status.success());
    assert_eq!(stop.stdout, b"stopping\n");
    let (output, timed_out) = daemon.wait();
    assert!(!timed_out, "fixture daemon did not stop");
    assert!(output.status.success());
}

#[test]
fn control_response_trickle_cannot_extend_the_absolute_deadline() {
    let endpoint = ControlEndpoint::new(Type::STREAM);
    let child = endpoint.spawn(&["proxy", "status"]);
    let mut stream = endpoint.accept();
    read_request(&mut stream, "STATUS\n");
    let writer = thread::spawn(move || {
        let mut sent = 0;
        for _ in 0..80 {
            if stream.write_all(b"x").is_err() {
                break;
            }
            sent += 1;
            thread::sleep(Duration::from_millis(50));
        }
        sent
    });
    let result = child.wait();
    assert!(
        writer.join().unwrap() >= 10,
        "fixture did not trickle bytes"
    );
    assert_unavailable(result, "cannot read daemon response");
}

#[test]
fn control_connect_and_response_share_one_deadline() {
    let endpoint = ControlEndpoint::new(Type::STREAM);
    let queued = endpoint.fill_queue();
    let child = endpoint.spawn(&["proxy", "status"]);
    thread::sleep(Duration::from_millis(1100));
    for _ in &queued {
        drop(endpoint.accept());
    }
    let mut stream = endpoint.accept();
    read_request(&mut stream, "STATUS\n");
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(1100));
        match stream.write_all(b"running\n") {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => panic!("cannot send delayed control response: {error}"),
        }
    });
    let result = child.wait();
    writer.join().unwrap();
    assert_unavailable(result, "cannot read daemon response");
}

#[test]
fn control_commands_preserve_framing_and_propagate_request_errors() {
    for (args, request) in [
        (&["proxy", "status"][..], "STATUS\n"),
        (&["proxy", "status", "--json"][..], "STATUS JSON\n"),
        (&["proxy", "check", "--live"][..], "CHECK LIVE\n"),
        (&["proxy", "check", "--ready"][..], "CHECK READY\n"),
        (&["proxy", "reload"][..], "RELOAD\n"),
        (&["proxy", "stop"][..], "STOP\n"),
    ] {
        let endpoint = ControlEndpoint::new(Type::STREAM);
        let child = endpoint.spawn(args);
        let mut stream = endpoint.accept();
        read_request(&mut stream, request);
        stream.write_all(b"ERROR fixture refusal\n").unwrap();
        drop(stream);
        assert_unavailable(
            child.wait(),
            "TLS proxy control request failed: fixture refusal",
        );
    }
}

#[test]
fn control_response_limits_and_utf8_validation_are_preserved() {
    for (response, expected) in [
        (
            vec![b'x'; 64 * 1024 + 1],
            "daemon response exceeds the 65536 byte limit",
        ),
        (vec![0xff], "daemon response is not valid UTF-8"),
    ] {
        let endpoint = ControlEndpoint::new(Type::STREAM);
        let child = endpoint.spawn(&["proxy", "status"]);
        let mut stream = endpoint.accept();
        read_request(&mut stream, "STATUS\n");
        stream.write_all(&response).unwrap();
        drop(stream);
        assert_unavailable(child.wait(), expected);
    }
}
