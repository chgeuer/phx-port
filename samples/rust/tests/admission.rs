#![cfg(any(target_os = "linux", target_os = "macos"))]

#[path = "../../../src/handoff_protocol.rs"]
mod handoff_protocol;

use handoff_protocol::{Handoff, Message, decode, encode};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr, connect, sendmsg, socket,
};
use std::fs::{self, File};
use std::io::{self, BufReader, IoSlice, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST: &[u8] = b"GET /admission HTTP/1.1\r\nHost: localhost\r\n\r\n";

struct BoundedChild(Child);

impl BoundedChild {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "owned child exceeded its deadline"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for BoundedChild {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

struct Server {
    child: BoundedChild,
    directory: TempDir,
    http: SocketAddr,
    https: SocketAddr,
    endpoint: PathBuf,
    tls: Arc<ClientConfig>,
}

impl Server {
    fn start(max_connections: usize, max_control_workers: usize) -> Self {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        let configuration = directory.path().join("openssl.cnf");
        fs::write(
            &configuration,
            "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = localhost\n",
        )
        .unwrap();
        let generator_errors = directory.path().join("openssl.stderr");
        // Runner defaults can add duplicate extensions before the explicit -addext options.
        let mut generator = BoundedChild(
            Command::new("openssl")
                .args(["req", "-config"])
                .arg(&configuration)
                .args([
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-sha256",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost",
                    "-addext",
                    "basicConstraints=critical,CA:FALSE",
                    "-keyout",
                ])
                .arg(&key)
                .arg("-out")
                .arg(&cert)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(File::create(&generator_errors).unwrap())
                .spawn()
                .expect("openssl is required to generate isolated TLS fixtures"),
        );
        assert!(
            generator.wait().success(),
            "fixture certificate generation failed: {}",
            fs::read_to_string(&generator_errors).unwrap()
        );

        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(&cert).unwrap())) {
            roots.add(cert.unwrap()).unwrap();
        }
        let tls = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let endpoint = directory.path().join("handoff").join("receiver.sock");
        let stdout = directory.path().join("stdout");
        let child = BoundedChild(
            Command::new(env!("CARGO_BIN_EXE_phxp-handoff-server"))
                .args(["--http", "127.0.0.1:0", "--https", "127.0.0.1:0", "--cert"])
                .arg(&cert)
                .arg("--key")
                .arg(&key)
                .arg("--project")
                .arg(directory.path())
                .arg("--handoff-socket")
                .arg(&endpoint)
                .env("PHXP_MAX_CONNECTIONS", max_connections.to_string())
                .env("PHXP_MAX_CONTROL_WORKERS", max_control_workers.to_string())
                .env("TOKIO_WORKER_THREADS", "2")
                .env_remove("PHXP_WORKLOAD_ID")
                .env("PHXP_ROLE", "https")
                .stdin(Stdio::null())
                .stdout(File::create(&stdout).unwrap())
                .stderr(File::create(directory.path().join("stderr")).unwrap())
                .spawn()
                .unwrap(),
        );
        let mut server = Self {
            child,
            directory,
            http: "127.0.0.1:0".parse().unwrap(),
            https: "127.0.0.1:0".parse().unwrap(),
            endpoint,
            tls,
        };
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            let output = fs::read_to_string(&stdout).unwrap();
            if let (Some(http), Some(https)) = (
                output
                    .lines()
                    .find_map(|line| line.strip_prefix("HTTP:  http://")),
                output
                    .lines()
                    .find_map(|line| line.strip_prefix("HTTPS: https://")),
            ) {
                server.http = http.parse().unwrap();
                server.https = https.parse().unwrap();
                return server;
            }
            assert!(
                server.child.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
                "sample did not start: {}",
                server.stderr()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn stderr(&self) -> String {
        fs::read_to_string(self.directory.path().join("stderr")).unwrap()
    }

    fn tcp(&self, address: SocketAddr) -> TcpStream {
        let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap();
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
    }

    fn https(&self) -> StreamOwned<ClientConnection, TcpStream> {
        self.tls_stream(self.tcp(self.https))
    }

    fn tls_stream(&self, stream: TcpStream) -> StreamOwned<ClientConnection, TcpStream> {
        StreamOwned::new(
            ClientConnection::new(Arc::clone(&self.tls), "localhost".try_into().unwrap()).unwrap(),
            stream,
        )
    }

    fn control(&self) -> UnixStream {
        #[cfg(target_os = "linux")]
        let socket_type = SockType::SeqPacket;
        #[cfg(target_os = "macos")]
        let socket_type = SockType::Stream;
        let fd = socket(AddressFamily::Unix, socket_type, SockFlag::empty(), None).unwrap();
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).unwrap();
        let control = UnixStream::from(fd);
        control.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        control.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        connect(control.as_raw_fd(), &UnixAddr::new(&self.endpoint).unwrap()).unwrap();
        control
    }

    fn wait_for_control_capacity(&self) -> UnixStream {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let mut control = self.control();
            match hello(&mut control) {
                Ok(()) => return control,
                Err(error) => {
                    assert!(
                        matches!(
                            error.kind(),
                            io::ErrorKind::BrokenPipe
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::UnexpectedEof
                        ),
                        "unexpected PHXP readiness failure: {error}"
                    );
                    assert!(
                        Instant::now() < deadline,
                        "PHXP capacity was not restored: {error}; {}",
                        self.stderr()
                    );
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn adopt(&self, id: u8) -> (TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let public_address = listener.local_addr().unwrap();
        let client = self.tcp(public_address);
        let (accepted, _) = listener.accept().unwrap();
        let mut control = self.wait_for_control_capacity();
        let packet = encode(&Message::Handoff(Handoff {
            connection_id: [id; 16],
            peeked_length: 0,
            accepted_at_ns: 0,
            requested_sni: "localhost".into(),
        }))
        .unwrap();
        assert_eq!(
            sendmsg::<UnixAddr>(
                control.as_raw_fd(),
                &[IoSlice::new(&packet)],
                &[ControlMessage::ScmRights(&[accepted.as_raw_fd()])],
                MsgFlags::empty(),
                None,
            )
            .unwrap(),
            packet.len()
        );
        drop(accepted);
        let mut response = [0; handoff_protocol::HEADER_LENGTH];
        control.read_exact(&mut response).unwrap();
        assert_eq!(
            decode(&response).unwrap(),
            Message::Adopted {
                connection_id: [id; 16]
            }
        );
        (client, public_address)
    }

    fn wait_for_http_capacity(&self) {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let mut replacement = self.tcp(self.http);
            if request(&mut replacement).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "closed connection retained its permit"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn shutdown(&mut self) {
        assert_eq!(
            unsafe { nix::libc::kill(self.child.0.id() as nix::libc::pid_t, nix::libc::SIGTERM) },
            0
        );
        let status = self.child.wait();
        assert!(
            status.success(),
            "sample shutdown failed: {status}; {}",
            self.stderr()
        );
        assert!(
            !self.endpoint.exists(),
            "shutdown left the owned endpoint behind"
        );
    }
}

fn request(stream: &mut (impl Read + Write)) -> io::Result<String> {
    stream.write_all(REQUEST)?;
    stream.flush()?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        assert!(
            headers.len() <= 4096,
            "fixture response headers exceeded their bound"
        );
    }
    let headers = String::from_utf8(headers).unwrap();
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
    let length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("sample must delimit its response")
        .parse()
        .unwrap();
    assert!(length <= 4096);
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(String::from_utf8(body).unwrap())
}

fn assert_closed(stream: &mut impl Read) {
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
        result => panic!("overload must close without starting another worker: {result:?}"),
    }
}

fn assert_rejected(stream: &mut (impl Read + Write), packet: &[u8]) {
    match stream.write_all(packet) {
        Ok(()) => assert_closed(stream),
        Err(error) => assert!(
            matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ),
            "overload must close, not stall: {error}"
        ),
    }
}

fn hello(control: &mut UnixStream) -> io::Result<()> {
    control.write_all(&encode(&Message::Hello).unwrap())?;
    let mut packet = [0; handoff_protocol::HEADER_LENGTH];
    control.read_exact(&mut packet)?;
    assert_eq!(decode(&packet).unwrap(), Message::Ready);
    Ok(())
}

#[test]
fn direct_http_and_https_share_a_connection_lifetime_limit() {
    let server = Server::start(2, 2);
    let mut http = server.tcp(server.http);
    assert!(request(&mut http).unwrap().contains("listener=http\n"));
    let mut https = server.https();
    assert!(request(&mut https).unwrap().contains("listener=https\n"));

    let mut excess = server.tcp(server.http);
    assert_rejected(&mut excess, REQUEST);
    assert!(request(&mut http).unwrap().contains("listener=http\n"));

    drop(https);
    server.wait_for_http_capacity();
}

#[test]
fn slow_phxp_negotiations_cannot_exceed_the_control_worker_limit() {
    let server = Server::start(8, 2);
    let mut first = server.control();
    hello(&mut first).unwrap();
    let mut second = server.control();
    hello(&mut second).unwrap();

    let mut excess = server.control();
    assert_rejected(&mut excess, &encode(&Message::Hello).unwrap());

    #[cfg(target_os = "linux")]
    {
        let workers = fs::read_dir(format!("/proc/{}/task", server.child.0.id()))
            .unwrap()
            .filter_map(
                |entry| match fs::read_to_string(entry.unwrap().path().join("comm")) {
                    Ok(name) => Some(name),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => panic!("cannot inspect owned control workers: {error}"),
                },
            )
            .filter(|name| name.trim() == "phxp-control")
            .count();
        assert_eq!(
            workers, 2,
            "slow negotiations must use exactly the configured worker bound"
        );
    }

    drop(first);
    let _replacement = server.wait_for_control_capacity();
}

#[test]
fn dequeued_adoptions_retain_the_shared_limit_until_tls_connections_close() {
    let server = Server::start(2, 2);
    let mut adopted = Vec::new();
    for id in 1..=2 {
        let (client, public_address) = server.adopt(id);
        let peer = client.local_addr().unwrap();
        let mut tls = server.tls_stream(client);
        let body = request(&mut tls).unwrap();
        assert!(body.contains("listener=phxp-handoff-https\n"));
        assert!(body.contains(&format!("peer={peer}\n")));
        assert!(body.contains(&format!("local={public_address}\n")));
        adopted.push(tls);
    }
    let mut direct = server.tcp(server.https);
    assert_closed(&mut direct);
    let mut control = server.control();
    assert_closed(&mut control);

    drop(adopted.pop());
    server.wait_for_http_capacity();
    assert!(
        request(&mut adopted[0])
            .unwrap()
            .contains("listener=phxp-handoff-https\n")
    );
}

#[test]
fn failed_direct_and_adopted_tls_handshakes_release_capacity_and_report_failures() {
    let mut server = Server::start(1, 1);
    for adopted in [false, true] {
        let mut client = if adopted {
            server.adopt(7).0
        } else {
            server.tcp(server.https)
        };
        client.write_all(b"not a TLS handshake").unwrap();
        let mut response = Vec::new();
        if let Err(error) = (&mut client).take(513).read_to_end(&mut response) {
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{error}");
        }
        assert!(response.len() <= 512, "failed TLS connection did not close");
        drop(client);
        server.wait_for_http_capacity();
    }
    server.shutdown();
    let stderr = server.stderr();
    let failed: u64 = stderr
        .lines()
        .filter(|line| line.starts_with("connections: "))
        .map(|line| {
            line.rsplit_once("failed=")
                .unwrap()
                .1
                .parse::<u64>()
                .unwrap()
        })
        .sum();
    assert_eq!(failed, 2, "{stderr}");
    assert!(
        !stderr.contains("localhost"),
        "ordinary failure logs must not expose SNI"
    );
}

#[test]
fn adoption_waits_for_readiness_probe_capacity_to_be_released() {
    let server = Server::start(1, 1);
    let mut probe = server.tcp(server.http);
    request(&mut probe).unwrap();

    let (client, _) = thread::scope(|scope| {
        scope.spawn(move || {
            thread::sleep(Duration::from_millis(100));
            drop(probe);
        });
        server.adopt(7)
    });
    let mut adopted = server.tls_stream(client);
    assert!(
        request(&mut adopted)
            .unwrap()
            .contains("listener=phxp-handoff-https\n")
    );
}

#[test]
fn shutdown_reaps_slow_control_workers_and_all_connection_paths() {
    let mut server = Server::start(4, 1);
    let mut http = server.tcp(server.http);
    request(&mut http).unwrap();
    let (client, _) = server.adopt(9);
    let mut adopted = server.tls_stream(client);
    request(&mut adopted).unwrap();
    let mut slow_tls = server.tcp(server.https);
    let mut control = server.control();
    hello(&mut control).unwrap();

    server.shutdown();

    assert_closed(&mut http);
    assert_closed(&mut slow_tls);
    assert_closed(&mut adopted.sock);
    assert_closed(&mut control);
}
