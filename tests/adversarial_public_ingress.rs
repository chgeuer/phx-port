#![cfg(target_os = "linux")]

#[path = "../src/handoff_protocol.rs"]
mod handoff_protocol;

use handoff_protocol::{Message, decode, encode};
use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector, TlsStream};
use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, rlim_t, setrlimit};
use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr, accept,
    bind, listen, recv, recvmsg, send, socket,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{ErrorKind, IoSliceMut, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::{TempDir, tempdir_in};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener as TokioTcpListener, TcpSocket as TokioTcpSocket, TcpStream as TokioTcpStream,
};
use tokio::sync::{Barrier, mpsc};
use tokio::task::JoinSet;

const TEST_RSA_PRIVATE_KEY: &str = include_str!("fixtures/proxy-test-rsa-key.pem");
const ROLE: &str = "https";
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const LOAD_RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);
const SIMULTANEOUS_RELEASE_MAX_SPAN: Duration = Duration::from_secs(1);
static HARNESS_LOCK: Mutex<()> = Mutex::new(());

fn harness_lock() -> std::sync::MutexGuard<'static, ()> {
    HARNESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn tempdir() -> std::io::Result<TempDir> {
    tempdir_in(Path::new("/tmp").canonicalize()?)
}

fn wait_until(description: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn reserve_v4_address() -> SocketAddr {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

fn reserve_v6_address() -> SocketAddr {
    TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Clone)]
struct TestIdentity {
    chain_pem: String,
    not_after_unix_seconds: u64,
}

impl TestIdentity {
    fn acceptor(&self) -> TlsAcceptor {
        let identity =
            Identity::from_pkcs8(self.chain_pem.as_bytes(), TEST_RSA_PRIVATE_KEY.as_bytes())
                .unwrap();
        TlsAcceptor::new(identity).unwrap()
    }
}

struct TestCa {
    params: CertificateParams,
    key: KeyPair,
    root_pem: String,
}

impl TestCa {
    fn new() -> Self {
        let now = SystemTime::now();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
        params.not_after = (now + Duration::from_secs(365 * 24 * 60 * 60)).into();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let certificate = params.self_signed(&key).unwrap();
        Self {
            params,
            key,
            root_pem: certificate.pem(),
        }
    }

    fn issue(&self, hostname: &str, valid_for: Duration) -> TestIdentity {
        let now = SystemTime::now();
        let server_key =
            KeyPair::from_pkcs8_pem_and_sign_algo(TEST_RSA_PRIVATE_KEY, &PKCS_RSA_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![hostname.to_string()]).unwrap();
        params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
        params.not_after = (now + valid_for).into();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let issuer = Issuer::from_params(&self.params, &self.key);
        let certificate = params.signed_by(&server_key, &issuer).unwrap();
        TestIdentity {
            chain_pem: format!("{}{}", certificate.pem(), self.root_pem),
            not_after_unix_seconds: (now + valid_for)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    fn connector(&self) -> TlsConnector {
        let mut builder = TlsConnector::builder();
        builder.disable_built_in_roots(true);
        builder.add_root_certificate(Certificate::from_pem(self.root_pem.as_bytes()).unwrap());
        builder.build().unwrap()
    }
}

#[derive(Default)]
struct BackendStats {
    accepted: AtomicUsize,
    handshakes: AtomicUsize,
    application_sessions: AtomicUsize,
    raw_sessions: AtomicUsize,
}

struct ActiveSession {
    count: Arc<AtomicUsize>,
}

impl ActiveSession {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self { count }
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

struct TestBackend {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    stats: Arc<BackendStats>,
    worker: Option<thread::JoinHandle<()>>,
}

impl TestBackend {
    fn start(identity: &TestIdentity, raw_hostname: &str) -> Self {
        Self::start_at(reserve_v4_address(), identity, raw_hostname)
    }

    fn start_at(address: SocketAddr, identity: &TestIdentity, raw_hostname: &str) -> Self {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket.bind(&SockAddr::from(address)).unwrap();
        socket.listen(1024).unwrap();
        socket.set_nonblocking(true).unwrap();
        let listener = TcpListener::from(socket);
        let address = listener.local_addr().unwrap();
        let acceptor = Arc::new(RwLock::new(identity.acceptor()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let active_sessions = Arc::new(AtomicUsize::new(0));
        let stats = Arc::new(BackendStats::default());
        let raw_hello = Arc::new(client_hello(Some(raw_hostname)));
        let worker_acceptor = Arc::clone(&acceptor);
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_active = Arc::clone(&active_sessions);
        let worker_stats = Arc::clone(&stats);
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TokioTcpListener::from_std(listener).unwrap();
                let mut sessions = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.unwrap();
                            worker_stats.accepted.fetch_add(1, Ordering::AcqRel);
                            let acceptor = Arc::clone(&worker_acceptor);
                            let shutdown = Arc::clone(&worker_shutdown);
                            let active = Arc::clone(&worker_active);
                            let stats = Arc::clone(&worker_stats);
                            let raw_hello = Arc::clone(&raw_hello);
                            sessions.spawn(async move {
                                serve_backend_connection(
                                    stream,
                                    acceptor,
                                    shutdown,
                                    active,
                                    stats,
                                    raw_hello,
                                )
                                .await
                            });
                        }
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {
                            if worker_shutdown.load(Ordering::Acquire) {
                                break;
                            }
                        }
                    }
                    while sessions.try_join_next().is_some() {}
                }
                sessions.abort_all();
                while sessions.join_next().await.is_some() {}
            });
        });
        Self {
            address,
            shutdown,
            stats,
            worker: Some(worker),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn stop(mut self) -> SocketAddr {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
        self.address
    }
}

impl Drop for TestBackend {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

async fn serve_backend_connection(
    stream: TokioTcpStream,
    acceptor: Arc<RwLock<TlsAcceptor>>,
    shutdown: Arc<AtomicBool>,
    active_sessions: Arc<AtomicUsize>,
    stats: Arc<BackendStats>,
    raw_hello: Arc<Vec<u8>>,
) -> Result<(), String> {
    let mut prefix = vec![0_u8; raw_hello.len().min(16)];
    let classification_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let raw = loop {
        let read = tokio::time::timeout_at(classification_deadline, stream.peek(&mut prefix))
            .await
            .map_err(|_| "backend classification timed out".to_string())?
            .map_err(|error| format!("backend classification failed: {error}"))?;
        if read == 0 || prefix[..read] != raw_hello[..read] {
            break false;
        }
        if read == prefix.len() {
            break true;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    if raw {
        stats.raw_sessions.fetch_add(1, Ordering::AcqRel);
        return serve_raw_session(stream, &raw_hello, shutdown, active_sessions).await;
    }

    let stream = stream
        .into_std()
        .map_err(|error| format!("cannot release backend stream from Tokio: {error}"))?;
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("cannot configure backend stream: {error}"))?;
    let acceptor = acceptor
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    tokio::task::spawn_blocking(move || {
        serve_tls_session(stream, acceptor, shutdown, active_sessions, stats)
    })
    .await
    .map_err(|error| format!("TLS backend task failed: {error}"))?
}

fn serve_tls_session(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    shutdown: Arc<AtomicBool>,
    active_sessions: Arc<AtomicUsize>,
    stats: Arc<BackendStats>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let mut tls = match acceptor.accept(stream) {
        Ok(tls) => tls,
        Err(_) => return Ok(()),
    };
    stats.handshakes.fetch_add(1, Ordering::AcqRel);
    let _active = ActiveSession::new(active_sessions);
    let mut application = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        match tls.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                if !application {
                    application = true;
                    stats.application_sessions.fetch_add(1, Ordering::AcqRel);
                }
                tls.write_all(&buffer[..read])
                    .map_err(|error| error.to_string())?;
                tls.flush().map_err(|error| error.to_string())?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                ) =>
            {
                if shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

async fn serve_raw_session(
    mut stream: TokioTcpStream,
    expected_hello: &[u8],
    shutdown: Arc<AtomicBool>,
    active_sessions: Arc<AtomicUsize>,
) -> Result<(), String> {
    let _active = ActiveSession::new(active_sessions);
    let mut hello = vec![0_u8; expected_hello.len()];
    stream
        .read_exact(&mut hello)
        .await
        .map_err(|error| format!("cannot read routed ClientHello: {error}"))?;
    if hello != expected_hello {
        return Err("routed ClientHello bytes changed".to_string());
    }
    let mut request = [0_u8; 8];
    loop {
        tokio::select! {
            result = stream.read_exact(&mut request) => {
                match result {
                    Ok(_) => stream
                        .write_all(&request)
                        .await
                        .map_err(|error| format!("cannot echo routed payload: {error}"))?,
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                    Err(error) => return Err(format!("cannot read routed payload: {error}")),
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                if shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
            }
        }
    }
}

fn endpoint_path(runtime: &Path, workload: &str) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(workload.as_bytes());
    digest.update([0]);
    digest.update(ROLE.as_bytes());
    let hash = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    runtime.join("handoff").join(format!("{hash}.sock"))
}

#[derive(Clone, Copy)]
enum ReceiverMode {
    AdoptTls,
    AdoptRaw,
    InvalidBeforeDelivery,
    InvalidAfterDelivery,
}

struct HandoffReceiver {
    endpoint: PathBuf,
    expected: usize,
    expected_successful: usize,
    successful: Arc<AtomicUsize>,
    control_worker: Option<thread::JoinHandle<()>>,
    tls_workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    raw_sender: Option<mpsc::UnboundedSender<TcpStream>>,
    raw_worker: Option<thread::JoinHandle<()>>,
    raw_shutdown: Arc<AtomicBool>,
}

impl HandoffReceiver {
    fn start(
        runtime: &Path,
        workload: &str,
        hostname: &str,
        identity: &TestIdentity,
        mode: ReceiverMode,
        expected: usize,
    ) -> Self {
        let endpoint = endpoint_path(runtime, workload);
        let expected_successful = if matches!(mode, ReceiverMode::AdoptTls | ReceiverMode::AdoptRaw)
        {
            expected
        } else {
            0
        };
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
        listen(&listener, Backlog::new(1024).unwrap()).unwrap();

        let successful = Arc::new(AtomicUsize::new(0));
        let tls_workers = Arc::new(Mutex::new(Vec::new()));
        let raw_shutdown = Arc::new(AtomicBool::new(false));
        let (raw_sender, mut raw_receiver) = mpsc::unbounded_channel::<TcpStream>();
        let expected_hello = Arc::new(client_hello(Some(hostname)));
        let raw_worker_shutdown = Arc::clone(&raw_shutdown);
        let raw_worker_hello = Arc::clone(&expected_hello);
        let raw_worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let mut sessions = JoinSet::new();
                while let Some(stream) = raw_receiver.recv().await {
                    stream.set_nonblocking(true).unwrap();
                    let stream = TokioTcpStream::from_std(stream).unwrap();
                    let hello = Arc::clone(&raw_worker_hello);
                    let shutdown = Arc::clone(&raw_worker_shutdown);
                    sessions.spawn(async move {
                        serve_raw_session(stream, &hello, shutdown, Arc::new(AtomicUsize::new(0)))
                            .await
                    });
                    while sessions.try_join_next().is_some() {}
                }
                while sessions.join_next().await.is_some() {}
            });
        });

        let worker_successful = Arc::clone(&successful);
        let worker_tls_workers = Arc::clone(&tls_workers);
        let worker_raw_sender = raw_sender.clone();
        let acceptor = identity.acceptor();
        let control_worker = thread::spawn(move || {
            for _ in 0..expected {
                let control = accept(listener.as_raw_fd()).unwrap();
                let control = unsafe { OwnedFd::from_raw_fd(control) };
                let mut packet = [0_u8; handoff_protocol::MAX_PACKET_LENGTH + 1];
                let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty()).unwrap();
                assert_eq!(decode(&packet[..length]).unwrap(), Message::Hello);

                if matches!(mode, ReceiverMode::InvalidBeforeDelivery) {
                    send(control.as_raw_fd(), b"invalid", MsgFlags::empty()).unwrap();
                    continue;
                }
                send(
                    control.as_raw_fd(),
                    &encode(&Message::Ready).unwrap(),
                    MsgFlags::empty(),
                )
                .unwrap();

                let (packet_length, mut descriptors) = receive_descriptor(&control, &mut packet);
                assert_eq!(descriptors.len(), 1);
                let connection_id = match decode(&packet[..packet_length]).unwrap() {
                    Message::Handoff(request) => request.connection_id,
                    request => panic!("unexpected PHXP request: {request:?}"),
                };
                let stream = TcpStream::from(descriptors.pop().unwrap());

                if matches!(mode, ReceiverMode::InvalidAfterDelivery) {
                    send(
                        control.as_raw_fd(),
                        &encode(&Message::Adopted {
                            connection_id: [0xFF; 16],
                        })
                        .unwrap(),
                        MsgFlags::empty(),
                    )
                    .unwrap();
                    drop(stream);
                    continue;
                }

                send(
                    control.as_raw_fd(),
                    &encode(&Message::Adopted { connection_id }).unwrap(),
                    MsgFlags::empty(),
                )
                .unwrap();
                worker_successful.fetch_add(1, Ordering::AcqRel);
                match mode {
                    ReceiverMode::AdoptTls => {
                        let acceptor = acceptor.clone();
                        worker_tls_workers
                            .lock()
                            .unwrap()
                            .push(thread::spawn(move || {
                                serve_tls_session(
                                    stream,
                                    acceptor,
                                    Arc::new(AtomicBool::new(false)),
                                    Arc::new(AtomicUsize::new(0)),
                                    Arc::new(BackendStats::default()),
                                )
                                .unwrap();
                            }));
                    }
                    ReceiverMode::AdoptRaw => worker_raw_sender.send(stream).unwrap(),
                    ReceiverMode::InvalidBeforeDelivery | ReceiverMode::InvalidAfterDelivery => {
                        unreachable!()
                    }
                }
            }
        });

        Self {
            endpoint,
            expected,
            expected_successful,
            successful,
            control_worker: Some(control_worker),
            tls_workers,
            raw_sender: Some(raw_sender),
            raw_worker: Some(raw_worker),
            raw_shutdown,
        }
    }

    fn finish(mut self) {
        self.control_worker.take().unwrap().join().unwrap();
        assert_eq!(
            self.successful.load(Ordering::Acquire),
            self.expected_successful,
            "{} of {} PHXP transfers were confirmed",
            self.successful.load(Ordering::Acquire),
            self.expected
        );
        for worker in self.tls_workers.lock().unwrap().drain(..) {
            worker.join().unwrap();
        }
        self.raw_shutdown.store(true, Ordering::Release);
        self.raw_sender.take();
        self.raw_worker.take().unwrap().join().unwrap();
        let _ = fs::remove_file(&self.endpoint);
    }
}

fn receive_descriptor(control: &OwnedFd, packet: &mut [u8]) -> (usize, Vec<OwnedFd>) {
    let mut ancillary = nix::cmsg_space!([i32; 1]);
    let mut iov = [IoSliceMut::new(packet)];
    let message = recvmsg::<UnixAddr>(
        control.as_raw_fd(),
        &mut iov,
        Some(&mut ancillary),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .unwrap();
    let descriptors = message
        .cmsgs()
        .unwrap()
        .flat_map(|control| match control {
            ControlMessageOwned::ScmRights(descriptors) => descriptors,
            _ => Vec::new(),
        })
        .map(|descriptor| unsafe { OwnedFd::from_raw_fd(descriptor) })
        .collect();
    (message.bytes, descriptors)
}

#[derive(Clone)]
struct Route {
    hostname: String,
    workload: String,
    port: u16,
    idle_timeout_seconds: Option<u64>,
}

impl Route {
    fn new(hostname: &str, workload: &str, port: u16) -> Self {
        Self {
            hostname: hostname.to_string(),
            workload: workload.to_string(),
            port,
            idle_timeout_seconds: None,
        }
    }

    fn with_disabled_idle_timeout(mut self) -> Self {
        self.idle_timeout_seconds = Some(0);
        self
    }
}

#[derive(Clone)]
struct HarnessLimits {
    active: usize,
    pre_routing: usize,
    relays: usize,
    handoffs: usize,
    accept_rate: usize,
    accept_burst: usize,
    source_rate: usize,
    source_burst: usize,
    source_pre_routing: usize,
    source_table: usize,
    source_ttl_seconds: u64,
    client_hello_timeout_ms: u64,
    source_policy: Option<String>,
}

impl Default for HarnessLimits {
    fn default() -> Self {
        Self {
            active: 64,
            pre_routing: 64,
            relays: 32,
            handoffs: 16,
            accept_rate: 10_000,
            accept_burst: 10_000,
            source_rate: 10_000,
            source_burst: 10_000,
            source_pre_routing: 64,
            source_table: 64,
            source_ttl_seconds: 1,
            client_hello_timeout_ms: 500,
            source_policy: None,
        }
    }
}

struct HarnessHost {
    root: TempDir,
    runtime: PathBuf,
    registry: PathBuf,
    ingress_config: PathBuf,
    root_certificate: PathBuf,
    stderr: PathBuf,
    metrics_address: SocketAddr,
    listen_addresses: Vec<SocketAddr>,
    routes: Vec<Route>,
    config: String,
    limits: HarnessLimits,
}

impl HarnessHost {
    fn new(root_pem: &str, routes: Vec<Route>, limits: HarnessLimits, with_ipv6: bool) -> Self {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
        fs::create_dir(runtime.join("handoff")).unwrap();
        fs::set_permissions(runtime.join("handoff"), fs::Permissions::from_mode(0o700)).unwrap();

        let registry = state.join("ports.toml");
        let mut registry_content = String::from("[ports]\n");
        for route in &routes {
            registry_content.push_str(&format!(
                "\n[ports.{}]\n{} = {}\n",
                route.workload, ROLE, route.port
            ));
        }
        fs::write(&registry, registry_content).unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();

        let metrics_address = reserve_v4_address();
        let ingress_config = root.path().join("ingress.toml");
        let config = render_config(metrics_address, &routes);
        fs::write(&ingress_config, &config).unwrap();
        fs::set_permissions(&ingress_config, fs::Permissions::from_mode(0o600)).unwrap();
        let root_certificate = root.path().join("root.pem");
        fs::write(&root_certificate, root_pem).unwrap();
        fs::set_permissions(&root_certificate, fs::Permissions::from_mode(0o600)).unwrap();
        let stderr = root.path().join("daemon.stderr");
        let mut listen_addresses = vec![reserve_v4_address()];
        if with_ipv6 {
            listen_addresses.push(reserve_v6_address());
        }

        Self {
            root,
            runtime,
            registry,
            ingress_config,
            root_certificate,
            stderr,
            metrics_address,
            listen_addresses,
            routes,
            config,
            limits,
        }
    }

    fn start(self) -> Daemon {
        let stderr = File::create(&self.stderr).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        command.arg("daemon");
        for address in &self.listen_addresses {
            command.args(["--listen", &address.to_string()]);
        }
        let limits = &self.limits;
        command.args([
            "--ingress-config",
            self.ingress_config.to_str().unwrap(),
            "--active-connections",
            &limits.active.to_string(),
            "--pre-routing-connections",
            &limits.pre_routing.to_string(),
            "--relay-connections",
            &limits.relays.to_string(),
            "--handoff-negotiations",
            &limits.handoffs.to_string(),
            "--accepts-per-second",
            &limits.accept_rate.to_string(),
            "--accept-burst",
            &limits.accept_burst.to_string(),
            "--source-accepts-per-second",
            &limits.source_rate.to_string(),
            "--source-accept-burst",
            &limits.source_burst.to_string(),
            "--source-pre-routing-connections",
            &limits.source_pre_routing.to_string(),
            "--source-table-capacity",
            &limits.source_table.to_string(),
            "--source-entry-ttl-seconds",
            &limits.source_ttl_seconds.to_string(),
            "--client-hello-timeout-ms",
            &limits.client_hello_timeout_ms.to_string(),
            "--task-budget",
            "512",
        ]);
        if let Some(policy) = &limits.source_policy {
            command.args(["--source-policy", policy]);
        }
        let child = command
            .env("HOME", self.root.path())
            .env("PHX_PORT_CONFIG", &self.registry)
            .env("PHX_PORT_RUNTIME_DIR", &self.runtime)
            .env("SSL_CERT_FILE", &self.root_certificate)
            .env_remove("PHX_PORT_INGRESS_CONFIG")
            .env_remove("XDG_RUNTIME_DIR")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        let mut daemon = Daemon {
            host: self,
            child: Some(child),
        };
        daemon.wait_until_live();
        daemon
    }
}

fn render_config(metrics_address: SocketAddr, routes: &[Route]) -> String {
    let mut config = format!(
        "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n\n\
         [ingress.metrics]\nlisten = \"{metrics_address}\"\n"
    );
    for route in routes {
        config.push_str(&format!(
            "\n[ingress.hosts.\"{}\"]\nworkload = \"{}\"\nrole = \"{}\"\nrequired = true\n",
            route.hostname, route.workload, ROLE
        ));
        if let Some(seconds) = route.idle_timeout_seconds {
            config.push_str(&format!("relay_idle_timeout_seconds = {seconds}\n"));
        }
    }
    config
}

struct Daemon {
    host: HarnessHost,
    child: Option<Child>,
}

impl Daemon {
    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn address_v4(&self) -> SocketAddr {
        *self
            .host
            .listen_addresses
            .iter()
            .find(|address| address.is_ipv4())
            .unwrap()
    }

    fn address_v6(&self) -> Option<SocketAddr> {
        self.host
            .listen_addresses
            .iter()
            .copied()
            .find(SocketAddr::is_ipv6)
    }

    fn control_path(&self) -> PathBuf {
        self.host.runtime.join("control/control.sock")
    }

    fn wait_until_live(&mut self) {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        loop {
            if self.control_path().exists() && self.status()["live"] == true {
                return;
            }
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "daemon exited before becoming live ({status}):\n{}",
                    fs::read_to_string(&self.host.stderr).unwrap_or_default()
                );
            }
            assert!(Instant::now() < deadline, "daemon did not become live");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_until_ready(&self) {
        wait_until("all required routes to become ready", || {
            let status = self.status();
            status["ready"] == true
                && status["active_routes"].as_u64() == Some(self.host.routes.len() as u64)
        });
    }

    fn status(&self) -> Value {
        let response = control_request(&self.control_path(), "STATUS JSON").unwrap();
        serde_json::from_str(&response).unwrap()
    }

    fn counter(&self, name: &str) -> u64 {
        self.status()["counters"][name]
            .as_u64()
            .unwrap_or_else(|| panic!("missing counter {name}"))
    }

    fn wait_counter_at_least(&self, name: &str, expected: u64) {
        wait_until(&format!("counter {name} >= {expected}"), || {
            self.counter(name) >= expected
        });
    }

    fn wait_for_no_active_connections(&self) {
        wait_until("ingress admission to return to zero", || {
            let status = self.status();
            status["admission"]["active_connections"]["in_use"] == 0
                && status["admission"]["pre_routing_connections"]["in_use"] == 0
                && status["admission"]["relay_connections"]["in_use"] == 0
                && status["admission"]["handoff_negotiations"]["in_use"] == 0
        });
    }

    fn metrics(&self) -> String {
        http_request(
            self.host.metrics_address,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
    }

    fn stop(mut self) -> String {
        let child = self.child.as_mut().unwrap();
        let result = unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGINT) };
        assert_eq!(result, 0, "cannot signal daemon");
        wait_until("daemon to stop", || child.try_wait().unwrap().is_some());
        let status = self.child.take().unwrap().wait().unwrap();
        let stderr = fs::read_to_string(&self.host.stderr).unwrap();
        assert!(status.success(), "daemon failed ({status}):\n{stderr}");
        stderr
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            let _ = unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGINT) };
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

fn control_request(path: &Path, request: &str) -> std::io::Result<String> {
    let mut stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("{request}\n").as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn http_request(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn connect_tls(
    connector: &TlsConnector,
    hostname: &str,
    address: SocketAddr,
) -> Result<TlsStream<TcpStream>, String> {
    let stream = TcpStream::connect(address).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    connector
        .connect(hostname, stream)
        .map_err(|error| error.to_string())
}

fn tls_round_trip(connector: &TlsConnector, hostname: &str, address: SocketAddr, payload: &[u8]) {
    let mut tls = connect_tls(connector, hostname, address).unwrap();
    tls.write_all(payload).unwrap();
    tls.flush().unwrap();
    let mut response = vec![0_u8; payload.len()];
    tls.read_exact(&mut response).unwrap();
    assert_eq!(response, payload);
}

fn client_hello(hostname: Option<&str>) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);

    let extensions = if let Some(hostname) = hostname {
        let name = hostname.as_bytes();
        let list_len = 1 + 2 + name.len();
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&(list_len as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server_name.extend_from_slice(name);

        let mut extension = vec![0, 0];
        extension.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extension.extend_from_slice(&server_name);
        extension
    } else {
        Vec::new()
    };
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![
        1,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);
    let split = handshake.len() / 2;
    let mut records = Vec::new();
    for part in [&handshake[..split], &handshake[split..]] {
        records.extend_from_slice(&[22, 3, 1]);
        records.extend_from_slice(&(part.len() as u16).to_be_bytes());
        records.extend_from_slice(part);
    }
    records
}

fn send_raw(address: SocketAddr, bytes: &[u8]) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(bytes).unwrap();
    let _ = stream.shutdown(Shutdown::Write);
}

fn assert_eventually_closed(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof
            ) => {}
        result => panic!("connection was not closed: {result:?}"),
    }
}

fn fragmented_tls_round_trip(connector: &TlsConnector, hostname: &str, ingress: SocketAddr) {
    let bridge = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let bridge_address = bridge.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (client, _) = bridge.accept().unwrap();
        let upstream = TcpStream::connect(ingress).unwrap();
        let mut from_client = client.try_clone().unwrap();
        let mut to_upstream = upstream.try_clone().unwrap();
        let client_to_ingress = thread::spawn(move || {
            let mut buffer = [0_u8; 16 * 1024];
            let mut fragments_remaining = 32;
            loop {
                let read = match from_client.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                let fragmented = read.min(fragments_remaining);
                for byte in &buffer[..fragmented] {
                    if to_upstream.write_all(std::slice::from_ref(byte)).is_err() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                fragments_remaining -= fragmented;
                if fragmented < read && to_upstream.write_all(&buffer[fragmented..read]).is_err() {
                    return;
                }
            }
            let _ = to_upstream.shutdown(Shutdown::Write);
        });
        let mut from_upstream = upstream;
        let mut to_client = client;
        let _ = std::io::copy(&mut from_upstream, &mut to_client);
        let _ = to_client.shutdown(Shutdown::Write);
        client_to_ingress.join().unwrap();
    });
    tls_round_trip(connector, hostname, bridge_address, b"fragmented");
    worker.join().unwrap();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceSnapshot {
    file_descriptors: usize,
    tasks: usize,
    resident_kibibytes: u64,
}

impl ResourceSnapshot {
    fn read(pid: u32) -> Self {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let resident_kibibytes = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|value| value.split_ascii_whitespace().next())
            .unwrap()
            .parse()
            .unwrap();
        Self {
            file_descriptors: fs::read_dir(format!("/proc/{pid}/fd")).unwrap().count(),
            tasks: fs::read_dir(format!("/proc/{pid}/task")).unwrap().count(),
            resident_kibibytes,
        }
    }

    fn max(self, other: Self) -> Self {
        Self {
            file_descriptors: self.file_descriptors.max(other.file_descriptors),
            tasks: self.tasks.max(other.tasks),
            resident_kibibytes: self.resident_kibibytes.max(other.resident_kibibytes),
        }
    }
}

struct ResourcePeak {
    snapshot: ResourceSnapshot,
    samples: usize,
}

impl ResourcePeak {
    fn new(snapshot: ResourceSnapshot) -> Self {
        Self {
            snapshot,
            samples: 1,
        }
    }

    fn observe(&mut self, snapshot: ResourceSnapshot) {
        self.snapshot = self.snapshot.max(snapshot);
        self.samples = self.samples.saturating_add(1);
    }
}

struct ProcessResourceSampler {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<ResourcePeak>>,
}

impl ProcessResourceSampler {
    fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut peak = ResourcePeak::new(ResourceSnapshot::read(pid));
            while !worker_stop.load(Ordering::Acquire) {
                thread::sleep(LOAD_RESOURCE_SAMPLE_INTERVAL);
                peak.observe(ResourceSnapshot::read(pid));
            }
            peak
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> ResourcePeak {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for ProcessResourceSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn resource_peaks_combine_every_sample_component_wise() {
    let first = ResourceSnapshot {
        file_descriptors: 100,
        tasks: 20,
        resident_kibibytes: 1_000,
    };
    let second = ResourceSnapshot {
        file_descriptors: 90,
        tasks: 30,
        resident_kibibytes: 900,
    };
    let third = ResourceSnapshot {
        file_descriptors: 80,
        tasks: 10,
        resident_kibibytes: 2_000,
    };
    let mut peak = ResourcePeak::new(first);
    peak.observe(second);
    peak.observe(third);
    assert_eq!(
        peak.snapshot,
        ResourceSnapshot {
            file_descriptors: 100,
            tasks: 30,
            resident_kibibytes: 2_000,
        }
    );
    assert_eq!(peak.samples, 3);
}

fn emit_qualification_resources(stage: &str, snapshot: ResourceSnapshot) {
    println!(
        "{}",
        serde_json::json!({
            "metric": "ingress_resources",
            "stage": stage,
            "file_descriptors": snapshot.file_descriptors,
            "tasks": snapshot.tasks,
            "resident_kibibytes": snapshot.resident_kibibytes,
        })
    );
}

fn emit_qualification_resource_peak(stage: &str, snapshot: ResourceSnapshot, samples: usize) {
    println!(
        "{}",
        serde_json::json!({
            "metric": "ingress_resources",
            "stage": stage,
            "file_descriptors": snapshot.file_descriptors,
            "tasks": snapshot.tasks,
            "resident_kibibytes": snapshot.resident_kibibytes,
            "samples": samples,
        })
    );
}

fn assert_resource_sample_floor(context: &str, samples: usize, elapsed: Duration) {
    let minimum_samples = usize::try_from(elapsed.as_secs())
        .unwrap_or(usize::MAX)
        .saturating_mul(10)
        .max(2);
    assert!(
        samples >= minimum_samples,
        "{context} sampled resources {samples} times, below the \
         {minimum_samples}-sample qualification floor"
    );
}

#[test]
fn relay_handoff_and_phxp_failures_are_end_to_end() {
    let _guard = harness_lock();
    const RELAY_HOST: &str = "relay.phase8.test";
    const HANDOFF_HOST: &str = "handoff.phase8.test";
    const PRE_FAILURE_HOST: &str = "pre-failure.phase8.test";
    const POST_FAILURE_HOST: &str = "post-failure.phase8.test";

    let ca = TestCa::new();
    let relay_identity = ca.issue(RELAY_HOST, Duration::from_secs(60 * 24 * 60 * 60));
    let handoff_identity = ca.issue(HANDOFF_HOST, Duration::from_secs(60 * 24 * 60 * 60));
    let pre_identity = ca.issue(PRE_FAILURE_HOST, Duration::from_secs(60 * 24 * 60 * 60));
    let post_identity = ca.issue(POST_FAILURE_HOST, Duration::from_secs(60 * 24 * 60 * 60));
    let relay_backend = TestBackend::start(&relay_identity, RELAY_HOST);
    let handoff_backend = TestBackend::start(&handoff_identity, HANDOFF_HOST);
    let pre_backend = TestBackend::start(&pre_identity, PRE_FAILURE_HOST);
    let post_backend = TestBackend::start(&post_identity, POST_FAILURE_HOST);
    let host = HarnessHost::new(
        &ca.root_pem,
        vec![
            Route::new(RELAY_HOST, "relay-workload", relay_backend.port()),
            Route::new(HANDOFF_HOST, "handoff-workload", handoff_backend.port()),
            Route::new(PRE_FAILURE_HOST, "pre-workload", pre_backend.port()),
            Route::new(POST_FAILURE_HOST, "post-workload", post_backend.port()),
        ],
        HarnessLimits::default(),
        false,
    );
    let handoff_receiver = HandoffReceiver::start(
        &host.runtime,
        "handoff-workload",
        HANDOFF_HOST,
        &handoff_identity,
        ReceiverMode::AdoptTls,
        1,
    );
    let pre_receiver = HandoffReceiver::start(
        &host.runtime,
        "pre-workload",
        PRE_FAILURE_HOST,
        &pre_identity,
        ReceiverMode::InvalidBeforeDelivery,
        1,
    );
    let post_receiver = HandoffReceiver::start(
        &host.runtime,
        "post-workload",
        POST_FAILURE_HOST,
        &post_identity,
        ReceiverMode::InvalidAfterDelivery,
        1,
    );
    let daemon = host.start();
    daemon.wait_until_ready();
    let connector = ca.connector();

    tls_round_trip(&connector, RELAY_HOST, daemon.address_v4(), b"relay path");
    tls_round_trip(
        &connector,
        HANDOFF_HOST,
        daemon.address_v4(),
        b"handoff path",
    );

    let backend_accepts = [
        relay_backend.stats.accepted.load(Ordering::Acquire),
        handoff_backend.stats.accepted.load(Ordering::Acquire),
        pre_backend.stats.accepted.load(Ordering::Acquire),
        post_backend.stats.accepted.load(Ordering::Acquire),
    ];
    assert!(connect_tls(&connector, "undeclared.phase8.test", daemon.address_v4()).is_err());
    daemon.wait_counter_at_least("rejected_connections", 1);
    assert_eq!(
        backend_accepts,
        [
            relay_backend.stats.accepted.load(Ordering::Acquire),
            handoff_backend.stats.accepted.load(Ordering::Acquire),
            pre_backend.stats.accepted.load(Ordering::Acquire),
            post_backend.stats.accepted.load(Ordering::Acquire),
        ],
        "undeclared SNI reached a Workload"
    );
    assert_eq!(daemon.status()["activity"]["active_probes"], 0);

    tls_round_trip(
        &connector,
        PRE_FAILURE_HOST,
        daemon.address_v4(),
        b"safe fallback",
    );
    let relays_before_post_failure = daemon.counter("relayed_connections");
    assert!(
        connect_tls(&connector, POST_FAILURE_HOST, daemon.address_v4()).is_err(),
        "post-delivery PHXP failure unexpectedly produced a TLS service"
    );

    daemon.wait_counter_at_least("successful_handoffs", 1);
    daemon.wait_counter_at_least("handoff_fallbacks", 2);
    daemon.wait_counter_at_least("delivered_handoff_failures", 1);
    assert_eq!(
        daemon.counter("relayed_connections"),
        relays_before_post_failure,
        "post-delivery failure illegally fell back to relay"
    );
    daemon.wait_for_no_active_connections();
    let metrics = daemon.metrics();
    assert!(metrics.contains("phx_port_handoffs_total{outcome=\"success\"} 1"));
    assert!(metrics.contains("phx_port_handoffs_total{outcome=\"post_delivery_failure\"} 1"));
    let denied = control_request(&daemon.control_path(), "RELOAD").unwrap();
    assert_eq!(denied, "ERROR control command is not authorized\n");
    let metrics_post = http_request(
        daemon.host.metrics_address,
        "POST /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(metrics_post.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

    handoff_receiver.finish();
    pre_receiver.finish();
    post_receiver.finish();
    let stderr = daemon.stop();
    assert!(!stderr.contains("undeclared.phase8.test"));
}

#[test]
fn malformed_fragmented_slow_and_ipv6_client_hellos_are_bounded() {
    let _guard = harness_lock();
    const HOSTNAME: &str = "parser.phase8.test";

    let ca = TestCa::new();
    let identity = ca.issue(HOSTNAME, Duration::from_secs(60 * 24 * 60 * 60));
    let backend = TestBackend::start(&identity, HOSTNAME);
    let host = HarnessHost::new(
        &ca.root_pem,
        vec![Route::new(HOSTNAME, "parser-workload", backend.port())],
        HarnessLimits::default(),
        true,
    );
    let daemon = host.start();
    daemon.wait_until_ready();
    let initial_rejections = daemon.counter("rejected_connections");

    send_raw(daemon.address_v4(), b"not tls");
    send_raw(daemon.address_v4(), &client_hello(None));
    send_raw(daemon.address_v4(), &[22, 3, 1, 0, 4, 1, 1, 0, 0]);
    daemon.wait_counter_at_least("rejected_connections", initial_rejections + 3);

    let mut slow = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(daemon.address_v4()).unwrap();
        stream.write_all(&[22]).unwrap();
        slow.push(stream);
    }
    thread::sleep(Duration::from_millis(700));
    for stream in slow {
        assert_eventually_closed(stream);
    }
    daemon.wait_counter_at_least("rejected_connections", initial_rejections + 7);

    let connector = ca.connector();
    fragmented_tls_round_trip(&connector, HOSTNAME, daemon.address_v4());
    tls_round_trip(
        &connector,
        HOSTNAME,
        daemon.address_v6().unwrap(),
        b"ipv6 path",
    );
    daemon.wait_for_no_active_connections();
    assert!(
        backend.stats.application_sessions.load(Ordering::Acquire) >= 2,
        "fragmented IPv4 and IPv6 traffic did not reach the declared Workload"
    );
    let status = daemon.status();
    assert_eq!(status["admission"]["active_connections"]["in_use"], 0);
    assert_eq!(status["admission"]["pre_routing_connections"]["in_use"], 0);
    daemon.stop();
}

#[test]
fn reload_rotation_long_lived_connections_and_log_flood_are_safe() {
    let _guard = harness_lock();
    const HOSTNAME: &str = "lifecycle.phase8.test";

    let ca = TestCa::new();
    let initial_identity = ca.issue(HOSTNAME, Duration::from_secs(60 * 24 * 60 * 60));
    let rotated_identity = ca.issue(HOSTNAME, Duration::from_secs(13 * 24 * 60 * 60));
    let backend = TestBackend::start(&initial_identity, HOSTNAME);
    let host = HarnessHost::new(
        &ca.root_pem,
        vec![
            Route::new(HOSTNAME, "lifecycle-workload", backend.port()).with_disabled_idle_timeout(),
        ],
        HarnessLimits::default(),
        false,
    );
    let daemon = host.start();
    daemon.wait_until_ready();
    let initial_not_after = daemon.status()["certificate_routes"][0]["not_after_unix_seconds"]
        .as_u64()
        .unwrap();
    let connector = ca.connector();

    let mut http2 = connect_tls(&connector, HOSTNAME, daemon.address_v4()).unwrap();
    let mut websocket = connect_tls(&connector, HOSTNAME, daemon.address_v4()).unwrap();
    for (stream, payload) in [
        (&mut http2, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()),
        (&mut websocket, b"\x81\x08websocket".as_slice()),
    ] {
        stream.write_all(payload).unwrap();
        let mut response = vec![0_u8; payload.len()];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(response, payload);
    }

    let rejected_before_flood = daemon.counter("rejected_connections");
    let random_names = (0..64)
        .map(|index| format!("random-{index}.phase8.test"))
        .collect::<Vec<_>>();
    for hostname in &random_names {
        send_raw(daemon.address_v4(), &client_hello(Some(hostname)));
    }
    daemon.wait_counter_at_least("rejected_connections", rejected_before_flood + 64);

    fs::write(
        &daemon.host.ingress_config,
        "[ingress]\nmode = \"public\"\nunknown_key = true\n",
    )
    .unwrap();
    wait_until("invalid reload rejection", || {
        let status = daemon.status();
        status["configuration"]["rejected_config_reloads"]
            .as_u64()
            .is_some_and(|count| count >= 1)
            && status["configuration"]["last_reload_error"] == "config_invalid"
            && status["generation"] == 1
    });
    for (stream, payload) in [
        (&mut http2, b"h2-alive".as_slice()),
        (&mut websocket, b"ws-alive".as_slice()),
    ] {
        stream.write_all(payload).unwrap();
        let mut response = vec![0_u8; payload.len()];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(response, payload);
    }
    fs::write(&daemon.host.ingress_config, &daemon.host.config).unwrap();
    wait_until("valid configuration recovery", || {
        daemon.status()["configuration"]["last_reload_error"].is_null()
    });
    drop(http2);
    drop(websocket);
    daemon.wait_for_no_active_connections();

    let backend_address = backend.stop();
    assert!(
        connect_tls(&connector, HOSTNAME, daemon.address_v4()).is_err(),
        "unavailable Workload unexpectedly served traffic"
    );
    wait_until("required route to become unavailable", || {
        daemon.status()["ready"] == false
    });
    let rotated_backend = TestBackend::start_at(backend_address, &rotated_identity, HOSTNAME);
    wait_until("rotated Workload certificate to activate", || {
        let status = daemon.status();
        status["ready"] == true
            && status["certificate_routes"][0]["not_after_unix_seconds"]
                .as_u64()
                .is_some_and(|not_after| not_after != initial_not_after)
    });
    tls_round_trip(
        &connector,
        HOSTNAME,
        daemon.address_v4(),
        b"rotated certificate",
    );
    daemon.wait_for_no_active_connections();
    assert!(
        daemon.counter("relay_backend_connect_failures") >= 1,
        "backend outage was not observed"
    );

    let stderr = daemon.stop();
    assert!(
        random_names
            .iter()
            .all(|hostname| !stderr.contains(hostname)),
        "random SNI was amplified into logs:\n{stderr}"
    );
    assert!(
        stderr.lines().count() < 128,
        "bounded random-SNI flood produced too many log lines:\n{stderr}"
    );
    assert!(!stderr.lines().any(|line| line.contains(" source=")));
    drop(rotated_backend);
    assert_ne!(
        initial_identity.not_after_unix_seconds,
        rotated_identity.not_after_unix_seconds
    );
}

#[derive(Clone, Copy)]
struct LoadProfile {
    handoffs: usize,
    mixed_relays: usize,
    long_lived_handoffs: usize,
    relay_limit: usize,
    relay_attempts: usize,
    sustain: Duration,
    launch_rate: usize,
}

const LOAD_CONNECTIONS_PER_SOURCE: usize = 16;

impl LoadProfile {
    fn from_environment() -> Self {
        match std::env::var("PHX_PORT_PHASE8_PROFILE").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("smoke") => Self {
                handoffs: 8,
                mixed_relays: 17,
                long_lived_handoffs: 4,
                relay_limit: 17,
                relay_attempts: 25,
                sustain: Duration::from_millis(250),
                launch_rate: 500,
            },
            Ok("qualification") => Self {
                handoffs: 25_000,
                mixed_relays: 5_000,
                long_lived_handoffs: 2_500,
                relay_limit: 5_000,
                relay_attempts: 7_500,
                sustain: Duration::from_secs(30 * 60),
                launch_rate: 1_000,
            },
            Ok(other) => panic!(
                "PHX_PORT_PHASE8_PROFILE must be \"smoke\" or \"qualification\", got {other:?}"
            ),
            Err(error) => panic!("cannot read PHX_PORT_PHASE8_PROFILE: {error}"),
        }
    }

    fn sustained_accepts(self) -> usize {
        let accepts = self
            .sustain
            .as_nanos()
            .checked_mul(self.generator_rate() as u128)
            .expect("sustained accept count overflowed")
            / Duration::from_secs(1).as_nanos();
        usize::try_from(accepts).expect("sustained accept count does not fit usize")
    }

    fn generator_rate(self) -> usize {
        self.launch_rate
            .saturating_add(self.launch_rate.div_ceil(100))
    }
}

async fn open_raw_connection(
    address: SocketAddr,
    hostname: String,
    id: u64,
    source: Option<Ipv4Addr>,
) -> Result<TokioTcpStream, String> {
    let stream = connect_raw_connection(address, &hostname, id, source).await?;
    route_raw_connection(stream, &hostname, id, source).await
}

fn raw_connection_context(hostname: &str, id: u64, source: Option<Ipv4Addr>) -> String {
    format!(
        "connection {id} for {hostname} from {}",
        source
            .map(|address| address.to_string())
            .unwrap_or_else(|| "the default source".to_string())
    )
}

async fn connect_raw_connection(
    address: SocketAddr,
    hostname: &str,
    id: u64,
    source: Option<Ipv4Addr>,
) -> Result<TokioTcpStream, String> {
    let context = || raw_connection_context(hostname, id, source);
    let stream = match source {
        Some(source) => {
            let socket = TokioTcpSocket::new_v4()
                .map_err(|error| format!("cannot create {}: {error}", context()))?;
            socket
                .bind(SocketAddr::from((source, 0)))
                .map_err(|error| format!("cannot bind {}: {error}", context()))?;
            socket
                .connect(address)
                .await
                .map_err(|error| format!("cannot connect {}: {error}", context()))?
        }
        None => TokioTcpStream::connect(address)
            .await
            .map_err(|error| format!("cannot connect {}: {error}", context()))?,
    };
    Ok(stream)
}

async fn route_raw_connection(
    mut stream: TokioTcpStream,
    hostname: &str,
    id: u64,
    source: Option<Ipv4Addr>,
) -> Result<TokioTcpStream, String> {
    let context = || raw_connection_context(hostname, id, source);
    stream
        .write_all(&client_hello(Some(hostname)))
        .await
        .map_err(|error| format!("cannot write ClientHello for {}: {error}", context()))?;
    stream
        .write_all(&id.to_be_bytes())
        .await
        .map_err(|error| format!("cannot write payload for {}: {error}", context()))?;
    let mut response = [0_u8; 8];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .map_err(|_| format!("routed payload response timed out for {}", context()))?
        .map_err(|error| format!("cannot read routed payload for {}: {error}", context()))?;
    if response != id.to_be_bytes() {
        return Err(format!("routed payload was corrupted for {}", context()));
    }
    Ok(stream)
}

struct MixedConnections {
    streams_by_route: Vec<Vec<TokioTcpStream>>,
    elapsed: Duration,
    resource_peak: ResourceSnapshot,
    resource_samples: usize,
}

fn loopback_source(group: usize) -> Ipv4Addr {
    let group = u32::try_from(group).expect("loopback source group does not fit IPv4");
    Ipv4Addr::from(
        0x7f01_0001_u32
            .checked_add(group)
            .expect("loopback source group overflowed"),
    )
}

fn load_source(id: usize) -> Ipv4Addr {
    loopback_source(id / LOAD_CONNECTIONS_PER_SOURCE)
}

#[test]
fn load_generator_never_exceeds_source_pre_routing_limit() {
    let first = load_source(0);
    assert!(
        (1..LOAD_CONNECTIONS_PER_SOURCE).all(|id| load_source(id) == first),
        "one source group should use every allowed pre-routing slot"
    );
    assert_ne!(
        load_source(LOAD_CONNECTIONS_PER_SOURCE),
        first,
        "the first connection beyond the source limit must use a new source"
    );
}

async fn open_mixed_raw_connections(
    address: SocketAddr,
    routes: &[(String, usize)],
    launch_rate: usize,
    pid: u32,
) -> Result<MixedConnections, String> {
    let mut jobs = JoinSet::new();
    let mut id = 0_u64;
    let resource_sampler = ProcessResourceSampler::start(pid);
    let started = tokio::time::Instant::now();
    for (route_index, (hostname, count)) in routes.iter().enumerate() {
        for _ in 0..*count {
            if launch_rate > 0 {
                let offset = Duration::from_nanos(
                    id.saturating_mul(1_000_000_000) / u64::try_from(launch_rate).unwrap(),
                );
                tokio::time::sleep_until(started + offset).await;
            }
            let hostname = hostname.clone();
            let source = load_source(id as usize);
            jobs.spawn(async move {
                open_raw_connection(address, hostname, id, Some(source))
                    .await
                    .map(|stream| (route_index, stream))
            });
            id = id.saturating_add(1);
        }
    }
    let mut streams_by_route = routes
        .iter()
        .map(|(_, count)| Vec::with_capacity(*count))
        .collect::<Vec<_>>();
    while let Some(result) = jobs.join_next().await {
        let (route_index, stream) = result.map_err(|error| error.to_string())??;
        streams_by_route[route_index].push(stream);
    }
    let elapsed = started.elapsed();
    let resource_peak = resource_sampler.finish();
    Ok(MixedConnections {
        streams_by_route,
        elapsed,
        resource_peak: resource_peak.snapshot,
        resource_samples: resource_peak.samples,
    })
}

async fn ping_raw_connections(streams: Vec<TokioTcpStream>) -> Result<Vec<TokioTcpStream>, String> {
    let mut jobs = JoinSet::new();
    for (index, mut stream) in streams.into_iter().enumerate() {
        jobs.spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let payload = (index as u64).to_be_bytes();
                stream
                    .write_all(&payload)
                    .await
                    .map_err(|error| format!("connection {index} write failed: {error}"))?;
                let mut response = [0_u8; 8];
                stream
                    .read_exact(&mut response)
                    .await
                    .map_err(|error| format!("connection {index} read failed: {error}"))?;
                if response != payload {
                    return Err(format!("connection {index} routed payload was corrupted"));
                }
                Ok::<_, String>(stream)
            })
            .await
            .map_err(|_| format!("connection {index} integrity check timed out"))?
        });
    }
    let mut returned = Vec::new();
    while let Some(result) = jobs.join_next().await {
        returned.push(result.map_err(|error| error.to_string())??);
    }
    Ok(returned)
}

struct SustainedConnections {
    streams: Vec<TokioTcpStream>,
    elapsed: Duration,
    accepted: usize,
    resource_peak: ResourceSnapshot,
    resource_samples: usize,
}

async fn sustain_handoff_accepts(
    address: SocketAddr,
    hostname: &str,
    streams: Vec<TokioTcpStream>,
    launch_rate: usize,
    sustain: Duration,
    accepted_offset: usize,
    pid: u32,
) -> Result<SustainedConnections, String> {
    if streams.is_empty() {
        return Err("sustained load requires replaceable handoff connections".to_string());
    }
    let accepts = sustain
        .as_nanos()
        .checked_mul(launch_rate as u128)
        .ok_or_else(|| "sustained accept count overflowed".to_string())?
        / Duration::from_secs(1).as_nanos();
    let accepts = usize::try_from(accepts)
        .map_err(|_| "sustained accept count does not fit usize".to_string())?;
    let accepted_offset = u64::try_from(accepted_offset).map_err(|error| error.to_string())?;
    let max_pending = launch_rate.saturating_mul(5).max(1);
    let resource_sampler = ProcessResourceSampler::start(pid);
    let started = tokio::time::Instant::now();
    let deadline = started + sustain;
    let mut rotating = VecDeque::from(streams);
    let mut jobs = JoinSet::new();
    let mut accepted = 0;

    for index in 0..accepts {
        let index = u64::try_from(index).map_err(|error| error.to_string())?;
        let offset = Duration::from_nanos(index.saturating_mul(1_000_000_000) / launch_rate as u64);
        tokio::time::sleep_until(started + offset).await;
        while let Some(result) = jobs.try_join_next() {
            let stream = result.map_err(|error| error.to_string())??;
            drop(
                rotating
                    .pop_front()
                    .expect("replaceable handoff pool cannot become empty"),
            );
            rotating.push_back(stream);
            accepted += 1;
        }
        if jobs.len() >= max_pending {
            return Err(format!(
                "sustained generator exceeded its {max_pending}-connection pending bound"
            ));
        }
        let id = accepted_offset.saturating_add(index);
        let source = load_source(id as usize);
        let hostname = hostname.to_string();
        jobs.spawn(open_raw_connection(address, hostname, id, Some(source)));
    }

    while let Some(result) = jobs.join_next().await {
        let stream = result.map_err(|error| error.to_string())??;
        drop(
            rotating
                .pop_front()
                .expect("replaceable handoff pool cannot become empty"),
        );
        rotating.push_back(stream);
        accepted += 1;
    }
    tokio::time::sleep_until(deadline).await;
    let elapsed = started.elapsed();
    let resource_peak = resource_sampler.finish();

    Ok(SustainedConnections {
        streams: rotating.into(),
        elapsed,
        accepted,
        resource_peak: resource_peak.snapshot,
        resource_samples: resource_peak.samples,
    })
}

struct AttemptedConnections {
    admitted: Vec<TokioTcpStream>,
    rejected: usize,
    elapsed: Duration,
    preconnected: usize,
    preconnect_elapsed: Duration,
    simultaneous_release_span: Duration,
    resource_peak: ResourceSnapshot,
    resource_samples: usize,
}

async fn attempt_simultaneous_raw_connections(
    address: SocketAddr,
    hostname: &str,
    count: usize,
    preconnect_rate: usize,
    pid: u32,
) -> Result<AttemptedConnections, String> {
    if count == 0 {
        return Err("simultaneous relay attempt requires at least one connection".to_string());
    }

    let resource_sampler = ProcessResourceSampler::start(pid);
    let started = tokio::time::Instant::now();
    let mut pending = Vec::with_capacity(count);
    for id in 0..count {
        if preconnect_rate > 0 {
            let offset = Duration::from_nanos(
                u64::try_from(id).unwrap().saturating_mul(1_000_000_000)
                    / u64::try_from(preconnect_rate).unwrap(),
            );
            tokio::time::sleep_until(started + offset).await;
        }
        let source = load_source(id);
        let stream = connect_raw_connection(address, hostname, id as u64, Some(source)).await?;
        pending.push((id, source, stream));
    }
    let preconnect_elapsed = started.elapsed();
    let preconnected = pending.len();

    // Route selection starts with the ClientHello. Preconnecting avoids losing
    // clients to the kernel listen backlog while this barrier keeps the actual
    // relay attempts simultaneous.
    let release_barrier = Arc::new(Barrier::new(count));
    let release_epoch = tokio::time::Instant::now();
    let mut jobs = JoinSet::new();
    for (id, source, stream) in pending {
        let hostname = hostname.to_string();
        let release_barrier = Arc::clone(&release_barrier);
        jobs.spawn(async move {
            release_barrier.wait().await;
            let released_at = release_epoch.elapsed();
            let result = route_raw_connection(stream, &hostname, id as u64, Some(source)).await;
            (released_at, result)
        });
    }

    let mut admitted = Vec::new();
    let mut rejected = 0;
    let mut first_release = None;
    let mut last_release = Duration::ZERO;
    while let Some(result) = jobs.join_next().await {
        let (released_at, result) = result.map_err(|error| error.to_string())?;
        first_release =
            Some(first_release.map_or(released_at, |first: Duration| first.min(released_at)));
        last_release = last_release.max(released_at);
        match result {
            Ok(stream) => admitted.push(stream),
            Err(_) => rejected += 1,
        }
    }
    let elapsed = started.elapsed();
    let resource_peak = resource_sampler.finish();
    let simultaneous_release_span =
        last_release.saturating_sub(first_release.unwrap_or(Duration::ZERO));
    Ok(AttemptedConnections {
        admitted,
        rejected,
        elapsed,
        preconnected,
        preconnect_elapsed,
        simultaneous_release_span,
        resource_peak: resource_peak.snapshot,
        resource_samples: resource_peak.samples,
    })
}

fn ensure_open_file_limit(required: rlim_t) {
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    if soft >= required || soft == RLIM_INFINITY {
        return;
    }
    assert!(
        hard == RLIM_INFINITY || hard >= required,
        "qualification harness requires {required} file descriptors, hard limit is {hard}"
    );
    setrlimit(Resource::RLIMIT_NOFILE, required, hard).unwrap();
}

fn assert_resource_bounds(
    context: &str,
    snapshot: ResourceSnapshot,
    baseline: ResourceSnapshot,
    active_limit: usize,
    relay_count: usize,
    handoff_workers: usize,
) {
    assert!(
        snapshot.file_descriptors
            <= baseline.file_descriptors + active_limit + relay_count + handoff_workers + 16,
        "{context} FD use exceeded its configuration-derived bound: \
         baseline={baseline:?}, snapshot={snapshot:?}"
    );
    assert!(
        snapshot.tasks <= baseline.tasks + handoff_workers + 4,
        "{context} task use exceeded its bounded pools: \
         baseline={baseline:?}, snapshot={snapshot:?}"
    );
    assert!(
        snapshot.resident_kibibytes
            <= baseline.resident_kibibytes + u64::try_from(relay_count).unwrap() * 256 + 64 * 1024,
        "{context} RSS use exceeded its configuration-derived bound: \
         baseline={baseline:?}, snapshot={snapshot:?}"
    );
}

#[test]
#[ignore = "qualification-scale resource gate"]
fn qualification_scale_relay_shedding_uses_relay_capacity() {
    let _guard = harness_lock();
    const RELAY_HOST: &str = "shedding-relay.phase8.test";
    const ACTIVE_LIMIT: usize = 7_500;
    const RELAY_LIMIT: usize = 5_000;
    const RELAY_ATTEMPTS: usize = 7_500;

    ensure_open_file_limit(30_000);
    let ca = TestCa::new();
    let relay_identity = ca.issue(RELAY_HOST, Duration::from_secs(60 * 24 * 60 * 60));
    let relay_backend = TestBackend::start(&relay_identity, RELAY_HOST);
    let limits = HarnessLimits {
        active: ACTIVE_LIMIT,
        pre_routing: ACTIVE_LIMIT,
        relays: RELAY_LIMIT,
        handoffs: 256,
        accept_rate: RELAY_ATTEMPTS + 128,
        accept_burst: RELAY_ATTEMPTS + 128,
        source_rate: RELAY_ATTEMPTS + 128,
        source_burst: RELAY_ATTEMPTS + 128,
        source_pre_routing: LOAD_CONNECTIONS_PER_SOURCE,
        source_table: RELAY_ATTEMPTS
            .div_ceil(LOAD_CONNECTIONS_PER_SOURCE)
            .saturating_add(LOAD_CONNECTIONS_PER_SOURCE),
        source_ttl_seconds: 1,
        client_hello_timeout_ms: 10_000,
        source_policy: None,
    };
    let host = HarnessHost::new(
        &ca.root_pem,
        vec![
            Route::new(RELAY_HOST, "shedding-relay", relay_backend.port())
                .with_disabled_idle_timeout(),
        ],
        limits,
        false,
    );
    let daemon = host.start();
    daemon.wait_until_ready();
    let baseline = ResourceSnapshot::read(daemon.pid());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    let attempted = runtime
        .block_on(attempt_simultaneous_raw_connections(
            daemon.address_v4(),
            RELAY_HOST,
            RELAY_ATTEMPTS,
            1_010,
            daemon.pid(),
        ))
        .unwrap();
    let status = daemon.status();
    assert_eq!(attempted.preconnected, RELAY_ATTEMPTS, "{status}");
    assert!(
        attempted.simultaneous_release_span <= SIMULTANEOUS_RELEASE_MAX_SPAN,
        "barrier-released ClientHellos spanned {:?}, above the {:?} simultaneous-attempt bound",
        attempted.simultaneous_release_span,
        SIMULTANEOUS_RELEASE_MAX_SPAN
    );
    assert_resource_sample_floor(
        "qualification-scale relay shedding",
        attempted.resource_samples,
        attempted.elapsed,
    );
    assert_eq!(
        daemon.counter("accepted_connections"),
        RELAY_ATTEMPTS as u64,
        "{status}"
    );
    assert_eq!(attempted.admitted.len(), RELAY_LIMIT, "{status}");
    assert_eq!(attempted.rejected, RELAY_ATTEMPTS - RELAY_LIMIT, "{status}");
    assert_eq!(
        daemon.counter("rejected_relay_capacity"),
        (RELAY_ATTEMPTS - RELAY_LIMIT) as u64,
        "{status}"
    );

    let admitted = runtime
        .block_on(ping_raw_connections(attempted.admitted))
        .unwrap();
    drop(admitted);
    daemon.wait_for_no_active_connections();
    wait_until(
        "relay tasks and memory to return to their quiescent bounds",
        || {
            let recovered = ResourceSnapshot::read(daemon.pid());
            recovered.tasks <= baseline.tasks + 4
                && recovered.resident_kibibytes <= baseline.resident_kibibytes + 16 * 1024
        },
    );
    daemon.stop();
}

#[test]
fn mixed_load_and_fd_pressure_recover_to_baseline() {
    let _guard = harness_lock();
    const RELAY_HOST: &str = "load-relay.phase8.test";
    const HANDOFF_HOST: &str = "load-handoff.phase8.test";

    let profile = LoadProfile::from_environment();
    let qualification = std::env::var("PHX_PORT_PHASE8_PROFILE").as_deref() == Ok("qualification");
    let sustained_accepts = profile.sustained_accepts();
    assert!(
        profile.long_lived_handoffs < profile.handoffs,
        "load profile must retain replaceable handoff connections"
    );
    if qualification {
        assert_ne!(
            nix::unistd::geteuid().as_raw(),
            0,
            "qualification must run as an unprivileged service user"
        );
        assert_eq!(profile.handoffs, 25_000);
        assert_eq!(profile.mixed_relays, 5_000);
        assert_eq!(profile.long_lived_handoffs + profile.mixed_relays, 7_500);
        assert_eq!(profile.relay_attempts, 7_500);
        assert_eq!(profile.relay_limit, 5_000);
        assert_eq!(profile.launch_rate, 1_000);
        assert_eq!(profile.sustain, Duration::from_secs(30 * 60));
        ensure_open_file_limit(100_000);
    }
    let ca = TestCa::new();
    let relay_identity = ca.issue(RELAY_HOST, Duration::from_secs(60 * 24 * 60 * 60));
    let handoff_identity = ca.issue(HANDOFF_HOST, Duration::from_secs(60 * 24 * 60 * 60));
    let relay_backend = TestBackend::start(&relay_identity, RELAY_HOST);
    let handoff_backend = TestBackend::start(&handoff_identity, HANDOFF_HOST);
    let active_limit = profile
        .relay_attempts
        .max(profile.mixed_relays + 32)
        .min(8_192);
    assert!(
        profile.relay_attempts <= active_limit,
        "relay shedding attempt exceeds the ingress state-machine limit"
    );
    let handoff_worker_limit = active_limit.min(256);
    let burst = profile
        .handoffs
        .saturating_add(profile.mixed_relays)
        .saturating_add(profile.relay_attempts)
        .saturating_add(128);
    let limits = HarnessLimits {
        active: active_limit,
        pre_routing: active_limit,
        relays: profile.relay_limit,
        handoffs: handoff_worker_limit,
        accept_rate: burst,
        accept_burst: burst,
        source_rate: burst,
        source_burst: burst,
        source_pre_routing: LOAD_CONNECTIONS_PER_SOURCE,
        source_table: profile
            .relay_attempts
            .div_ceil(LOAD_CONNECTIONS_PER_SOURCE)
            .saturating_add(LOAD_CONNECTIONS_PER_SOURCE),
        source_ttl_seconds: 1,
        client_hello_timeout_ms: if qualification { 10_000 } else { 2_000 },
        source_policy: Some(format!(
            "127.0.0.1/32={burst},{burst},{LOAD_CONNECTIONS_PER_SOURCE}"
        )),
    };
    let host = HarnessHost::new(
        &ca.root_pem,
        vec![
            Route::new(RELAY_HOST, "load-relay", relay_backend.port()).with_disabled_idle_timeout(),
            Route::new(HANDOFF_HOST, "load-handoff", handoff_backend.port())
                .with_disabled_idle_timeout(),
        ],
        limits,
        false,
    );
    let handoff_receiver = HandoffReceiver::start(
        &host.runtime,
        "load-handoff",
        HANDOFF_HOST,
        &handoff_identity,
        ReceiverMode::AdoptRaw,
        profile.handoffs.saturating_add(sustained_accepts),
    );
    let log_window_started = Instant::now();
    let daemon = host.start();
    daemon.wait_until_ready();
    let baseline = ResourceSnapshot::read(daemon.pid());
    if qualification {
        emit_qualification_resources("baseline", baseline);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let mixed = runtime
        .block_on(open_mixed_raw_connections(
            daemon.address_v4(),
            &[
                (HANDOFF_HOST.to_string(), profile.handoffs),
                (RELAY_HOST.to_string(), profile.mixed_relays),
            ],
            profile.generator_rate(),
            daemon.pid(),
        ))
        .unwrap_or_else(|error| {
            panic!(
                "initial mixed load failed: {error}; daemon status: {}",
                daemon.status()
            )
        });
    if qualification {
        let achieved_rate =
            (profile.handoffs + profile.mixed_relays) as f64 / mixed.elapsed.as_secs_f64();
        assert!(
            achieved_rate >= profile.launch_rate as f64,
            "qualification generator achieved {achieved_rate:.1} connections/s, below the \
             required {} connections/s",
            profile.launch_rate
        );
        println!(
            "{{\"metric\":\"initial_accepted_connection_rate\",\"value\":{achieved_rate:.3},\
             \"unit\":\"connections_per_second\"}}"
        );
    }
    assert_eq!(mixed.streams_by_route.len(), 2);
    let mut initial_peak = mixed.resource_peak;
    let mut initial_resource_samples = mixed.resource_samples;
    let mut streams_by_route = mixed.streams_by_route;
    let mut handoffs = streams_by_route.remove(0);
    let mut relays = streams_by_route.remove(0);
    daemon.wait_counter_at_least("successful_handoffs", profile.handoffs as u64);
    daemon.wait_counter_at_least("relayed_connections", profile.mixed_relays as u64);
    wait_until("all mixed relays to remain admitted", || {
        daemon.status()["admission"]["relay_connections"]["in_use"] == profile.mixed_relays as u64
    });
    assert!(
        profile.mixed_relays > 16,
        "smoke profile must prove source permits are released after routing"
    );
    initial_peak = initial_peak.max(ResourceSnapshot::read(daemon.pid()));
    initial_resource_samples += 1;
    assert_resource_sample_floor("initial load", initial_resource_samples, mixed.elapsed);
    assert!(
        initial_peak.file_descriptors >= baseline.file_descriptors + profile.mixed_relays * 2,
        "relay FD pressure was not observable: baseline={baseline:?}, peak={initial_peak:?}"
    );
    assert_resource_bounds(
        "initial mixed load",
        initial_peak,
        baseline,
        active_limit,
        profile.mixed_relays,
        handoff_worker_limit,
    );
    if qualification {
        emit_qualification_resource_peak(
            "initial_mixed_peak",
            initial_peak,
            initial_resource_samples,
        );
        println!(
            "{}",
            serde_json::json!({
                "metric": "live_connection_mix",
                "total": profile.handoffs + profile.mixed_relays,
                "confirmed_handoffs": profile.handoffs,
                "relays": profile.mixed_relays,
                "unchanged_long_lived_handoffs": profile.long_lived_handoffs,
                "unchanged_long_lived_relays": profile.mixed_relays,
            })
        );
    }

    handoffs = runtime.block_on(ping_raw_connections(handoffs)).unwrap();
    relays = runtime.block_on(ping_raw_connections(relays)).unwrap();
    let mut rotating_handoffs = handoffs.split_off(profile.long_lived_handoffs);
    let mut long_lived_handoffs = handoffs;
    let sustained = runtime
        .block_on(sustain_handoff_accepts(
            daemon.address_v4(),
            HANDOFF_HOST,
            rotating_handoffs,
            profile.generator_rate(),
            profile.sustain,
            profile.handoffs + profile.mixed_relays,
            daemon.pid(),
        ))
        .unwrap();
    assert_eq!(
        sustained.accepted, sustained_accepts,
        "sustained generator did not complete every scheduled accept"
    );
    let sustained_rate = sustained.accepted as f64 / sustained.elapsed.as_secs_f64();
    if qualification {
        assert!(
            sustained_rate >= profile.launch_rate as f64,
            "qualification sustained rate was {sustained_rate:.1} connections/s, below the \
             required {} connections/s",
            profile.launch_rate
        );
        println!(
            "{{\"metric\":\"sustained_accepted_connection_rate\",\"value\":\
             {sustained_rate:.3},\"unit\":\"connections_per_second\",\
             \"duration_seconds\":{:.3}}}",
            sustained.elapsed.as_secs_f64()
        );
    }
    rotating_handoffs = sustained.streams;
    let sustained_resource_samples = sustained.resource_samples.saturating_add(1);
    let sustained_peak = sustained
        .resource_peak
        .max(ResourceSnapshot::read(daemon.pid()));
    assert_resource_sample_floor(
        "sustained mixed load",
        sustained_resource_samples,
        sustained.elapsed,
    );
    assert_resource_bounds(
        "sustained mixed load",
        sustained_peak,
        baseline,
        active_limit,
        profile.mixed_relays,
        handoff_worker_limit,
    );
    if qualification {
        emit_qualification_resource_peak(
            "sustained_mixed_peak",
            sustained_peak,
            sustained_resource_samples,
        );
    }
    daemon.wait_counter_at_least(
        "successful_handoffs",
        profile.handoffs.saturating_add(sustained_accepts) as u64,
    );
    assert_eq!(
        long_lived_handoffs.len() + rotating_handoffs.len() + relays.len(),
        profile.handoffs + profile.mixed_relays,
        "sustained replacement did not preserve the live connection target"
    );
    long_lived_handoffs = runtime
        .block_on(ping_raw_connections(long_lived_handoffs))
        .unwrap();
    rotating_handoffs = runtime
        .block_on(ping_raw_connections(rotating_handoffs))
        .unwrap();
    relays = runtime.block_on(ping_raw_connections(relays)).unwrap();
    let final_live = ResourceSnapshot::read(daemon.pid());
    assert_resource_bounds(
        "end of sustained mixed load",
        final_live,
        baseline,
        active_limit,
        profile.mixed_relays,
        handoff_worker_limit,
    );
    if qualification {
        emit_qualification_resources("end_of_sustained_load", final_live);
        println!(
            "{}",
            serde_json::json!({
                "metric": "sustained_handoff_replacements",
                "accepted": sustained.accepted,
                "live_connections_preserved": profile.handoffs + profile.mixed_relays,
                "unchanged_long_lived_connections":
                    profile.long_lived_handoffs + profile.mixed_relays,
            })
        );
    }
    drop(long_lived_handoffs);
    drop(rotating_handoffs);
    drop(relays);
    daemon.wait_for_no_active_connections();
    handoff_receiver.finish();

    let accepted_before_shedding = daemon.counter("accepted_connections");
    let relay_rejections_before_shedding = daemon.counter("rejected_relay_capacity");
    let attempted = runtime
        .block_on(attempt_simultaneous_raw_connections(
            daemon.address_v4(),
            RELAY_HOST,
            profile.relay_attempts,
            profile.generator_rate(),
            daemon.pid(),
        ))
        .unwrap();
    let rejected = attempted.rejected;
    assert_eq!(
        attempted.preconnected, profile.relay_attempts,
        "not every relay TCP connection was established before the simultaneous release"
    );
    assert!(
        attempted.simultaneous_release_span <= SIMULTANEOUS_RELEASE_MAX_SPAN,
        "barrier-released ClientHellos spanned {:?}, above the {:?} simultaneous-attempt bound",
        attempted.simultaneous_release_span,
        SIMULTANEOUS_RELEASE_MAX_SPAN
    );
    assert_resource_sample_floor(
        "simultaneous relay shedding",
        attempted.resource_samples,
        attempted.elapsed,
    );
    let relay_pressure = attempted.resource_peak;
    let attempted_relays = attempted.admitted;
    assert_eq!(
        daemon.counter("accepted_connections") - accepted_before_shedding,
        profile.relay_attempts as u64,
        "not every preconnected relay attempt reached ingress"
    );
    assert_eq!(
        attempted_relays.len(),
        profile.relay_limit,
        "relay shedding did not preserve exactly the configured maximum"
    );
    assert_eq!(
        rejected,
        profile.relay_attempts - profile.relay_limit,
        "unexpected relay attempt outcome"
    );
    wait_until(
        "exact relay limit to remain admitted after overload",
        || {
            daemon.status()["admission"]["relay_connections"]["in_use"]
                == profile.relay_limit as u64
        },
    );
    daemon.wait_counter_at_least(
        "rejected_relay_capacity",
        relay_rejections_before_shedding + (profile.relay_attempts - profile.relay_limit) as u64,
    );
    let relay_capacity_rejections =
        daemon.counter("rejected_relay_capacity") - relay_rejections_before_shedding;
    assert_eq!(
        relay_capacity_rejections,
        (profile.relay_attempts - profile.relay_limit) as u64,
        "relay attempts were rejected for an unexpected reason"
    );
    let attempted_relays = runtime
        .block_on(ping_raw_connections(attempted_relays))
        .unwrap();
    assert_resource_bounds(
        "relay overload",
        relay_pressure,
        baseline,
        active_limit,
        profile.relay_limit,
        handoff_worker_limit,
    );
    if qualification {
        emit_qualification_resource_peak(
            "relay_shedding_peak",
            relay_pressure,
            attempted.resource_samples,
        );
        println!(
            "{}",
            serde_json::json!({
                "metric": "relay_shedding",
                "attempted": profile.relay_attempts,
                "admitted": profile.relay_limit,
                "rejected": rejected,
                "relay_capacity_rejections": relay_capacity_rejections,
                "tcp_connections_preestablished": attempted.preconnected,
                "tcp_preconnect_duration_seconds":
                    attempted.preconnect_elapsed.as_secs_f64(),
                "client_hello_release": "barrier",
                "client_hello_release_span_milliseconds":
                    attempted.simultaneous_release_span.as_secs_f64() * 1_000.0,
            })
        );
    }
    drop(attempted_relays);
    daemon.wait_for_no_active_connections();
    thread::sleep(Duration::from_millis(1_100));
    let rejections_before_eviction = daemon.counter("rejected_connections");
    send_raw(daemon.address_v4(), b"expired source table trigger");
    daemon.wait_counter_at_least("rejected_connections", rejections_before_eviction + 1);
    wait_until("expired source buckets to be evicted", || {
        daemon.status()["admission"]["source_entries"]["in_use"]
            .as_u64()
            .is_some_and(|entries| entries <= 1)
    });
    wait_until("idle PHXP worker threads to retire", || {
        ResourceSnapshot::read(daemon.pid()).tasks <= baseline.tasks + 4
    });

    let recovered = ResourceSnapshot::read(daemon.pid());
    assert!(
        recovered.file_descriptors <= baseline.file_descriptors + 2,
        "daemon FDs did not return to baseline: baseline={baseline:?}, recovered={recovered:?}"
    );
    assert!(
        recovered.tasks <= baseline.tasks + 4,
        "daemon tasks did not return to their quiescent bound after load: \
         baseline={baseline:?}, recovered={recovered:?}"
    );
    let peak_resident = initial_peak
        .resident_kibibytes
        .max(sustained_peak.resident_kibibytes)
        .max(final_live.resident_kibibytes)
        .max(relay_pressure.resident_kibibytes);
    assert!(
        recovered.resident_kibibytes <= peak_resident
            && recovered.resident_kibibytes <= baseline.resident_kibibytes + 16 * 1024,
        "daemon memory did not recover within the bounded allocator allowance: \
         baseline={baseline:?}, peak={initial_peak:?}, recovered={recovered:?}"
    );
    if qualification {
        emit_qualification_resources("recovered", recovered);
        println!(
            "{}",
            serde_json::json!({
                "metric": "source_table_recovery",
                "entries": daemon.status()["admission"]["source_entries"]["in_use"],
            })
        );
    }
    let stderr = daemon.stop();
    let event_windows = usize::try_from(
        log_window_started
            .elapsed()
            .as_secs()
            .div_ceil(10)
            .saturating_add(1),
    )
    .unwrap();
    let handoff_success_events = stderr
        .lines()
        .filter(|line| line.contains("event=handoff result=success"))
        .count();
    assert!(
        handoff_success_events <= event_windows,
        "handoff success logs exceeded one aggregate per ten-second window: \
         events={handoff_success_events}, windows={event_windows}"
    );
    // Production has seven delivery outcomes and ten admission-rejection reasons.
    const RATE_LIMITED_EVENT_KINDS: usize = 7 + 10;
    let log_line_limit = 64 + event_windows * RATE_LIMITED_EVENT_KINDS;
    assert!(
        stderr.lines().count() <= log_line_limit,
        "bounded overload produced excessive logs (limit {log_line_limit}):\n{stderr}"
    );
    if qualification {
        println!(
            "{}",
            serde_json::json!({
                "metric": "bounded_stderr",
                "lines": stderr.lines().count(),
                "limit": log_line_limit,
                "handoff_success_events": handoff_success_events,
                "aggregation_windows": event_windows,
            })
        );
    }
}

fn checked_output(command: &mut Command, action: &str) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{action} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct TransientSystemdUnit {
    service: String,
    socket: String,
}

impl TransientSystemdUnit {
    fn stop(&self) {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &self.socket, &self.service])
            .output();
        let _ = Command::new("systemctl")
            .args(["--user", "reset-failed", &self.socket, &self.service])
            .output();
    }

    fn stop_checked(&self) {
        let _ = checked_output(
            Command::new("systemctl").args(["--user", "stop", &self.socket, &self.service]),
            "stop transient systemd units",
        );
        let _ = Command::new("systemctl")
            .args(["--user", "reset-failed", &self.socket, &self.service])
            .output();

        // Repeated queries keep transient units referenced and defer systemd's GC.
        for delay in [250, 500, 1_000, 2_000] {
            thread::sleep(Duration::from_millis(delay));
            let loaded = [&self.socket, &self.service]
                .into_iter()
                .filter(|unit| {
                    let output = Command::new("systemctl")
                        .args(["--user", "show", "--property=LoadState", "--value", unit])
                        .output()
                        .unwrap();
                    !output.status.success()
                        || String::from_utf8_lossy(&output.stdout).trim() != "not-found"
                })
                .collect::<Vec<_>>();
            if loaded.is_empty() {
                return;
            }
        }
        panic!(
            "transient systemd units did not unload: {}, {}",
            self.socket, self.service
        );
    }

    fn main_pid(&self) -> u32 {
        let output = checked_output(
            Command::new("systemctl").args([
                "--user",
                "show",
                "--property=MainPID",
                "--value",
                &self.service,
            ]),
            "read transient service PID",
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn journal(&self) -> String {
        let output = Command::new("journalctl")
            .args([
                "--user",
                "--unit",
                &self.service,
                "--no-pager",
                "--output=cat",
            ])
            .output()
            .unwrap();
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

impl Drop for TransientSystemdUnit {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait_for_systemd_ready(unit: &TransientSystemdUnit, control: &Path) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if control_request(control, "STATUS JSON")
            .ok()
            .and_then(|response| serde_json::from_str::<Value>(&response).ok())
            .is_some_and(|status| status["ready"] == true)
        {
            return;
        }
        if Instant::now() >= deadline {
            let status = Command::new("systemctl")
                .args(["--user", "status", "--no-pager", &unit.service])
                .output()
                .unwrap();
            panic!(
                "transient systemd service did not become ready:\nstatus:\n{}{}\njournal:\n{}",
                String::from_utf8_lossy(&status.stdout),
                String::from_utf8_lossy(&status.stderr),
                unit.journal()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires a real Linux per-user systemd manager"]
fn real_systemd_crash_restart_and_sandbox_denial() {
    let _guard = harness_lock();
    const HOSTNAME: &str = "systemd.phase8.test";

    checked_output(
        Command::new("systemctl").args(["--user", "show-environment"]),
        "connect to the per-user systemd manager",
    );
    let ca = TestCa::new();
    let identity = ca.issue(HOSTNAME, Duration::from_secs(60 * 24 * 60 * 60));
    let backend = TestBackend::start(&identity, HOSTNAME);
    let host = HarnessHost::new(
        &ca.root_pem,
        vec![Route::new(HOSTNAME, "systemd-workload", backend.port())],
        HarnessLimits::default(),
        false,
    );
    let binary = host.root.path().join("phx-port");
    fs::copy(env!("CARGO_BIN_EXE_phx-port"), &binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let launcher = host.root.path().join("launch.sh");
    let repository_sentinel = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let address = host.listen_addresses[0];
    let sandbox_root = Path::new("/tmp");
    fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nset -eu\n\
             if [ -r '{sentinel}' ]; then\n\
               echo event=phase8_sandbox result=failed >&2\n\
               exit 97\n\
             fi\n\
             echo event=phase8_sandbox result=denied >&2\n\
             export HOME='{home}'\n\
             export PHX_PORT_CONFIG='{registry}'\n\
             export PHX_PORT_RUNTIME_DIR='{runtime}'\n\
             export SSL_CERT_FILE='{root}'\n\
             unset PHX_PORT_INGRESS_CONFIG XDG_RUNTIME_DIR\n\
             exec '{binary}' daemon --listen '{address}' --ingress-config '{config}' \
               --active-connections 64 --pre-routing-connections 64 \
               --relay-connections 32 --handoff-negotiations 16 \
               --accepts-per-second 10000 --accept-burst 10000 \
               --source-accepts-per-second 10000 --source-accept-burst 10000 \
               --source-pre-routing-connections 64 --source-table-capacity 64 \
               --source-entry-ttl-seconds 1 --client-hello-timeout-ms 500 \
               --task-budget 512\n",
            sentinel = repository_sentinel.display(),
            home = sandbox_root.display(),
            registry = sandbox_root.join("state/ports.toml").display(),
            runtime = sandbox_root.join("runtime").display(),
            root = sandbox_root.join("root.pem").display(),
            binary = sandbox_root.join("phx-port").display(),
            config = sandbox_root.join("ingress.toml").display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    let launcher_name = host.root.path().file_name().unwrap();
    let namespaced_launcher = host.root.path().join(launcher_name).join("launch.sh");
    fs::create_dir(namespaced_launcher.parent().unwrap()).unwrap();
    fs::copy(&launcher, &namespaced_launcher).unwrap();
    fs::set_permissions(
        namespaced_launcher.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&namespaced_launcher, fs::Permissions::from_mode(0o700)).unwrap();

    let stem = format!("phx-port-phase8-{}", std::process::id());
    let service = format!("{stem}.service");
    let socket = format!("{stem}.socket");
    let unit = TransientSystemdUnit { service, socket };
    unit.stop();
    checked_output(
        Command::new("systemd-run").args([
            "--user",
            "--quiet",
            "--collect",
            &format!("--unit={stem}"),
            &format!("--socket-property=ListenStream={address}"),
            "--socket-property=FileDescriptorName=tls-ipv4",
            "--property=Restart=on-failure",
            "--property=RestartSec=100ms",
            "--property=NoNewPrivileges=true",
            &format!("--property=BindPaths={}:/tmp", host.root.path().display()),
            &format!(
                "--property=InaccessiblePaths={}",
                repository_sentinel.display()
            ),
            "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            launcher.to_str().unwrap(),
        ]),
        "start transient systemd socket and service",
    );
    let activation = TcpStream::connect(address).unwrap();
    drop(activation);

    let control = host.runtime.join("control/control.sock");
    wait_for_systemd_ready(&unit, &control);
    let first_pid = unit.main_pid();
    assert_ne!(first_pid, 0);
    let process_status = fs::read_to_string(format!("/proc/{first_pid}/status")).unwrap();
    assert!(
        process_status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .is_some_and(|line| {
                line.split_ascii_whitespace()
                    .skip(1)
                    .all(|uid| uid == nix::unistd::geteuid().as_raw().to_string())
            })
    );
    assert!(process_status.lines().any(|line| line == "NoNewPrivs:\t1"));
    tls_round_trip(&ca.connector(), HOSTNAME, address, b"before crash");

    let result = unsafe { nix::libc::kill(first_pid as nix::libc::pid_t, nix::libc::SIGKILL) };
    assert_eq!(result, 0, "cannot crash transient systemd service");
    wait_until("systemd to replace the crashed process", || {
        let pid = unit.main_pid();
        pid != 0 && pid != first_pid
    });
    wait_for_systemd_ready(&unit, &control);
    let second_pid = unit.main_pid();
    assert_ne!(first_pid, second_pid);
    tls_round_trip(&ca.connector(), HOSTNAME, address, b"after crash");

    let journal = unit.journal();
    assert!(
        journal.contains("event=phase8_sandbox result=denied"),
        "service did not prove unrelated home access was denied:\n{journal}"
    );
    assert!(
        !journal.contains("event=phase8_sandbox result=failed"),
        "systemd sandbox exposed the repository to the service:\n{journal}"
    );
    unit.stop_checked();
}
