#![cfg(unix)]

use fs2::FileExt;
#[cfg(target_os = "linux")]
use native_tls::{Identity, TlsAcceptor};
#[cfg(target_os = "linux")]
use nix::poll::{PollFd, PollFlags, poll};
#[cfg(target_os = "linux")]
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Read};
#[cfg(target_os = "linux")]
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Child;
use std::process::{Command, Output, Stdio};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
#[cfg(target_os = "linux")]
use std::time::SystemTime;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir_in};

const HOSTNAME: &str = "preflight.example.test";
const WORKLOAD: &str = "preflight-web";
static TEST_LOCK: Mutex<()> = Mutex::new(());
#[cfg(target_os = "linux")]
const TEST_RSA_PRIVATE_KEY: &str = include_str!("fixtures/proxy-test-rsa-key.pem");

fn tempdir() -> std::io::Result<TempDir> {
    let root = std::env::var_os("PHX_PORT_TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    tempdir_in(root.canonicalize()?)
}

fn reserve_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn hold_registry_lock(path: &Path) -> fs::File {
    let lock_path = path.with_file_name(format!(
        "{}.lock",
        path.file_name().unwrap().to_str().unwrap()
    ));
    let lock = fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)
        .unwrap();
    FileExt::lock_exclusive(&lock).unwrap();
    lock
}

fn assert_registry_timeout_report(output: &Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(1),
        "preflight must report failure before its external five-second watchdog kills it:\n{output:?}"
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    for check in [
        "registry operation timed out",
        "PASS ingress configuration",
        "PASS capacity",
        "PASS listener acquisition",
        "PASS system trust roots",
        "Preflight failed",
    ] {
        assert!(stdout.contains(check), "missing {check:?} in:\n{stdout}");
    }
    stdout
}

#[cfg(target_os = "linux")]
struct TestCertificate {
    chain_pem: String,
    root_pem: String,
}

#[cfg(target_os = "linux")]
impl TestCertificate {
    fn for_hostname(hostname: &str) -> Self {
        let now = SystemTime::now();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
        ca_params.not_after = (now + Duration::from_secs(30 * 24 * 60 * 60)).into();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let server_key =
            KeyPair::from_pkcs8_pem_and_sign_algo(TEST_RSA_PRIVATE_KEY, &PKCS_RSA_SHA256).unwrap();
        let mut server_params = CertificateParams::new(vec![hostname.to_string()]).unwrap();
        server_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
        server_params.not_after = (now + Duration::from_secs(7 * 24 * 60 * 60)).into();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let server = server_params.signed_by(&server_key, &issuer).unwrap();

        Self {
            chain_pem: format!("{}{}", server.pem(), ca.pem()),
            root_pem: ca.pem(),
        }
    }
}

#[cfg(target_os = "linux")]
struct TlsBackend {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handshakes: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl TlsBackend {
    fn start(certificate: &TestCertificate) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let identity = Identity::from_pkcs8(
            certificate.chain_pem.as_bytes(),
            TEST_RSA_PRIVATE_KEY.as_bytes(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::new(identity).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_handshakes = Arc::clone(&handshakes);
        let worker = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        if acceptor.accept(stream).is_ok() {
                            worker_handshakes.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("test TLS backend accept failed: {error}"),
                }
            }
        });
        Self {
            port,
            shutdown,
            handshakes,
            worker: Some(worker),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for TlsBackend {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

/// A workload that demands a client certificate in its initial handshake, run
/// out of process on OTP's `:ssl` so the matrix observes a real handshake
/// rather than a Rust stand-in. This is the transport seam a Bandit endpoint
/// forwards its HTTPS options to, not a running web framework.
#[cfg(target_os = "linux")]
struct MandatoryClientAuthWorkload {
    port: u16,
    child: Child,
    transcript: Arc<Mutex<Vec<String>>>,
    reader: Option<thread::JoinHandle<()>>,
    _materials: TempDir,
}

#[cfg(target_os = "linux")]
impl MandatoryClientAuthWorkload {
    fn start(certificate: &TestCertificate, version: &str) -> Self {
        let materials = tempdir().unwrap();
        let certfile = materials.path().join("workload-chain.pem");
        fs::write(&certfile, &certificate.chain_pem).unwrap();
        let keyfile = materials.path().join("workload-key.pem");
        fs::write(&keyfile, TEST_RSA_PRIVATE_KEY).unwrap();
        fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o600)).unwrap();
        let cacertfile = materials.path().join("workload-root.pem");
        fs::write(&cacertfile, &certificate.root_pem).unwrap();

        let mut child = Command::new("elixir")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/mandatory_client_auth_workload.exs"),
            )
            .arg(&certfile)
            .arg(&keyfile)
            .arg(&cacertfile)
            .arg(version)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the mandatory-client-auth matrix needs an Elixir/OTP toolchain on PATH");

        let stdout = child.stdout.take().unwrap();
        let transcript = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&transcript);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => collected.lock().unwrap().push(line),
                    Err(_) => break,
                }
            }
        });

        let mut workload = Self {
            port: 0,
            child,
            transcript,
            reader: Some(reader),
            _materials: materials,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        let port = loop {
            if let Some(port) = workload
                .lines()
                .iter()
                .find_map(|line| line.strip_prefix("LISTENING "))
                .and_then(|port| port.parse::<u16>().ok())
            {
                break port;
            }
            assert!(
                Instant::now() < deadline,
                "the mandatory-client-auth workload never reported a listening port: {:?}",
                workload.lines()
            );
            thread::sleep(Duration::from_millis(50));
        };
        workload.port = port;
        workload
    }

    fn lines(&self) -> Vec<String> {
        self.transcript.lock().unwrap().clone()
    }

    fn toolchain(&self) -> String {
        self.lines()
            .into_iter()
            .find(|line| line.starts_with("OTP "))
            .unwrap_or_else(|| "OTP unknown".to_string())
    }

    /// Server-side handshake results, once the workload has reported all of
    /// them or the external deadline expires.
    fn handshake_results(&self, expected: usize) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let results = self
                .lines()
                .into_iter()
                .filter_map(|line| {
                    line.strip_prefix("HANDSHAKE ")
                        .and_then(|line| line.split_once(' '))
                        .map(|(_index, result)| result.to_string())
                })
                .collect::<Vec<_>>();
            if results.len() >= expected || Instant::now() >= deadline {
                return results;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for MandatoryClientAuthWorkload {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(target_os = "linux")]
struct ProbeCosts {
    durations: Vec<Duration>,
    per_workload: Vec<usize>,
    peak_open: usize,
}

#[cfg(target_os = "linux")]
struct StalledWorkloads {
    ports: Vec<u16>,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<ProbeCosts>>,
}

#[cfg(target_os = "linux")]
impl StalledWorkloads {
    fn start(workloads: usize) -> Self {
        assert!((1..=100).contains(&workloads));
        let listeners = (0..workloads)
            .map(|_| {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                listener
            })
            .collect::<Vec<_>>();
        let ports = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::spawn(move || {
            let mut costs = ProbeCosts {
                durations: Vec::new(),
                per_workload: vec![0; workloads],
                peak_open: 0,
            };
            let mut probes: Vec<(usize, TcpStream, Instant, usize)> = Vec::new();
            let mut shutdown_deadline = None;
            loop {
                if worker_shutdown.load(Ordering::Acquire) {
                    let deadline = shutdown_deadline
                        .get_or_insert_with(|| Instant::now() + Duration::from_secs(1));
                    assert!(
                        Instant::now() < *deadline,
                        "stalled fixture sockets did not close after child exit"
                    );
                }
                let ready = {
                    let mut descriptors = listeners
                        .iter()
                        .map(|listener| PollFd::new(listener.as_fd(), PollFlags::POLLIN))
                        .chain(probes.iter().map(|(_, stream, _, _)| {
                            PollFd::new(stream.as_fd(), PollFlags::POLLIN)
                        }))
                        .collect::<Vec<_>>();
                    poll(&mut descriptors, 10_u16).unwrap();
                    descriptors
                        .iter()
                        .map(|descriptor| descriptor.revents().unwrap())
                        .collect::<Vec<_>>()
                };
                for index in (0..probes.len()).rev() {
                    if ready[workloads + index].is_empty() {
                        continue;
                    }
                    let (_, stream, _, received) = &mut probes[index];
                    let mut buffer = [0; 1024];
                    let closed = loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => {
                                assert!(*received > 0, "probe sent no TLS ClientHello");
                                break true;
                            }
                            Ok(size) => {
                                *received += size;
                                assert!(*received <= 64 * 1024, "unbounded fixture input");
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                break false;
                            }
                            Err(error) => panic!("stalled fixture read failed: {error}"),
                        }
                    };
                    if closed {
                        let (workload, _, started, _) = probes.swap_remove(index);
                        costs.durations.push(started.elapsed());
                        costs.per_workload[workload] += 1;
                        assert!(costs.durations.len() <= 1_000);
                    }
                }
                for (workload, listener) in listeners.iter().enumerate() {
                    if ready[workload].contains(PollFlags::POLLIN) {
                        let (stream, _) = listener.accept().unwrap();
                        stream.set_nonblocking(true).unwrap();
                        probes.push((workload, stream, Instant::now(), 0));
                        assert!(probes.len() <= 100, "fixture probe capacity exceeded");
                        costs.peak_open = costs.peak_open.max(probes.len());
                    }
                }
                if worker_shutdown.load(Ordering::Acquire) && probes.is_empty() {
                    return costs;
                }
            }
        });
        Self {
            ports,
            shutdown,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> ProbeCosts {
        self.shutdown.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}

#[cfg(target_os = "linux")]
impl Drop for StalledWorkloads {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

struct HostFixture {
    root: TempDir,
    ingress_config: PathBuf,
    registry: PathBuf,
    runtime: PathBuf,
    trust_roots: Option<PathBuf>,
    ingress_address: SocketAddr,
}

impl HostFixture {
    fn new(backend_port: Option<u16>, trust_roots_pem: Option<&str>) -> Self {
        Self::at(backend_port, trust_roots_pem, reserve_address(), true)
    }

    fn at(
        backend_port: Option<u16>,
        trust_roots_pem: Option<&str>,
        ingress_address: SocketAddr,
        required: bool,
    ) -> Self {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
        let registry = state.join("ports.toml");
        let registry_content = match backend_port {
            Some(port) => format!("[ports]\n\n[ports.{WORKLOAD}]\nhttps = {port}\n"),
            None => "[ports]\n".to_string(),
        };
        fs::write(&registry, registry_content).unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();

        let ingress_config = root.path().join("ingress.toml");
        fs::write(
            &ingress_config,
            format!(
                "[ingress]\n\
                 mode = \"public\"\n\
                 unknown_sni = \"reject\"\n\
                 listen = [\"{ingress_address}\"]\n\n\
                 [ingress.hosts.\"{HOSTNAME}\"]\n\
                 workload = \"{WORKLOAD}\"\n\
                 role = \"https\"\n\
                 required = {required}\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&ingress_config, fs::Permissions::from_mode(0o600)).unwrap();
        let trust_roots = trust_roots_pem.map(|pem| {
            let path = root.path().join("root.pem");
            fs::write(&path, pem).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        });

        Self {
            root,
            ingress_config,
            registry,
            runtime,
            trust_roots,
            ingress_address,
        }
    }

    fn arguments(&self, extra: &[&str]) -> Vec<String> {
        let mut arguments = vec![
            "proxy".to_string(),
            "preflight".to_string(),
            "--file".to_string(),
            self.ingress_config.display().to_string(),
            "--listen".to_string(),
            self.ingress_address.to_string(),
            "--active-connections".to_string(),
            "4".to_string(),
            "--pre-routing-connections".to_string(),
            "4".to_string(),
            "--relay-connections".to_string(),
            "4".to_string(),
            "--handoff-negotiations".to_string(),
            "4".to_string(),
        ];
        arguments.extend(extra.iter().map(|argument| (*argument).to_string()));
        arguments
    }

    fn configure(&self, command: &mut Command) {
        command
            .env("HOME", self.root.path())
            .env("PHX_PORT_CONFIG", &self.registry)
            .env("PHX_PORT_RUNTIME_DIR", &self.runtime)
            .env_remove("PHX_PORT_INGRESS_CONFIG")
            .env_remove("XDG_RUNTIME_DIR");
        if let Some(trust_roots) = &self.trust_roots {
            command.env("SSL_CERT_FILE", trust_roots);
        } else {
            command.env_remove("SSL_CERT_FILE");
        }
    }

    fn command(&self, extra: &[&str]) -> Output {
        self.command_with_timeout(extra, Duration::from_secs(5))
    }

    fn command_with_timeout(&self, extra: &[&str], timeout: Duration) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        command.args(self.arguments(extra));
        self.configure(&mut command);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + timeout;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    }
}

#[cfg(target_os = "linux")]
fn measure_stalled_preflight(workloads: usize, hostnames_per_workload: usize) {
    let routes = workloads * hostnames_per_workload;
    assert!((1..=1_000).contains(&routes));
    let backends = StalledWorkloads::start(workloads);
    let host = HostFixture::new(None, None);
    let mut registry = "[ports]\n".to_string();
    let mut ingress = format!(
        "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\nlisten = [\"{}\"]\n",
        host.ingress_address
    );
    for (workload, port) in backends.ports.iter().enumerate() {
        registry.push_str(&format!("\n[ports.scale-{workload:03}]\nhttps = {port}\n"));
        for hostname in 0..hostnames_per_workload {
            let index = workload * hostnames_per_workload + hostname;
            ingress.push_str(&format!(
                "\n[ingress.hosts.\"scale-{index:04}.example.test\"]\n\
                 workload = \"scale-{workload:03}\"\nrole = \"https\"\nrequired = {}\n",
                index.is_multiple_of(2)
            ));
        }
    }
    fs::write(&host.registry, &registry).unwrap();
    fs::write(&host.ingress_config, ingress).unwrap();

    // Two probe budgets per declaration plus setup slack: a watchdog, not an SLO.
    let watchdog = Duration::from_millis(400 * routes as u64) + Duration::from_secs(5);
    let started = Instant::now();
    let output = host.command_with_timeout(&["--task-budget", "128"], watchdog);
    let elapsed = started.elapsed();
    let mut costs = backends.finish();
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected a complete FAIL report, not a watchdog kill: {output:?}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    for check in [
        "PASS execution identity",
        "PASS ingress configuration",
        "PASS production paths",
        "PASS sandbox access",
        "PASS control authorization",
        "PASS capacity",
        "PASS listener acquisition",
        "PASS system trust roots",
        "PASS registrations",
        "Preflight failed: 1 blocking check(s)",
    ] {
        assert!(stdout.contains(check), "missing {check:?} in:\n{stdout}");
    }
    for (status, kind, count) in [
        ("FAIL", "required", routes.div_ceil(2)),
        ("WARN", "optional", routes / 2),
    ] {
        if count == 0 {
            continue;
        }
        let line = stdout
            .lines()
            .find(|line| line.starts_with(&format!("{status} route certificates:")))
            .unwrap();
        assert!(
            line.contains(&format!("{count} {kind} route(s) failed")),
            "{line}"
        );
        assert_eq!(
            line.matches("(route selection timed out)").count(),
            count.min(16),
            "{line}"
        );
        if count > 16 {
            assert!(
                line.contains(&format!("{} additional failure(s) omitted", count - 16)),
                "{line}"
            );
        }
    }
    assert_eq!(costs.durations.len(), routes);
    assert_eq!(costs.per_workload, vec![hostnames_per_workload; workloads]);
    assert!(
        elapsed < watchdog,
        "preflight exceeded its fixture watchdog"
    );
    assert_eq!(fs::read_to_string(&host.registry).unwrap(), registry);
    assert!(!host.runtime.join("control/control.sock").exists());
    drop(TcpListener::bind(host.ingress_address).unwrap());

    costs.durations.sort_unstable();
    let probe_total = costs.durations.iter().sum::<Duration>().as_secs_f64() * 1_000.0;
    println!(
        "preflight_scale workloads={workloads} routes={routes} probes={} \
         probe_min_ms={:.3} probe_mean_ms={:.3} probe_p50_ms={:.3} probe_max_ms={:.3} \
         probe_total_ms={probe_total:.3} command_ms={:.3} peak_observed_open_probes={}",
        costs.durations.len(),
        costs.durations[0].as_secs_f64() * 1_000.0,
        probe_total / routes as f64,
        costs.durations[routes / 2].as_secs_f64() * 1_000.0,
        costs.durations[routes - 1].as_secs_f64() * 1_000.0,
        elapsed.as_secs_f64() * 1_000.0,
        costs.peak_open,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn preflight_stalled_routes_complete_all_diagnostics() {
    let _guard = TEST_LOCK.lock().unwrap();
    measure_stalled_preflight(2, 2);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "route-scale characterization takes approximately 221 seconds"]
fn preflight_stalled_routes_at_supported_scale() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (workloads, hostnames_per_workload) in [(1, 1), (10, 10), (100, 10)] {
        measure_stalled_preflight(workloads, hostnames_per_workload);
    }
}

#[test]
fn preflight_registry_deadline_covers_path_validation_and_assignments() {
    let guard = TEST_LOCK.lock().unwrap();
    let host = HostFixture::at(None, None, reserve_address(), false);
    let _lock = hold_registry_lock(&host.registry);

    let output = host.command(&["--task-budget", "128"]);
    drop(guard);
    let stdout = assert_registry_timeout_report(&output);
    assert!(
        stdout.contains("FAIL production paths: registry operation timed out"),
        "{stdout}"
    );
    assert!(
        stdout.contains("FAIL registrations: registry operation timed out"),
        "{stdout}"
    );
    assert_eq!(fs::read_to_string(&host.registry).unwrap(), "[ports]\n");
}

#[test]
fn preflight_registry_deadline_covers_assignments_after_path_rejection() {
    let guard = TEST_LOCK.lock().unwrap();
    let mut host = HostFixture::at(None, None, reserve_address(), false);
    host.runtime = host.registry.parent().unwrap().to_path_buf();
    let _lock = hold_registry_lock(&host.registry);

    let output = host.command(&["--task-budget", "128"]);
    drop(guard);
    let stdout = assert_registry_timeout_report(&output);
    assert!(
        stdout.contains(
            "FAIL production paths: production state directory and runtime root must be distinct"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("FAIL registrations: registry operation timed out"),
        "{stdout}"
    );
}

#[test]
fn preflight_registry_deadline_covers_derived_state_without_skipping_assignments() {
    let guard = TEST_LOCK.lock().unwrap();
    let host = HostFixture::at(None, None, reserve_address(), false);
    let _lock = hold_registry_lock(&host.registry.with_file_name("routes.toml"));

    let output = host.command(&["--task-budget", "128"]);
    drop(guard);
    let stdout = assert_registry_timeout_report(&output);
    assert!(
        stdout.contains("FAIL production paths: registry operation timed out"),
        "{stdout}"
    );
    assert!(stdout.contains("WARN registrations"), "{stdout}");
    assert!(!stdout.contains("FAIL registrations"), "{stdout}");
    assert!(stdout.contains("WARN route certificates"), "{stdout}");
}

#[cfg(target_os = "linux")]
#[test]
fn preflight_proves_a_ready_host_without_accepting_public_connections() {
    let _guard = TEST_LOCK.lock().unwrap();
    let certificate = TestCertificate::for_hostname(HOSTNAME);
    let backend = TlsBackend::start(&certificate);
    let host = HostFixture::new(Some(backend.port), Some(&certificate.root_pem));

    let output = host.command(&["--task-budget", "128"]);
    assert!(
        output.status.success(),
        "preflight failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    for check in [
        "PASS execution identity",
        "PASS ingress configuration",
        "PASS production paths",
        "PASS sandbox access",
        "PASS control authorization",
        "PASS system trust roots",
        "PASS registrations",
        "PASS route certificates",
        "PASS capacity",
        "PASS listener acquisition",
        "Preflight passed",
    ] {
        assert!(stdout.contains(check), "missing {check:?} in:\n{stdout}");
    }
    assert_eq!(backend.handshakes.load(Ordering::Acquire), 1);
    assert!(host.runtime.join("control").is_dir());
    assert!(!host.runtime.join("control/control.sock").exists());
    let rebound = TcpListener::bind(host.ingress_address)
        .expect("preflight retained its non-serving listener");
    drop(rebound);
}

#[test]
#[cfg(target_os = "linux")]
fn preflight_certificate_discovery_requires_runtime_proof_and_durable_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    let certificate = TestCertificate::for_hostname("*.preflight.example.test");
    let backend = TlsBackend::start(&certificate);
    let host = HostFixture::new(Some(backend.port), Some(&certificate.root_pem));
    fs::write(
        &host.ingress_config,
        format!(
            "[ingress]\nmode = \"public\"\nrouting_policy = \"certificate_discovery\"\nlisten = [\"{}\"]\n",
            host.ingress_address
        ),
    )
    .unwrap();

    let output = host.command(&["--task-budget", "128"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "public certificate_discovery without per-host declarations",
        "PASS production paths",
        "PASS registrations",
        "WARN route certificates",
        "running daemon must verify SANs and durable ownership",
    ] {
        assert!(stdout.contains(expected), "{stdout}");
    }
    assert!(!stdout.contains("PASS route certificates"), "{stdout}");
    assert_eq!(backend.handshakes.load(Ordering::Acquire), 0);

    let mut check = Command::new(env!("CARGO_BIN_EXE_phx-port"));
    host.configure(&mut check);
    let output = check
        .args(["proxy", "config", "check", "--file"])
        .arg(&host.ingress_config)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "config check must remain root-owned intent only"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("owned by unexpected UID"), "{stderr}");

    let claims = host.registry.with_file_name("route-claims.toml");
    fs::write(&claims, "version = 999\n").unwrap();
    fs::set_permissions(&claims, fs::Permissions::from_mode(0o600)).unwrap();
    let output = host.command(&["--task-budget", "128"]);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("FAIL production paths"), "{stdout}");
    assert_eq!(fs::read_to_string(&claims).unwrap(), "version = 999\n");
}

#[test]
fn preflight_reports_independent_blockers_in_one_run() {
    let _guard = TEST_LOCK.lock().unwrap();
    let host = HostFixture::new(None, None);
    let mut ingress_config = fs::read_to_string(&host.ingress_config).unwrap();
    ingress_config.push_str(
        "\n[ingress.hosts.\"optional-preflight.example.test\"]\n\
         workload = \"optional-web\"\n\
         role = \"https\"\n\
         required = false\n",
    );
    fs::write(&host.ingress_config, ingress_config).unwrap();
    let occupied = TcpListener::bind(host.ingress_address).unwrap();

    let output = host.command(&["--task-budget", "1"]);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for check in [
        "FAIL registrations",
        "WARN registrations",
        "FAIL route certificates",
        "WARN route certificates",
        "FAIL capacity",
        "FAIL listener acquisition",
        "Preflight failed",
    ] {
        assert!(stdout.contains(check), "missing {check:?} in:\n{stdout}");
    }
    assert!(host.runtime.join("control").is_dir());
    assert!(!host.runtime.join("control/control.sock").exists());
    drop(occupied);
}

#[cfg(target_os = "linux")]
#[test]
fn preflight_capacity_check_does_not_raise_the_soft_file_limit() {
    use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, setrlimit};

    let _guard = TEST_LOCK.lock().unwrap();
    let host = HostFixture::at(None, None, reserve_address(), false);
    let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    assert!(
        hard == RLIM_INFINITY || hard >= 64,
        "test process hard file limit is unexpectedly below 64"
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
    command.args(host.arguments(&["--task-budget", "128"]));
    host.configure(&mut command);
    unsafe {
        command.pre_exec(move || {
            setrlimit(Resource::RLIMIT_NOFILE, 64, hard).map_err(std::io::Error::other)
        });
    }

    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("FAIL capacity"), "{stdout}");
    assert!(stdout.contains("RLIMIT_NOFILE=64"), "{stdout}");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("Raised RLIMIT_NOFILE"),
        "preflight mutated its soft file limit"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn preflight_validates_named_systemd_listener_without_accepting() {
    let _guard = TEST_LOCK.lock().unwrap();
    let inherited = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = inherited.local_addr().unwrap();
    let inherited_fd = inherited.as_raw_fd();
    let host = HostFixture::at(None, None, address, false);

    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "export LISTEN_PID=$$; exec \"$@\"",
            "phx-port-preflight-test",
            env!("CARGO_BIN_EXE_phx-port"),
        ])
        .args(host.arguments(&["--task-budget", "128"]))
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "tls-ipv4")
        .env_remove("LISTEN_PIDFDID");
    host.configure(&mut command);
    unsafe {
        command.pre_exec(move || {
            if nix::libc::dup2(inherited_fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::fcntl(3, nix::libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "systemd preflight failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("Systemd(\"tls-ipv4\")"),
        "named listener was not adopted:\n{stdout}"
    );
    assert!(stdout.contains("Preflight passed"), "{stdout}");
    inherited.set_nonblocking(true).unwrap();
    assert_eq!(
        inherited.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!host.runtime.join("control/control.sock").exists());
}

#[test]
fn preflight_never_auto_detects_production() {
    let _guard = TEST_LOCK.lock().unwrap();
    let root = tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args(["proxy", "preflight"])
        .env("HOME", root.path())
        .env_remove("PHX_PORT_CONFIG")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("PHX_PORT_RUNTIME_DIR")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("requires --file PATH or PHX_PORT_INGRESS_CONFIG"),
        "unexpected error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.path().join(".config").exists());
}

#[cfg(target_os = "linux")]
const MANDATORY_CLIENT_AUTH_ATTEMPTS: usize = 20;

/// ING-Q1: characterize whether a workload that demands a client certificate
/// in its initial handshake can produce the completed certificate proof a
/// Verified Route requires.
///
/// `phx-port` never holds a workload private key, so its probe offers no client
/// identity. Preflight and runtime route activation share one probe, so this
/// matrix drives the shipped `proxy preflight` gate and records both the
/// ingress verdict and the workload's own handshake result per TLS version.
///
/// The outcome is specific to this client and server pair: `native-tls` over
/// the system OpenSSL against an OTP `:ssl` listener on Linux. It is not a
/// general TLS-version rule, and it says nothing about Darwin, other TLS
/// implementations, or end-to-end mutually authenticated requests.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an Elixir/OTP toolchain to run a mandatory-client-auth workload"]
fn preflight_route_certificates_across_mandatory_client_auth_tls_versions() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut matrix = Vec::new();

    for version in ["tlsv1.2", "tlsv1.3"] {
        let certificate = TestCertificate::for_hostname(HOSTNAME);
        let workload = MandatoryClientAuthWorkload::start(&certificate, version);
        let host = HostFixture::new(Some(workload.port), Some(&certificate.root_pem));

        let mut verified = 0usize;
        let mut ingress_details = BTreeSet::new();
        for _ in 0..MANDATORY_CLIENT_AUTH_ATTEMPTS {
            let output = host.command(&["--task-budget", "128"]);
            let stdout = String::from_utf8(output.stdout).unwrap();
            if stdout.contains("PASS route certificates") {
                assert!(
                    output.status.success(),
                    "a verified route must leave preflight passing:\n{stdout}"
                );
                verified += 1;
            } else {
                ingress_details.insert(
                    stdout
                        .lines()
                        .find(|line| line.contains("route certificates"))
                        .unwrap_or("route certificates check missing")
                        .trim()
                        .to_string(),
                );
            }
        }

        let results = workload.handshake_results(MANDATORY_CLIENT_AUTH_ATTEMPTS);
        matrix.push((
            version,
            workload.toolchain(),
            verified,
            ingress_details,
            results.iter().cloned().collect::<BTreeSet<_>>(),
            results.len(),
        ));
    }

    for (version, toolchain, verified, ingress_details, workload_results, attempts) in &matrix {
        println!(
            "ING-Q1 {version}: {toolchain} verified={verified}/{MANDATORY_CLIENT_AUTH_ATTEMPTS} \
             workload_handshakes={attempts} workload_results={workload_results:?} \
             ingress={ingress_details:?}"
        );
    }

    for (version, _, _, _, workload_results, attempts) in &matrix {
        assert_eq!(
            *attempts, MANDATORY_CLIENT_AUTH_ATTEMPTS,
            "{version}: every probe must reach the workload"
        );
        assert!(
            !workload_results.contains("result=accepted"),
            "{version}: the ingress must never present a client identity, got {workload_results:?}"
        );
    }

    let (_, _, tls12_verified, tls12_details, tls12_results, _) = &matrix[0];
    assert_eq!(
        *tls12_verified, 0,
        "TLS 1.2 mandatory client authentication must fail closed, not activate a route"
    );
    assert!(
        tls12_details
            .iter()
            .all(|detail| detail.starts_with("FAIL route certificates")),
        "TLS 1.2 must report a required-route certificate failure, got {tls12_details:?}"
    );
    assert!(
        tls12_details
            .iter()
            .all(|detail| detail.contains("TLS validation failed")),
        "TLS 1.2 must attribute the failure to the handshake, got {tls12_details:?}"
    );
    assert_eq!(
        tls12_results.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["result=rejected alert=handshake_failure"],
        "TLS 1.2 must reject the anonymous client during the handshake"
    );

    let (_, _, tls13_verified, tls13_details, tls13_results, _) = &matrix[1];
    assert_eq!(
        *tls13_verified, MANDATORY_CLIENT_AUTH_ATTEMPTS,
        "TLS 1.3 must deterministically verify the workload certificate, saw {tls13_details:?}"
    );
    assert_eq!(
        tls13_results.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["result=rejected alert=certificate_required"],
        "TLS 1.3 must reject the anonymous client after the probe verified the \
         complete server flight, which is not mutual authentication"
    );
}
