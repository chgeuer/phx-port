#![cfg(unix)]

#[cfg(target_os = "linux")]
use native_tls::{Identity, TlsAcceptor};
#[cfg(target_os = "linux")]
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
use std::fs;
use std::net::{SocketAddr, TcpListener};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, SystemTime};
use tempfile::{TempDir, tempdir_in};

const HOSTNAME: &str = "preflight.example.test";
const WORKLOAD: &str = "preflight-web";
static TEST_LOCK: Mutex<()> = Mutex::new(());
#[cfg(target_os = "linux")]
const TEST_RSA_PRIVATE_KEY: &str = include_str!("fixtures/proxy-test-rsa-key.pem");

fn tempdir() -> std::io::Result<TempDir> {
    tempdir_in(Path::new("/tmp").canonicalize()?)
}

fn reserve_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        command.args(self.arguments(extra));
        self.configure(&mut command);
        command.output().unwrap()
    }
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
