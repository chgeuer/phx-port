#![cfg(target_os = "linux")]

use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use tempfile::{TempDir, tempdir_in};

const TEST_RSA_PRIVATE_KEY: &str = include_str!("fixtures/proxy-test-rsa-key.pem");

fn tempdir() -> std::io::Result<TempDir> {
    tempdir_in(Path::new("/tmp").canonicalize()?)
}

fn request(path: &Path, request: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("{request}\n").as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn wait_until_ready(child: &mut Child, control: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if control.exists() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("daemon exited before becoming ready ({status}): {stderr}");
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not create its control socket"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn daemon_adopts_named_systemd_listener_without_rebinding() {
    let home = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let inherited_fd = listener.as_raw_fd();
    let state = home.path().join("state");
    let runtime = home.path().join("runtime");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o750)).unwrap();
    let ingress_config = home.path().join("ingress.toml");
    std::fs::write(
        &ingress_config,
        "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n\
         [ingress.hosts.\"inactive.example.test\"]\n\
         workload = \"inactive-web\"\nrole = \"https\"\nrequired = false\n",
    )
    .unwrap();
    let control = runtime.join("control/control.sock");

    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "export LISTEN_PID=$$; exec \"$@\"",
            "phx-port-systemd-test",
            env!("CARGO_BIN_EXE_phx-port"),
            "daemon",
            "--ingress-config",
        ])
        .arg(&ingress_config)
        .args([
            "--listen",
            &address.to_string(),
            "--active-connections",
            "4",
            "--pre-routing-connections",
            "4",
            "--relay-connections",
            "4",
            "--handoff-negotiations",
            "4",
            "--task-budget",
            "64",
        ])
        .env("HOME", home.path())
        .env("PHX_PORT_CONFIG", state.join("ports.toml"))
        .env("PHX_PORT_RUNTIME_DIR", &runtime)
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "tls-ipv4")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("XDG_RUNTIME_DIR")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    unsafe {
        command.pre_exec(move || {
            if nix::libc::dup2(inherited_fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::fcntl(3, nix::libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            nix::libc::umask(0o077);
            Ok(())
        });
    }

    let mut child = command.spawn().unwrap();
    wait_until_ready(&mut child, &control);

    let status = request(&control, "STATUS").unwrap();
    assert!(
        status.contains(&format!("listeners={address}")),
        "unexpected daemon status: {status}"
    );
    assert!(status.contains("hosting_profile=public"), "{status}");
    assert_eq!(
        std::fs::metadata(runtime.join("control"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o750
    );
    assert_eq!(request(&control, "STOP").unwrap(), "stopping\n");

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Adopted systemd listener tls-ipv4"),
        "daemon did not report descriptor adoption: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    drop((listener, home));
}

#[test]
fn stale_systemd_metadata_does_not_disable_direct_binding() {
    let home = tempdir().unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let control = home.path().join(".config/phx-port-runtime/control.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--listen",
            &address.to_string(),
            "--active-connections",
            "4",
            "--pre-routing-connections",
            "4",
            "--relay-connections",
            "4",
            "--handoff-negotiations",
            "4",
            "--task-budget",
            "64",
        ])
        .env("HOME", home.path())
        .env("LISTEN_PID", "1")
        .env("LISTEN_PIDFDID", "not-for-this-process")
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "tls-ipv4")
        .env_remove("PHX_PORT_CONFIG")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("PHX_PORT_RUNTIME_DIR")
        .env_remove("XDG_RUNTIME_DIR")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_until_ready(&mut child, &control);

    let status = request(&control, "STATUS").unwrap();
    assert!(status.contains(&format!("listeners={address}")), "{status}");
    assert_eq!(request(&control, "STOP").unwrap(), "stopping\n");
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains(&format!("TLS proxy listening on {address}")),
        "daemon did not fall back to direct binding: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct TestCertificate {
    chain_pem: String,
    root_pem: String,
    private_key_pem: String,
}

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
            private_key_pem: TEST_RSA_PRIVATE_KEY.to_string(),
        }
    }

    fn connector(&self) -> TlsConnector {
        let mut builder = TlsConnector::builder();
        builder.disable_built_in_roots(true);
        builder.add_root_certificate(Certificate::from_pem(self.root_pem.as_bytes()).unwrap());
        builder.build().unwrap()
    }
}

struct TlsBackend {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl TlsBackend {
    fn start(certificate: &TestCertificate) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let identity = Identity::from_pkcs8(
            certificate.chain_pem.as_bytes(),
            certificate.private_key_pem.as_bytes(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::new(identity).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
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
                        if let Ok(mut tls) = acceptor.accept(stream) {
                            let mut request = [0_u8; 7];
                            if tls.read_exact(&mut request).is_ok() {
                                assert_eq!(&request, b"request");
                                tls.write_all(b"systemd").unwrap();
                                tls.flush().unwrap();
                            }
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
            address,
            shutdown,
            worker: Some(worker),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }
}

impl Drop for TlsBackend {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

struct SystemdTestUnits {
    service: String,
    socket: String,
    service_path: PathBuf,
    socket_path: PathBuf,
    workspace: PathBuf,
}

impl SystemdTestUnits {
    fn new(stem: &str, workspace: PathBuf) -> Self {
        let service = format!("{stem}.service");
        let socket = format!("{stem}.socket");
        Self {
            service_path: Path::new("/run/systemd/system").join(&service),
            socket_path: Path::new("/run/systemd/system").join(&socket),
            service,
            socket,
            workspace,
        }
    }

    fn prepare_workspace(&self, user: &str, group: &str) {
        run_checked(
            Command::new("sudo")
                .args([
                    "-n",
                    "install",
                    "--directory",
                    "--mode=0700",
                    "--owner",
                    user,
                    "--group",
                    group,
                ])
                .arg(&self.workspace),
            "create systemd test workspace",
        );
    }

    fn install(&self, directory: &Path, service: &str, socket: &str) {
        let staged_service = directory.join(&self.service);
        let staged_socket = directory.join(&self.socket);
        std::fs::write(&staged_service, service).unwrap();
        std::fs::write(&staged_socket, socket).unwrap();
        run_checked(
            Command::new("sudo")
                .args(["-n", "install", "--mode=0644"])
                .arg(&staged_service)
                .arg(&self.service_path),
            "install test service unit",
        );
        run_checked(
            Command::new("sudo")
                .args(["-n", "install", "--mode=0644"])
                .arg(&staged_socket)
                .arg(&self.socket_path),
            "install test socket unit",
        );
        run_checked(
            Command::new("sudo").args(["-n", "systemctl", "daemon-reload"]),
            "reload systemd after installing test units",
        );
    }

    fn start(&self) {
        run_checked(
            Command::new("sudo")
                .args(["-n", "systemctl", "start"])
                .arg(&self.socket),
            "start test socket unit",
        );
        run_checked(
            Command::new("sudo")
                .args(["-n", "systemctl", "start"])
                .arg(&self.service),
            "start test service unit",
        );
    }

    fn restart(&self) {
        run_checked(
            Command::new("sudo")
                .args(["-n", "systemctl", "restart"])
                .arg(&self.service),
            "restart test service unit",
        );
    }

    fn main_pid(&self) -> u32 {
        let output = checked_output(
            Command::new("sudo")
                .args(["-n", "systemctl", "show", "--property=MainPID", "--value"])
                .arg(&self.service),
            "read test service PID",
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn journal(&self) -> String {
        let output = Command::new("sudo")
            .args([
                "-n",
                "journalctl",
                "--unit",
                &self.service,
                "--lines=50",
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

impl Drop for SystemdTestUnits {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "systemctl", "stop", &self.service, &self.socket])
            .output();
        let _ = Command::new("sudo")
            .args([
                "-n",
                "rm",
                "--force",
                "--",
                self.service_path.to_str().unwrap(),
                self.socket_path.to_str().unwrap(),
            ])
            .output();
        let _ = Command::new("sudo")
            .args(["-n", "rm", "--recursive", "--force", "--"])
            .arg(&self.workspace)
            .output();
        let _ = Command::new("sudo")
            .args(["-n", "systemctl", "daemon-reload"])
            .output();
        let _ = Command::new("sudo")
            .args(["-n", "systemctl", "reset-failed", &self.service])
            .output();
    }
}

fn checked_output(command: &mut Command, action: &str) -> std::process::Output {
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

fn run_checked(command: &mut Command, action: &str) {
    let _ = checked_output(command, action);
}

fn wait_for_public_ready(units: &SystemdTestUnits, control: &Path, routes: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(status) = request(control, "STATUS")
            && status.contains("ready=true")
            && status.contains("active_routes=1")
            && std::fs::read_to_string(routes).is_ok()
        {
            return status;
        }
        if Instant::now() >= deadline {
            panic!("systemd service did not become ready:\n{}", units.journal());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn assert_rootless_process(pid: u32, uid: u32, gid: u32) {
    assert_ne!(pid, 0, "systemd service has no main process");
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .unwrap();
    let gid_line = status
        .lines()
        .find(|line| line.starts_with("Gid:"))
        .unwrap();
    let no_new_privileges = status
        .lines()
        .find(|line| line.starts_with("NoNewPrivs:"))
        .unwrap();
    let capabilities = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .unwrap();
    assert_eq!(
        uid_line
            .split_ascii_whitespace()
            .skip(1)
            .collect::<Vec<_>>(),
        vec![uid.to_string(); 4],
        "unexpected process identity: {uid_line}"
    );
    assert_eq!(
        gid_line
            .split_ascii_whitespace()
            .skip(1)
            .collect::<Vec<_>>(),
        vec![gid.to_string(); 4],
        "unexpected process group identity: {gid_line}"
    );
    assert_eq!(no_new_privileges, "NoNewPrivs:\t1");
    assert_eq!(capabilities, "CapEff:\t0000000000000000");
}

fn assert_routed(address: SocketAddr, hostname: &str, connector: &TlsConnector) {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut tls = connector.connect(hostname, stream).unwrap();
    tls.write_all(b"request").unwrap();
    tls.flush().unwrap();
    let mut response = [0_u8; 7];
    tls.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"systemd");
}

#[test]
#[ignore = "requires a Linux systemd system manager and passwordless sudo"]
fn real_systemd_unit_routes_writes_state_and_restarts_rootlessly() {
    const HOSTNAME: &str = "systemd-rnu.example.test";
    const WORKLOAD: &str = "systemd-rnu-web";

    let uid = nix::unistd::geteuid();
    let gid = nix::unistd::getegid();
    assert!(
        !uid.is_root(),
        "the data-plane identity test must start non-root"
    );
    run_checked(
        Command::new("sudo").args(["-n", "true"]),
        "verify noninteractive sudo",
    );
    let user = nix::unistd::User::from_uid(uid)
        .unwrap()
        .expect("effective user has no account");
    let group = nix::unistd::Group::from_gid(gid)
        .unwrap()
        .expect("effective group has no account");

    let staging = tempdir().unwrap();
    let stem = format!("phx-port-rnu-test-{}", std::process::id());
    let workspace = Path::new("/run").join(&stem);
    let units = SystemdTestUnits::new(&stem, workspace.clone());
    units.prepare_workspace(&user.name, &group.name);

    let state = workspace.join("state");
    let runtime = workspace.join("runtime");
    let binary_directory = workspace.join("bin");
    for (path, mode) in [
        (&state, 0o700),
        (&runtime, 0o750),
        (&binary_directory, 0o700),
    ] {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let binary = binary_directory.join("phx-port");
    std::fs::copy(env!("CARGO_BIN_EXE_phx-port"), &binary).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();

    let certificate = TestCertificate::for_hostname(HOSTNAME);
    let root_path = workspace.join("root.pem");
    std::fs::write(&root_path, &certificate.root_pem).unwrap();
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let backend = TlsBackend::start(&certificate);

    let registry = state.join("ports.toml");
    std::fs::write(
        &registry,
        format!(
            "[ports]\n\n[ports.{WORKLOAD}]\nhttps = {}\n",
            backend.port()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o600)).unwrap();
    let routes = state.join("routes.toml");
    let ingress_config = workspace.join("ingress.toml");
    std::fs::write(
        &ingress_config,
        format!(
            "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n\n\
             [ingress.hosts.\"{HOSTNAME}\"]\n\
             workload = \"{WORKLOAD}\"\nrole = \"https\"\nrequired = true\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ingress_config, std::fs::Permissions::from_mode(0o600)).unwrap();

    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let ingress_address = reserved.local_addr().unwrap();
    drop(reserved);
    let service_unit = format!(
        "[Unit]\n\
         Requires={socket}\n\
         After={socket}\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={group}\n\
         Sockets={socket}\n\
         Environment=\"PHX_PORT_CONFIG={registry}\"\n\
         Environment=\"PHX_PORT_RUNTIME_DIR={runtime}\"\n\
         Environment=\"SSL_CERT_FILE={root}\"\n\
         ExecStartPre=/usr/bin/install --directory --mode=0700 {runtime}/handoff\n\
         ExecStart={binary} daemon --ingress-config {config} --listen {address} \
         --active-connections 8 --pre-routing-connections 8 --relay-connections 8 \
         --handoff-negotiations 8 --task-budget 128\n\
         Restart=on-failure\n\
         RestartSec=200ms\n\
         TimeoutStopSec=65s\n\
         LimitNOFILE=65536\n\
         TasksMax=128\n\
         MemoryMax=512M\n\
         UMask=0077\n\
         ReadOnlyPaths={config} {root}\n\
         ReadWritePaths={state} {runtime}\n\
         NoNewPrivileges=true\n\
         CapabilityBoundingSet=\n\
         AmbientCapabilities=\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictSUIDSGID=true\n\
         LockPersonality=true\n\
         RestrictRealtime=true\n\
         SystemCallArchitectures=native\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
        socket = units.socket,
        user = user.name,
        group = group.name,
        registry = registry.display(),
        runtime = runtime.display(),
        root = root_path.display(),
        binary = binary.display(),
        config = ingress_config.display(),
        address = ingress_address,
        state = state.display(),
    );
    let socket_unit = format!(
        "[Socket]\n\
         ListenStream={ingress_address}\n\
         FileDescriptorName=tls-ipv4\n\
         Service={service}\n\
         Backlog=1024\n\
         NoDelay=true\n",
        service = units.service
    );
    units.install(staging.path(), &service_unit, &socket_unit);
    units.start();

    let control = runtime.join("control/control.sock");
    let status = wait_for_public_ready(&units, &control, &routes);
    assert!(status.contains(&format!("listeners={ingress_address}")));
    assert!(
        std::fs::read_to_string(&routes).unwrap().contains(HOSTNAME),
        "verified route state was not persisted"
    );
    assert_eq!(
        std::fs::metadata(&routes).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    let first_pid = units.main_pid();
    assert_rootless_process(first_pid, uid.as_raw(), gid.as_raw());
    assert_routed(ingress_address, HOSTNAME, &certificate.connector());

    units.restart();
    let second_pid = units.main_pid();
    assert_ne!(
        first_pid, second_pid,
        "systemd did not replace the service process"
    );
    let status = wait_for_public_ready(&units, &control, &routes);
    assert!(status.contains("ready=true"));
    assert_rootless_process(second_pid, uid.as_raw(), gid.as_raw());
    assert_routed(ingress_address, HOSTNAME, &certificate.connector());
}
