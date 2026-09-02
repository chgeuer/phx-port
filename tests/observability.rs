#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::{TempDir, tempdir_in};

fn tempdir() -> std::io::Result<TempDir> {
    tempdir_in(Path::new("/tmp").canonicalize()?)
}

fn reserve_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Daemon {
    child: Option<Child>,
    home: TempDir,
    ingress_config: PathBuf,
    registry: PathBuf,
    runtime: PathBuf,
    ingress_address: SocketAddr,
}

impl Daemon {
    fn start(metrics_address: Option<SocketAddr>, source_diagnostics_expiry: Option<u64>) -> Self {
        let home = tempdir().unwrap();
        let state = home.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = home.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
        let ingress_config = home.path().join("ingress.toml");
        let registry = state.join("ports.toml");
        let mut config = String::from(
            "[ingress]\n\
             mode = \"public\"\n\
             unknown_sni = \"reject\"\n",
        );
        if let Some(address) = metrics_address {
            config.push_str(&format!("\n[ingress.metrics]\nlisten = \"{address}\"\n"));
        }
        if let Some(expires_at) = source_diagnostics_expiry {
            config.push_str(&format!(
                "\n[ingress.source_diagnostics]\n\
                 sample_every = 1\n\
                 expires_at_unix_seconds = {expires_at}\n"
            ));
        }
        config.push_str(
            "\n[ingress.hosts.\"required.example.test\"]\n\
             workload = \"required-web\"\n\
             role = \"https\"\n\
             required = true\n",
        );
        fs::write(&ingress_config, config).unwrap();

        let ingress_address = reserve_address();
        let child = Command::new(env!("CARGO_BIN_EXE_phx-port"))
            .args([
                "daemon",
                "--listen",
                &ingress_address.to_string(),
                "--ingress-config",
                ingress_config.to_str().unwrap(),
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
            .env("PHX_PORT_CONFIG", &registry)
            .env("PHX_PORT_RUNTIME_DIR", &runtime)
            .env_remove("PHX_PORT_INGRESS_CONFIG")
            .env_remove("XDG_RUNTIME_DIR")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut daemon = Self {
            child: Some(child),
            home,
            ingress_config,
            registry,
            runtime,
            ingress_address,
        };
        daemon.wait_until_ready();
        daemon
    }

    fn control_path(&self) -> PathBuf {
        self.runtime.join("control/control.sock")
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.control_path().exists() {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                let mut stderr = String::new();
                self.child
                    .as_mut()
                    .unwrap()
                    .stderr
                    .as_mut()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                panic!("daemon exited before creating control socket ({status}): {stderr}");
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not create its control socket"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn command(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_phx-port"))
            .args(args)
            .env("HOME", self.home.path())
            .env("PHX_PORT_INGRESS_CONFIG", &self.ingress_config)
            .env("PHX_PORT_CONFIG", &self.registry)
            .env("PHX_PORT_RUNTIME_DIR", &self.runtime)
            .env_remove("XDG_RUNTIME_DIR")
            .output()
            .unwrap()
    }

    fn emit_client_hello(&self) {
        let stream = TcpStream::connect(self.ingress_address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        assert!(connector.connect("required.example.test", stream).is_err());
    }

    fn stop_and_stderr(mut self) -> String {
        let child = self.child.as_mut().unwrap();
        let result = unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGINT) };
        assert_eq!(result, 0, "cannot terminate test daemon");
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "daemon shutdown failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stderr).unwrap()
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
        let _ = child.wait();
    }
}

fn http_request(address: SocketAddr, request: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match TcpStream::connect(address) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("metrics listener did not become reachable: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn metrics_listener_is_bounded_read_only_and_uses_only_declared_labels() {
    let metrics_address = reserve_address();
    let daemon = Daemon::start(Some(metrics_address), None);

    let response = http_request(
        metrics_address,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert_eq!(content_length, body.len());
    assert!(content_length <= 1024 * 1024);
    assert!(body.contains("phx_port_build_info{version=\"0.1.0\"} 1"));
    assert!(body.contains("phx_port_admission_limit{stage=\"active\"} 4"));
    assert!(body.contains("phx_port_handoffs_total{outcome=\"success\"} 0"));
    assert!(body.contains("phx_port_relays_total{outcome=\"started\"} 0"));
    assert!(body.contains("phx_port_config_reloads_total{outcome=\"rejected\"} 0"));
    assert!(
        body.contains(
            "phx_port_route_state{hostname=\"required.example.test\",workload=\"required-web\",role=\"https\",required=\"true\",state=\""
        ),
        "{body}"
    );
    for forbidden in ["source=", "connection_id", "certificate", "error="] {
        assert!(
            !body.contains(forbidden),
            "metrics leaked forbidden label {forbidden:?}:\n{body}"
        );
    }

    let post = http_request(
        metrics_address,
        "POST /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(post.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    let missing = http_request(
        metrics_address,
        "GET /not-metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(missing.starts_with("HTTP/1.1 404 Not Found\r\n"));

    let status = daemon.command(&["proxy", "status", "--json"]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stderr = daemon.stop_and_stderr();
    assert!(
        !stderr.lines().any(|line| line.contains(" source=")),
        "normal logs exposed a source address:\n{stderr}"
    );
}

#[test]
fn source_diagnostics_are_sampled_only_before_the_explicit_expiry() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let enabled = Daemon::start(None, Some(now + 60));
    enabled.emit_client_hello();
    let enabled_stderr = enabled.stop_and_stderr();
    assert!(
        enabled_stderr.lines().any(|line| {
            line == "event=source_diagnostic source=127.0.0.1 hostname=required.example.test"
        }),
        "missing explicitly enabled source diagnostic:\n{enabled_stderr}"
    );

    let expired = Daemon::start(None, Some(now.saturating_sub(1)));
    expired.emit_client_hello();
    let expired_stderr = expired.stop_and_stderr();
    assert!(
        !expired_stderr
            .lines()
            .any(|line| line.starts_with("event=source_diagnostic ")),
        "source diagnostic remained active after expiry:\n{expired_stderr}"
    );
}

#[test]
fn unavailable_metrics_listener_does_not_stop_the_data_plane() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let metrics_address = occupied.local_addr().unwrap();
    let daemon = Daemon::start(Some(metrics_address), None);

    let status = daemon.command(&["proxy", "status", "--json"]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stderr = daemon.stop_and_stderr();
    assert!(
        stderr
            .lines()
            .any(|line| line == "event=metrics_listener result=unavailable reason=bind_failed"),
        "missing bounded metrics failure event:\n{stderr}"
    );
}
