use std::process::Command;

#[test]
fn invalid_capacity_is_rejected_before_listener_binding() {
    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--active-connections",
            "0",
            "--listen",
            "not-a-listener",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("active_connections must be greater than zero"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("cannot listen"),
        "listener binding ran before capacity validation: {stderr}"
    );
}

#[cfg(unix)]
mod unix {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::{TempDir, tempdir_in};

    fn tempdir() -> std::io::Result<TempDir> {
        let root = Path::new("/tmp").canonicalize()?;
        tempdir_in(root)
    }

    struct Daemon {
        child: Option<Child>,
        home: TempDir,
    }

    impl Daemon {
        fn start(address: SocketAddr) -> Self {
            Self::start_with_limits(address, 1, 1)
        }

        fn start_with_limits(
            address: SocketAddr,
            active_connections: usize,
            pre_routing_connections: usize,
        ) -> Self {
            let home = tempdir().unwrap();
            let child = Command::new(env!("CARGO_BIN_EXE_phx-port"))
                .args([
                    "daemon".to_string(),
                    "--listen".to_string(),
                    address.to_string(),
                    "--active-connections".to_string(),
                    active_connections.to_string(),
                    "--pre-routing-connections".to_string(),
                    pre_routing_connections.to_string(),
                    "--relay-connections".to_string(),
                    "1".to_string(),
                    "--handoff-negotiations".to_string(),
                    "1".to_string(),
                    "--client-hello-timeout-ms".to_string(),
                    "10000".to_string(),
                    "--task-budget".to_string(),
                    "128".to_string(),
                ])
                .env("HOME", home.path())
                .env_remove("PHX_PORT_CONFIG")
                .env_remove("XDG_RUNTIME_DIR")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut daemon = Self {
                child: Some(child),
                home,
            };
            daemon.wait_until_ready();
            daemon
        }

        fn wait_until_ready(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if self.control_path().exists() {
                    return;
                }
                if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                    panic!("daemon exited before becoming ready: {status}");
                }
                assert!(
                    Instant::now() < deadline,
                    "daemon did not create its control socket"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }

        fn control_path(&self) -> std::path::PathBuf {
            self.home
                .path()
                .join(".config/phx-port-runtime/control.sock")
        }

        fn request(&self, request: &str) -> std::io::Result<String> {
            let mut stream = UnixStream::connect(self.control_path())?;
            stream.set_read_timeout(Some(Duration::from_secs(1)))?;
            stream.write_all(format!("{request}\n").as_bytes())?;
            stream.shutdown(Shutdown::Write)?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            Ok(response)
        }

        fn wait_for_count(&self, name: &str, expected: usize) {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Ok(status) = self.request("STATUS")
                    && status.lines().any(|line| {
                        line.strip_prefix(&format!("{name}="))
                            .and_then(|value| value.parse::<usize>().ok())
                            == Some(expected)
                    })
                {
                    return;
                }
                assert!(Instant::now() < deadline, "{name} did not reach {expected}");
                thread::sleep(Duration::from_millis(20));
            }
        }

        fn stop_and_stderr(mut self) -> String {
            self.request("STOP").unwrap();
            let output = self.child.take().unwrap().wait_with_output().unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stderr).unwrap()
        }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.request("STOP");
            let Some(mut child) = self.child.take() else {
                return;
            };
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if child.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn reserve_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    #[test]
    fn connection_admission_rejects_before_worker_and_recovers() {
        let address = reserve_address();
        let daemon = Daemon::start(address);

        let first = TcpStream::connect(address).unwrap();
        daemon.wait_for_count("active_connections", 1);
        daemon.wait_for_count("pre_routing_connections", 1);

        let mut rejected = TcpStream::connect(address).unwrap();
        rejected
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        match rejected.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                ) => {}
            result => panic!("second connection was not rejected immediately: {result:?}"),
        }
        daemon.wait_for_count("rejected_global_capacity", 1);

        drop(first);
        daemon.wait_for_count("active_connections", 0);
        daemon.wait_for_count("pre_routing_connections", 0);

        let recovered = TcpStream::connect(address).unwrap();
        daemon.wait_for_count("active_connections", 1);
        daemon.wait_for_count("pre_routing_connections", 1);
        drop(recovered);
        daemon.wait_for_count("active_connections", 0);
        daemon.wait_for_count("pre_routing_connections", 0);
    }

    #[test]
    fn repeated_global_overload_emits_one_bounded_aggregate_event() {
        let address = reserve_address();
        let daemon = Daemon::start(address);

        let admitted = TcpStream::connect(address).unwrap();
        daemon.wait_for_count("active_connections", 1);

        for _ in 0..20 {
            drop(TcpStream::connect(address).unwrap());
        }
        daemon.wait_for_count("rejected_global_capacity", 20);

        drop(admitted);
        daemon.wait_for_count("active_connections", 0);
        let stderr = daemon.stop_and_stderr();
        let overload_events = stderr
            .lines()
            .filter(|line| line.starts_with("event=ingress_overload "))
            .collect::<Vec<_>>();
        assert_eq!(
            overload_events,
            ["event=ingress_overload reason=global_capacity rejected=1 suppressed=0"],
            "unexpected overload events in stderr:\n{stderr}"
        );
        assert!(
            !stderr.contains("TLS proxy connection rejected"),
            "per-connection rejection details leaked to stderr:\n{stderr}"
        );
    }

    #[test]
    fn source_pre_routing_limit_rejects_before_worker_and_recovers() {
        let address = reserve_address();
        let daemon = Daemon::start_with_limits(address, 32, 32);
        let mut admitted = Vec::new();

        for expected in 1..=16 {
            admitted.push(TcpStream::connect(address).unwrap());
            daemon.wait_for_count("active_connections", expected);
            daemon.wait_for_count("pre_routing_connections", expected);
        }

        let mut rejected = TcpStream::connect(address).unwrap();
        rejected
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        match rejected.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                ) => {}
            result => panic!("seventeenth source connection was not rejected: {result:?}"),
        }
        daemon.wait_for_count("rejected_source_concurrency", 1);
        daemon.wait_for_count("active_connections", 16);
        daemon.wait_for_count("pre_routing_connections", 16);

        drop(admitted.pop());
        daemon.wait_for_count("active_connections", 15);
        daemon.wait_for_count("pre_routing_connections", 15);

        admitted.push(TcpStream::connect(address).unwrap());
        daemon.wait_for_count("active_connections", 16);
        daemon.wait_for_count("pre_routing_connections", 16);

        drop(admitted);
        daemon.wait_for_count("active_connections", 0);
        daemon.wait_for_count("pre_routing_connections", 0);
    }
}
