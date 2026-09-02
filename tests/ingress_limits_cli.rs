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
    #[cfg(target_os = "linux")]
    use {
        nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, rlim_t, setrlimit},
        std::fs,
    };

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

        #[cfg(target_os = "linux")]
        fn start_for_idle_scale(address: SocketAddr, connections: usize) -> Self {
            let home = tempdir().unwrap();
            let child = Command::new(env!("CARGO_BIN_EXE_phx-port"))
                .args([
                    "daemon".to_string(),
                    "--listen".to_string(),
                    address.to_string(),
                    "--active-connections".to_string(),
                    connections.to_string(),
                    "--pre-routing-connections".to_string(),
                    connections.to_string(),
                    "--relay-connections".to_string(),
                    "1".to_string(),
                    "--handoff-negotiations".to_string(),
                    "1".to_string(),
                    "--accepts-per-second".to_string(),
                    connections.to_string(),
                    "--accept-burst".to_string(),
                    connections.to_string(),
                    "--source-accepts-per-second".to_string(),
                    connections.to_string(),
                    "--source-accept-burst".to_string(),
                    connections.to_string(),
                    "--source-pre-routing-connections".to_string(),
                    connections.to_string(),
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

        #[cfg(target_os = "linux")]
        fn stop_with_active_connections(mut self) {
            self.request("STOP").unwrap();
            let mut child = self.child.take().unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "daemon exited unsuccessfully: {status}");
                    return;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "daemon did not cancel idle ClientHello tasks during shutdown:\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                thread::sleep(Duration::from_millis(20));
            }
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

    #[cfg(target_os = "linux")]
    fn ensure_open_file_limit(required: rlim_t) {
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        if soft >= required {
            return;
        }
        assert!(
            hard == RLIM_INFINITY || hard >= required,
            "idle ClientHello regression requires {required} file descriptors, hard limit is {hard}"
        );
        setrlimit(Resource::RLIMIT_NOFILE, required, hard).unwrap();
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
    fn clean_shutdown_emits_one_bounded_drain_event() {
        let daemon = Daemon::start(reserve_address());
        let stderr = daemon.stop_and_stderr();
        let drain_events = stderr
            .lines()
            .filter(|line| line.starts_with("event=ingress_shutdown "))
            .collect::<Vec<_>>();
        assert_eq!(
            drain_events.len(),
            1,
            "shutdown must emit exactly one bounded result event:\n{stderr}"
        );
        let event = drain_events[0];
        assert!(event.contains(" result=complete "), "{event}");
        assert!(event.contains(" forced_connections=0 "), "{event}");
        assert!(event.ends_with(" active_connections=0"), "{event}");
        let duration_ms = event
            .split_whitespace()
            .find_map(|field| field.strip_prefix("duration_ms="))
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(
            duration_ms < 3_000,
            "clean shutdown took an unexpected {duration_ms}ms"
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

    #[cfg(target_os = "linux")]
    #[test]
    fn two_thousand_idle_client_hellos_use_constant_threads_and_cancel_on_stop() {
        const CONNECTIONS: usize = 2_000;

        ensure_open_file_limit((CONNECTIONS + 256) as rlim_t);
        let address = reserve_address();
        let daemon = Daemon::start_for_idle_scale(address, CONNECTIONS);
        let pid = daemon.child.as_ref().unwrap().id();
        let baseline_threads = fs::read_dir(format!("/proc/{pid}/task")).unwrap().count();
        let clients = (0..CONNECTIONS)
            .map(|_| TcpStream::connect(address).unwrap())
            .collect::<Vec<_>>();

        daemon.wait_for_count("active_connections", CONNECTIONS);
        daemon.wait_for_count("pre_routing_connections", CONNECTIONS);
        let loaded_threads = fs::read_dir(format!("/proc/{pid}/task")).unwrap().count();
        assert!(
            loaded_threads <= baseline_threads + 4,
            "native threads grew from {baseline_threads} to {loaded_threads} for \
             {CONNECTIONS} idle ClientHellos"
        );

        daemon.stop_with_active_connections();
        drop(clients);
    }
}
