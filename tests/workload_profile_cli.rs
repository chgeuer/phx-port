use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir_in;
use toml_edit::DocumentMut;

fn tempdir() -> std::io::Result<tempfile::TempDir> {
    #[cfg(unix)]
    let root = Path::new("/tmp").canonicalize()?;
    #[cfg(not(unix))]
    let root = std::env::temp_dir().canonicalize()?;
    tempdir_in(root)
}

#[cfg(unix)]
struct RunningDaemon {
    child: Option<std::process::Child>,
    home: tempfile::TempDir,
    ingress_config: Option<std::path::PathBuf>,
    public_registry: Option<std::path::PathBuf>,
    public_runtime: Option<std::path::PathBuf>,
}

#[cfg(unix)]
impl RunningDaemon {
    fn start(ingress_config: Option<&Path>, workload_id: Option<&str>) -> Self {
        use std::net::TcpListener;
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let home = tempdir().unwrap();
        let (public_registry, public_runtime) = if ingress_config.is_some() {
            use std::os::unix::fs::PermissionsExt;

            let state = home.path().join("state");
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            let runtime = home.path().join("runtime");
            fs::create_dir(&runtime).unwrap();
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
            (Some(state.join("ports.toml")), Some(runtime))
        } else {
            (None, None)
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        command
            .args([
                "daemon",
                "--listen",
                &address.to_string(),
                "--active-connections",
                "1",
                "--pre-routing-connections",
                "1",
                "--relay-connections",
                "1",
                "--handoff-negotiations",
                "1",
                "--client-hello-timeout-ms",
                "500",
                "--task-budget",
                "128",
            ])
            .env("HOME", home.path())
            .env_remove("PHX_PORT_CONFIG")
            .env_remove("PHX_PORT_INGRESS_CONFIG")
            .env_remove("XDG_RUNTIME_DIR")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(path) = ingress_config {
            command.args(["--ingress-config", path.to_str().unwrap()]);
            command
                .env("PHX_PORT_CONFIG", public_registry.as_ref().unwrap())
                .env("PHX_PORT_RUNTIME_DIR", public_runtime.as_ref().unwrap());
        }
        if let Some(workload_id) = workload_id {
            command.env("PHX_PORT_WORKLOAD_ID", workload_id);
        } else {
            command.env_remove("PHX_PORT_WORKLOAD_ID");
        }
        let child = command.spawn().unwrap();
        let mut daemon = Self {
            child: Some(child),
            home,
            ingress_config: ingress_config.map(Path::to_path_buf),
            public_registry,
            public_runtime,
        };

        let control = daemon.control_path();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !control.exists() {
            if let Some(status) = daemon.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("daemon exited before creating control socket: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not create its control socket"
            );
            thread::sleep(Duration::from_millis(20));
        }
        daemon
    }

    fn control_path(&self) -> std::path::PathBuf {
        if let Some(runtime) = &self.public_runtime {
            return runtime.join("control/control.sock");
        }
        self.home
            .path()
            .join(".config/phx-port-runtime/control.sock")
    }

    fn control(&self, command: &str) -> std::process::Output {
        let mut process = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        process
            .args(["proxy", command])
            .env("HOME", self.home.path())
            .env_remove("XDG_RUNTIME_DIR");
        if let Some(ingress_config) = &self.ingress_config {
            process
                .env("PHX_PORT_INGRESS_CONFIG", ingress_config)
                .env("PHX_PORT_CONFIG", self.public_registry.as_ref().unwrap())
                .env(
                    "PHX_PORT_RUNTIME_DIR",
                    self.public_runtime.as_ref().unwrap(),
                );
        } else {
            process
                .env_remove("PHX_PORT_CONFIG")
                .env_remove("PHX_PORT_INGRESS_CONFIG")
                .env_remove("PHX_PORT_RUNTIME_DIR");
        }
        process.output().unwrap()
    }

    fn status(&self) -> String {
        let output = self.control("status");
        assert!(
            output.status.success(),
            "status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn stop(mut self) {
        if self.ingress_config.is_some() {
            let mut child = self.child.take().unwrap();
            let result =
                unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGINT) };
            assert_eq!(result, 0, "cannot terminate public test daemon");
            let status = child.wait().unwrap();
            assert!(status.success(), "daemon failed during shutdown: {status}");
            return;
        }
        let output = self.control("stop");
        assert!(
            output.status.success(),
            "stop failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let status = self.child.take().unwrap().wait().unwrap();
        assert!(status.success(), "daemon failed during shutdown: {status}");
    }
}

#[cfg(unix)]
impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if self.ingress_config.is_some() {
                let _ =
                    unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGINT) };
            } else {
                let _ = self.control("stop");
            }
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

#[test]
fn concurrent_logical_workload_starts_share_one_stable_port_without_ingress() {
    let directory = tempdir().unwrap();
    let registry = directory.path().join("registry/ports.toml");
    let barrier = Arc::new(Barrier::new(12));
    let mut workers = Vec::new();

    for index in 0..12 {
        let cwd = directory.path().join(format!("release-{index}"));
        fs::create_dir(&cwd).unwrap();
        let registry = registry.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            Command::new(env!("CARGO_BIN_EXE_phx-port"))
                .current_dir(cwd)
                .env("PHX_PORT_CONFIG", registry)
                .env("PHX_PORT_WORKLOAD_ID", "contoso-web")
                .env_remove("PHX_PORT_INGRESS_CONFIG")
                .output()
                .unwrap()
        }));
    }

    let outputs = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    for output in &outputs {
        assert!(
            output.status.success(),
            "allocation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let ports = outputs
        .iter()
        .map(|output| {
            String::from_utf8(output.stdout.clone())
                .unwrap()
                .trim()
                .parse::<u16>()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(
        ports.iter().all(|port| *port == ports[0]),
        "one logical Workload received different ports: {ports:?}"
    );

    let document = fs::read_to_string(&registry)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    let assignments = document["ports"].as_table().unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(
        assignments["contoso-web"]["main"].as_integer(),
        Some(i64::from(ports[0]))
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(registry.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(&registry).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let lock = registry.with_file_name("ports.toml.lock");
        assert_eq!(
            fs::metadata(lock).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
}

#[test]
fn concurrent_distinct_logical_workloads_receive_distinct_ports() {
    let directory = tempdir().unwrap();
    let registry = directory.path().join("registry/ports.toml");
    let barrier = Arc::new(Barrier::new(12));
    let mut workers = Vec::new();

    for index in 0..12 {
        let registry = registry.clone();
        let cwd = directory.path().to_path_buf();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            allocate(&cwd, &registry, Some(&format!("workload-{index}")), &[])
        }));
    }

    let ports = workers
        .into_iter()
        .map(|worker| output_port(&worker.join().unwrap()))
        .collect::<BTreeSet<_>>();
    assert_eq!(ports.len(), 12);
}

fn allocate(
    cwd: &Path,
    registry: &Path,
    workload_id: Option<&str>,
    arguments: &[&str],
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
    command
        .args(arguments)
        .current_dir(cwd)
        .env("PHX_PORT_CONFIG", registry)
        .env_remove("PHX_PORT_INGRESS_CONFIG");
    match workload_id {
        Some(workload_id) => {
            command.env("PHX_PORT_WORKLOAD_ID", workload_id);
        }
        None => {
            command.env_remove("PHX_PORT_WORKLOAD_ID");
        }
    }
    command.output().unwrap()
}

fn output_port(output: &std::process::Output) -> u16 {
    assert!(
        output.status.success(),
        "allocation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn explicit_cli_workload_id_overrides_path_and_allocates_named_roles() {
    let directory = tempdir().unwrap();
    let registry = directory.path().join("registry/ports.toml");
    let first_release = directory.path().join("release-a");
    let second_release = directory.path().join("release-b");
    fs::create_dir(&first_release).unwrap();
    fs::create_dir(&second_release).unwrap();

    let first = allocate(
        &first_release,
        &registry,
        None,
        &["--workload-id", "contoso-web", "https"],
    );
    let second = allocate(
        &second_release,
        &registry,
        Some("ignored-environment-id"),
        &["--workload-id", "contoso-web", "https"],
    );
    let https_port = output_port(&first);
    assert_eq!(https_port, output_port(&second));
    let main_port = output_port(&allocate(
        &second_release,
        &registry,
        Some("contoso-web"),
        &[],
    ));
    assert_ne!(https_port, main_port);

    let document = fs::read_to_string(registry)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    assert_eq!(
        document["ports"]["contoso-web"]["https"].as_integer(),
        Some(i64::from(https_port))
    );
    assert_eq!(
        document["ports"]["contoso-web"]["main"].as_integer(),
        Some(i64::from(main_port))
    );
    assert!(
        document["ports"]
            .as_table()
            .unwrap()
            .get("ignored-environment-id")
            .is_none()
    );
}

#[test]
fn identical_logical_workload_ids_allocate_from_each_hosts_local_registry() {
    let directory = tempdir().unwrap();
    let first_registry = directory.path().join("host-a/ports.toml");
    let second_registry = directory.path().join("host-b/ports.toml");

    assert_eq!(
        output_port(&allocate(
            directory.path(),
            &first_registry,
            Some("already-present"),
            &[],
        )),
        4001
    );
    let first_host_port = output_port(&allocate(
        directory.path(),
        &first_registry,
        Some("contoso-web"),
        &[],
    ));
    let second_host_port = output_port(&allocate(
        directory.path(),
        &second_registry,
        Some("contoso-web"),
        &[],
    ));

    assert_eq!(first_host_port, 4002);
    assert_eq!(second_host_port, 4001);
}

#[test]
fn development_allocation_remains_keyed_by_current_directory() {
    let directory = tempdir().unwrap();
    let registry = directory.path().join("ports.toml");
    let first_project = directory.path().join("project-a");
    let second_project = directory.path().join("project-b");
    fs::create_dir(&first_project).unwrap();
    fs::create_dir(&second_project).unwrap();

    let first = output_port(&allocate(&first_project, &registry, None, &[]));
    let second = output_port(&allocate(&second_project, &registry, None, &[]));
    assert_ne!(first, second);

    let document = fs::read_to_string(registry)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    assert_eq!(
        document["ports"][first_project.to_str().unwrap()]["main"].as_integer(),
        Some(i64::from(first))
    );
    assert_eq!(
        document["ports"][second_project.to_str().unwrap()]["main"].as_integer(),
        Some(i64::from(second))
    );
}

#[test]
fn logical_workload_ids_are_strictly_validated_without_directory_fallback() {
    let directory = tempdir().unwrap();
    let cwd = directory.path().join("release");
    fs::create_dir(&cwd).unwrap();
    let invalid_ids = [
        String::new(),
        "Contoso".to_string(),
        "-contoso".to_string(),
        "contoso-".to_string(),
        "contoso/web".to_string(),
        "cöntoso".to_string(),
        "a".repeat(129),
    ];

    for (index, workload_id) in invalid_ids.iter().enumerate() {
        let registry = directory
            .path()
            .join(format!("registry-{index}/ports.toml"));
        let output = allocate(&cwd, &registry, Some(workload_id), &[]);
        assert!(
            !output.status.success(),
            "invalid Workload ID was accepted: {workload_id:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("logical Workload ID"),
            "unexpected error for {workload_id:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!registry.exists(), "invalid ID created a registry");
    }
}

#[cfg(unix)]
#[test]
fn logical_registry_refuses_file_and_lock_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempdir().unwrap();
    let registry_directory = directory.path().join("registry");
    fs::create_dir(&registry_directory).unwrap();
    fs::set_permissions(&registry_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let registry = registry_directory.join("ports.toml");
    let lock = registry_directory.join("ports.toml.lock");
    let target = directory.path().join("target.toml");
    fs::write(&target, "[ports]\n").unwrap();
    symlink(&target, &registry).unwrap();

    let output = allocate(directory.path(), &registry, Some("contoso-web"), &[]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing symbolic link"),
        "unexpected registry symlink error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_file(&registry).unwrap();
    fs::remove_file(&lock).unwrap();

    symlink(&target, &lock).unwrap();
    let output = allocate(directory.path(), &registry, Some("contoso-web"), &[]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing symbolic link"),
        "unexpected lock symlink error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let linked_directory = directory.path().join("linked-registry");
    symlink(&registry_directory, &linked_directory).unwrap();
    let output = allocate(
        directory.path(),
        &linked_directory.join("other.toml"),
        Some("contoso-web"),
        &[],
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing symbolic link"),
        "unexpected directory symlink error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(target).unwrap(), "[ports]\n");
}

#[cfg(unix)]
#[test]
fn logical_registry_rejects_unsafe_modes_and_duplicate_ports() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let unsafe_directory = directory.path().join("unsafe-registry");
    fs::create_dir(&unsafe_directory).unwrap();
    fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o755)).unwrap();
    let unsafe_registry = unsafe_directory.join("ports.toml");
    let output = allocate(directory.path(), &unsafe_registry, Some("contoso-web"), &[]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must have mode 0700"),
        "unexpected directory mode error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let registry_directory = directory.path().join("private-registry");
    fs::create_dir(&registry_directory).unwrap();
    fs::set_permissions(&registry_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let registry = registry_directory.join("ports.toml");
    fs::write(
        &registry,
        "[ports]\n[ports.alpha]\nmain = 4001\n[ports.beta]\nhttps = 4001\n",
    )
    .unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();

    let output = allocate(directory.path(), &registry, Some("contoso-web"), &[]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("registry port 4001 is assigned to both"),
        "unexpected duplicate port error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    fs::write(
        &registry,
        "[ports]\n[ports.contoso-web]\nmain = \"not-a-port\"\n",
    )
    .unwrap();
    let output = allocate(directory.path(), &registry, Some("contoso-web"), &[]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be an integer"),
        "unexpected malformed assignment error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn production_migration_splits_derived_state_and_preserves_rollback_source() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let source_directory = directory.path().join("legacy");
    fs::create_dir(&source_directory).unwrap();
    fs::set_permissions(&source_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let missing_source = source_directory.join("missing.toml");
    let missing_output = directory.path().join("missing-output");
    let missing = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "proxy",
            "config",
            "migrate",
            "--from",
            missing_source.to_str().unwrap(),
            "--output",
            missing_output.to_str().unwrap(),
        ])
        .env_remove("PHX_PORT_CONFIG")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("PHX_PORT_RUNTIME_DIR")
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("does not exist"),
        "unexpected missing source error: {}",
        String::from_utf8_lossy(&missing.stderr)
    );
    assert!(!missing_output.exists());
    assert!(!source_directory.join("missing.toml.lock").exists());

    let source = source_directory.join("combined.toml");
    let original = "\
[ports]

[ports.contoso-web]
https = 4401

[discovered_routes.\"www.contoso.test\"]
project = \"contoso-web\"
role = \"https\"
certificate_fingerprint = \"AA:BB\"
last_verified_unix = 1788321600
";
    fs::write(&source, original).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let output_directory = directory.path().join("production-state");

    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "proxy",
            "config",
            "migrate",
            "--from",
            source.to_str().unwrap(),
            "--output",
            output_directory.to_str().unwrap(),
        ])
        .env_remove("PHX_PORT_CONFIG")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("PHX_PORT_RUNTIME_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "migration failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(fs::read_to_string(&source).unwrap(), original);
    assert_eq!(
        fs::metadata(&source).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(&output_directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );

    let ports_path = output_directory.join("ports.toml");
    let routes_path = output_directory.join("routes.toml");
    for path in [&ports_path, &routes_path] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o600,
            "{} was not private",
            path.display()
        );
    }

    let ports = fs::read_to_string(&ports_path)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    assert_eq!(
        ports["ports"]["contoso-web"]["https"].as_integer(),
        Some(4401)
    );
    assert!(ports.get("discovered_routes").is_none());

    let routes = fs::read_to_string(&routes_path)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    assert_eq!(
        routes["discovered_routes"]["www.contoso.test"]["project"].as_str(),
        Some("contoso-web")
    );
    assert!(routes.get("ports").is_none());

    let repeated = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "proxy",
            "config",
            "migrate",
            "--from",
            source.to_str().unwrap(),
            "--output",
            output_directory.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!repeated.status.success());
    assert!(
        String::from_utf8_lossy(&repeated.stderr).contains("refusing to overwrite"),
        "unexpected repeated migration error: {}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    assert_eq!(fs::read_to_string(&source).unwrap(), original);
}

#[test]
fn ingress_config_requires_public_mode_for_cli_and_environment_activation() {
    let directory = tempdir().unwrap();
    let public_config = directory.path().join("public.toml");
    fs::write(
        &public_config,
        "[ingress]\nmode = \"public\"\n\
         [ingress.hosts.\"www.example.com\"]\n\
         workload = \"contoso-web\"\nrole = \"https\"\n",
    )
    .unwrap();
    let non_public_config = directory.path().join("non-public.toml");
    fs::write(&non_public_config, "[ingress]\nmode = \"development\"\n").unwrap();

    let accepted_cli = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--ingress-config",
            public_config.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--active-connections",
            "0",
        ])
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .output()
        .unwrap();
    assert!(!accepted_cli.status.success());
    assert!(
        String::from_utf8_lossy(&accepted_cli.stderr)
            .contains("active_connections must be greater than zero"),
        "public CLI config was not accepted: {}",
        String::from_utf8_lossy(&accepted_cli.stderr)
    );

    let accepted_environment = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--active-connections",
            "0",
        ])
        .env("PHX_PORT_INGRESS_CONFIG", &public_config)
        .output()
        .unwrap();
    assert!(!accepted_environment.status.success());
    assert!(
        String::from_utf8_lossy(&accepted_environment.stderr)
            .contains("active_connections must be greater than zero"),
        "public environment config was not accepted: {}",
        String::from_utf8_lossy(&accepted_environment.stderr)
    );

    let rejected = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--ingress-config",
            non_public_config.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--active-connections",
            "0",
        ])
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("must declare [ingress] mode = \"public\""),
        "non-public ingress config did not fail closed: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[cfg(unix)]
#[test]
fn non_loopback_public_listener_requires_root_owned_intent() {
    let directory = tempdir().unwrap();
    let public_config = directory.path().join("public.toml");
    fs::write(
        &public_config,
        "[ingress]\nmode = \"public\"\n\
         [ingress.hosts.\"www.example.com\"]\n\
         workload = \"contoso-web\"\nrole = \"https\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--listen",
            "0.0.0.0:0",
            "--ingress-config",
            public_config.to_str().unwrap(),
        ])
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("owned by unexpected UID"),
        "unexpected intent ownership error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn explicit_ingress_config_activates_public_profile_but_workload_id_does_not() {
    let directory = tempdir().unwrap();
    let public_config = directory.path().join("public.toml");
    fs::write(
        &public_config,
        "[ingress]\nmode = \"public\"\n\
         [ingress.hosts.\"www.example.com\"]\n\
         workload = \"contoso-web\"\nrole = \"https\"\n",
    )
    .unwrap();

    let public = RunningDaemon::start(Some(&public_config), None);
    assert!(public.status().contains("hosting_profile=public"));
    public.stop();

    let development = RunningDaemon::start(None, Some("contoso-web"));
    assert!(development.status().contains("hosting_profile=development"));
    development.stop();
}

#[cfg(unix)]
#[test]
fn public_profile_reconciles_multiple_routes_and_preserves_valid_generation() {
    use std::time::{Duration, Instant};

    let directory = tempdir().unwrap();
    let public_config = directory.path().join("public.toml");
    fs::write(
        &public_config,
        "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n\
         [ingress.hosts.\"required.example.test\"]\n\
         workload = \"required-web\"\nrole = \"https\"\nrequired = true\n\
         [ingress.hosts.\"optional.example.test\"]\n\
         workload = \"optional-web\"\nrole = \"https\"\nrequired = false\n",
    )
    .unwrap();

    let daemon = RunningDaemon::start(Some(&public_config), None);
    let initial = daemon.status();
    assert!(initial.contains("config_generation=1"), "{initial}");
    assert!(initial.contains("declared_routes=2"), "{initial}");
    assert!(initial.contains("required_routes=1"), "{initial}");
    assert!(initial.contains("optional_routes=1"), "{initial}");
    assert!(initial.contains("ready=false"), "{initial}");
    assert!(initial.contains("degraded_routes=2"), "{initial}");

    fs::write(
        &public_config,
        "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n\
         [ingress.hosts.\"DUPLICATE.example.test.\"]\n\
         workload = \"first-web\"\nrole = \"https\"\nrequired = true\n\
         [ingress.hosts.\"duplicate.example.test\"]\n\
         workload = \"second-web\"\nrole = \"https\"\nrequired = true\n",
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let rejected = loop {
        let status = daemon.status();
        if status.contains("last_reload_error=config_invalid") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not reject the invalid generation: {status}"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(rejected.contains("config_generation=1"), "{rejected}");
    assert!(
        rejected.contains("last_rejected_config_generation=2"),
        "{rejected}"
    );
    assert!(rejected.contains("declared_routes=2"), "{rejected}");
    assert!(rejected.contains("required_routes=1"), "{rejected}");

    fs::write(
        &public_config,
        "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n\
         [ingress.hosts.\"replacement.example.test\"]\n\
         workload = \"replacement-web\"\nrole = \"https\"\nrequired = false\n",
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let replaced = loop {
        let status = daemon.status();
        if status.lines().any(|line| line == "config_generation=2")
            && status.contains("last_reload_error=none")
        {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not install the replacement generation: {status}"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(replaced.contains("declared_routes=1"), "{replaced}");
    assert!(replaced.contains("required_routes=0"), "{replaced}");
    assert!(replaced.contains("optional_routes=1"), "{replaced}");
    assert!(replaced.contains("ready=true"), "{replaced}");
    assert!(replaced.contains("degraded_routes=1"), "{replaced}");
    assert!(replaced.contains("last_reload_error=none"), "{replaced}");
    daemon.stop();
}
