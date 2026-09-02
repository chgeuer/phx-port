#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir_in};

fn tempdir() -> std::io::Result<TempDir> {
    tempdir_in(Path::new("/tmp").canonicalize()?)
}

fn environment_assignment(name: &str, value: &Path) -> String {
    format!("{name}={}", value.display())
}

fn request(path: &Path, command: &str) -> std::io::Result<(String, u32, Option<i32>)> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;

    #[cfg(target_os = "linux")]
    let (peer_uid, peer_pid) = {
        use nix::sys::socket::{getsockopt, sockopt};

        let credentials = getsockopt(&stream, sockopt::PeerCredentials)?;
        (credentials.uid(), Some(credentials.pid()))
    };
    #[cfg(target_os = "macos")]
    let (peer_uid, peer_pid) = {
        let (uid, _) = nix::unistd::getpeereid(&stream)?;
        (uid.as_raw(), None)
    };

    stream.write_all(format!("{command}\n").as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok((response, peer_uid, peer_pid))
}

struct Daemon {
    child: Option<Child>,
    control: PathBuf,
}

impl Daemon {
    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.control.exists() {
                return;
            }
            let child = self.child.as_mut().unwrap();
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = request(&self.control, "STOP");
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

fn assert_owned_mode(path: &Path, uid: u32, gid: u32, mode: u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert_eq!(
        metadata.uid(),
        uid,
        "unexpected owner for {}",
        path.display()
    );
    assert_eq!(
        metadata.gid(),
        gid,
        "unexpected group for {}",
        path.display()
    );
    assert_eq!(
        metadata.permissions().mode() & 0o7777,
        mode,
        "unexpected mode for {}",
        path.display()
    );
}

#[test]
#[ignore = "requires passwordless sudo and a real Unix privilege transition"]
fn manual_privileged_startup_drops_before_public_files_and_input() {
    let uid = nix::unistd::geteuid();
    let user = nix::unistd::User::from_uid(uid)
        .unwrap()
        .expect("effective user has no account");
    assert!(!uid.is_root(), "test must start as a non-root user");
    assert!(
        Command::new("sudo")
            .args(["-n", "true"])
            .status()
            .unwrap()
            .success(),
        "test requires passwordless sudo"
    );

    let directory = tempdir().unwrap();
    let state = directory.path().join("state");
    let runtime = directory.path().join("runtime");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();

    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let listener = reserved.local_addr().unwrap();
    drop(reserved);
    let ingress_config = directory.path().join("ingress.toml");
    fs::write(
        &ingress_config,
        format!(
            "[ingress]\n\
             mode = \"public\"\n\
             unknown_sni = \"reject\"\n\
             listen = [\"{listener}\"]\n\
             \n\
             [ingress.hosts.\"inactive.example.test\"]\n\
             workload = \"inactive-web\"\n\
             role = \"https\"\n\
             required = false\n"
        ),
    )
    .unwrap();

    let control = runtime.join("control/control.sock");
    let child = Command::new("sudo")
        .args(["-n", "--", "/usr/bin/env"])
        .arg(environment_assignment("HOME", directory.path()))
        .arg(environment_assignment(
            "PHX_PORT_CONFIG",
            &state.join("ports.toml"),
        ))
        .arg(environment_assignment("PHX_PORT_RUNTIME_DIR", &runtime))
        .arg(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--run-as",
            &user.name,
            "--ingress-config",
            ingress_config.to_str().unwrap(),
            "--listen",
            &listener.to_string(),
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
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut daemon = Daemon {
        child: Some(child),
        control,
    };
    daemon.wait_until_ready();

    let (status, peer_uid, _peer_pid) = request(&daemon.control, "STATUS").unwrap();
    assert!(status.contains("hosting_profile=public"), "{status}");
    assert!(
        status.contains(&format!("listeners={listener}")),
        "{status}"
    );
    assert_eq!(peer_uid, uid.as_raw(), "control peer retained root");

    #[cfg(target_os = "linux")]
    {
        let process_status =
            fs::read_to_string(format!("/proc/{}/status", _peer_pid.unwrap())).unwrap();
        assert!(
            process_status.contains(&format!(
                "Uid:\t{uid}\t{uid}\t{uid}\t{uid}",
                uid = uid.as_raw()
            )),
            "{process_status}"
        );
        assert!(
            process_status.contains("NoNewPrivs:\t1"),
            "{process_status}"
        );
    }

    assert_owned_mode(&runtime, uid.as_raw(), user.gid.as_raw(), 0o750);
    assert_owned_mode(
        &runtime.join("control"),
        uid.as_raw(),
        user.gid.as_raw(),
        0o750,
    );
    assert_owned_mode(
        &runtime.join("control/control.sock"),
        uid.as_raw(),
        user.gid.as_raw(),
        0o600,
    );

    assert_eq!(request(&daemon.control, "STOP").unwrap().0, "stopping\n");
    let output = daemon.child.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&format!(
            "Dropped privileges to {} (uid {},",
            user.name, uid
        )),
        "missing privilege-drop diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires passwordless sudo and a real Unix privilege transition"]
fn manual_privileged_startup_rejects_listener_mismatch_before_state() {
    let uid = nix::unistd::geteuid();
    let user = nix::unistd::User::from_uid(uid)
        .unwrap()
        .expect("effective user has no account");
    assert!(!uid.is_root(), "test must start as a non-root user");

    let directory = tempdir().unwrap();
    let state = directory.path().join("state");
    let runtime = directory.path().join("runtime");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();

    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let bound = first.local_addr().unwrap();
    drop(first);
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let declared = second.local_addr().unwrap();
    drop(second);
    assert_ne!(bound, declared);

    let ingress_config = directory.path().join("ingress.toml");
    fs::write(
        &ingress_config,
        format!(
            "[ingress]\n\
             mode = \"public\"\n\
             unknown_sni = \"reject\"\n\
             listen = [\"{declared}\"]\n\
             [ingress.hosts.\"inactive.example.test\"]\n\
             workload = \"inactive-web\"\n\
             role = \"https\"\n"
        ),
    )
    .unwrap();

    let output = Command::new("sudo")
        .args(["-n", "--", "/usr/bin/env"])
        .arg(environment_assignment("HOME", directory.path()))
        .arg(environment_assignment(
            "PHX_PORT_CONFIG",
            &state.join("ports.toml"),
        ))
        .arg(environment_assignment("PHX_PORT_RUNTIME_DIR", &runtime))
        .arg(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--run-as",
            &user.name,
            "--ingress-config",
            ingress_config.to_str().unwrap(),
            "--listen",
            &bound.to_string(),
            "--task-budget",
            "512",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("do not match"),
        "unexpected mismatch error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.join("routes.toml").exists());
    assert!(!runtime.join("control").exists());
}

#[test]
#[ignore = "requires passwordless sudo"]
fn root_daemon_requires_run_as_but_other_root_cli_semantics_remain() {
    let directory = tempdir().unwrap();
    let daemon = Command::new("sudo")
        .args(["-n", "--", "/usr/bin/env"])
        .arg(environment_assignment("HOME", directory.path()))
        .arg(env!("CARGO_BIN_EXE_phx-port"))
        .args(["daemon", "--listen", "127.0.0.1:0", "--task-budget", "512"])
        .output()
        .unwrap();
    assert!(!daemon.status.success());
    assert!(
        String::from_utf8_lossy(&daemon.stderr).contains("refusing to run the daemon as UID 0"),
        "unexpected root daemon error: {}",
        String::from_utf8_lossy(&daemon.stderr)
    );

    let version = Command::new("sudo")
        .args(["-n", "--", env!("CARGO_BIN_EXE_phx-port"), "--version"])
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "non-daemon root command failed: {}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("phx-port "));
}
