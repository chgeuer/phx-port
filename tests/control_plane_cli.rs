#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir_in};

fn tempdir() -> std::io::Result<TempDir> {
    tempdir_in(Path::new("/tmp").canonicalize()?)
}

struct Daemon {
    child: Option<Child>,
    home: TempDir,
    ingress_config: Option<PathBuf>,
    registry: Option<PathBuf>,
    runtime: Option<PathBuf>,
}

impl Daemon {
    fn start_public() -> Self {
        let home = tempdir().unwrap();
        let state = home.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = home.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
        let ingress_config = home.path().join("ingress.toml");
        fs::write(
            &ingress_config,
            "[ingress]\n\
             mode = \"public\"\n\
             unknown_sni = \"reject\"\n\
             \n\
             [ingress.hosts.\"required.example.test\"]\n\
             workload = \"required-web\"\n\
             role = \"https\"\n\
             required = true\n",
        )
        .unwrap();

        Self::start(
            home,
            Some(ingress_config),
            Some(state.join("ports.toml")),
            Some(runtime),
        )
    }

    fn start_development() -> Self {
        Self::start(tempdir().unwrap(), None, None, None)
    }

    fn start(
        home: TempDir,
        ingress_config: Option<PathBuf>,
        registry: Option<PathBuf>,
        runtime: Option<PathBuf>,
    ) -> Self {
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);

        let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        command
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
            .env_remove("PHX_PORT_CONFIG")
            .env_remove("PHX_PORT_INGRESS_CONFIG")
            .env_remove("PHX_PORT_RUNTIME_DIR")
            .env_remove("XDG_RUNTIME_DIR")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(path) = &ingress_config {
            command.args(["--ingress-config", path.to_str().unwrap()]);
            command
                .env("PHX_PORT_CONFIG", registry.as_ref().unwrap())
                .env("PHX_PORT_RUNTIME_DIR", runtime.as_ref().unwrap());
        }
        let child = command.spawn().unwrap();
        let mut daemon = Self {
            child: Some(child),
            home,
            ingress_config,
            registry,
            runtime,
        };
        daemon.wait_until_ready();
        daemon
    }

    fn control_path(&self) -> PathBuf {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.join("control/control.sock"))
            .unwrap_or_else(|| {
                self.home
                    .path()
                    .join(".config/phx-port-runtime/control.sock")
            })
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.control_path().exists() {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                let mut stderr = String::new();
                use std::io::Read;
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        command
            .args(args)
            .env("HOME", self.home.path())
            .env_remove("PHX_PORT_CONFIG")
            .env_remove("PHX_PORT_INGRESS_CONFIG")
            .env_remove("PHX_PORT_RUNTIME_DIR")
            .env_remove("XDG_RUNTIME_DIR");
        if let Some(ingress_config) = &self.ingress_config {
            command
                .env("PHX_PORT_INGRESS_CONFIG", ingress_config)
                .env("PHX_PORT_CONFIG", self.registry.as_ref().unwrap())
                .env("PHX_PORT_RUNTIME_DIR", self.runtime.as_ref().unwrap());
        }
        command.output().unwrap()
    }

    fn root_command(&self, args: &[&str]) -> Output {
        let ingress_config = self
            .ingress_config
            .as_ref()
            .expect("root control is only exercised for public ingress");
        Command::new("sudo")
            .args(["-n", "--", "/usr/bin/env"])
            .arg(format!("HOME={}", self.home.path().display()))
            .arg(format!(
                "PHX_PORT_INGRESS_CONFIG={}",
                ingress_config.display()
            ))
            .arg(format!(
                "PHX_PORT_CONFIG={}",
                self.registry.as_ref().unwrap().display()
            ))
            .arg(format!(
                "PHX_PORT_RUNTIME_DIR={}",
                self.runtime.as_ref().unwrap().display()
            ))
            .arg(env!("CARGO_BIN_EXE_phx-port"))
            .args(args)
            .output()
            .unwrap()
    }

    fn terminate(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().unwrap().is_none() {
            let result =
                unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGINT) };
            assert_eq!(result, 0, "cannot terminate test daemon");
        }
        assert!(child.wait().unwrap().success());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGINT) };
            let _ = child.wait();
        }
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON output ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn public_health_is_machine_readable_and_service_uid_cannot_mutate() {
    let mut daemon = Daemon::start_public();

    let status = daemon.command(&["proxy", "status", "--json"]);
    assert!(
        status.status.success(),
        "JSON status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status = json(&status);
    assert_eq!(status["schema_version"], 1);
    assert_eq!(status["live"], true);
    assert_eq!(status["draining"], false);
    assert_eq!(status["ready"], false);
    assert_eq!(status["generation"], 1);
    assert_eq!(status["degraded_routes"].as_array().unwrap().len(), 1);
    assert_eq!(
        status["degraded_routes"][0]["hostname"],
        "required.example.test"
    );

    let live = daemon.command(&["proxy", "check", "--live"]);
    assert!(live.status.success());
    assert_eq!(json(&live)["live"], true);

    let ready = daemon.command(&["proxy", "check", "--ready"]);
    assert_eq!(ready.status.code(), Some(1));
    assert_eq!(json(&ready)["ready"], false);

    let routes = daemon.command(&["proxy", "routes"]);
    assert!(routes.status.success());
    assert!(
        String::from_utf8_lossy(&routes.stdout).contains("required.example.test"),
        "{}",
        String::from_utf8_lossy(&routes.stdout)
    );

    let stop = daemon.command(&["proxy", "stop"]);
    assert_eq!(stop.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&stop.stderr).contains("not authorized"),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(daemon.child.as_mut().unwrap().try_wait().unwrap().is_none());

    let reload = daemon.command(&["proxy", "reload"]);
    assert_eq!(reload.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&reload.stderr).contains("not authorized"),
        "{}",
        String::from_utf8_lossy(&reload.stderr)
    );

    let runtime = daemon.runtime.as_ref().unwrap();
    let runtime_group = fs::symlink_metadata(runtime).unwrap().gid();
    let control_directory = fs::symlink_metadata(runtime.join("control")).unwrap();
    assert_eq!(control_directory.gid(), runtime_group);
    assert_eq!(control_directory.permissions().mode() & 0o7777, 0o750);
    let control_socket = fs::symlink_metadata(daemon.control_path()).unwrap();
    assert_eq!(control_socket.gid(), runtime_group);
    assert_eq!(control_socket.permissions().mode() & 0o7777, 0o660);

    daemon.terminate();
}

#[test]
fn development_control_remains_current_user_full_authority() {
    let mut daemon = Daemon::start_development();

    let status = daemon.command(&["proxy", "status", "--json"]);
    assert!(status.status.success());
    assert_eq!(json(&status)["hosting_profile"], "development");

    let stop = daemon.command(&["proxy", "stop"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert_eq!(String::from_utf8(stop.stdout).unwrap(), "stopping\n");
    assert!(daemon.child.take().unwrap().wait().unwrap().success());
}

#[test]
#[ignore = "requires passwordless sudo for a real UID 0 control peer"]
fn uid_zero_can_reload_and_stop_public_ingress() {
    assert!(!nix::unistd::geteuid().is_root());
    assert!(
        Command::new("sudo")
            .args(["-n", "true"])
            .status()
            .unwrap()
            .success(),
        "test requires passwordless sudo"
    );
    let mut daemon = Daemon::start_public();

    let reload = daemon.root_command(&["proxy", "reload"]);
    assert!(
        reload.status.success(),
        "{}",
        String::from_utf8_lossy(&reload.stderr)
    );
    assert_eq!(
        String::from_utf8(reload.stdout).unwrap(),
        "unchanged generation=1\n"
    );

    let stop = daemon.root_command(&["proxy", "stop"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert_eq!(String::from_utf8(stop.stdout).unwrap(), "stopping\n");
    assert!(daemon.child.take().unwrap().wait().unwrap().success());
}
