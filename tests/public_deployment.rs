#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use tempfile::{TempDir, tempdir};

fn script(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn installer_function(function: &str, arguments: &[&Path], tail: &[&str]) -> Output {
    Command::new("bash")
        .args(["-c", "source \"$1\"; shift; \"$@\"", "installer-test"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/systemd/install-public.sh"))
        .arg(function)
        .args(arguments)
        .args(tail)
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct RunningExecutable(Child);

impl Drop for RunningExecutable {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn atomic_install_replaces_a_running_executable_without_truncation() {
    let root = tempdir().unwrap();
    let destination = root.path().join("phx-port");
    // Keep the writable executable out of descriptors inherited by concurrent test forks.
    assert_success(
        &Command::new("cp")
            .arg("/bin/sleep")
            .arg(&destination)
            .output()
            .unwrap(),
    );
    let previous_inode = destination.metadata().unwrap().ino();
    let mut running = RunningExecutable(Command::new(&destination).arg("30").spawn().unwrap());
    let source = root.path().join("release");
    script(&source, "#!/bin/sh\nprintf 'new release\\n'\n");
    let owner = nix::unistd::geteuid().to_string();
    let group = nix::unistd::getegid().to_string();

    for _ in 0..2 {
        let output = installer_function(
            "atomic_install",
            &[&source, &destination],
            &["0755", &owner, &group],
        );
        assert_success(&output);
        assert!(running.0.try_wait().unwrap().is_none());
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        assert_eq!(destination.metadata().unwrap().mode() & 0o777, 0o755);
        assert_ne!(destination.metadata().unwrap().ino(), previous_inode);
        assert_eq!(
            Command::new(&destination).output().unwrap().stdout,
            b"new release\n"
        );
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn failed_release_validation_preserves_the_previous_binary_and_cleans_staging() {
    let root = tempdir().unwrap();
    let source = root.path().join("release");
    let destination = root.path().join("phx-port");
    fs::write(&source, "new release").unwrap();
    fs::write(&destination, "previous release").unwrap();
    let previous_inode = destination.metadata().unwrap().ino();
    let owner = nix::unistd::geteuid().to_string();
    let group = nix::unistd::getegid().to_string();
    let output = installer_function(
        "atomic_install",
        &[&source, &destination],
        &["0755", &owner, &group, "false"],
    );
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(&destination).unwrap(),
        "previous release"
    );
    assert_eq!(destination.metadata().unwrap().ino(), previous_inode);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn policy_bootstrap_preserves_operator_edits_and_durable_state_on_rerun() {
    let root = tempdir().unwrap();
    let source = root.path().join("template.toml");
    let destination = root.path().join("ingress.toml");
    let state = root.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::write(&source, include_str!("../packaging/systemd/ingress.toml")).unwrap();
    let owner = nix::unistd::geteuid().to_string();
    let group = nix::unistd::getegid().to_string();
    let bootstrap = || {
        installer_function(
            "bootstrap_policy",
            &[&source, &destination, &state],
            &[&owner, &group],
        )
    };
    assert_success(&bootstrap());
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
    assert_eq!(destination.metadata().unwrap().mode() & 0o777, 0o640);
    assert_eq!(destination.metadata().unwrap().nlink(), 1);

    fs::write(&destination, "operator-managed policy").unwrap();
    let policy_inode = destination.metadata().unwrap().ino();
    for name in ["ports.toml", "routes.toml", "route-claims.toml"] {
        fs::write(state.join(name), format!("preserve {name}")).unwrap();
    }
    assert_success(&bootstrap());
    assert_eq!(
        fs::read_to_string(&destination).unwrap(),
        "operator-managed policy"
    );
    assert_eq!(destination.metadata().unwrap().ino(), policy_inode);
    for name in ["ports.toml", "routes.toml", "route-claims.toml"] {
        assert_eq!(
            fs::read_to_string(state.join(name)).unwrap(),
            format!("preserve {name}")
        );
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 3);
}

#[test]
fn missing_policy_with_existing_state_requires_recovery_not_new_authority() {
    for name in ["ports.toml", "routes.toml", "route-claims.toml"] {
        let root = tempdir().unwrap();
        let source = root.path().join("template.toml");
        let destination = root.path().join("ingress.toml");
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::write(&source, "new policy").unwrap();
        fs::write(state.join(name), "existing authority").unwrap();
        let output = installer_function(
            "bootstrap_policy",
            &[&source, &destination, &state],
            &["root", "root"],
        );
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("restore the policy"));
        assert!(!destination.exists());
        assert_eq!(
            fs::read_to_string(state.join(name)).unwrap(),
            "existing authority"
        );
    }
}

#[test]
fn installation_rejects_symlink_and_directory_destinations() {
    for directory in [false, true] {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let sentinel = root.path().join("sentinel");
        let destination = root.path().join("destination");
        fs::write(&source, "new").unwrap();
        fs::write(&sentinel, "untouched").unwrap();
        if directory {
            fs::create_dir(&destination).unwrap();
        } else {
            symlink(&sentinel, &destination).unwrap();
        }
        for (function, arguments) in [
            (
                "atomic_install",
                vec![source.as_path(), destination.as_path()],
            ),
            (
                "bootstrap_policy",
                vec![source.as_path(), destination.as_path(), root.path()],
            ),
        ] {
            let tail = if function == "atomic_install" {
                vec!["0755", "root", "root"]
            } else {
                vec!["root", "root"]
            };
            let output = installer_function(function, &arguments, &tail);
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("non-regular"));
            assert_eq!(fs::read_to_string(&sentinel).unwrap(), "untouched");
        }
    }
}

#[test]
fn default_policy_and_deployment_recipe_use_the_native_dual_stack_release() {
    let config = include_str!("../packaging/systemd/ingress.toml")
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    assert_eq!(config["ingress"]["mode"].as_str(), Some("public"));
    assert_eq!(
        config["ingress"]["routing_policy"].as_str(),
        Some("certificate_discovery")
    );
    assert_eq!(
        config["ingress"]["listen"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        ["0.0.0.0:443", "[::]:443"]
    );
    assert!(config["ingress"].get("hosts").is_none());
    let (_, recipe) = include_str!("../justfile")
        .split_once("[linux]\ndeploy-public:\n")
        .unwrap();
    let recipe = recipe
        .lines()
        .take_while(|line| line.starts_with("    "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        recipe.contains("cargo build --release --locked --target-dir target --target \"$host\"")
    );
    assert!(recipe.contains("just install-public \"target/$host/release/phx-port\""));
    assert!(!recipe.contains("systemctl"));
    assert!(!recipe.contains("public-on"));
    assert!(!recipe.contains("public-restart"));
    let installer = include_str!("../packaging/systemd/install-public.sh");
    assert_eq!(
        installer
            .lines()
            .filter(|line| line.trim_start().starts_with("systemctl "))
            .map(str::trim)
            .collect::<Vec<_>>(),
        ["systemctl daemon-reload"]
    );
}

#[test]
fn public_off_on_retains_workload_owned_handoff_endpoints() {
    assert!(
        include_str!("../packaging/systemd/phx-port.service")
            .lines()
            .any(|line| line == "RuntimeDirectoryPreserve=yes"),
        "stopping ingress must not unlink live Workload-owned PHXP endpoints"
    );
}

struct ServiceFixture {
    root: TempDir,
}

impl ServiceFixture {
    fn new() -> Self {
        let root = tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        script(
            &bin.join("sudo"),
            r#"#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$PHX_PORT_TEST_ROOT/sudo.log"
while (( $# )); do
    case "$1" in
        -n|-v) shift ;;
        -u|-g) shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done
(( $# )) || exit 0
args=("$@")
for ((index = 0; index < ${#args[@]}; index++)); do
    if [[ "${args[$index]}" == /usr/local/bin/phx-port ]]; then
        args[$index]="$PHX_PORT_TEST_ROOT/bin/phx-port"
    fi
done
exec "${args[@]}"
"#,
        );
        script(
            &bin.join("systemctl"),
            r#"#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$PHX_PORT_TEST_ROOT/systemctl.log"
case "$1" in
    enable)
        touch "$PHX_PORT_TEST_ROOT/enabled"
        if [[ ! -f "$PHX_PORT_TEST_ROOT/fail-start" ]]; then
            touch "$PHX_PORT_TEST_ROOT/running"
        fi ;;
    disable)
        rm -f -- "$PHX_PORT_TEST_ROOT/enabled" "$PHX_PORT_TEST_ROOT/running" ;;
    is-active) test -f "$PHX_PORT_TEST_ROOT/running" ;;
    try-restart) test -f "$PHX_PORT_TEST_ROOT/running" ;;
    --no-pager)
        if [[ -f "$PHX_PORT_TEST_ROOT/running" ]]; then
            printf 'ActiveState=active\n'
        else
            printf 'ActiveState=inactive\n'
        fi ;;
    *) printf 'Unexpected systemctl invocation\n' >&2; exit 1 ;;
esac
"#,
        );
        script(
            &bin.join("phx-port"),
            r#"#!/bin/bash
set -euo pipefail
test "$PHX_PORT_INGRESS_CONFIG" = /etc/phx-port/ingress.toml
test "$PHX_PORT_CONFIG" = /var/lib/phx-port/ports.toml
test "$PHX_PORT_RUNTIME_DIR" = /run/phx-port
printf '%s\n' "$*" >> "$PHX_PORT_TEST_ROOT/phx-port.log"
case "$*" in
    "proxy config check --file /etc/phx-port/ingress.toml")
        if [[ -f "$PHX_PORT_TEST_ROOT/invalid-policy" ]]; then
            printf 'invalid public policy\n' >&2
            exit 1
        fi ;;
    "proxy check --live") test -f "$PHX_PORT_TEST_ROOT/running" ;;
    "proxy check --ready")
        if [[ -f "$PHX_PORT_TEST_ROOT/not-ready" ]]; then
            printf 'no verified routes\n' >&2
            exit 1
        fi ;;
    "proxy routes") printf 'verified routes\n' ;;
    "--workload-id sub-domain https") printf '4104\n' ;;
    *) printf 'Unexpected phx-port invocation\n' >&2; exit 1 ;;
esac
"#,
        );
        script(
            &bin.join("journalctl"),
            "#!/bin/sh\nprintf 'service startup diagnostics\\n'\n",
        );
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/systemd/public-service.sh"))
            .args(args)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("HOME", self.root.path())
            .env("PHX_PORT_TEST_ROOT", self.root.path())
            .output()
            .unwrap()
    }

    fn mark(&self, name: &str) {
        fs::write(self.path(name), "").unwrap();
    }
}

#[test]
fn service_on_and_off_are_repeatable_and_include_both_socket_units() {
    let fixture = ServiceFixture::new();
    for _ in 0..2 {
        assert_success(&fixture.run(&["on"]));
        assert!(fixture.path("running").exists());
        assert!(fixture.path("enabled").exists());
    }
    for _ in 0..2 {
        assert_success(&fixture.run(&["off"]));
        assert!(!fixture.path("running").exists());
        assert!(!fixture.path("enabled").exists());
    }
    assert_eq!(
        fs::read_to_string(fixture.path("systemctl.log")).unwrap(),
        "enable --now phx-port.service phx-port-ipv4.socket phx-port-ipv6.socket\n\
         enable --now phx-port.service phx-port-ipv4.socket phx-port-ipv6.socket\n\
         disable --now phx-port.service phx-port-ipv4.socket phx-port-ipv6.socket\n\
         disable --now phx-port.service phx-port-ipv4.socket phx-port-ipv6.socket\n"
    );
    let status = fixture.run(&["status"]);
    assert_success(&status);
    assert_eq!(status.stdout, b"ActiveState=inactive\n");
}

#[test]
fn restart_never_activates_an_off_service_or_changes_boot_enablement() {
    let fixture = ServiceFixture::new();
    let off = fixture.run(&["restart"]);
    assert!(!off.status.success());
    assert!(String::from_utf8_lossy(&off.stderr).contains("use just public-on"));
    assert!(!fixture.path("running").exists());

    fixture.mark("running");
    assert_success(&fixture.run(&["restart"]));
    assert!(!fixture.path("enabled").exists());
    assert_eq!(
        fs::read_to_string(fixture.path("systemctl.log")).unwrap(),
        "is-active --quiet phx-port.service\n\
         is-active --quiet phx-port.service\n\
         try-restart phx-port.service\n"
    );
}

#[test]
fn invalid_policy_prevents_service_activation() {
    let fixture = ServiceFixture::new();
    fixture.mark("invalid-policy");
    let output = fixture.run(&["on"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid public policy"));
    assert!(!fixture.path("systemctl.log").exists());
    assert!(!fixture.path("running").exists());
}

#[test]
fn startup_failure_reports_diagnostics_instead_of_claiming_liveness() {
    let fixture = ServiceFixture::new();
    fixture.mark("fail-start");
    let output = fixture.run(&["on"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("service startup diagnostics"));
    assert!(stderr.contains("stopped before its control endpoint became live"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("ingress is live"));
}

#[test]
fn readiness_failure_is_not_hidden_by_a_live_daemon() {
    let fixture = ServiceFixture::new();
    fixture.mark("running");
    fixture.mark("not-ready");
    let output = fixture.run(&["check"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no verified routes"));
    assert_eq!(
        fs::read_to_string(fixture.path("phx-port.log")).unwrap(),
        "proxy check --live\nproxy check --ready\n"
    );
}

#[test]
fn public_port_uses_the_service_identity_and_prints_only_the_stable_port() {
    let fixture = ServiceFixture::new();
    for _ in 0..2 {
        let output = fixture.run(&["port", "sub-domain", "https"]);
        assert_success(&output);
        assert_eq!(output.stdout, b"4104\n");
    }
    let sudo = fs::read_to_string(fixture.path("sudo.log")).unwrap();
    for line in sudo.lines() {
        assert!(line.starts_with("-u phx-port -g phx-port -- env "));
        assert!(line.ends_with("/usr/local/bin/phx-port --workload-id sub-domain https"));
    }
    assert!(!fixture.path("systemctl.log").exists());
}
