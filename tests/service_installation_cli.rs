#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

struct ServiceFixture {
    directory: TempDir,
}

impl ServiceFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        for name in ["home", "work", "bin"] {
            fs::create_dir(directory.path().join(name)).unwrap();
        }
        let systemctl = directory.path().join("bin/systemctl");
        fs::write(
            &systemctl,
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PHX_PORT_TEST_SYSTEMCTL_LOG\"\n",
        )
        .unwrap();
        fs::set_permissions(systemctl, fs::Permissions::from_mode(0o700)).unwrap();
        Self { directory }
    }

    fn command(&self, action: &str, config_home: Option<&Path>) -> Command {
        let root = self.directory.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_phx-port"));
        command
            .args(["proxy", action])
            .current_dir(root.join("work"))
            .env_clear()
            .env("HOME", root.join("home"))
            .env("PHX_PORT_CONFIG", root.join("ports.toml"))
            .env("PATH", root.join("bin"))
            .env("PHX_PORT_TEST_SYSTEMCTL_LOG", root.join("systemctl.log"));
        if let Some(path) = config_home {
            command.env("XDG_CONFIG_HOME", path);
        }
        command
    }

    fn assert_round_trip(&self, config_home: Option<&Path>, expected_config_home: &Path) {
        let unit = expected_config_home.join("systemd/user/phx-port.service");
        for (action, message, installed) in [
            ("install-service", "Installed and started", true),
            ("uninstall-service", "Stopped and removed", false),
        ] {
            let output = self.command(action, config_home).output().unwrap();
            assert!(
                output.status.success(),
                "{action} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                unit.is_file(),
                installed,
                "{action} must use {}; stdout: {}",
                unit.display(),
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{message} {}\n", unit.display())
            );
            assert!(
                fs::read_dir(self.directory.path().join("work"))
                    .unwrap()
                    .next()
                    .is_none(),
                "{action} must not create files relative to the working directory"
            );
        }
        assert_eq!(
            fs::read_to_string(self.directory.path().join("systemctl.log")).unwrap(),
            "--user daemon-reload\n\
             --user enable --now phx-port.service\n\
             --user disable --now phx-port.service\n\
             --user daemon-reload\n"
        );
    }
}

#[test]
fn unset_xdg_config_home_uses_home_fallback() {
    let fixture = ServiceFixture::new();
    fixture.assert_round_trip(None, &fixture.directory.path().join("home/.config"));
}

#[test]
fn empty_xdg_config_home_uses_home_fallback() {
    let fixture = ServiceFixture::new();
    fixture.assert_round_trip(
        Some(Path::new("")),
        &fixture.directory.path().join("home/.config"),
    );
}

#[test]
fn absolute_xdg_config_home_is_honored() {
    let fixture = ServiceFixture::new();
    let config_home = fixture.directory.path().join("custom config");
    fixture.assert_round_trip(Some(&config_home), &config_home);
    assert!(!fixture.directory.path().join("home/.config").exists());
}

#[test]
fn relative_xdg_config_home_uses_home_fallback() {
    for config_home in ["relative-config", "."] {
        let fixture = ServiceFixture::new();
        fixture.assert_round_trip(
            Some(Path::new(config_home)),
            &fixture.directory.path().join("home/.config"),
        );
    }
}

#[test]
fn invalid_home_fallback_is_rejected_before_service_manager_calls() {
    for home in ["", "relative-home"] {
        let fixture = ServiceFixture::new();
        for action in ["install-service", "uninstall-service"] {
            let output = fixture
                .command(action, Some(Path::new("relative-config")))
                .env("HOME", home)
                .output()
                .unwrap();
            assert!(!output.status.success(), "{action} accepted HOME={home:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("HOME must be an absolute path"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
        }
        assert!(!fixture.directory.path().join("systemctl.log").exists());
        assert!(
            fs::read_dir(fixture.directory.path().join("work"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}
