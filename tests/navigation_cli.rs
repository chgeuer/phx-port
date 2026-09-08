use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;
use toml_edit::DocumentMut;

fn navigate(home: &Path, arguments: &[&str]) -> Output {
    let registry = home.join("ports.toml");
    let project = home.display().to_string();
    let child = home.join("api").display().to_string();
    let mut document = DocumentMut::new();
    document["ports"] = toml_edit::table();
    document["ports"][&project] = toml_edit::table();
    document["ports"][&project]["main"] = toml_edit::value(4001);
    document["ports"][&project]["debug"] = toml_edit::value(4002);
    document["ports"][&project]["https"] = toml_edit::value(4401);
    document["ports"][&child] = toml_edit::table();
    document["ports"][&child]["https"] = toml_edit::value(4402);
    let original = document.to_string();
    fs::write(&registry, &original).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args(arguments)
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PATH", home)
        .env("PHX_PORT_CONFIG", &registry)
        .env_remove("PHX_PORT_WORKLOAD_ID")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("PHX_PORT_RUNTIME_DIR")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&registry).unwrap(), original);
    output
}

#[test]
fn tree_urls_follow_roles_without_changing_port_only_or_flat_output() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();

    for (arguments, expected) in [
        (
            &["list"][..],
            format!(
                "{} .. http://localhost:4001, http://localhost:4002 (debug), https://localhost:4401 (https)\n\
                 \u{2514}\u{2500}\u{2500} api .. https://localhost:4402 (https)\n",
                home.display()
            ),
        ),
        (
            &["list", "--port-only"][..],
            format!(
                "{} .. 4001, 4002 (debug), 4401 (https)\n\
                 \u{2514}\u{2500}\u{2500} api .. 4402 (https)\n",
                home.display()
            ),
        ),
        (
            &["list", "--flat"][..],
            format!(
                " 4001  {0}\n 4002  {0} (debug)\n 4401  {0} (https)\n 4402  {1} (https)\n",
                home.display(),
                home.join("api").display()
            ),
        ),
    ] {
        let output = navigate(&home, arguments);
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
}

#[cfg(unix)]
fn assert_browser_navigation(command: &str) {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let opener = home.join(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    fs::write(&opener, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&opener, fs::Permissions::from_mode(0o700)).unwrap();

    for (role, expected) in [
        (None, "http://localhost:4001"),
        (Some("main"), "http://localhost:4001"),
        (Some("debug"), "http://localhost:4002"),
        (Some("https"), "https://localhost:4401"),
    ] {
        let mut arguments = vec![command];
        if let Some(role) = role {
            arguments.push(role);
        }
        let output = navigate(&home, &arguments);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{expected}\n"),
            "{arguments:?} browser arguments"
        );
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("Opening {expected}\n")
        );
    }
}

#[cfg(unix)]
#[test]
fn open_passes_the_role_url_to_the_browser() {
    assert_browser_navigation("open");
}

#[cfg(unix)]
#[test]
fn launch_passes_the_role_url_to_the_browser() {
    assert_browser_navigation("launch");
}
