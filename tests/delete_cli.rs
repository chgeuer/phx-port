use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;
use toml_edit::{DocumentMut, table, value};

const ROLES: [(&str, i64); 3] = [("main", 4001), ("https", 4401), ("debug", 4002)];

fn registry(home: &Path) -> DocumentMut {
    let mut document = DocumentMut::new();
    document["ports"] = table();
    document["discovered_routes"] = table();
    for (name, offset) in [("project", 0), ("other", 100)] {
        let project = home.join(name).display().to_string();
        document["ports"][&project] = table();
        for (role, port) in ROLES {
            document["ports"][&project][role] = value(port + offset);
            let hostname = format!("{name}-{role}.example.test");
            document["discovered_routes"][&hostname] = table();
            let route = &mut document["discovered_routes"][&hostname];
            route["project"] = value(&project);
            route["role"] = value(role);
            route["certificate_fingerprint"] = value("fixture");
            route["last_verified_unix"] = value(1);
        }
    }
    document
}

fn delete(home: &Path, document: &DocumentMut, arguments: &[&str]) -> (Output, String) {
    let registry = home.join("ports.toml");
    fs::write(&registry, document.to_string()).unwrap();
    let project = home.join("project");
    fs::create_dir_all(&project).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .arg("delete")
        .args(arguments)
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PHX_PORT_CONFIG", &registry)
        .env_remove("PHX_PORT_WORKLOAD_ID")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("PHX_PORT_RUNTIME_DIR")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
    (output, fs::read_to_string(registry).unwrap())
}

#[test]
fn unqualified_selectors_delete_every_role_and_derived_route_for_one_project() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let document = registry(&home);
    let mut expected = document.clone();
    expected["ports"].as_table_mut().unwrap().remove(&project);
    for (role, _) in ROLES {
        expected["discovered_routes"]
            .as_table_mut()
            .unwrap()
            .remove(&format!("project-{role}.example.test"));
    }
    let stderr = format!(
        "Removed {project} (was port 4001)\n\
         Removed {project} (https) (was port 4401)\n\
         Removed {project} (debug) (was port 4002)\n"
    );

    for selector in ["4001", "4401", "4002", "project", "."] {
        let (output, actual) = delete(&home, &document, &[selector]);
        assert!(output.status.success(), "{selector}: {output:?}");
        assert_eq!(actual, expected.to_string(), "{selector}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            stderr,
            "{selector}"
        );
    }
}

#[test]
fn explicit_role_is_independent_of_the_selector_port_role() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let document = registry(&home);

    for selector in ["4001", "4401", "4002", "project", "."] {
        for (role, port) in ROLES {
            let mut expected = document.clone();
            expected["ports"][&project]
                .as_table_mut()
                .unwrap()
                .remove(role);
            expected["discovered_routes"]
                .as_table_mut()
                .unwrap()
                .remove(&format!("project-{role}.example.test"));
            let (output, actual) = delete(&home, &document, &[selector, role]);
            assert!(output.status.success(), "{selector} {role}: {output:?}");
            assert_eq!(actual, expected.to_string(), "{selector} {role}");
            let suffix = if role == "main" {
                String::new()
            } else {
                format!(" ({role})")
            };
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                format!("Removed {project}{suffix} (was port {port})\n"),
                "{selector} {role}"
            );
        }
    }
}

#[test]
fn deleting_the_last_explicit_role_removes_the_project_entry() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let mut document = registry(&home);
    for role in ["main", "https"] {
        document["ports"][&project]
            .as_table_mut()
            .unwrap()
            .remove(role);
        document["discovered_routes"]
            .as_table_mut()
            .unwrap()
            .remove(&format!("project-{role}.example.test"));
    }
    let mut expected = document.clone();
    expected["ports"].as_table_mut().unwrap().remove(&project);
    expected["discovered_routes"]
        .as_table_mut()
        .unwrap()
        .remove("project-debug.example.test");

    for selector in ["4002", "project", "."] {
        let (output, actual) = delete(&home, &document, &[selector, "debug"]);
        assert!(output.status.success(), "{selector}: {output:?}");
        assert_eq!(actual, expected.to_string(), "{selector}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("Removed {project} (debug) (was port 4002)\n")
        );
    }
}

#[test]
fn missing_selectors_fail_without_changing_the_registry() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();

    for (selector, stderr) in [
        ("4999", "No mapping found for port 4999\n".to_string()),
        (
            "missing",
            "No mapping found matching 'missing'\n".to_string(),
        ),
        (
            ".",
            format!("Current directory is not registered: {project}\n"),
        ),
    ] {
        let mut document = registry(&home);
        if selector == "." {
            document["ports"].as_table_mut().unwrap().remove(&project);
        }
        for arguments in [vec![selector], vec![selector, "https"]] {
            let (output, actual) = delete(&home, &document, &arguments);
            assert_eq!(output.status.code(), Some(1), "{arguments:?}: {output:?}");
            assert_eq!(actual, document.to_string(), "{arguments:?}");
            assert_eq!(String::from_utf8(output.stderr).unwrap(), stderr);
        }
    }
}

#[test]
fn ambiguous_selectors_fail_without_changing_the_registry() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let duplicate = home.join("other/project").display().to_string();
    let mut document = registry(&home);
    document["ports"][&duplicate] = document["ports"][&project].clone();

    for (selector, description) in [("4001", "port 4001"), ("project", "'project'")] {
        for arguments in [vec![selector], vec![selector, "https"]] {
            let (output, actual) = delete(&home, &document, &arguments);
            assert_eq!(output.status.code(), Some(1), "{arguments:?}: {output:?}");
            assert_eq!(actual, document.to_string(), "{arguments:?}");
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                format!(
                    "Ambiguous match for {description}. Matching directories:\n  {project}\n  {duplicate}\n"
                )
            );
        }
    }
}

#[test]
fn missing_roles_fail_without_changing_any_assignment_or_route() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let document = registry(&home);

    for selector in ["4001", "4401", "4002", "project", "."] {
        let (output, actual) = delete(&home, &document, &[selector, "missing"]);
        assert_eq!(output.status.code(), Some(1), "{selector}: {output:?}");
        assert_eq!(actual, document.to_string(), "{selector}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("No missing port registered for {project}\n")
        );
    }
}

#[test]
fn a_port_shared_by_roles_in_one_project_still_resolves_one_project() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let mut document = registry(&home);
    document["ports"][&project]["https"] = value(4001);
    let mut expected = document.clone();
    expected["ports"][&project]
        .as_table_mut()
        .unwrap()
        .remove("main");
    expected["discovered_routes"]
        .as_table_mut()
        .unwrap()
        .remove("project-main.example.test");

    let (output, actual) = delete(&home, &document, &["4001", "main"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(actual, expected.to_string());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("Removed {project} (was port 4001)\n")
    );
}

#[test]
fn numeric_deletion_preserves_legacy_flat_registration_support() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let mut document = registry(&home);
    document["ports"][&project] = value(4001);
    let mut expected = document.clone();
    expected["ports"].as_table_mut().unwrap().remove(&project);
    for (role, _) in ROLES {
        expected["discovered_routes"]
            .as_table_mut()
            .unwrap()
            .remove(&format!("project-{role}.example.test"));
    }

    let (output, actual) = delete(&home, &document, &["4001"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(actual, expected.to_string());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("Removed {project} (was port 4001)\n")
    );
}
