use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;
use toml_edit::DocumentMut;

const TREE_MODES: [(&[&str], &str); 2] = [
    (&["list"], "http://localhost:"),
    (&["list", "--port-only"], ""),
];

fn list(home: &Path, assignments: &[(String, &str, i64)], arguments: &[&str]) -> String {
    let registry = home.join("ports.toml");
    let mut document = DocumentMut::new();
    document["ports"] = toml_edit::table();
    for (identity, role, port) in assignments {
        if document["ports"].get(identity).is_none() {
            document["ports"][identity] = toml_edit::table();
        }
        document["ports"][identity][role] = toml_edit::value(*port);
    }
    let original = document.to_string();
    fs::write(&registry, &original).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args(arguments)
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PHX_PORT_CONFIG", &registry)
        .env_remove("PHX_PORT_WORKLOAD_ID")
        .env_remove("PHX_PORT_INGRESS_CONFIG")
        .env_remove("PHX_PORT_RUNTIME_DIR")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&registry).unwrap(), original);
    String::from_utf8(output.stdout).unwrap()
}

fn assert_tree(output: &str, root: &str, mut expected: Vec<(String, String)>) {
    let mut lines = output.lines();
    assert_eq!(lines.next(), Some(root), "{output}");
    let mut actual = lines
        .map(|line| {
            let entry = line
                .strip_prefix("\u{251c}\u{2500}\u{2500} ")
                .or_else(|| line.strip_prefix("\u{2514}\u{2500}\u{2500} "))
                .unwrap_or_else(|| panic!("expected a direct tree child: {line}"));
            let (name, ports) = entry.split_once(" ..").unwrap();
            (
                name.to_string(),
                ports.trim_start_matches('.').trim_start().to_string(),
            )
        })
        .collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected, "{output}");
}

#[test]
fn tree_lists_registered_root_and_child_assignments_once() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();

    for parent in [home.clone(), home.join("projects")] {
        let child = parent.join("api").display().to_string();
        let parent = parent.display().to_string();
        let assignments = [
            (parent.clone(), "main", 4001),
            (child.clone(), "main", 4002),
        ];

        assert_eq!(
            list(&home, &assignments, &["list", "--flat"]),
            format!(" 4001  {parent}\n 4002  {child}\n")
        );
        for (arguments, prefix) in TREE_MODES {
            assert_tree(
                &list(&home, &assignments, arguments),
                &format!("{parent} .. {prefix}4001"),
                vec![("api".to_string(), format!("{prefix}4002"))],
            );
        }
    }
}

#[test]
fn tree_lists_multirole_registered_root_with_and_without_children() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let parent = home.join("projects").display().to_string();
    let child = home.join("projects/api").display().to_string();
    let assignments = [
        (parent.clone(), "main", 4001),
        (parent.clone(), "debug", 4003),
        (child.clone(), "main", 4002),
    ];

    assert_eq!(
        list(&home, &assignments[..2], &["list", "--flat"]),
        format!(" 4001  {parent}\n 4003  {parent} (debug)\n")
    );
    assert_eq!(
        list(&home, &assignments, &["list", "--flat"]),
        format!(" 4001  {parent}\n 4002  {child}\n 4003  {parent} (debug)\n")
    );
    for (arguments, prefix) in TREE_MODES {
        let root = format!("{parent} .. {prefix}4001, {prefix}4003 (debug)");
        assert_eq!(
            list(&home, &assignments[..2], arguments),
            format!("{root}\n")
        );
        assert_tree(
            &list(&home, &assignments, arguments),
            &root,
            vec![("api".to_string(), format!("{prefix}4002"))],
        );
    }
}

#[test]
fn tree_preserves_home_and_filesystem_root_project_assignments() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let root = home.ancestors().last().unwrap();
    let local = home.join("project");
    let external = root.join("project");
    let assignments = [
        (local.display().to_string(), "main", 4001),
        (external.display().to_string(), "main", 4002),
    ];

    assert_eq!(
        list(&home, &assignments, &["list", "--flat"]),
        format!(
            " 4001  {}\n 4002  {}\n",
            local.display(),
            external.display()
        )
    );
    for (arguments, prefix) in TREE_MODES {
        assert_tree(
            &list(&home, &assignments, arguments),
            &root.display().to_string(),
            vec![
                (
                    local.strip_prefix(root).unwrap().display().to_string(),
                    format!("{prefix}4001"),
                ),
                ("project".to_string(), format!("{prefix}4002")),
            ],
        );
    }
}

#[test]
fn tree_displays_external_and_home_prefix_sibling_paths_as_absolute() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let external = home.ancestors().last().unwrap().join("project");
    let sibling = PathBuf::from(format!("{}-other", home.display())).join("project");

    for identity in [
        external.display().to_string(),
        sibling.display().to_string(),
    ] {
        let assignments = [(identity.clone(), "main", 4001)];
        for (arguments, prefix) in TREE_MODES {
            assert_eq!(
                list(&home, &assignments, arguments),
                format!("{identity} .. {prefix}4001\n")
            );
        }
    }
}

#[test]
fn tree_distinguishes_logical_workloads_from_absolute_project_paths() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let external = home.ancestors().last().unwrap().join("project");

    for project in [home.join("project"), external] {
        let identity = project.display().to_string();
        let assignments = [
            (identity.clone(), "main", 4001),
            ("project".to_string(), "main", 4002),
        ];
        assert_eq!(
            list(&home, &assignments, &["list", "--flat"]),
            format!(" 4001  {identity}\n 4002  project\n")
        );
        for (arguments, prefix) in TREE_MODES {
            assert_tree(
                &list(&home, &assignments, arguments),
                "Workloads",
                vec![
                    (identity.clone(), format!("{prefix}4001")),
                    ("project".to_string(), format!("{prefix}4002")),
                ],
            );
        }
    }
}

#[test]
fn tree_preserves_home_grouping_and_all_named_roles() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let project = home.join("project").display().to_string();
    let second = home.join("second").display().to_string();
    let assignments = [
        (project.clone(), "main", 4001),
        (second.clone(), "main", 4002),
        (project.clone(), "debug", 4003),
    ];

    assert_eq!(
        list(&home, &assignments, &["list", "--flat"]),
        format!(" 4001  {project}\n 4002  {second}\n 4003  {project} (debug)\n")
    );
    for (arguments, prefix) in TREE_MODES {
        assert_tree(
            &list(&home, &assignments, arguments),
            &home.display().to_string(),
            vec![
                (
                    "project".to_string(),
                    format!("{prefix}4001, {prefix}4003 (debug)"),
                ),
                ("second".to_string(), format!("{prefix}4002")),
            ],
        );
    }
}

#[test]
fn tree_lists_logical_workloads_without_a_home_prefix() {
    let directory = tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let assignments = [
        ("project".to_string(), "main", 4001),
        ("second".to_string(), "main", 4002),
    ];

    for (arguments, prefix) in TREE_MODES {
        assert_tree(
            &list(&home, &assignments, arguments),
            "Workloads",
            vec![
                ("project".to_string(), format!("{prefix}4001")),
                ("second".to_string(), format!("{prefix}4002")),
            ],
        );
        assert_eq!(
            list(&home, &assignments[..1], arguments),
            format!("project .. {prefix}4001\n")
        );
    }
}
