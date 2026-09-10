fn configuration_lines(contents: &str) -> Vec<&str> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn linux_public_setup_uses_idempotent_system_accounts() {
    assert_eq!(
        configuration_lines(include_str!("../packaging/systemd/phx-port.sysusers.conf")),
        [
            "u phx-port - \"phx-port ingress service\" /var/lib/phx-port",
            "g phx-port-admin -",
            "m phx-port phx-port-admin",
        ],
        "sysusers must allocate a non-login service identity and read-only control group"
    );
}

#[test]
fn linux_public_setup_preserves_state_and_initializes_children_without_root() {
    assert_eq!(
        configuration_lines(include_str!("../packaging/systemd/phx-port.tmpfiles.conf")),
        [
            "d /etc/phx-port 0755 root phx-port - -",
            "d /var/lib/phx-port 0700 phx-port phx-port - -",
            "d /run/phx-port 0750 phx-port phx-port-admin - -",
        ],
        "root provisioning must only adjust top-level directories, without cleanup or file replacement"
    );

    let (_, recipe) = include_str!("../justfile")
        .split_once("[linux]\nsetup-public:\n")
        .expect("public setup must be an explicit Linux-only recipe");
    assert_eq!(
        recipe
            .lines()
            .take_while(|line| line.starts_with("    "))
            .map(str::trim)
            .collect::<Vec<_>>(),
        [
            "sudo systemd-sysusers packaging/systemd/phx-port.sysusers.conf",
            "sudo systemd-tmpfiles --create packaging/systemd/phx-port.tmpfiles.conf",
            "sudo -n -u phx-port -g phx-port -- install -d -o phx-port -g phx-port -m 0700 /run/phx-port/handoff",
            "sudo -n -u phx-port -g phx-port-admin -- install -d -o phx-port -g phx-port-admin -m 0750 /run/phx-port/control",
        ],
        "service-controlled children must be initialized unprivileged; setup must not start services"
    );
}

#[test]
fn launchd_drops_privileges_before_initializing_the_handoff_directory() {
    let plist = include_str!("../packaging/launchd/dev.phx-port.runtime.plist");
    let command = plist
        .lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix("<string>/usr/bin/install ")
                .and_then(|command| command.strip_suffix("</string>"))
        })
        .expect("runtime initializer must contain its install command");

    assert_eq!(
        command.split(" &amp;&amp; ").collect::<Vec<_>>(),
        [
            "-d -o phx-port -g phx-port-admin -m 0750 /private/var/run/phx-port",
            "/usr/bin/sudo -n -u phx-port -g phx-port -- /usr/bin/install -d -o phx-port -g phx-port -m 0700 /private/var/run/phx-port/handoff",
        ],
        "the service-controlled handoff path must never be initialized as root"
    );
}

#[test]
fn provisioning_examples_initialize_handoff_as_the_service_user() {
    for (path, contents) in [
        ("README.md", include_str!("../README.md")),
        (
            "docs/manual/public-server.md",
            include_str!("../docs/manual/public-server.md"),
        ),
        (
            "docs/public-hosting-recovery-runbook.md",
            include_str!("../docs/public-hosting-recovery-runbook.md"),
        ),
    ] {
        let normalized = contents.replace("\\\r\n", " ").replace("\\\n", " ");
        let commands: Vec<_> = normalized
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("install ") && line.contains("/phx-port/handoff"))
            .collect();

        assert!(
            !commands.is_empty(),
            "{path} must cover handoff provisioning"
        );
        for command in commands {
            assert!(
                command.starts_with(
                    "sudo -n -u phx-port -g phx-port -- install -d -o phx-port -g phx-port -m 0700 "
                ),
                "{path} must drop privileges before touching the service-controlled directory: {command}"
            );
        }
    }
}
