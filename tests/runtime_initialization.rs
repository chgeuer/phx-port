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
