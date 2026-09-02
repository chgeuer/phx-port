use std::process::Command;

#[test]
fn invalid_capacity_is_rejected_before_listener_binding() {
    let output = Command::new(env!("CARGO_BIN_EXE_phx-port"))
        .args([
            "daemon",
            "--active-connections",
            "0",
            "--listen",
            "not-a-listener",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("active_connections must be greater than zero"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("cannot listen"),
        "listener binding ran before capacity validation: {stderr}"
    );
}
