#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn qualification_memory_uses_effective_cgroup_v2_limit() {
    let root = tempdir().unwrap();
    let cgroup_root = root.path().join("cgroup");
    let scope = cgroup_root.join("user.slice/approved.scope");
    fs::create_dir_all(&scope).unwrap();
    fs::write(cgroup_root.join("memory.max"), "max\n").unwrap();
    fs::write(cgroup_root.join("user.slice/memory.max"), "8589934592\n").unwrap();
    fs::write(scope.join("memory.max"), "17179869184\n").unwrap();

    let proc_cgroup = root.path().join("cgroup.txt");
    fs::write(&proc_cgroup, "0::/user.slice/approved.scope\n").unwrap();
    let proc_meminfo = root.path().join("meminfo");
    fs::write(&proc_meminfo, "MemTotal:       98127636 kB\n").unwrap();

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/phase8-harness.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            "source \"$1\"; qualification_effective_memory_kib \"$2\" \"$3\" \"$4\"",
            "phase8-memory-test",
        ])
        .arg(script)
        .arg(proc_cgroup)
        .arg(cgroup_root)
        .arg(proc_meminfo)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "memory probe failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "8388608 cgroup_v2\n"
    );
}

#[test]
fn qualification_cpu_gate_uses_sched_getaffinity_not_openmp_or_nproc() {
    let allowed_cpu = first_allowed_cpu();
    let root = tempdir().unwrap();
    let fake_nproc = root.path().join("nproc");
    fs::write(&fake_nproc, "#!/bin/sh\nprintf '4\\n'\n").unwrap();
    fs::set_permissions(&fake_nproc, fs::Permissions::from_mode(0o700)).unwrap();

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/phase8-harness.sh");
    let path = format!(
        "{}:{}",
        root.path().display(),
        std::env::var("PATH").unwrap()
    );
    let mut command = Command::new("bash");
    command
        .args([
            "-c",
            "source \"$1\"; qualification_cpu_affinity",
            "phase8-affinity-test",
        ])
        .arg(script)
        .env("OMP_NUM_THREADS", "4")
        .env("PATH", path);
    unsafe {
        command.pre_exec(move || {
            let mut affinity = std::mem::zeroed::<nix::libc::cpu_set_t>();
            nix::libc::CPU_ZERO(&mut affinity);
            nix::libc::CPU_SET(allowed_cpu, &mut affinity);
            if nix::libc::sched_setaffinity(
                0,
                std::mem::size_of::<nix::libc::cpu_set_t>(),
                &affinity,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();

    assert!(
        output.status.success(),
        "affinity probe failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fields = String::from_utf8(output.stdout).unwrap();
    let fields = fields.split_ascii_whitespace().collect::<Vec<_>>();
    assert_eq!(fields[0], "1");
    assert_eq!(fields[1], allowed_cpu.to_string());
    assert_ne!(
        fields[0], "4",
        "OMP_NUM_THREADS or nproc spoofed the sched_getaffinity result"
    );
}

#[test]
fn qualification_host_gate_validates_and_emits_constrained_host_evidence() {
    let accepted = run_host_validation(&[
        "Linux",
        "1000",
        "4",
        "0,1,2,3",
        "24",
        "8388608",
        "cgroup_v2",
        "98127636",
    ]);
    assert!(accepted.status.success());
    assert_eq!(
        String::from_utf8(accepted.stdout).unwrap(),
        "{\"metric\":\"qualification_host\",\"kernel\":\"linux\",\"vcpus\":4,\
\"affinity_vcpus\":4,\"affinity_cpus\":[0,1,2,3],\"host_vcpus\":24,\
\"memory_kib\":8388608,\"memory_source\":\"cgroup_v2\",\
\"host_memory_kib\":98127636,\"environment\":\"cgroup_constrained_larger_host\",\
\"dedicated_vm_equivalent\":false,\"euid\":1000}\n"
    );

    let wrong_cpu = run_host_validation(&[
        "Linux",
        "1000",
        "3",
        "0,1,2",
        "24",
        "8388608",
        "cgroup_v2",
        "98127636",
    ]);
    assert!(!wrong_cpu.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_cpu.stderr)
            .contains("requires exactly 4 available vCPUs, found 3")
    );

    let wrong_memory = run_host_validation(&[
        "Linux",
        "1000",
        "4",
        "0,1,2,3",
        "24",
        "7549746",
        "cgroup_v2",
        "98127636",
    ]);
    assert!(!wrong_memory.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_memory.stderr)
            .contains("requires an 8 GiB host (within 10%), found 7549746 KiB")
    );
}

#[test]
fn qualification_transcript_counts_one_passing_linux_gate() {
    let root = tempdir().unwrap();
    let transcript = root.path().join("qualification.log");
    fs::write(
        &transcript,
        "running 1 test\n\
test mixed_load_and_fd_pressure_recover_to_baseline ... ok\n\
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out\n",
    )
    .unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/phase8-harness.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            "source \"$1\"; qualification_passing_test_count \"$2\"",
            "phase8-transcript-test",
        ])
        .arg(script)
        .arg(transcript)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "1\n");
}

fn run_host_validation(arguments: &[&str]) -> std::process::Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/phase8-harness.sh");
    let mut command = Command::new("bash");
    command
        .args([
            "-c",
            "source \"$1\"; shift; qualification_validate_host \"$@\"",
            "phase8-host-validation-test",
        ])
        .arg(script)
        .args(arguments)
        .output()
        .unwrap()
}

fn first_allowed_cpu() -> usize {
    let mut affinity = unsafe { std::mem::zeroed::<nix::libc::cpu_set_t>() };
    let result = unsafe {
        nix::libc::sched_getaffinity(
            0,
            std::mem::size_of::<nix::libc::cpu_set_t>(),
            &mut affinity,
        )
    };
    assert_eq!(result, 0, "sched_getaffinity failed");
    (0..nix::libc::CPU_SETSIZE as usize)
        .find(|cpu| unsafe { nix::libc::CPU_ISSET(*cpu, &affinity) })
        .expect("the test process has no allowed CPU")
}
