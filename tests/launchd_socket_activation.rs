#![cfg(target_os = "macos")]

use socket2::{Domain, Protocol, Socket, Type};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir_in};

fn tempdir() -> std::io::Result<TempDir> {
    tempdir_in(Path::new("/tmp").canonicalize()?)
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn checked_output(command: &mut Command, action: &str) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{action} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn request(path: &Path, command: &str) -> std::io::Result<(String, u32)> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let (peer_uid, _) = nix::unistd::getpeereid(&stream)?;
    stream.write_all(format!("{command}\n").as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok((response, peer_uid.as_raw()))
}

struct LaunchdJob {
    target: String,
    control: PathBuf,
}

impl Drop for LaunchdJob {
    fn drop(&mut self) {
        let _ = request(&self.control, "STOP");
        let _ = Command::new("launchctl")
            .args(["bootout", &self.target])
            .output();
    }
}

fn wait_until_ready(job: &LaunchdJob, stderr: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !job.control.exists() {
        if Instant::now() >= deadline {
            let state = Command::new("launchctl")
                .args(["print", &job.target])
                .output()
                .map(|output| {
                    format!(
                        "{}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )
                })
                .unwrap_or_else(|error| error.to_string());
            panic!(
                "launchd daemon did not create its control socket\nstate:\n{state}\nstderr:\n{}",
                fs::read_to_string(stderr).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires a real macOS launchd user domain"]
fn real_launchd_job_adopts_named_socket_and_runs_as_owner() {
    let uid = nix::unistd::geteuid();
    assert!(!uid.is_root(), "launchd test must start non-root");

    let directory = tempdir().unwrap();
    let state = directory.path().join("state");
    let runtime = directory.path().join("runtime");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();

    let ipv6 = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).unwrap();
    ipv6.set_only_v6(true).unwrap();
    ipv6.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)).into())
        .unwrap();
    ipv6.listen(16).unwrap();
    let ipv6_listener: TcpListener = ipv6.into();
    let port = ipv6_listener.local_addr().unwrap().port();
    let ipv4_listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let ipv4 = ipv4_listener.local_addr().unwrap();
    let ipv6 = ipv6_listener.local_addr().unwrap();
    drop((ipv4_listener, ipv6_listener));
    let ingress_config = directory.path().join("ingress.toml");
    fs::write(
        &ingress_config,
        format!(
            "[ingress]\n\
             mode = \"public\"\n\
             unknown_sni = \"reject\"\n\
             listen = [\"{ipv4}\", \"{ipv6}\"]\n\
             \n\
             [ingress.hosts.\"inactive.example.test\"]\n\
             workload = \"inactive-web\"\n\
             role = \"https\"\n\
             required = false\n"
        ),
    )
    .unwrap();

    let label = format!("dev.phx-port.launchd-test-{}", std::process::id());
    let target = format!("gui/{}/{label}", uid.as_raw());
    let stdout = directory.path().join("stdout.log");
    let stderr = directory.path().join("stderr.log");
    let control = runtime.join("control/control.sock");
    let plist = directory.path().join(format!("{label}.plist"));
    fs::write(
        &plist,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
               <key>Label</key><string>{label}</string>\n\
               <key>ProgramArguments</key>\n\
               <array>\n\
                 <string>{binary}</string>\n\
                 <string>daemon</string>\n\
                 <string>--ingress-config</string><string>{config}</string>\n\
                 <string>--listen</string><string>{ipv4}</string>\n\
                 <string>--listen</string><string>{ipv6}</string>\n\
                 <string>--active-connections</string><string>4</string>\n\
                 <string>--pre-routing-connections</string><string>4</string>\n\
                 <string>--relay-connections</string><string>4</string>\n\
                 <string>--handoff-negotiations</string><string>4</string>\n\
                 <string>--task-budget</string><string>64</string>\n\
               </array>\n\
               <key>EnvironmentVariables</key>\n\
               <dict>\n\
                 <key>HOME</key><string>{home}</string>\n\
                 <key>PHX_PORT_CONFIG</key><string>{registry}</string>\n\
                 <key>PHX_PORT_RUNTIME_DIR</key><string>{runtime}</string>\n\
               </dict>\n\
               <key>Sockets</key>\n\
               <dict>\n\
                 <key>tls-ipv4</key>\n\
                 <dict>\n\
                   <key>SockNodeName</key><string>127.0.0.1</string>\n\
                   <key>SockServiceName</key><string>{port}</string>\n\
                   <key>SockFamily</key><string>IPv4</string>\n\
                   <key>SockType</key><string>stream</string>\n\
                   <key>SockProtocol</key><string>TCP</string>\n\
                 </dict>\n\
                 <key>tls-ipv6</key>\n\
                 <dict>\n\
                   <key>SockNodeName</key><string>::1</string>\n\
                   <key>SockServiceName</key><string>{port}</string>\n\
                   <key>SockFamily</key><string>IPv6</string>\n\
                   <key>SockType</key><string>stream</string>\n\
                   <key>SockProtocol</key><string>TCP</string>\n\
                 </dict>\n\
               </dict>\n\
               <key>RunAtLoad</key><true/>\n\
               <key>Umask</key><integer>63</integer>\n\
               <key>StandardOutPath</key><string>{stdout}</string>\n\
               <key>StandardErrorPath</key><string>{stderr}</string>\n\
             </dict>\n\
             </plist>\n",
            label = xml(&label),
            binary = xml(env!("CARGO_BIN_EXE_phx-port")),
            config = xml(ingress_config.to_str().unwrap()),
            ipv4 = ipv4,
            ipv6 = ipv6,
            home = xml(directory.path().to_str().unwrap()),
            registry = xml(state.join("ports.toml").to_str().unwrap()),
            runtime = xml(runtime.to_str().unwrap()),
            port = port,
            stdout = xml(stdout.to_str().unwrap()),
            stderr = xml(stderr.to_str().unwrap()),
        ),
    )
    .unwrap();

    checked_output(
        Command::new("plutil").args(["-lint", plist.to_str().unwrap()]),
        "validate launchd test plist",
    );
    checked_output(
        Command::new("launchctl").args([
            "bootstrap",
            &format!("gui/{}", uid.as_raw()),
            plist.to_str().unwrap(),
        ]),
        "bootstrap launchd test job",
    );
    let job = LaunchdJob { target, control };
    wait_until_ready(&job, &stderr);

    let (status, peer_uid) = request(&job.control, "STATUS").unwrap();
    assert_eq!(peer_uid, uid.as_raw(), "launchd data plane ran as root");
    assert!(
        status.contains(&format!("listeners={ipv4},{ipv6}")),
        "{status}"
    );
    assert_eq!(
        fs::symlink_metadata(runtime.join("control")).unwrap().uid(),
        uid.as_raw()
    );
    assert_eq!(
        fs::symlink_metadata(runtime.join("control"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o750
    );
    assert_eq!(
        fs::symlink_metadata(runtime.join("control/control.sock"))
            .unwrap()
            .uid(),
        uid.as_raw()
    );
    assert_eq!(
        fs::symlink_metadata(runtime.join("control/control.sock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(
        fs::read_to_string(&stderr)
            .unwrap()
            .contains(&format!("Adopted launchd listener tls-ipv4 on {ipv4}")),
        "daemon did not report launchd adoption:\n{}",
        fs::read_to_string(&stderr).unwrap()
    );
    assert!(
        fs::read_to_string(&stderr)
            .unwrap()
            .contains(&format!("Adopted launchd listener tls-ipv6 on {ipv6}")),
        "daemon did not report launchd IPv6 adoption:\n{}",
        fs::read_to_string(&stderr).unwrap()
    );
}
