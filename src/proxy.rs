use crate::{config_path, is_port_open, read_config, tls_client_hello};
use native_tls::TlsConnector;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);
const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_PROBES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Backend {
    project: String,
    role: String,
    port: u16,
}

type Routes = Arc<RwLock<HashMap<String, Backend>>>;

pub fn run(listen_addresses: &[String]) -> Result<(), String> {
    let routes = Arc::new(RwLock::new(HashMap::new()));
    let mut listeners = Vec::new();

    for address in listen_addresses {
        let listener = TcpListener::bind(address)
            .map_err(|error| format!("cannot listen on {address}: {error}"))?;
        eprintln!("TLS proxy listening on {}", listener.local_addr().unwrap());
        listeners.push(listener);
    }

    for listener in listeners {
        let routes = Arc::clone(&routes);
        thread::spawn(move || {
            for accepted in listener.incoming() {
                match accepted {
                    Ok(stream) => {
                        let routes = Arc::clone(&routes);
                        thread::spawn(move || {
                            if let Err(error) = handle_connection(stream, routes) {
                                eprintln!("TLS proxy connection rejected: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("TLS proxy accept failed: {error}"),
                }
            }
        });
    }

    loop {
        thread::park();
    }
}

fn handle_connection(mut client: TcpStream, routes: Routes) -> Result<(), String> {
    client
        .set_read_timeout(Some(CLIENT_HELLO_TIMEOUT))
        .map_err(|error| format!("cannot set ClientHello timeout: {error}"))?;
    let (hostname, buffered) =
        tls_client_hello::read_sni(&mut client).map_err(|error| error.to_string())?;
    client.set_read_timeout(None).ok();

    let cached = routes
        .read()
        .map_err(|_| "route table lock poisoned".to_string())?
        .get(&hostname)
        .cloned();

    let (backend, upstream) = if let Some(backend) = cached {
        match connect_backend(&backend) {
            Ok(stream) => (backend, stream),
            Err(_) => {
                routes
                    .write()
                    .map_err(|_| "route table lock poisoned".to_string())?
                    .remove(&hostname);
                discover_and_connect(&hostname, &routes)?
            }
        }
    } else {
        discover_and_connect(&hostname, &routes)?
    };

    eprintln!(
        "Routing {hostname} to 127.0.0.1:{} ({} {})",
        backend.port, backend.project, backend.role
    );
    relay(client, upstream, &buffered).map_err(|error| format!("relay failed: {error}"))
}

fn discover_and_connect(hostname: &str, routes: &Routes) -> Result<(Backend, TcpStream), String> {
    let candidates = candidate_backends();
    let matches = probe_candidates(hostname, candidates);

    if matches.len() != 1 {
        return Err(match matches.len() {
            0 => format!("no active backend presents a trusted certificate for {hostname}"),
            count => format!("{count} active backends present trusted certificates for {hostname}"),
        });
    }

    let backend = matches.into_iter().next().unwrap();
    let upstream = connect_backend(&backend)
        .map_err(|error| format!("verified backend disappeared before relay: {error}"))?;
    routes
        .write()
        .map_err(|_| "route table lock poisoned".to_string())?
        .insert(hostname.to_string(), backend.clone());
    eprintln!(
        "Discovered {hostname} at 127.0.0.1:{} ({} {})",
        backend.port, backend.project, backend.role
    );
    Ok((backend, upstream))
}

fn candidate_backends() -> Vec<Backend> {
    let config = config_path();
    let document = read_config(&config);
    let mut by_project = BTreeMap::<String, Backend>::new();

    if let Some(projects) = document.get("ports").and_then(|value| value.as_table()) {
        for (project, roles) in projects {
            let Some(roles) = roles.as_table() else {
                continue;
            };
            for role in ["https", "main"] {
                let Some(port) = roles
                    .get(role)
                    .and_then(|value| value.as_integer())
                    .and_then(|port| u16::try_from(port).ok())
                else {
                    continue;
                };
                if !is_port_open(i64::from(port)) {
                    continue;
                }
                let candidate = Backend {
                    project: project.to_string(),
                    role: role.to_string(),
                    port,
                };
                by_project.entry(project.to_string()).or_insert(candidate);
            }
        }
    }

    by_project.into_values().take(MAX_PROBES).collect()
}

fn probe_candidates(hostname: &str, candidates: Vec<Backend>) -> Vec<Backend> {
    let (sender, receiver) = mpsc::channel();
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;

    for backend in candidates {
        let sender = sender.clone();
        let hostname = hostname.to_string();
        thread::spawn(move || match probe_backend(&hostname, &backend) {
            Ok(()) => {
                let _ = sender.send(backend);
            }
            Err(error) => {
                eprintln!(
                    "Probe rejected {hostname} at 127.0.0.1:{} ({} {}): {error}",
                    backend.port, backend.project, backend.role
                );
            }
        });
    }
    drop(sender);

    let mut matches = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(remaining) {
            Ok(backend) => matches.push(backend),
            Err(mpsc::RecvTimeoutError::Disconnected | mpsc::RecvTimeoutError::Timeout) => break,
        }
    }
    matches
}

fn probe_backend(hostname: &str, backend: &Backend) -> Result<(), String> {
    let stream = connect_backend_with_timeout(backend, PROBE_TIMEOUT)
        .map_err(|error| format!("TCP connection failed: {error}"))?;
    let connector =
        TlsConnector::new().map_err(|error| format!("cannot create TLS connector: {error}"))?;
    connector
        .connect(hostname, stream)
        .map(|_| ())
        .map_err(|error| format!("TLS validation failed: {error}"))
}

fn connect_backend(backend: &Backend) -> io::Result<TcpStream> {
    connect_backend_with_timeout(backend, Duration::from_secs(2))
}

fn connect_backend_with_timeout(backend: &Backend, timeout: Duration) -> io::Result<TcpStream> {
    let address: SocketAddr = ([127, 0, 0, 1], backend.port).into();
    let stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

fn relay(mut client: TcpStream, mut upstream: TcpStream, buffered: &[u8]) -> io::Result<()> {
    upstream.write_all(buffered)?;
    upstream.set_read_timeout(None)?;
    upstream.set_write_timeout(None)?;

    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let client_to_upstream = thread::spawn(move || {
        let result = io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
        result
    });

    let upstream_to_client = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let client_to_upstream = client_to_upstream
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))?;

    upstream_to_client?;
    client_to_upstream?;
    Ok(())
}
