#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the PHXP socket-handoff example requires Linux or macOS");

mod handoff;

#[path = "../../../src/handoff_protocol.rs"]
mod handoff_protocol;
#[cfg(any(target_os = "macos", test))]
#[path = "../../../src/handoff_stream.rs"]
mod handoff_stream;

use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::{Extension, Router};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tower::Service;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_CONNECTIONS: usize = 128;
const DEFAULT_MAX_CONTROL_WORKERS: usize = 16;

type ConnectionResult = Result<(), Box<dyn Error + Send + Sync>>;

struct ActivityStats {
    label: &'static str,
    rejected: u64,
    failed: u64,
}

impl ActivityStats {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            rejected: 0,
            failed: 0,
        }
    }

    fn report(&mut self) {
        if self.rejected != 0 || self.failed != 0 {
            eprintln!(
                "{}: rejected={}, failed={}",
                self.label, self.rejected, self.failed
            );
            self.rejected = 0;
            self.failed = 0;
        }
    }
}

impl Drop for ActivityStats {
    fn drop(&mut self) {
        self.report();
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConnMeta {
    pub(crate) listener: &'static str,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) sni: Option<String>,
    pub(crate) peeked: Option<u32>,
}

fn format_response_body(meta: &ConnMeta, request_line: &str) -> String {
    let peer = meta
        .peer
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".into());
    let local = meta
        .local
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".into());
    let mut body = format!(
        "phxp Rust handoff example\nlistener={}\npeer={peer}\nlocal={local}\nrequest={request_line}\n",
        meta.listener,
    );
    if let Some(sni) = &meta.sni {
        body.push_str(&format!(
            "handoff_sni={sni}\npeeked_length={}\n",
            meta.peeked.unwrap_or_default(),
        ));
    }
    body
}

async fn diagnostics(Extension(meta): Extension<Arc<ConnMeta>>, req: Request) -> String {
    let method = req.method().as_str().to_owned();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let version_str = match req.version() {
        axum::http::Version::HTTP_10 => "HTTP/1.0",
        axum::http::Version::HTTP_11 => "HTTP/1.1",
        axum::http::Version::HTTP_2 => "HTTP/2",
        axum::http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/?",
    };
    format_response_body(&meta, &format!("{method} {path} {version_str}"))
}

fn build_app() -> Router {
    Router::new().fallback(diagnostics)
}

async fn serve_connection<I>(stream: I, app: Router, meta: Arc<ConnMeta>) -> ConnectionResult
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
        request.extensions_mut().insert(Arc::clone(&meta));
        app.clone().call(request)
    });
    let mut server = auto::Builder::new(TokioExecutor::new());
    server
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_TIMEOUT);
    server
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

async fn serve_tls(
    tcp: tokio::net::TcpStream,
    app: Router,
    meta: Arc<ConnMeta>,
    tls: TlsAcceptor,
) -> ConnectionResult {
    let tls_stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    serve_connection(tls_stream, app, meta).await
}

async fn serve_adopted(
    conn: handoff::AdoptedConn,
    app: Router,
    tls: TlsAcceptor,
) -> ConnectionResult {
    let _permit = conn.permit;
    let _guard = conn.active_id;
    let tcp = tokio::net::TcpStream::from_std(conn.stream)?;
    let meta = Arc::new(ConnMeta {
        listener: "phxp-handoff-https",
        peer: conn.peer,
        local: conn.local,
        sni: Some(conn.sni),
        peeked: Some(conn.peeked),
    });

    serve_tls(tcp, app, meta, tls).await
}

#[derive(Clone, Copy, Debug)]
struct AdmissionLimits {
    max_connections: usize,
    max_control_workers: usize,
}

struct Server {
    http: TcpListener,
    https: TcpListener,
    handoff: handoff::HandoffListener,
    app: Router,
    tls: TlsAcceptor,
    limits: AdmissionLimits,
}

impl Server {
    async fn serve(self, shutdown: impl Future<Output = Result<(), String>>) -> Result<(), String> {
        let Self {
            http,
            https,
            handoff,
            app,
            tls,
            limits,
        } = self;
        let admission = Arc::new(Semaphore::new(limits.max_connections));
        let (adopted_tx, mut adopted_rx) = tokio::sync::mpsc::channel(limits.max_connections);
        let mut handoff = Box::pin(handoff.run(
            adopted_tx,
            Arc::clone(&admission),
            limits.max_control_workers,
        ));
        let mut connections = JoinSet::new();
        let mut stats = ActivityStats::new("connections");
        let mut reporting = tokio::time::interval(Duration::from_secs(1));
        tokio::pin!(shutdown);

        let mut result = loop {
            let mut failure = None;
            while let Some(joined) = connections.try_join_next() {
                if let Err(error) = observe_connection(joined, &mut stats) {
                    failure = Some(error);
                }
            }
            if let Some(error) = failure {
                break Err(error);
            }
            tokio::select! {
                result = &mut shutdown => break result,
                result = &mut handoff => {
                    break result.and_then(|()| Err("PHXP listener stopped unexpectedly".into()));
                }
                joined = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = observe_connection(joined.expect("nonempty task set"), &mut stats) {
                        break Err(error);
                    }
                }
                _ = reporting.tick() => stats.report(),
                conn = adopted_rx.recv() => {
                    let Some(conn) = conn else {
                        break Err("PHXP adoption channel closed unexpectedly".into());
                    };
                    connections.spawn(serve_adopted(conn, app.clone(), tls.clone()));
                }
                accepted = http.accept() => {
                    let (tcp, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(format!("HTTP listener failed: {error}")),
                    };
                    let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
                        stats.rejected = stats.rejected.saturating_add(1);
                        continue;
                    };
                    let meta = Arc::new(ConnMeta {
                        listener: "http",
                        peer: Some(peer),
                        local: tcp.local_addr().ok(),
                        sni: None,
                        peeked: None,
                    });
                    let app = app.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        serve_connection(tcp, app, meta).await
                    });
                }
                accepted = https.accept() => {
                    let (tcp, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(format!("HTTPS listener failed: {error}")),
                    };
                    let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
                        stats.rejected = stats.rejected.saturating_add(1);
                        continue;
                    };
                    let meta = Arc::new(ConnMeta {
                        listener: "https",
                        peer: Some(peer),
                        local: tcp.local_addr().ok(),
                        sni: None,
                        peeked: None,
                    });
                    let app = app.clone();
                    let tls = tls.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        serve_tls(tcp, app, meta, tls).await
                    });
                }
            }
        };

        drop(http);
        drop(https);
        drop(handoff);
        drop(adopted_rx);
        connections.abort_all();
        while let Some(joined) = connections.join_next().await {
            if matches!(&joined, Err(error) if error.is_cancelled()) {
                continue;
            }
            if let Err(error) = observe_connection(joined, &mut stats) {
                eprintln!("{error}");
                result = Err(error);
            }
        }
        result
    }
}

fn observe_connection(
    joined: Result<ConnectionResult, JoinError>,
    stats: &mut ActivityStats,
) -> Result<(), String> {
    match joined {
        Ok(Err(error)) if !is_expected_disconnect(error.as_ref()) => {
            stats.failed = stats.failed.saturating_add(1);
        }
        Err(error) if error.is_panic() => return Err("connection task panicked".into()),
        Err(_) => return Err("connection task was cancelled unexpectedly".into()),
        _ => {}
    }
    Ok(())
}

async fn shutdown_signal() -> Result<(), String> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("cannot observe SIGTERM: {error}"))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| format!("cannot observe Ctrl-C: {error}"))
        }
        signal = terminate.recv() => {
            signal.ok_or_else(|| "SIGTERM listener closed unexpectedly".into())
        }
    }
}

fn is_expected_disconnect(err: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(error) = err.downcast_ref::<hyper::Error>()
        && error.is_parse()
    {
        return true;
    }
    if matches!(
        err.downcast_ref::<tokio_rustls::rustls::Error>(),
        Some(tokio_rustls::rustls::Error::AlertReceived(_))
    ) {
        return true;
    }
    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        return matches!(
            io_err.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
        );
    }
    err.source().is_some_and(is_expected_disconnect)
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, String> {
    let mut cert_reader = BufReader::new(
        File::open(cert_path)
            .map_err(|e| format!("cannot open certificate {}: {e}", cert_path.display()))?,
    );
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cannot parse certificate {}: {e}", cert_path.display()))?;
    if certificates.is_empty() {
        return Err(format!(
            "certificate file {} contains no certificates",
            cert_path.display()
        ));
    }

    let mut key_reader = BufReader::new(
        File::open(key_path)
            .map_err(|e| format!("cannot open private key {}: {e}", key_path.display()))?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("cannot parse private key {}: {e}", key_path.display()))?
        .ok_or_else(|| format!("private key file {} contains no key", key_path.display()))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|e| format!("certificate and private key are incompatible: {e}"))?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let config = Config::from_process()?;
    let tls_config = Arc::new(load_tls_config(&config.cert, &config.key)?);

    let http_listener = TcpListener::bind(config.http)
        .await
        .map_err(|e| format!("cannot bind HTTP {}: {e}", config.http))?;
    let https_listener = TcpListener::bind(config.https)
        .await
        .map_err(|e| format!("cannot bind HTTPS {}: {e}", config.https))?;
    let handoff = handoff::HandoffListener::bind(
        &config.handoff_socket,
        config.validate_handoff_runtime_root,
    )?;

    println!(
        "HTTP:  http://{}",
        http_listener.local_addr().map_err(|e| e.to_string())?
    );
    println!(
        "HTTPS: https://{}",
        https_listener.local_addr().map_err(|e| e.to_string())?
    );
    println!("PHXP:  {}", config.handoff_socket.display());
    println!("project: {}", config.project);
    println!("role:    {}", config.role);

    Server {
        http: http_listener,
        https: https_listener,
        handoff,
        app: build_app(),
        tls: TlsAcceptor::from(tls_config),
        limits: config.limits,
    }
    .serve(shutdown_signal())
    .await
}

#[derive(Debug)]
struct Config {
    http: SocketAddr,
    https: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    project: String,
    role: String,
    handoff_socket: PathBuf,
    validate_handoff_runtime_root: bool,
    limits: AdmissionLimits,
}

impl Config {
    fn from_process() -> Result<Self, String> {
        let mut http = env_value("PHXP_HTTP_ADDR").unwrap_or_else(|| "127.0.0.1:8080".into());
        let mut https = env_value("PHXP_HTTPS_ADDR").unwrap_or_else(|| "127.0.0.1:8443".into());
        let mut cert = env_value("PHXP_TLS_CERT");
        let mut key = env_value("PHXP_TLS_KEY");
        let mut project = env_value("PHXP_PROJECT");
        let mut workload_id = env_value("PHXP_WORKLOAD_ID");
        let mut role = env_value("PHXP_ROLE").unwrap_or_else(|| "https".into());
        let mut handoff_socket = env_value("PHXP_HANDOFF_SOCKET").map(PathBuf::from);
        let mut max_connections = env::var_os("PHXP_MAX_CONNECTIONS")
            .unwrap_or_else(|| DEFAULT_MAX_CONNECTIONS.to_string().into());
        let mut max_control_workers = env::var_os("PHXP_MAX_CONTROL_WORKERS")
            .unwrap_or_else(|| DEFAULT_MAX_CONTROL_WORKERS.to_string().into());

        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            let value = |arguments: &mut std::iter::Skip<env::Args>| {
                arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))
            };
            match argument.as_str() {
                "--http" => http = value(&mut arguments)?,
                "--https" => https = value(&mut arguments)?,
                "--cert" => cert = Some(value(&mut arguments)?),
                "--key" => key = Some(value(&mut arguments)?),
                "--project" => project = Some(value(&mut arguments)?),
                "--workload-id" => workload_id = Some(value(&mut arguments)?),
                "--role" => role = value(&mut arguments)?,
                "--handoff-socket" => {
                    handoff_socket = Some(PathBuf::from(value(&mut arguments)?));
                }
                "--max-connections" => max_connections = value(&mut arguments)?.into(),
                "--max-control-workers" => max_control_workers = value(&mut arguments)?.into(),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument {argument:?}; use --help")),
            }
        }

        let project_path = match project {
            Some(p) => std::path::absolute(p)
                .map_err(|e| format!("cannot make project path absolute: {e}"))?,
            None => env::current_dir()
                .map_err(|e| format!("cannot determine current directory: {e}"))?,
        };
        let project = project_path
            .to_str()
            .ok_or_else(|| "project path is not valid UTF-8".to_string())?
            .to_string();
        if let Some(workload_id) = workload_id.as_deref() {
            validate_workload_id(workload_id)?;
        }
        let (handoff_socket, validate_handoff_runtime_root) = match handoff_socket {
            Some(path) => (path, false),
            None => {
                let identity = match workload_id.as_deref() {
                    Some(workload_id) => handoff::HandoffIdentity::Production(workload_id),
                    None => handoff::HandoffIdentity::Development(&project),
                };
                (
                    handoff::endpoint_path(identity, &role)?,
                    workload_id.is_none(),
                )
            }
        };

        Ok(Self {
            http: http
                .parse()
                .map_err(|e| format!("invalid HTTP address {http:?}: {e}"))?,
            https: https
                .parse()
                .map_err(|e| format!("invalid HTTPS address {https:?}: {e}"))?,
            cert: PathBuf::from(cert.ok_or_else(|| "set --cert or PHXP_TLS_CERT".to_string())?),
            key: PathBuf::from(key.ok_or_else(|| "set --key or PHXP_TLS_KEY".to_string())?),
            project,
            role,
            handoff_socket,
            validate_handoff_runtime_root,
            limits: AdmissionLimits {
                max_connections: parse_limit(&max_connections, "max-connections")?,
                max_control_workers: parse_limit(&max_control_workers, "max-control-workers")?,
            },
        })
    }
}

fn parse_limit(value: &OsStr, name: &str) -> Result<usize, String> {
    value
        .to_str()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|limit| (1..=Semaphore::MAX_PERMITS).contains(limit))
        .ok_or_else(|| {
            format!(
                "{name} must be a positive integer no greater than {}",
                Semaphore::MAX_PERMITS
            )
        })
}

fn validate_workload_id(workload_id: &str) -> Result<(), String> {
    let bytes = workload_id.as_bytes();
    if !(1..=128).contains(&bytes.len())
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(
            "PHXP_WORKLOAD_ID must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-', and start and end with a letter or digit"
                .to_string(),
        );
    }
    Ok(())
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn print_help() {
    println!(
        "PHXP Rust handoff server (Linux and macOS)\n\n\
         Usage: phxp-handoff-server [OPTIONS]\n\n\
         Options:\n\
           --http ADDR             HTTP listener [env PHXP_HTTP_ADDR, default 127.0.0.1:8080]\n\
           --https ADDR            HTTPS listener [env PHXP_HTTPS_ADDR, default 127.0.0.1:8443]\n\
           --cert PATH             PEM certificate chain [env PHXP_TLS_CERT, required]\n\
           --key PATH              PEM private key [env PHXP_TLS_KEY, required]\n\
           --project PATH          Registered project path [env PHXP_PROJECT, default cwd]\n\
           --workload-id ID        Explicit logical production Workload [env PHXP_WORKLOAD_ID]\n\
           --role NAME             Registered TLS role [env PHXP_ROLE, default https]\n\
           --handoff-socket PATH   Override derived PHXP endpoint [env PHXP_HANDOFF_SOCKET]\n\
           --max-connections N    Shared connection limit [env PHXP_MAX_CONNECTIONS, default 128]\n\
           --max-control-workers N PHXP negotiation limit [env PHXP_MAX_CONTROL_WORKERS, default 16]\n\
           -h, --help              Show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn unused_tls_acceptor() -> TlsAcceptor {
        TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(
                    tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        ))
    }

    #[test]
    fn connection_limits_reject_zero_invalid_and_non_unicode_values() {
        use std::os::unix::ffi::OsStrExt;

        assert_eq!(parse_limit(OsStr::new("2"), "limit").unwrap(), 2);
        for value in [
            OsStr::new("0"),
            OsStr::new(""),
            OsStr::new("-1"),
            OsStr::new("invalid"),
            OsStr::new("18446744073709551616"),
            OsStr::from_bytes(b"\xff"),
        ] {
            assert!(parse_limit(value, "limit").is_err(), "{value:?}");
        }
    }

    #[tokio::test]
    async fn queued_and_unpolled_adoptions_release_ids_and_permits_when_dropped() {
        use std::collections::HashSet;
        use std::sync::Mutex;

        for queued in [true, false] {
            let listener = std::net::TcpListener::bind(localhost(0)).unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (stream, _) = listener.accept().unwrap();
            stream.set_nonblocking(true).unwrap();
            let admission = Arc::new(Semaphore::new(1));
            let ids = Arc::new(Mutex::new(HashSet::from([[1; 16]])));
            let conn = handoff::AdoptedConn {
                stream,
                peer: None,
                local: None,
                sni: "localhost".into(),
                peeked: 0,
                active_id: handoff::ActiveIdGuard::new([1; 16], Arc::clone(&ids)),
                permit: Arc::clone(&admission).try_acquire_owned().unwrap(),
            };
            if queued {
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                assert!(sender.try_send(conn).is_ok());
                drop(receiver);
            } else {
                drop(serve_adopted(conn, build_app(), unused_tls_acceptor()));
            }
            assert_eq!(admission.available_permits(), 1);
            assert!(ids.lock().unwrap().is_empty());
            client.set_nonblocking(true).unwrap();
            let mut client = tokio::net::TcpStream::from_std(client).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), client.read(&mut [0]))
                    .await
                    .expect("dropped adoption did not close the TCP peer")
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test]
    async fn a_connection_task_panic_stops_the_server_and_cleans_up() {
        async fn fail_connection() -> &'static str {
            panic!("injected connection task failure");
        }

        let directory = tempfile::tempdir().unwrap();
        let endpoint = directory.path().join("handoff").join("receiver.sock");
        let http = TcpListener::bind(localhost(0)).await.unwrap();
        let address = http.local_addr().unwrap();
        let server = Server {
            http,
            https: TcpListener::bind(localhost(0)).await.unwrap(),
            handoff: handoff::HandoffListener::bind(&endpoint, false).unwrap(),
            app: Router::new().fallback(fail_connection),
            tls: unused_tls_acceptor(),
            limits: AdmissionLimits {
                max_connections: 2,
                max_control_workers: 1,
            },
        };
        let worker = tokio::spawn(server.serve(std::future::pending()));
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err(), "connection task panicked");
        assert!(!endpoint.exists());
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    }

    #[test]
    fn http_response_body_contains_required_keys() {
        let meta = ConnMeta {
            listener: "http",
            peer: Some(localhost(54321)),
            local: Some(localhost(8080)),
            sni: None,
            peeked: None,
        };
        let body = format_response_body(&meta, "GET /check HTTP/1.1");
        assert!(
            body.starts_with("phxp Rust handoff example\n"),
            "missing banner"
        );
        assert!(body.contains("listener=http\n"), "listener key");
        assert!(body.contains("peer=127.0.0.1:54321\n"), "peer key");
        assert!(body.contains("local=127.0.0.1:8080\n"), "local key");
        assert!(
            body.contains("request=GET /check HTTP/1.1\n"),
            "request key"
        );
        assert!(!body.contains("handoff_sni="), "no sni for plain http");
    }

    #[test]
    fn https_response_body_includes_sni() {
        let meta = ConnMeta {
            listener: "https",
            peer: Some(localhost(12345)),
            local: Some(localhost(8443)),
            sni: Some("api.example.test".into()),
            peeked: None,
        };
        let body = format_response_body(&meta, "GET / HTTP/1.1");
        assert!(body.contains("listener=https\n"));
        assert!(body.contains("handoff_sni=api.example.test\n"));
        assert!(body.contains("peeked_length=0\n"));
    }

    #[test]
    fn phxp_response_body_matches_show_sh_expectations() {
        let meta = ConnMeta {
            listener: "phxp-handoff-https",
            peer: Some(localhost(51234)),
            local: Some(localhost(443)),
            sni: Some("www.example.test".into()),
            peeked: Some(517),
        };
        let body = format_response_body(&meta, "GET / HTTP/1.1");
        assert!(body.contains("listener=phxp-handoff-https\n"));
        assert!(body.contains("peer=127.0.0.1:51234\n"));
        assert!(body.contains("local=127.0.0.1:443\n"));
        assert!(body.contains("handoff_sni=www.example.test\n"));
        assert!(body.contains("peeked_length=517\n"));
    }

    #[test]
    fn missing_addresses_display_as_unknown() {
        let meta = ConnMeta {
            listener: "http",
            peer: None,
            local: None,
            sni: None,
            peeked: None,
        };
        let body = format_response_body(&meta, "GET / HTTP/1.0");
        assert!(body.contains("peer=unknown\n"));
        assert!(body.contains("local=unknown\n"));
    }

    #[test]
    fn expected_disconnect_recognises_network_teardown() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(
                is_expected_disconnect(&io::Error::from(kind)),
                "should suppress {kind:?}"
            );
        }
    }

    #[test]
    fn expected_disconnect_does_not_suppress_real_errors() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::InvalidData,
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
        ] {
            assert!(
                !is_expected_disconnect(&io::Error::from(kind)),
                "should NOT suppress {kind:?}"
            );
        }
    }

    #[test]
    fn expected_disconnect_walks_error_source_chain() {
        use std::fmt;

        // Simulate a hyper-like wrapper whose source is a plain io::Error.
        #[derive(Debug)]
        struct WrapError(io::Error);

        impl fmt::Display for WrapError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "wrapped: {}", self.0)
            }
        }

        impl std::error::Error for WrapError {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let wrapped = WrapError(io::Error::from(io::ErrorKind::ConnectionReset));
        assert!(is_expected_disconnect(&wrapped));

        let not_wrapped = WrapError(io::Error::from(io::ErrorKind::InvalidData));
        assert!(!is_expected_disconnect(&not_wrapped));
    }

    #[test]
    fn logical_workload_id_validation_matches_the_allocator_contract() {
        for workload_id in ["a", "contoso-web", "api.v2_worker"] {
            assert!(validate_workload_id(workload_id).is_ok());
        }
        for workload_id in ["", "-contoso", "contoso-", "Contoso", "../contoso"] {
            assert!(validate_workload_id(workload_id).is_err());
        }
        assert!(validate_workload_id(&"a".repeat(129)).is_err());
    }
}
