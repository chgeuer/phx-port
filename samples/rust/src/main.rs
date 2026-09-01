#[cfg(not(target_os = "linux"))]
compile_error!("the PHXP socket-handoff example requires Linux");

mod handoff;

#[path = "../../../src/handoff_protocol.rs"]
mod handoff_protocol;

use std::env;
use std::error::Error;
use std::fs::File;
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
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tower::Service;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

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

async fn serve_connection<I>(
    stream: I,
    app: Router,
    meta: Arc<ConnMeta>,
) -> Result<(), Box<dyn Error + Send + Sync>>
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

async fn run_http(listener: TcpListener, app: Router) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("HTTP accept error: {e}");
                continue;
            }
        };
        let local = tcp.local_addr().ok();
        let meta = Arc::new(ConnMeta {
            listener: "http",
            peer: Some(peer),
            local,
            sni: None,
            peeked: None,
        });
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(tcp, app, meta).await
                && !is_expected_disconnect(error.as_ref())
            {
                eprintln!("HTTP connection error: {error}");
            }
        });
    }
}

async fn run_https(listener: TcpListener, app: Router, tls: TlsAcceptor) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("HTTPS accept error: {e}");
                continue;
            }
        };
        let local = tcp.local_addr().ok();
        let tls = tls.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        // Handshake failures from probes/scanners are not actionable.
                        if !is_expected_disconnect(&error) {
                            eprintln!("TLS handshake from {peer}: {error}");
                        }
                        return;
                    }
                    Err(_) => {
                        eprintln!("TLS handshake from {peer} timed out");
                        return;
                    }
                };
            let meta = Arc::new(ConnMeta {
                listener: "https",
                peer: Some(peer),
                local,
                sni: None,
                peeked: None,
            });
            if let Err(error) = serve_connection(tls_stream, app, meta).await
                && !is_expected_disconnect(error.as_ref())
            {
                eprintln!("HTTPS connection error: {error}");
            }
        });
    }
}

async fn serve_adopted(conn: handoff::AdoptedConn, app: Router, tls: TlsAcceptor) {
    let _guard = handoff::ActiveIdGuard::new(conn.connection_id, Arc::clone(&conn.active_ids));

    let tcp = match tokio::net::TcpStream::from_std(conn.stream) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("PHXP: cannot adopt fd into Tokio: {e}");
            return;
        }
    };

    let tls_stream = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            if !is_expected_disconnect(&error) {
                eprintln!("PHXP TLS handshake failed: {error}");
            }
            return;
        }
        Err(_) => {
            eprintln!("PHXP TLS handshake timed out");
            return;
        }
    };

    let meta = Arc::new(ConnMeta {
        listener: "phxp-handoff-https",
        peer: conn.peer,
        local: conn.local,
        sni: Some(conn.sni),
        peeked: Some(conn.peeked),
    });

    if let Err(error) = serve_connection(tls_stream, app, meta).await
        && !is_expected_disconnect(error.as_ref())
    {
        eprintln!("PHXP connection error: {error}");
    }
}

async fn consume_adopted(
    mut rx: tokio::sync::mpsc::Receiver<handoff::AdoptedConn>,
    app: Router,
    tls: TlsAcceptor,
) {
    while let Some(conn) = rx.recv().await {
        tokio::spawn(serve_adopted(conn, app.clone(), tls.clone()));
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
    let handoff = handoff::HandoffListener::bind(&config.handoff_socket)?;

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

    let app = build_app();
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let (adopted_tx, adopted_rx) = tokio::sync::mpsc::channel(128);

    handoff.spawn(adopted_tx);

    tokio::spawn(run_http(http_listener, app.clone()));
    tokio::spawn(consume_adopted(
        adopted_rx,
        app.clone(),
        tls_acceptor.clone(),
    ));

    run_https(https_listener, app, tls_acceptor).await;

    Ok(())
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
}

impl Config {
    fn from_process() -> Result<Self, String> {
        let mut http = env_value("PHXP_HTTP_ADDR").unwrap_or_else(|| "127.0.0.1:8080".into());
        let mut https = env_value("PHXP_HTTPS_ADDR").unwrap_or_else(|| "127.0.0.1:8443".into());
        let mut cert = env_value("PHXP_TLS_CERT");
        let mut key = env_value("PHXP_TLS_KEY");
        let mut project = env_value("PHXP_PROJECT");
        let mut role = env_value("PHXP_ROLE").unwrap_or_else(|| "https".into());
        let mut handoff_socket = env_value("PHXP_HANDOFF_SOCKET").map(PathBuf::from);

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
                "--role" => role = value(&mut arguments)?,
                "--handoff-socket" => {
                    handoff_socket = Some(PathBuf::from(value(&mut arguments)?));
                }
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
        let handoff_socket =
            handoff_socket.map_or_else(|| handoff::endpoint_path(&project, &role), Ok)?;

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
        })
    }
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn print_help() {
    println!(
        "PHXP Rust handoff server (Linux only)\n\n\
         Usage: phxp-handoff-server [OPTIONS]\n\n\
         Options:\n\
           --http ADDR             HTTP listener [env PHXP_HTTP_ADDR, default 127.0.0.1:8080]\n\
           --https ADDR            HTTPS listener [env PHXP_HTTPS_ADDR, default 127.0.0.1:8443]\n\
           --cert PATH             PEM certificate chain [env PHXP_TLS_CERT, required]\n\
           --key PATH              PEM private key [env PHXP_TLS_KEY, required]\n\
           --project PATH          Registered project path [env PHXP_PROJECT, default cwd]\n\
           --role NAME             Registered TLS role [env PHXP_ROLE, default https]\n\
           --handoff-socket PATH   Override derived PHXP endpoint [env PHXP_HANDOFF_SOCKET]\n\
           -h, --help              Show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
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
}
