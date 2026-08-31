#[cfg(not(target_os = "linux"))]
compile_error!("the PHXP socket-handoff example requires Linux");

mod handoff;

#[path = "../../../src/handoff_protocol.rs"]
mod handoff_protocol;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_REQUEST_HEAD: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::from_process()?;
    let tls = Arc::new(load_tls_config(&config.cert, &config.key)?);
    let http = TcpListener::bind(config.http)
        .map_err(|error| format!("cannot bind HTTP listener {}: {error}", config.http))?;
    let https = TcpListener::bind(config.https)
        .map_err(|error| format!("cannot bind HTTPS listener {}: {error}", config.https))?;
    let handoff = handoff::HandoffListener::bind(&config.handoff_socket)?;

    println!("HTTP:   http://{}", http.local_addr().map_err(io_error)?);
    println!("HTTPS:  https://{}", https.local_addr().map_err(io_error)?);
    println!("PHXP:   {}", config.handoff_socket.display());
    println!("project: {}", config.project);
    println!("role:    {}", config.role);

    spawn_http_listener(http);
    spawn_https_listener(https, Arc::clone(&tls));
    handoff.run(tls)
}

fn spawn_http_listener(listener: TcpListener) {
    thread::Builder::new()
        .name("http-listener".into())
        .spawn(move || {
            for accepted in listener.incoming() {
                match accepted {
                    Ok(stream) => spawn_plain_connection(stream),
                    Err(error) => eprintln!("HTTP accept failed: {error}"),
                }
            }
        })
        .expect("failed to start HTTP listener thread");
}

fn spawn_plain_connection(stream: TcpStream) {
    let peer = stream.peer_addr().ok();
    let local = stream.local_addr().ok();
    thread::spawn(move || {
        if let Err(error) = configure_stream(&stream)
            .and_then(|_| serve_http(stream, ResponseInfo::ordinary("http", peer, local)))
        {
            eprintln!("HTTP connection failed: {error}");
        }
    });
}

fn spawn_https_listener(listener: TcpListener, tls: Arc<ServerConfig>) {
    thread::Builder::new()
        .name("https-listener".into())
        .spawn(move || {
            for accepted in listener.incoming() {
                match accepted {
                    Ok(stream) => {
                        let tls = Arc::clone(&tls);
                        let peer = stream.peer_addr().ok();
                        let local = stream.local_addr().ok();
                        thread::spawn(move || {
                            if let Err(error) =
                                serve_tls(stream, tls, ResponseInfo::ordinary("https", peer, local))
                            {
                                eprintln!("HTTPS connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("HTTPS accept failed: {error}"),
                }
            }
        })
        .expect("failed to start HTTPS listener thread");
}

pub(crate) fn serve_tls(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    info: ResponseInfo,
) -> io::Result<()> {
    configure_stream(&stream)?;
    let connection =
        ServerConnection::new(config).map_err(|error| io::Error::other(error.to_string()))?;
    serve_http(StreamOwned::new(connection, stream), info)
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}

fn serve_http(mut stream: impl Read + Write, info: ResponseInfo) -> io::Result<()> {
    let request_line = read_request_head(&mut stream)?;
    let body = info.body(&request_line);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        body.len(),
        body
    )?;
    stream.flush()
}

fn read_request_head(stream: &mut impl Read) -> io::Result<String> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    while request.len() < MAX_REQUEST_HEAD {
        let remaining = MAX_REQUEST_HEAD - request.len();
        let read_length = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..read_length])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before sending an HTTP request",
            ));
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            let line = request.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
            return Ok(String::from_utf8_lossy(line).trim().to_string());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP request headers exceed 16 KiB",
    ))
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseInfo {
    listener: &'static str,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    handoff_sni: Option<String>,
    peeked_length: Option<u32>,
}

impl ResponseInfo {
    fn ordinary(
        listener: &'static str,
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> Self {
        Self {
            listener,
            peer,
            local,
            handoff_sni: None,
            peeked_length: None,
        }
    }

    pub(crate) fn handed_off(
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
        handoff_sni: String,
        peeked_length: u32,
    ) -> Self {
        Self {
            listener: "phxp-handoff-https",
            peer,
            local,
            handoff_sni: Some(handoff_sni),
            peeked_length: Some(peeked_length),
        }
    }

    fn body(&self, request_line: &str) -> String {
        let peer = self
            .peer
            .map(|address| address.to_string())
            .unwrap_or_else(|| "unknown".into());
        let local = self
            .local
            .map(|address| address.to_string())
            .unwrap_or_else(|| "unknown".into());
        let mut body = format!(
            "phxp Rust handoff example\nlistener={}\npeer={peer}\nlocal={local}\nrequest={request_line}\n",
            self.listener
        );
        if let Some(sni) = &self.handoff_sni {
            body.push_str(&format!(
                "handoff_sni={sni}\npeeked_length={}\n",
                self.peeked_length.unwrap_or_default()
            ));
        }
        body
    }
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, String> {
    let mut cert_reader =
        BufReader::new(File::open(cert_path).map_err(|error| {
            format!("cannot open certificate {}: {error}", cert_path.display())
        })?);
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|error| format!("cannot parse certificate {}: {error}", cert_path.display()))?;
    if certificates.is_empty() {
        return Err(format!(
            "certificate file {} contains no certificates",
            cert_path.display()
        ));
    }

    let mut key_reader = BufReader::new(
        File::open(key_path)
            .map_err(|error| format!("cannot open private key {}: {error}", key_path.display()))?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| format!("cannot parse private key {}: {error}", key_path.display()))?
        .ok_or_else(|| format!("private key file {} contains no key", key_path.display()))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| format!("certificate and private key are incompatible: {error}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
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
                "--handoff-socket" => handoff_socket = Some(PathBuf::from(value(&mut arguments)?)),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument {argument:?}; use --help")),
            }
        }

        let project_path = match project {
            Some(project) => std::path::absolute(project)
                .map_err(|error| format!("cannot make project path absolute: {error}"))?,
            None => env::current_dir()
                .map_err(|error| format!("cannot determine current directory: {error}"))?,
        };
        let project = project_path
            .to_str()
            .ok_or_else(|| "project path is not valid UTF-8".to_string())?
            .to_string();
        let handoff_socket = match handoff_socket {
            Some(path) => path,
            None => handoff::endpoint_path(&project, &role)?,
        };

        Ok(Self {
            http: http
                .parse()
                .map_err(|error| format!("invalid HTTP address {http:?}: {error}"))?,
            https: https
                .parse()
                .map_err(|error| format!("invalid HTTPS address {https:?}: {error}"))?,
            cert: PathBuf::from(cert.ok_or_else(|| "set --cert or PHXP_TLS_CERT".to_string())?),
            key: PathBuf::from(key.ok_or_else(|| "set --key or PHXP_TLS_KEY".to_string())?),
            project,
            role,
            handoff_socket,
        })
    }
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
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

fn io_error(error: io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::{ResponseInfo, read_request_head};
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn reads_only_the_http_request_head() {
        let mut request = Cursor::new(b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assert_eq!(
            read_request_head(&mut request).unwrap(),
            "GET /hello HTTP/1.1"
        );
    }

    #[test]
    fn handed_off_response_reports_original_addresses() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51234);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let body =
            ResponseInfo::handed_off(Some(peer), Some(local), "www.example.test".into(), 517)
                .body("GET / HTTP/1.1");

        assert!(body.contains("listener=phxp-handoff-https"));
        assert!(body.contains("peer=127.0.0.1:51234"));
        assert!(body.contains("local=127.0.0.1:443"));
        assert!(body.contains("handoff_sni=www.example.test"));
        assert!(body.contains("peeked_length=517"));
    }
}
