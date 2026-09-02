use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub const PROMETHEUS_BODY_LIMIT: usize = 1024 * 1024;
const METRICS_REQUEST_LIMIT: usize = 1024;
const METRICS_IO_TIMEOUT: Duration = Duration::from_secs(2);
const METRICS_IO_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricsStartError {
    UnsafeAddress,
    Bind,
    Configure,
    Thread,
}

impl MetricsStartError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::UnsafeAddress => "non_loopback_address",
            Self::Bind => "bind_failed",
            Self::Configure => "configure_failed",
            Self::Thread => "thread_failed",
        }
    }
}

pub fn start_metrics_server(
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    render: impl Fn() -> String + Send + Sync + 'static,
) -> Result<thread::JoinHandle<()>, MetricsStartError> {
    if !address.ip().is_loopback() {
        return Err(MetricsStartError::UnsafeAddress);
    }
    let listener = TcpListener::bind(address).map_err(|_| MetricsStartError::Bind)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| MetricsStartError::Configure)?;
    let render = Arc::new(render);

    thread::Builder::new()
        .name("phx-port-metrics".to_string())
        .spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ =
                            serve_metrics_request(&mut stream, render.as_ref(), shutdown.as_ref());
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        })
        .map_err(|_| MetricsStartError::Thread)
}

fn serve_metrics_request(
    stream: &mut TcpStream,
    render: &(impl Fn() -> String + ?Sized),
    shutdown: &AtomicBool,
) -> io::Result<()> {
    stream.set_read_timeout(Some(METRICS_IO_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(METRICS_IO_POLL_INTERVAL))?;
    let deadline = Instant::now()
        .checked_add(METRICS_IO_TIMEOUT)
        .ok_or_else(|| io::Error::other("metrics request deadline overflowed"))?;

    let request = match read_request(stream, shutdown, deadline) {
        Ok(request) => request,
        Err(RequestError::TooLarge) => {
            return write_response(
                stream,
                "413 Payload Too Large",
                "text/plain; charset=utf-8",
                "request exceeds fixed limit\n",
                None,
                shutdown,
                deadline,
            );
        }
        Err(RequestError::Invalid) => {
            return write_response(
                stream,
                "400 Bad Request",
                "text/plain; charset=utf-8",
                "invalid request\n",
                None,
                shutdown,
                deadline,
            );
        }
        Err(RequestError::Io(error)) => return Err(error),
    };

    match request {
        MetricsRequest::Get => {
            let body = render();
            if body.len() > PROMETHEUS_BODY_LIMIT {
                return write_response(
                    stream,
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    "metrics response exceeds fixed limit\n",
                    None,
                    shutdown,
                    deadline,
                );
            }
            write_response(
                stream,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
                None,
                shutdown,
                deadline,
            )
        }
        MetricsRequest::MethodNotAllowed => write_response(
            stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n",
            Some("GET"),
            shutdown,
            deadline,
        ),
        MetricsRequest::NotFound => write_response(
            stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n",
            None,
            shutdown,
            deadline,
        ),
    }
}

enum MetricsRequest {
    Get,
    MethodNotAllowed,
    NotFound,
}

enum RequestError {
    TooLarge,
    Invalid,
    Io(io::Error),
}

fn read_request(
    stream: &mut TcpStream,
    shutdown: &AtomicBool,
    deadline: Instant,
) -> Result<MetricsRequest, RequestError> {
    let mut bytes = Vec::with_capacity(METRICS_REQUEST_LIMIT);
    loop {
        check_io_window(shutdown, deadline).map_err(RequestError::Io)?;
        let mut chunk = [0_u8; 256];
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if retryable_io(&error) => continue,
            Err(error) => return Err(RequestError::Io(error)),
        };
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > METRICS_REQUEST_LIMIT {
            return Err(RequestError::TooLarge);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n")
            || bytes.windows(2).any(|window| window == b"\n\n")
        {
            break;
        }
    }

    let first_line_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(RequestError::Invalid)?;
    let first_line = std::str::from_utf8(&bytes[..first_line_end])
        .map_err(|_| RequestError::Invalid)?
        .trim_end_matches('\r');
    let mut fields = first_line.split_ascii_whitespace();
    let method = fields.next().ok_or(RequestError::Invalid)?;
    let target = fields.next().ok_or(RequestError::Invalid)?;
    let version = fields.next().ok_or(RequestError::Invalid)?;
    if fields.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(RequestError::Invalid);
    }
    if method != "GET" {
        return Ok(MetricsRequest::MethodNotAllowed);
    }
    if target != "/metrics" {
        return Ok(MetricsRequest::NotFound);
    }
    Ok(MetricsRequest::Get)
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    allow: Option<&str>,
    shutdown: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body.len()
    );
    if let Some(allow) = allow {
        response.push_str(&format!("Allow: {allow}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    write_all_until(stream, response.as_bytes(), shutdown, deadline)
}

fn write_all_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    shutdown: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        check_io_window(shutdown, deadline)?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "metrics response socket stopped accepting bytes",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if retryable_io(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn check_io_window(shutdown: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if shutdown.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "metrics request cancelled during shutdown",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "metrics request exceeded its absolute deadline",
        ));
    }
    Ok(())
}

fn retryable_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
