use std::io;
use std::net::IpAddr;
use std::time::Duration;
#[cfg(test)]
use {std::net::TcpStream, std::thread, std::time::Instant};

const MAX_CLIENT_HELLO: usize = 64 * 1024;
const INITIAL_PEEK_BUFFER: usize = 4 * 1024;
const PEEK_RETRY_INTERVAL: Duration = Duration::from_millis(1);
const MAX_PEEK_RETRY_INTERVAL: Duration = Duration::from_millis(32);

enum ParseResult {
    Incomplete,
    Complete(Option<String>),
}

#[cfg(test)]
pub fn peek_sni(stream: &TcpStream, timeout: Duration) -> io::Result<(String, usize)> {
    let deadline = Instant::now() + timeout;
    let mut buffered = vec![0_u8; INITIAL_PEEK_BUFFER];
    let mut previous_length = 0;

    loop {
        let length = stream.peek(&mut buffered)?;
        if let Some(result) = inspect_peeked(&buffered, length)? {
            return Ok(result);
        }
        grow_peek_buffer(&mut buffered, length);
        if Instant::now() >= deadline {
            return client_hello_timeout();
        }
        if length == previous_length {
            thread::sleep(PEEK_RETRY_INTERVAL);
        }
        previous_length = length;
    }
}

pub async fn peek_sni_async(
    stream: &tokio::net::TcpStream,
    deadline: tokio::time::Instant,
) -> io::Result<(String, usize)> {
    let mut buffered = vec![0_u8; INITIAL_PEEK_BUFFER];
    let mut previous_length = 0;
    let mut retry_interval = PEEK_RETRY_INTERVAL;

    loop {
        if tokio::time::Instant::now() >= deadline {
            return client_hello_timeout();
        }
        let length = tokio::time::timeout_at(deadline, stream.peek(&mut buffered))
            .await
            .map_err(|_| client_hello_timeout_error())??;
        if tokio::time::Instant::now() >= deadline {
            return client_hello_timeout();
        }
        if let Some(result) = inspect_peeked(&buffered, length)? {
            return Ok(result);
        }
        grow_peek_buffer(&mut buffered, length);

        if length == previous_length {
            let retry_at = (tokio::time::Instant::now() + retry_interval).min(deadline);
            tokio::time::sleep_until(retry_at).await;
            retry_interval = retry_interval
                .saturating_mul(2)
                .min(MAX_PEEK_RETRY_INTERVAL);
        } else {
            retry_interval = PEEK_RETRY_INTERVAL;
        }
        previous_length = length;

        if tokio::time::Instant::now() >= deadline {
            return client_hello_timeout();
        }
    }
}

fn inspect_peeked(buffered: &[u8], length: usize) -> io::Result<Option<(String, usize)>> {
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before a complete TLS ClientHello",
        ));
    }
    match parse_records(&buffered[..length])? {
        ParseResult::Complete(Some(hostname)) => Ok(Some((hostname, length))),
        ParseResult::Complete(None) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS ClientHello does not contain SNI",
        )),
        ParseResult::Incomplete if length >= MAX_CLIENT_HELLO => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS ClientHello exceeds 64 KiB",
        )),
        ParseResult::Incomplete => Ok(None),
    }
}

fn grow_peek_buffer(buffered: &mut Vec<u8>, length: usize) {
    if length == buffered.len() && buffered.len() < MAX_CLIENT_HELLO {
        buffered.resize(buffered.len().saturating_mul(2).min(MAX_CLIENT_HELLO), 0);
    }
}

fn client_hello_timeout<T>() -> io::Result<T> {
    Err(client_hello_timeout_error())
}

fn client_hello_timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out waiting for a complete TLS ClientHello",
    )
}

fn parse_records(input: &[u8]) -> io::Result<ParseResult> {
    let mut offset = 0;
    let mut handshake = Vec::new();

    loop {
        if input.len().saturating_sub(offset) < 5 {
            return Ok(ParseResult::Incomplete);
        }

        let content_type = input[offset];
        let record_len = usize::from(u16::from_be_bytes([input[offset + 3], input[offset + 4]]));
        if record_len > MAX_CLIENT_HELLO {
            return invalid("TLS record exceeds ClientHello limit");
        }
        if input.len().saturating_sub(offset + 5) < record_len {
            return Ok(ParseResult::Incomplete);
        }

        if content_type != 22 {
            return invalid("expected a TLS handshake record");
        }

        handshake.extend_from_slice(&input[offset + 5..offset + 5 + record_len]);
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return invalid("first TLS handshake message is not ClientHello");
            }
            let hello_len = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if hello_len > MAX_CLIENT_HELLO - 4 {
                return invalid("TLS ClientHello exceeds 64 KiB");
            }
            if handshake.len() >= hello_len + 4 {
                return parse_client_hello(&handshake[4..4 + hello_len]);
            }
        }

        offset += 5 + record_len;
    }
}

fn parse_client_hello(hello: &[u8]) -> io::Result<ParseResult> {
    let mut cursor = Cursor::new(hello);
    cursor.take(2 + 32)?;
    let session_len = usize::from(cursor.u8()?);
    cursor.take(session_len)?;
    let cipher_len = usize::from(cursor.u16()?);
    cursor.take(cipher_len)?;
    let compression_len = usize::from(cursor.u8()?);
    cursor.take(compression_len)?;

    if cursor.remaining() == 0 {
        return Ok(ParseResult::Complete(None));
    }

    let extensions_len = usize::from(cursor.u16()?);
    let mut extensions = Cursor::new(cursor.take(extensions_len)?);
    while extensions.remaining() > 0 {
        let extension_type = extensions.u16()?;
        let extension_len = usize::from(extensions.u16()?);
        let extension = extensions.take(extension_len)?;
        if extension_type == 0 {
            return parse_server_name(extension);
        }
    }

    Ok(ParseResult::Complete(None))
}

fn parse_server_name(extension: &[u8]) -> io::Result<ParseResult> {
    let mut names = Cursor::new(extension);
    let list_len = usize::from(names.u16()?);
    let mut list = Cursor::new(names.take(list_len)?);

    while list.remaining() > 0 {
        let name_type = list.u8()?;
        let name_len = usize::from(list.u16()?);
        let name = list.take(name_len)?;
        if name_type == 0 {
            let hostname = std::str::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SNI is not UTF-8"))?;
            let hostname = normalize_hostname(hostname)?;
            return Ok(ParseResult::Complete(Some(hostname)));
        }
    }

    Ok(ParseResult::Complete(None))
}

pub fn normalize_hostname(hostname: &str) -> io::Result<String> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname.is_ascii()
        || hostname.parse::<IpAddr>().is_ok()
    {
        return invalid("SNI hostname is invalid");
    }

    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return invalid("SNI hostname is invalid");
        }
    }
    Ok(hostname)
}

fn invalid<T>(message: &str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if self.remaining() < len {
            return invalid("truncated TLS ClientHello");
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseResult, normalize_hostname, parse_records, peek_sni, peek_sni_async};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn client_hello(hostname: Option<&str>) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);

        let extensions = if let Some(hostname) = hostname {
            let name = hostname.as_bytes();
            let list_len = 1 + 2 + name.len();
            let mut server_name = Vec::new();
            server_name.extend_from_slice(&(list_len as u16).to_be_bytes());
            server_name.push(0);
            server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
            server_name.extend_from_slice(name);

            let mut extension = vec![0, 0];
            extension.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
            extension.extend_from_slice(&server_name);
            extension
        } else {
            Vec::new()
        };
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![
            1,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let split = handshake.len() / 2;
        let mut records = Vec::new();
        for part in [&handshake[..split], &handshake[split..]] {
            records.extend_from_slice(&[22, 3, 1]);
            records.extend_from_slice(&(part.len() as u16).to_be_bytes());
            records.extend_from_slice(part);
        }
        records
    }

    #[test]
    fn parses_sni_across_multiple_tls_records() {
        let input = client_hello(Some("WWW.Example.COM"));
        match parse_records(&input).unwrap() {
            ParseResult::Complete(Some(hostname)) => assert_eq!(hostname, "www.example.com"),
            _ => panic!("expected an SNI hostname"),
        }
    }

    #[test]
    fn peeking_leaves_the_complete_client_hello_unconsumed() {
        let input = client_hello(Some("www.contoso.com"));
        let expected = input.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            stream.write_all(&input).unwrap();
            let (mut accepted, _) = listener.accept().unwrap();
            let (hostname, length) = peek_sni(&accepted, Duration::from_secs(1)).unwrap();
            assert_eq!(hostname, "www.contoso.com");
            assert_eq!(length, expected.len());

            let mut received = vec![0; length];
            accepted.read_exact(&mut received).unwrap();
            assert_eq!(received, expected);
        });

        writer.join().unwrap();
    }

    #[test]
    fn async_peeking_leaves_the_complete_client_hello_unconsumed() {
        let input = client_hello(Some("www.contoso.com"));
        let expected = input.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&input).unwrap();
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (accepted, _) = listener.accept().await.unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            let (hostname, length) = peek_sni_async(&accepted, deadline).await.unwrap();
            assert_eq!(hostname, "www.contoso.com");
            assert_eq!(length, expected.len());

            let mut accepted = accepted.into_std().unwrap();
            accepted.set_nonblocking(false).unwrap();
            let mut received = vec![0; length];
            accepted.read_exact(&mut received).unwrap();
            assert_eq!(received, expected);
        });
        writer.join().unwrap();
    }

    #[test]
    fn async_peeking_uses_one_total_deadline_for_partial_input() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (release_sender, release_receiver) = mpsc::channel();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&[22]).unwrap();
            release_receiver.recv().unwrap();
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        let started = Instant::now();
        let error = runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (accepted, _) = listener.accept().await.unwrap();
            peek_sni_async(
                &accepted,
                tokio::time::Instant::now() + Duration::from_millis(50),
            )
            .await
            .unwrap_err()
        });
        release_sender.send(()).unwrap();
        writer.join().unwrap();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "partial input reset the total ClientHello deadline"
        );
    }

    #[test]
    fn async_peeking_rejects_complete_input_after_the_total_deadline() {
        let input = client_hello(Some("www.contoso.com"));
        let expected = input.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&input).unwrap();
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (accepted, _) = listener.accept().await.unwrap();
            let error = peek_sni_async(
                &accepted,
                tokio::time::Instant::now() - Duration::from_millis(1),
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

            let mut accepted = accepted.into_std().unwrap();
            accepted.set_nonblocking(false).unwrap();
            let mut received = vec![0; expected.len()];
            accepted.read_exact(&mut received).unwrap();
            assert_eq!(received, expected);
        });
        writer.join().unwrap();
    }

    #[test]
    fn reports_a_complete_client_hello_without_sni() {
        let input = client_hello(None);
        assert!(matches!(
            parse_records(&input).unwrap(),
            ParseResult::Complete(None)
        ));
    }

    #[test]
    fn waits_for_an_incomplete_record() {
        let input = client_hello(Some("example.com"));
        assert!(matches!(
            parse_records(&input[..input.len() - 1]).unwrap(),
            ParseResult::Incomplete
        ));
    }

    #[test]
    fn normalizes_dns_names_and_rejects_non_dns_sni() {
        assert_eq!(
            normalize_hostname("WWW.Example.COM.").unwrap(),
            "www.example.com"
        );
        for invalid in [
            "",
            "bad host.example",
            "a/b.example",
            "-bad.example",
            "bad-.example",
            "127.0.0.1",
            "bad..example",
        ] {
            assert!(normalize_hostname(invalid).is_err(), "{invalid}");
        }
    }
}
