use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

const RELAY_BUFFER_SIZE: usize = 16 * 1024;

pub(crate) struct RelayReport {
    pub client_to_workload_bytes: u64,
    pub workload_to_client_bytes: u64,
    pub elapsed: Duration,
    pub error: Option<io::Error>,
}

pub(crate) async fn copy_bidirectional<Client, Workload>(
    client: &mut Client,
    workload: &mut Workload,
    idle_timeout: Option<Duration>,
) -> RelayReport
where
    Client: AsyncRead + AsyncWrite + Unpin,
    Workload: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let client_to_workload_bytes = AtomicU64::new(0);
    let workload_to_client_bytes = AtomicU64::new(0);
    let (progress_sender, mut progress_receiver) = mpsc::channel(1);
    let (client_reader, client_writer) = tokio::io::split(client);
    let (workload_reader, workload_writer) = tokio::io::split(workload);
    let client_to_workload = copy_direction(
        client_reader,
        workload_writer,
        progress_sender.clone(),
        &client_to_workload_bytes,
    );
    let workload_to_client = copy_direction(
        workload_reader,
        client_writer,
        progress_sender,
        &workload_to_client_bytes,
    );
    tokio::pin!(client_to_workload);
    tokio::pin!(workload_to_client);

    let idle = tokio::time::sleep(idle_timeout.unwrap_or(Duration::ZERO));
    tokio::pin!(idle);
    let mut client_to_workload_done = false;
    let mut workload_to_client_done = false;
    let mut progress_open = true;
    let mut relay_error = None;

    while !client_to_workload_done || !workload_to_client_done {
        tokio::select! {
            biased;
            result = &mut client_to_workload, if !client_to_workload_done => {
                client_to_workload_done = true;
                if let Err(error) = result {
                    relay_error = Some(error);
                    break;
                }
            }
            result = &mut workload_to_client, if !workload_to_client_done => {
                workload_to_client_done = true;
                if let Err(error) = result {
                    relay_error = Some(error);
                    break;
                }
            }
            progress = progress_receiver.recv(), if idle_timeout.is_some() && progress_open => {
                match progress {
                    Some(()) => {
                        idle.as_mut().reset(Instant::now() + idle_timeout.unwrap());
                    }
                    None => progress_open = false,
                }
            }
            _ = &mut idle, if idle_timeout.is_some() => {
                relay_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay idle timeout elapsed",
                ));
                break;
            }
        }
    }

    RelayReport {
        client_to_workload_bytes: client_to_workload_bytes.load(Ordering::Relaxed),
        workload_to_client_bytes: workload_to_client_bytes.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
        error: relay_error,
    }
}

async fn copy_direction<Reader, Writer>(
    mut reader: Reader,
    mut writer: Writer,
    progress: mpsc::Sender<()>,
    bytes: &AtomicU64,
) -> io::Result<()>
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; RELAY_BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return writer.shutdown().await;
        }
        let mut remaining = &buffer[..read];
        while !remaining.is_empty() {
            let written = writer.write(remaining).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            saturating_add(bytes, u64::try_from(written).unwrap_or(u64::MAX));
            let _ = progress.try_send(());
            remaining = &remaining[written..];
        }
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

#[cfg(test)]
mod tests {
    use super::{RELAY_BUFFER_SIZE, copy_bidirectional};
    use crate::ingress_config::DEFAULT_RELAY_IDLE_TIMEOUT;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpListener, TcpSocket, TcpStream};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn previously_peeked_bytes_are_forwarded_once_and_half_closes_propagate() {
        let (mut public_peer, mut accepted) = tcp_pair().await;
        let (mut upstream, mut workload_peer) = tcp_pair().await;
        public_peer.write_all(b"peeked request").await.unwrap();

        let mut peeked = [0_u8; 14];
        assert_eq!(accepted.peek(&mut peeked).await.unwrap(), peeked.len());
        assert_eq!(&peeked, b"peeked request");

        let relay =
            tokio::spawn(
                async move { copy_bidirectional(&mut accepted, &mut upstream, None).await },
            );
        public_peer.shutdown().await.unwrap();

        let mut request = Vec::new();
        workload_peer.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"peeked request");
        workload_peer.write_all(b"response").await.unwrap();
        workload_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        public_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");

        let report = relay.await.unwrap();
        assert!(report.error.is_none());
        assert_eq!(report.client_to_workload_bytes, 14);
        assert_eq!(report.workload_to_client_bytes, 8);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_deadline_resets_on_progress_in_either_direction() {
        let (mut public_peer, mut accepted) = duplex(64);
        let (mut upstream, mut workload_peer) = duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional(&mut accepted, &mut upstream, Some(Duration::from_secs(10))).await
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(9)).await;
        public_peer.write_all(b"a").await.unwrap();
        let mut byte = [0_u8; 1];
        workload_peer.read_exact(&mut byte).await.unwrap();
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(9)).await;
        workload_peer.write_all(b"b").await.unwrap();
        public_peer.read_exact(&mut byte).await.unwrap();
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!relay.is_finished());
        public_peer.shutdown().await.unwrap();
        workload_peer.shutdown().await.unwrap();

        let report = relay.await.unwrap();
        assert!(report.error.is_none());
        assert_eq!(report.client_to_workload_bytes, 1);
        assert_eq!(report.workload_to_client_bytes, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_writes_reset_idle_deadline_in_either_direction() {
        const CHUNK_SIZE: usize = 1024;
        let idle_timeout = DEFAULT_RELAY_IDLE_TIMEOUT;
        let progress_interval = idle_timeout / 3;

        for reverse in [false, true] {
            let (mut sending_peer, mut source) = duplex(RELAY_BUFFER_SIZE);
            let (mut destination, mut receiving_peer) = duplex(CHUNK_SIZE);
            sending_peer
                .write_all(&[0x5a; RELAY_BUFFER_SIZE])
                .await
                .unwrap();
            let relay = tokio::spawn(async move {
                if reverse {
                    copy_bidirectional(&mut destination, &mut source, Some(idle_timeout)).await
                } else {
                    copy_bidirectional(&mut source, &mut destination, Some(idle_timeout)).await
                }
            });
            tokio::task::yield_now().await;

            for step in 1..=4 {
                tokio::time::advance(progress_interval).await;
                let mut chunk = [0_u8; CHUNK_SIZE];
                receiving_peer.read_exact(&mut chunk).await.unwrap();
                assert_eq!(chunk, [0x5a; CHUNK_SIZE]);
                tokio::task::yield_now().await;
                assert!(
                    !relay.is_finished(),
                    "relay closed despite partial-write progress at step {step}, reverse={reverse}"
                );
            }

            tokio::time::advance(idle_timeout - Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            assert!(!relay.is_finished());
            tokio::time::advance(Duration::from_secs(1)).await;

            let report = relay.await.unwrap();
            assert_eq!(
                report.error.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::TimedOut)
            );
            let expected_bytes = u64::try_from(5 * CHUNK_SIZE).unwrap();
            assert_eq!(
                (
                    report.client_to_workload_bytes,
                    report.workload_to_client_bytes
                ),
                if reverse {
                    (0, expected_bytes)
                } else {
                    (expected_bytes, 0)
                }
            );
            let mut remaining = Vec::new();
            receiving_peer.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, [0x5a; CHUNK_SIZE]);
            assert_eq!(report.elapsed, progress_interval * 4 + idle_timeout);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn partial_writes_are_counted_before_a_write_error() {
        let (mut public_peer, mut accepted) = duplex(RELAY_BUFFER_SIZE);
        let (mut upstream, mut workload_peer) = duplex(1);
        public_peer
            .write_all(&[0x5a; RELAY_BUFFER_SIZE])
            .await
            .unwrap();
        let relay =
            tokio::spawn(
                async move { copy_bidirectional(&mut accepted, &mut upstream, None).await },
            );
        let mut byte = [0_u8; 1];
        workload_peer.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [0x5a]);
        drop(workload_peer);

        let report = relay.await.unwrap();
        assert_eq!(
            report.error.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::BrokenPipe)
        );
        assert_eq!(report.client_to_workload_bytes, 1);
        assert_eq!(report.workload_to_client_bytes, 0);
    }

    #[tokio::test]
    async fn partial_write_followed_by_zero_preserves_count_and_errors() {
        let mut destination = [0_u8; 1];
        let writer = io::Cursor::new(destination.as_mut_slice());
        let bytes = AtomicU64::new(0);
        let (progress, _receiver) = tokio::sync::mpsc::channel(1);

        let error = super::copy_direction(&b"ab"[..], writer, progress, &bytes)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(destination, [b'a']);
        assert_eq!(bytes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn tcp_backpressure_preserves_all_forwarded_bytes() {
        const MIN_PAYLOAD_SIZE: usize = 256 * 1024;

        tokio::time::timeout(Duration::from_secs(10), async {
            let (mut public_peer, accepted) = tcp_pair().await;
            let buffer_size = u32::try_from(RELAY_BUFFER_SIZE).unwrap();
            // Request small buffers before negotiating the receive window.
            let workload_socket = TcpSocket::new_v4().unwrap();
            workload_socket.set_recv_buffer_size(buffer_size).unwrap();
            workload_socket
                .bind("127.0.0.1:0".parse().unwrap())
                .unwrap();
            let listener = workload_socket.listen(1).unwrap();
            let upstream_socket = TcpSocket::new_v4().unwrap();
            upstream_socket.set_send_buffer_size(buffer_size).unwrap();
            let (upstream, workload_peer) = tokio::join!(
                upstream_socket.connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            let upstream = upstream.unwrap();
            let mut workload_peer = workload_peer.unwrap().0;
            let send_buffer = socket2::SockRef::from(&upstream)
                .send_buffer_size()
                .unwrap();
            let receive_buffer = socket2::SockRef::from(&workload_peer)
                .recv_buffer_size()
                .unwrap();
            // macOS can enlarge loopback buffers despite the explicit size requests.
            let payload_size =
                MIN_PAYLOAD_SIZE.max(2 * (send_buffer + receive_buffer + RELAY_BUFFER_SIZE));
            let bytes = Arc::new(AtomicU64::new(0));
            let copied_bytes = Arc::clone(&bytes);
            let (progress, mut receiver) = tokio::sync::mpsc::channel(1);
            let copy = tokio::spawn(async move {
                super::copy_direction(accepted, upstream, progress, &copied_bytes).await
            });

            let payload: Vec<_> = (0_u8..=250).cycle().take(payload_size).collect();
            let expected_bytes = u64::try_from(payload_size).unwrap();
            let outgoing = payload.clone();
            let sender = tokio::spawn(async move {
                public_peer.write_all(&outgoing).await.unwrap();
                public_peer.shutdown().await.unwrap();
            });
            receiver.recv().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !copy.is_finished(),
                "fixture did not impose TCP backpressure"
            );
            let before_drain = bytes.load(Ordering::Relaxed);
            assert!(before_drain > 0 && before_drain < expected_bytes);

            let mut received = Vec::new();
            workload_peer.read_to_end(&mut received).await.unwrap();
            sender.await.unwrap();
            copy.await.unwrap().unwrap();
            assert_eq!(received, payload);
            assert_eq!(bytes.load(Ordering::Relaxed), expected_bytes);
            eprintln!(
                "loopback backpressure: {before_drain}/{payload_size} bytes written before drain; \
                 all {payload_size} bytes delivered and counted after drain"
            );
        })
        .await
        .expect("bounded loopback backpressure fixture");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_policy_times_out_and_can_be_disabled() {
        let (_public_peer, mut accepted) = duplex(64);
        let (_workload_peer, mut upstream) = duplex(64);
        let timed = tokio::spawn(async move {
            copy_bidirectional(&mut accepted, &mut upstream, Some(Duration::from_secs(10))).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        let report = timed.await.unwrap();
        assert_eq!(
            report.error.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::TimedOut)
        );

        let (public_peer, mut accepted) = duplex(64);
        let (workload_peer, mut upstream) = duplex(64);
        let disabled =
            tokio::spawn(
                async move { copy_bidirectional(&mut accepted, &mut upstream, None).await },
            );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(24 * 60 * 60)).await;
        assert!(!disabled.is_finished());
        drop(public_peer);
        drop(workload_peer);
        assert!(disabled.await.unwrap().error.is_none());
    }
}
