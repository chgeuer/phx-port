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
        writer.write_all(&buffer[..read]).await?;
        saturating_add(bytes, u64::try_from(read).unwrap_or(u64::MAX));
        let _ = progress.try_send(());
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

#[cfg(test)]
mod tests {
    use super::copy_bidirectional;
    use std::io;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpListener, TcpStream};

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
