#[cfg(test)]
use crate::ingress_limits::{IngressLimits, SystemCapacity};
use crate::{
    admission::{AdmissionController, AdmissionRejection, PreRoutingAdmission, RelayPermit},
    config_path, handoff,
    ingress_config::HostingProfile,
    ingress_limits::{DaemonConfig, ValidatedIngressLimits},
    is_port_open, read_config, route_cache, tls_client_hello,
    worker_pool::BoundedWorkerPool,
};
use native_tls::TlsConnector;
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_PROBES: usize = 32;
const MAX_WAITING_CLIENTS: usize = 64;
const MAX_NEGATIVE_ROUTES: usize = 1024;
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const LIVENESS_INTERVAL: Duration = Duration::from_secs(1);
const TLS_REVALIDATION_INTERVAL: Duration = Duration::from_secs(30);
const TCP_FAILURE_THRESHOLD: u8 = 3;
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_QUEUE_CAPACITY: usize = 1;
const OVERLOAD_EVENT_INTERVAL: Duration = Duration::from_secs(10);
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Backend {
    project: String,
    role: String,
    port: u16,
}

struct ProbeMatch {
    backend: Backend,
    certificate_fingerprint: String,
}

#[derive(Clone)]
struct ActiveRoute {
    backend: Backend,
    certificate_fingerprint: String,
    last_tls_check: Instant,
    tcp_failures: u8,
}

struct DiscoveryFlight {
    result: Mutex<Option<Result<Backend, String>>>,
    ready: Condvar,
}

impl DiscoveryFlight {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn complete(&self, result: Result<Backend, String>) {
        if let Ok(mut slot) = self.result.lock() {
            *slot = Some(result);
            self.ready.notify_all();
        }
    }

    fn wait(&self, deadline: Instant) -> Result<Backend, String> {
        let mut slot = self
            .result
            .lock()
            .map_err(|_| "discovery result lock poisoned".to_string())?;
        loop {
            if let Some(result) = slot.as_ref() {
                return result.clone();
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err("hostname discovery timed out".to_string());
            };
            let (next, timeout) = self
                .ready
                .wait_timeout(slot, remaining)
                .map_err(|_| "discovery result lock poisoned".to_string())?;
            slot = next;
            if timeout.timed_out() && slot.is_none() {
                return Err("hostname discovery timed out".to_string());
            }
        }
    }
}

struct ProbeLimiter {
    in_use: Mutex<usize>,
    available: Condvar,
}

impl ProbeLimiter {
    fn new() -> Self {
        Self {
            in_use: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>, deadline: Instant) -> Option<ProbePermit> {
        let mut in_use = self.in_use.lock().ok()?;
        while *in_use >= MAX_PROBES {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let (next, timeout) = self.available.wait_timeout(in_use, remaining).ok()?;
            in_use = next;
            if timeout.timed_out() && *in_use >= MAX_PROBES {
                return None;
            }
        }
        *in_use += 1;
        Some(ProbePermit {
            limiter: Arc::clone(self),
        })
    }
}

struct ProbePermit {
    limiter: Arc<ProbeLimiter>,
}

impl Drop for ProbePermit {
    fn drop(&mut self) {
        if let Ok(mut in_use) = self.limiter.in_use.lock() {
            *in_use = in_use.saturating_sub(1);
            self.limiter.available.notify_one();
        }
    }
}

#[derive(Clone, Copy, Default)]
struct OverloadEventWindow {
    last_emitted: Option<Instant>,
    pending: u64,
}

struct OverloadEvents {
    windows: [OverloadEventWindow; AdmissionRejection::COUNT],
}

impl OverloadEvents {
    fn new() -> Self {
        Self {
            windows: [OverloadEventWindow::default(); AdmissionRejection::COUNT],
        }
    }

    fn record(&mut self, reason: AdmissionRejection, now: Instant) -> Option<OverloadEvent> {
        let window = &mut self.windows[reason.index()];
        window.pending = window.pending.saturating_add(1);
        let should_emit = match window.last_emitted {
            Some(last_emitted) => {
                now.saturating_duration_since(last_emitted) >= OVERLOAD_EVENT_INTERVAL
            }
            None => true,
        };
        if !should_emit {
            return None;
        }

        window.last_emitted = Some(now);
        let rejected = std::mem::take(&mut window.pending);
        Some(OverloadEvent { reason, rejected })
    }
}

struct OverloadEvent {
    reason: AdmissionRejection,
    rejected: u64,
}

impl std::fmt::Display for OverloadEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "event=ingress_overload reason={} rejected={} suppressed={}",
            self.reason.event_reason(),
            self.rejected,
            self.rejected.saturating_sub(1)
        )
    }
}

struct ProxyState {
    config: PathBuf,
    hosting_profile: HostingProfile,
    limits: ValidatedIngressLimits,
    admission: AdmissionController,
    listeners: RwLock<Vec<SocketAddr>>,
    routes: RwLock<HashMap<String, ActiveRoute>>,
    conflicts: RwLock<HashMap<String, Vec<Backend>>>,
    flights: Mutex<HashMap<String, Arc<DiscoveryFlight>>>,
    negative: Mutex<HashMap<String, Instant>>,
    workloads: Mutex<Vec<Backend>>,
    waiting_clients: AtomicUsize,
    queued_connections: Arc<AtomicUsize>,
    probes: Arc<ProbeLimiter>,
    accepted_connections: AtomicU64,
    relayed_connections: AtomicU64,
    rejected_connections: AtomicU64,
    rejected_accept_rate: AtomicU64,
    rejected_global_capacity: AtomicU64,
    rejected_source_rate: AtomicU64,
    rejected_source_concurrency: AtomicU64,
    rejected_source_state_capacity: AtomicU64,
    rejected_pre_routing_capacity: AtomicU64,
    rejected_relay_capacity: AtomicU64,
    rejected_worker_queue: AtomicU64,
    overload_events: Mutex<OverloadEvents>,
    successful_discoveries: AtomicU64,
    handoff_attempts: AtomicU64,
    successful_handoffs: AtomicU64,
    handoff_fallbacks: AtomicU64,
    handoff_capacity_skips: AtomicU64,
    delivered_handoff_failures: AtomicU64,
}

impl ProxyState {
    fn with_limits(
        config: PathBuf,
        hosting_profile: HostingProfile,
        limits: ValidatedIngressLimits,
    ) -> Self {
        let admission = AdmissionController::new(&limits);
        Self {
            config,
            hosting_profile,
            limits,
            admission,
            listeners: RwLock::new(Vec::new()),
            routes: RwLock::new(HashMap::new()),
            conflicts: RwLock::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
            workloads: Mutex::new(Vec::new()),
            waiting_clients: AtomicUsize::new(0),
            queued_connections: Arc::new(AtomicUsize::new(0)),
            probes: Arc::new(ProbeLimiter::new()),
            accepted_connections: AtomicU64::new(0),
            relayed_connections: AtomicU64::new(0),
            rejected_connections: AtomicU64::new(0),
            rejected_accept_rate: AtomicU64::new(0),
            rejected_global_capacity: AtomicU64::new(0),
            rejected_source_rate: AtomicU64::new(0),
            rejected_source_concurrency: AtomicU64::new(0),
            rejected_source_state_capacity: AtomicU64::new(0),
            rejected_pre_routing_capacity: AtomicU64::new(0),
            rejected_relay_capacity: AtomicU64::new(0),
            rejected_worker_queue: AtomicU64::new(0),
            overload_events: Mutex::new(OverloadEvents::new()),
            successful_discoveries: AtomicU64::new(0),
            handoff_attempts: AtomicU64::new(0),
            successful_handoffs: AtomicU64::new(0),
            handoff_fallbacks: AtomicU64::new(0),
            handoff_capacity_skips: AtomicU64::new(0),
            delivered_handoff_failures: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn new(config: PathBuf) -> Self {
        Self::new_with_profile(config, HostingProfile::Development)
    }

    #[cfg(test)]
    fn new_with_profile(config: PathBuf, hosting_profile: HostingProfile) -> Self {
        let limits = IngressLimits::default()
            .validate(
                SystemCapacity {
                    file_descriptors: None,
                    tasks: None,
                },
                2,
            )
            .unwrap();
        Self::with_limits(config, hosting_profile, limits)
    }

    fn discover_once(
        &self,
        hostname: &str,
        discover: impl FnOnce() -> Result<Backend, String>,
    ) -> Result<Backend, String> {
        let _waiting = WaitingClient::acquire(&self.waiting_clients)?;
        let deadline = Instant::now() + DISCOVERY_TIMEOUT;
        let (flight, leader) = {
            let mut flights = self
                .flights
                .lock()
                .map_err(|_| "discovery map lock poisoned".to_string())?;
            if let Some(flight) = flights.get(hostname) {
                (Arc::clone(flight), false)
            } else {
                let flight = Arc::new(DiscoveryFlight::new());
                flights.insert(hostname.to_string(), Arc::clone(&flight));
                (flight, true)
            }
        };

        if !leader {
            return flight.wait(deadline);
        }

        let result = discover();
        flight.complete(result.clone());
        if let Ok(mut flights) = self.flights.lock() {
            flights.remove(hostname);
        }
        result
    }

    fn record_admission_rejection(&self, rejection: AdmissionRejection) {
        if let Some(event) = self.record_admission_rejection_at(rejection, Instant::now()) {
            eprintln!("{event}");
        }
    }

    fn record_admission_rejection_at(
        &self,
        rejection: AdmissionRejection,
        now: Instant,
    ) -> Option<OverloadEvent> {
        let counter = match rejection {
            AdmissionRejection::AcceptRate => &self.rejected_accept_rate,
            AdmissionRejection::Global => &self.rejected_global_capacity,
            AdmissionRejection::SourceRate => &self.rejected_source_rate,
            AdmissionRejection::SourceConcurrency => &self.rejected_source_concurrency,
            AdmissionRejection::SourceStateCapacity => &self.rejected_source_state_capacity,
            AdmissionRejection::PreRouting => &self.rejected_pre_routing_capacity,
            AdmissionRejection::Relay => &self.rejected_relay_capacity,
            AdmissionRejection::Handoff => &self.handoff_capacity_skips,
            AdmissionRejection::WorkerQueue => &self.rejected_worker_queue,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.overload_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(rejection, now)
    }
}

struct WaitingClient<'a> {
    count: &'a AtomicUsize,
}

impl<'a> WaitingClient<'a> {
    fn acquire(count: &'a AtomicUsize) -> Result<Self, String> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_WAITING_CLIENTS).then_some(current + 1)
            })
            .map_err(|_| "too many clients are waiting for hostname discovery".to_string())?;
        Ok(Self { count })
    }
}

impl Drop for WaitingClient<'_> {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

struct QueuedConnection {
    count: Arc<AtomicUsize>,
}

impl QueuedConnection {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self { count }
    }
}

impl Drop for QueuedConnection {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ConnectionJob {
    client: TcpStream,
    accepted_at: Instant,
    admission: PreRoutingAdmission,
    queued: QueuedConnection,
}

pub fn run(config: DaemonConfig) -> Result<(), String> {
    PROCESS_START.get_or_init(Instant::now);
    let DaemonConfig {
        listen_addresses,
        limits,
        task_budget,
        hosting_profile,
    } = config;
    let limits = limits.validate_for_startup(task_budget, listen_addresses.len())?;
    let state = Arc::new(ProxyState::with_limits(
        config_path(),
        hosting_profile,
        limits,
    ));
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut listeners = Vec::new();

    for address in &listen_addresses {
        let listener = bind_listener(address)
            .map_err(|error| format!("cannot listen on {address}: {error}"))?;
        eprintln!("TLS proxy listening on {}", listener.local_addr().unwrap());
        listeners.push(listener);
    }
    *state
        .listeners
        .write()
        .map_err(|_| "listener state lock poisoned".to_string())? = listeners
        .iter()
        .filter_map(|listener| listener.local_addr().ok())
        .collect();

    let signal = Arc::clone(&shutdown);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .map_err(|error| format!("cannot install shutdown signal handler: {error}"))?;

    let worker_state = Arc::clone(&state);
    let mut connection_workers = BoundedWorkerPool::start(
        "phx-port-connection",
        state.limits.active_connections(),
        CONNECTION_QUEUE_CAPACITY,
        move |job: ConnectionJob| {
            let ConnectionJob {
                client,
                accepted_at,
                admission,
                queued,
            } = job;
            drop(queued);
            if handle_connection(client, accepted_at, Arc::clone(&worker_state), admission).is_err()
            {
                worker_state
                    .rejected_connections
                    .fetch_add(1, Ordering::Relaxed);
            }
        },
    )?;

    #[cfg(unix)]
    let (control_path, control_thread) =
        start_control_server(Arc::clone(&state), Arc::clone(&shutdown))?;

    let mut listener_threads = Vec::new();
    for listener in listeners {
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("cannot configure listener: {error}"))?;
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        let connection_sender = connection_workers.sender();
        listener_threads.push(thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        let accepted_at = Instant::now();
                        state.accepted_connections.fetch_add(1, Ordering::Relaxed);
                        let admission = match state.admission.try_admit(peer.ip()) {
                            Ok(admission) => admission,
                            Err(rejection) => {
                                state.record_admission_rejection(rejection);
                                state.rejected_connections.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };
                        let job = ConnectionJob {
                            client: stream,
                            accepted_at,
                            admission,
                            queued: QueuedConnection::new(Arc::clone(&state.queued_connections)),
                        };
                        match connection_sender.try_send(job) {
                            Ok(()) => {}
                            Err(mpsc::TrySendError::Full(_)) => {
                                state.record_admission_rejection(AdmissionRejection::WorkerQueue);
                                state.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(mpsc::TrySendError::Disconnected(_)) => {
                                state.rejected_connections.fetch_add(1, Ordering::Relaxed);
                                if !shutdown.swap(true, Ordering::AcqRel) {
                                    eprintln!("TLS proxy connection worker pool stopped");
                                }
                                break;
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(error) => eprintln!("TLS proxy accept failed: {error}"),
                }
            }
        }));
    }

    let reconciler_thread = {
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                thread::sleep(LIVENESS_INTERVAL);
                reconcile_workloads(&state);
                reconcile_routes(&state);
            }
        })
    };

    while !shutdown.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(100));
    }
    for listener_thread in listener_threads {
        let _ = listener_thread.join();
    }
    connection_workers.close();
    #[cfg(unix)]
    let _ = control_thread.join();
    let _ = reconciler_thread.join();

    let drain_deadline = Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;
    while state.admission.snapshot().global.in_use > 0 && Instant::now() < drain_deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let remaining = state.admission.snapshot().global.in_use;
    let worker_join_error = if remaining > 0 {
        eprintln!("TLS proxy shutdown drain timed out with {remaining} connection(s) still active");
        None
    } else {
        connection_workers.join().err()
    };

    #[cfg(unix)]
    if let Err(error) = std::fs::remove_file(&control_path)
        && error.kind() != io::ErrorKind::NotFound
    {
        eprintln!("Could not remove control socket: {error}");
    }
    if let Some(error) = worker_join_error {
        return Err(error);
    }
    eprintln!("TLS proxy stopped");
    Ok(())
}

fn bind_listener(address: &str) -> io::Result<TcpListener> {
    let address: SocketAddr = address.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid socket address: {error}"),
        )
    })?;
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

pub fn query_control(command: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        let mut stream = UnixStream::connect(control_socket_path())
            .map_err(|error| format!("TLS proxy daemon is not reachable: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|error| format!("cannot configure control connection: {error}"))?;
        stream
            .write_all(format!("{command}\n").as_bytes())
            .map_err(|error| format!("cannot send daemon command: {error}"))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| format!("cannot finish daemon command: {error}"))?;
        let mut response = String::new();
        stream
            .take(64 * 1024)
            .read_to_string(&mut response)
            .map_err(|error| format!("cannot read daemon response: {error}"))?;
        Ok(response)
    }

    #[cfg(not(unix))]
    Err("live daemon status is not supported on this platform".to_string())
}

#[cfg(unix)]
fn control_socket_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("phx-port").join("control.sock");
    }
    config_path()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("phx-port-runtime")
        .join("control.sock")
}

#[cfg(unix)]
fn start_control_server(
    state: Arc<ProxyState>,
    shutdown: Arc<AtomicBool>,
) -> Result<(PathBuf, thread::JoinHandle<()>), String> {
    let path = control_socket_path();
    let directory = path
        .parent()
        .ok_or_else(|| "control socket has no parent directory".to_string())?;
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("cannot create control directory: {error}"))?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot secure control directory: {error}"))?;

    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            return Err(format!(
                "another TLS proxy daemon is already using {}",
                path.display()
            ));
        }
        std::fs::remove_file(&path)
            .map_err(|error| format!("cannot remove stale control socket: {error}"))?;
    }

    let listener = UnixListener::bind(&path)
        .map_err(|error| format!("cannot bind control socket {}: {error}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot secure control socket: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("cannot configure control socket: {error}"))?;

    let thread = thread::spawn(move || {
        while !shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Err(error) = stream.set_read_timeout(Some(Duration::from_secs(2))) {
                        let _ = writeln!(stream, "ERROR cannot configure request timeout: {error}");
                        continue;
                    }
                    let mut request = String::new();
                    let response = match (&mut stream).take(1024).read_to_string(&mut request) {
                        Ok(_) => render_control_response(&state, &shutdown, request.trim()),
                        Err(error) => format!("ERROR cannot read request: {error}\n"),
                    };
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => eprintln!("TLS proxy control accept failed: {error}"),
            }
        }
    });

    Ok((path, thread))
}

fn render_control_response(state: &ProxyState, shutdown: &AtomicBool, request: &str) -> String {
    match request {
        "STATUS" => {
            let admission = state.admission.snapshot();
            let listeners = state
                .listeners
                .read()
                .map(|listeners| {
                    listeners
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            let active_routes = state.routes.read().map(|routes| routes.len()).unwrap_or(0);
            let conflicts = state
                .conflicts
                .read()
                .map(|conflicts| conflicts.len())
                .unwrap_or(0);
            let discoveries = state
                .flights
                .lock()
                .map(|flights| flights.len())
                .unwrap_or(0);
            let probes = state.probes.in_use.lock().map(|count| *count).unwrap_or(0);
            format!(
                "running\nhosting_profile={hosting_profile}\nlisteners={listeners}\nactive_routes={active_routes}\nconflicts={conflicts}\nactive_connections={active_connections}\nactive_connection_limit={active_connection_limit}\npre_routing_connections={pre_routing_connections}\npre_routing_connection_limit={pre_routing_connection_limit}\nactive_relays={active_relays}\nrelay_connection_limit={relay_connection_limit}\nhandoff_negotiations={handoff_negotiations}\nhandoff_negotiation_limit={handoff_negotiation_limit}\naccepts_per_second_limit={accepts_per_second_limit}\naccept_burst_limit={accept_burst_limit}\nsource_entries={source_entries}\nsource_entry_limit={source_entry_limit}\nsource_accepts_per_second_limit={source_accepts_per_second_limit}\nsource_accept_burst_limit={source_accept_burst_limit}\nsource_pre_routing_limit={source_pre_routing_limit}\nsource_ipv6_prefix={source_ipv6_prefix}\nsource_entry_ttl_seconds={source_entry_ttl_seconds}\nsource_policy_overrides={source_policy_overrides}\nqueued_connections={queued_connections}\nconnection_queue_limit={CONNECTION_QUEUE_CAPACITY}\nconnection_workers={connection_workers}\nwaiting_clients={waiting_clients}\ninflight_discoveries={discoveries}\nactive_probes={probes}\naccepted_connections={accepted_connections}\nrelayed_connections={relayed_connections}\nrejected_connections={rejected_connections}\nrejected_accept_rate={rejected_accept_rate}\nrejected_global_capacity={rejected_global_capacity}\nrejected_source_rate={rejected_source_rate}\nrejected_source_concurrency={rejected_source_concurrency}\nrejected_source_state_capacity={rejected_source_state_capacity}\nrejected_pre_routing_capacity={rejected_pre_routing_capacity}\nrejected_relay_capacity={rejected_relay_capacity}\nrejected_worker_queue={rejected_worker_queue}\nsuccessful_discoveries={successful_discoveries}\nhandoff_attempts={handoff_attempts}\nsuccessful_handoffs={successful_handoffs}\nhandoff_fallbacks={handoff_fallbacks}\nhandoff_capacity_skips={handoff_capacity_skips}\ndelivered_handoff_failures={delivered_handoff_failures}\n",
                hosting_profile = state.hosting_profile.name(),
                active_connections = admission.global.in_use,
                active_connection_limit = admission.global.limit,
                pre_routing_connections = admission.pre_routing.in_use,
                pre_routing_connection_limit = admission.pre_routing.limit,
                active_relays = admission.relay.in_use,
                relay_connection_limit = admission.relay.limit,
                handoff_negotiations = admission.handoff.in_use,
                handoff_negotiation_limit = admission.handoff.limit,
                accepts_per_second_limit = state.limits.accepts_per_second(),
                accept_burst_limit = state.limits.accept_burst(),
                source_entries = admission.source_entries,
                source_entry_limit = admission.source_entry_limit,
                source_accepts_per_second_limit = state.limits.source().accepts_per_second,
                source_accept_burst_limit = state.limits.source().accept_burst,
                source_pre_routing_limit = state.limits.source().pre_routing_connections,
                source_ipv6_prefix = state.limits.source().ipv6_prefix,
                source_entry_ttl_seconds = state.limits.source().entry_ttl_seconds,
                source_policy_overrides = state.limits.source().overrides.len(),
                queued_connections = state.queued_connections.load(Ordering::Relaxed),
                connection_workers = state.limits.active_connections(),
                waiting_clients = state.waiting_clients.load(Ordering::Relaxed),
                accepted_connections = state.accepted_connections.load(Ordering::Relaxed),
                relayed_connections = state.relayed_connections.load(Ordering::Relaxed),
                rejected_connections = state.rejected_connections.load(Ordering::Relaxed),
                rejected_accept_rate = state.rejected_accept_rate.load(Ordering::Relaxed),
                rejected_global_capacity = state.rejected_global_capacity.load(Ordering::Relaxed),
                rejected_source_rate = state.rejected_source_rate.load(Ordering::Relaxed),
                rejected_source_concurrency =
                    state.rejected_source_concurrency.load(Ordering::Relaxed),
                rejected_source_state_capacity =
                    state.rejected_source_state_capacity.load(Ordering::Relaxed),
                rejected_pre_routing_capacity =
                    state.rejected_pre_routing_capacity.load(Ordering::Relaxed),
                rejected_relay_capacity = state.rejected_relay_capacity.load(Ordering::Relaxed),
                rejected_worker_queue = state.rejected_worker_queue.load(Ordering::Relaxed),
                successful_discoveries = state.successful_discoveries.load(Ordering::Relaxed),
                handoff_attempts = state.handoff_attempts.load(Ordering::Relaxed),
                successful_handoffs = state.successful_handoffs.load(Ordering::Relaxed),
                handoff_fallbacks = state.handoff_fallbacks.load(Ordering::Relaxed),
                handoff_capacity_skips = state.handoff_capacity_skips.load(Ordering::Relaxed),
                delivered_handoff_failures =
                    state.delivered_handoff_failures.load(Ordering::Relaxed),
            )
        }
        "ROUTES" => {
            let mut lines = Vec::new();
            if let Ok(routes) = state.routes.read() {
                for (hostname, route) in routes.iter() {
                    lines.push(format!(
                        "active\t{hostname}\t{}\t{}\t{}\t{}",
                        route.backend.project,
                        route.backend.role,
                        route.backend.port,
                        route.certificate_fingerprint
                    ));
                }
            }
            if let Ok(conflicts) = state.conflicts.read() {
                for (hostname, backends) in conflicts.iter() {
                    let owners = backends
                        .iter()
                        .map(|backend| {
                            format!("{}:{}:{}", backend.project, backend.role, backend.port)
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    lines.push(format!("conflict\t{hostname}\t{owners}"));
                }
            }
            lines.sort();
            if lines.is_empty() {
                "No active TLS routes.\n".to_string()
            } else {
                format!("{}\n", lines.join("\n"))
            }
        }
        "STOP" => {
            shutdown.store(true, Ordering::Release);
            "stopping\n".to_string()
        }
        _ => "ERROR unknown command\n".to_string(),
    }
}

fn handle_connection(
    mut client: TcpStream,
    accepted_at: Instant,
    state: Arc<ProxyState>,
    admission: PreRoutingAdmission,
) -> Result<(), String> {
    client
        .set_nonblocking(false)
        .map_err(|error| format!("cannot configure accepted client socket: {error}"))?;
    let process_start = *PROCESS_START.get_or_init(Instant::now);
    let accepted_at_ns = accepted_at
        .saturating_duration_since(process_start)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let client_hello_timeout = state.limits.client_hello_timeout();
    let client_hello_deadline = accepted_at
        .checked_add(client_hello_timeout)
        .ok_or_else(|| "ClientHello deadline overflowed".to_string())?;
    let client_hello_remaining = client_hello_deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "ClientHello deadline elapsed before worker dispatch".to_string())?;
    client
        .set_read_timeout(Some(client_hello_remaining))
        .map_err(|error| format!("cannot set ClientHello timeout: {error}"))?;
    let (hostname, peeked_length) = tls_client_hello::peek_sni(&client, client_hello_remaining)
        .map_err(|error| error.to_string())?;
    client
        .set_read_timeout(None)
        .map_err(|error| format!("cannot clear ClientHello timeout before handoff: {error}"))?;

    let cached = state
        .routes
        .read()
        .map_err(|_| "route table lock poisoned".to_string())?
        .get(&hostname)
        .map(|route| route.backend.clone());

    let mut backend = if let Some(backend) = cached.as_ref() {
        backend.clone()
    } else {
        resolve_backend(&hostname, &state)?
    };

    match state.admission.try_acquire_handoff() {
        Ok(_handoff_permit) => {
            let mut connection_id = [0_u8; 16];
            match getrandom::fill(&mut connection_id) {
                Ok(()) => {
                    state.handoff_attempts.fetch_add(1, Ordering::Relaxed);
                    match handoff::try_transfer(
                        client,
                        &backend.project,
                        &backend.role,
                        &hostname,
                        peeked_length,
                        connection_id,
                        accepted_at_ns,
                    ) {
                        handoff::Outcome::Transferred => {
                            state.successful_handoffs.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "Handed off {hostname} to {} ({})",
                                backend.project, backend.role
                            );
                            return Ok(());
                        }
                        handoff::Outcome::Delivered(error) => {
                            state
                                .delivered_handoff_failures
                                .fetch_add(1, Ordering::Relaxed);
                            return Err(error);
                        }
                        handoff::Outcome::Unavailable(returned) => {
                            state.handoff_fallbacks.fetch_add(1, Ordering::Relaxed);
                            client = returned;
                        }
                    }
                }
                Err(error) => {
                    state.handoff_fallbacks.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "TLS socket handoff unavailable: cannot create connection ID: {error}"
                    );
                }
            }
        }
        Err(rejection) => state.record_admission_rejection(rejection),
    }

    let relay_permit = match acquire_relay_capacity(&state) {
        Some(permit) => permit,
        None => return Ok(()),
    };

    let (upstream, relay_permit) = match connect_backend(&backend) {
        Ok(stream) => (stream, relay_permit),
        Err(_) if cached.is_some() => {
            drop(relay_permit);
            state
                .routes
                .write()
                .map_err(|_| "route table lock poisoned".to_string())?
                .remove(&hostname);
            backend = resolve_backend(&hostname, &state)?;
            let relay_permit = match acquire_relay_capacity(&state) {
                Some(permit) => permit,
                None => return Ok(()),
            };
            let stream = connect_backend(&backend)
                .map_err(|error| format!("verified backend disappeared: {error}"))?;
            (stream, relay_permit)
        }
        Err(error) => return Err(format!("verified backend disappeared: {error}")),
    };
    let _relay_admission = admission.into_relay(relay_permit);

    let mut buffered = vec![0_u8; peeked_length];
    client
        .set_read_timeout(Some(client_hello_timeout))
        .map_err(|error| format!("cannot restore ClientHello timeout: {error}"))?;
    client
        .read_exact(&mut buffered)
        .map_err(|error| format!("cannot consume peeked ClientHello: {error}"))?;
    client
        .set_read_timeout(None)
        .map_err(|error| format!("cannot clear ClientHello timeout: {error}"))?;
    eprintln!(
        "Routing {hostname} to 127.0.0.1:{} ({} {})",
        backend.port, backend.project, backend.role
    );
    state.relayed_connections.fetch_add(1, Ordering::Relaxed);
    match relay(client, upstream, &buffered) {
        Ok(()) => Ok(()),
        Err(error) => Err(format!("relay failed: {error}")),
    }
}

fn acquire_relay_capacity(state: &ProxyState) -> Option<RelayPermit> {
    match state.admission.try_acquire_relay() {
        Ok(permit) => Some(permit),
        Err(rejection) => {
            state.record_admission_rejection(rejection);
            state.rejected_connections.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn resolve_backend(hostname: &str, state: &ProxyState) -> Result<Backend, String> {
    if state.hosting_profile.is_public() {
        return Err(format!(
            "public ingress has no verified Route Declaration for {hostname}"
        ));
    }
    let cached = route_cache::load(&state.config, hostname);
    let candidates = candidate_backends(&state.config, cached.as_ref());
    observe_workloads(state, &candidates);

    {
        let mut negative = state
            .negative
            .lock()
            .map_err(|_| "negative route cache lock poisoned".to_string())?;
        let now = Instant::now();
        negative.retain(|_, expires_at| *expires_at > now);
        if negative.contains_key(hostname) {
            return Err(format!(
                "no unique trusted backend was found recently for {hostname}"
            ));
        }
    }

    state.discover_once(hostname, || discover_backend(hostname, state, candidates))
}

fn discover_backend(
    hostname: &str,
    state: &ProxyState,
    candidates: Vec<Backend>,
) -> Result<Backend, String> {
    let matches = probe_candidates(hostname, candidates, state);

    if matches.len() != 1 {
        if matches.len() > 1 {
            record_conflict(
                state,
                hostname,
                matches
                    .iter()
                    .map(|matched| matched.backend.clone())
                    .collect(),
            );
        }
        let error = match matches.len() {
            0 => format!("no active backend presents a trusted certificate for {hostname}"),
            count => format!("{count} active backends present trusted certificates for {hostname}"),
        };
        cache_negative(state, hostname);
        return Err(error);
    }

    let matched = matches.into_iter().next().unwrap();
    let backend = matched.backend.clone();
    clear_conflict(state, hostname);
    install_active_route(state, hostname, matched);
    state.successful_discoveries.fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "Discovered {hostname} at 127.0.0.1:{} ({} {})",
        backend.port, backend.project, backend.role
    );
    Ok(backend)
}

fn cache_negative(state: &ProxyState, hostname: &str) {
    if let Ok(mut negative) = state.negative.lock() {
        if negative.len() >= MAX_NEGATIVE_ROUTES {
            let now = Instant::now();
            negative.retain(|_, expires_at| *expires_at > now);
            if negative.len() >= MAX_NEGATIVE_ROUTES
                && let Some(oldest) = negative
                    .iter()
                    .min_by_key(|(_, expires_at)| **expires_at)
                    .map(|(hostname, _)| hostname.clone())
            {
                negative.remove(&oldest);
            }
        }
        negative.insert(hostname.to_string(), Instant::now() + NEGATIVE_TTL);
    }
}

fn record_conflict(state: &ProxyState, hostname: &str, mut backends: Vec<Backend>) {
    backends.sort();
    backends.dedup();
    if let Ok(mut conflicts) = state.conflicts.write() {
        conflicts.insert(hostname.to_string(), backends.clone());
    }
    let owners = backends
        .iter()
        .map(|backend| format!("{} {}:{}", backend.project, backend.role, backend.port))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!("TLS route conflict for {hostname}: {owners}");
}

fn clear_conflict(state: &ProxyState, hostname: &str) {
    if let Ok(mut conflicts) = state.conflicts.write() {
        conflicts.remove(hostname);
    }
}

fn observe_workloads(state: &ProxyState, candidates: &[Backend]) -> Vec<Backend> {
    let mut snapshot = candidates.to_vec();
    snapshot.sort();
    if let Ok(mut workloads) = state.workloads.lock()
        && *workloads != snapshot
    {
        let added = snapshot
            .iter()
            .filter(|backend| !workloads.contains(backend))
            .cloned()
            .collect();
        *workloads = snapshot;
        if let Ok(mut negative) = state.negative.lock() {
            negative.clear();
        }
        return added;
    }
    Vec::new()
}

fn reconcile_workloads(state: &ProxyState) {
    if state.hosting_profile.is_public() {
        return;
    }
    let candidates = candidate_backends(&state.config, None);
    let added = observe_workloads(state, &candidates);

    for backend in added {
        if !supports_eager_discovery(&backend) {
            continue;
        }
        let names = match default_certificate_dns_names(state, &backend) {
            Ok(names) => names,
            Err(error) => {
                eprintln!(
                    "Eager TLS discovery unavailable at 127.0.0.1:{} ({} {}): {error}",
                    backend.port, backend.project, backend.role
                );
                continue;
            }
        };

        for hostname in names {
            let incumbent = state
                .routes
                .read()
                .ok()
                .and_then(|routes| routes.get(&hostname).cloned());
            if let Some(incumbent) = incumbent {
                if incumbent.backend != backend
                    && let Some(_permit) = state.probes.acquire(Instant::now() + DISCOVERY_TIMEOUT)
                    && probe_backend(&hostname, &backend).is_ok()
                {
                    record_conflict(state, &hostname, vec![incumbent.backend, backend.clone()]);
                }
                continue;
            }
            let cached = route_cache::load(&state.config, &hostname);
            let candidates = candidate_backends(&state.config, cached.as_ref());
            let result =
                state.discover_once(&hostname, || discover_backend(&hostname, state, candidates));
            if let Err(error) = result {
                eprintln!("Eager TLS discovery rejected {hostname}: {error}");
            }
        }
    }
}

fn supports_eager_discovery(backend: &Backend) -> bool {
    backend.role == "https"
}

fn default_certificate_dns_names(
    state: &ProxyState,
    backend: &Backend,
) -> Result<Vec<String>, String> {
    let _permit = state
        .probes
        .acquire(Instant::now() + DISCOVERY_TIMEOUT)
        .ok_or_else(|| "probe capacity unavailable".to_string())?;
    let stream = connect_backend_with_timeout(backend, PROBE_TIMEOUT)
        .map_err(|error| format!("TCP connection failed: {error}"))?;
    let mut builder = TlsConnector::builder();
    builder.use_sni(false);
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
    let connector = builder
        .build()
        .map_err(|error| format!("cannot create TLS connector: {error}"))?;
    let tls = connector
        .connect("localhost", stream)
        .map_err(|error| format!("no-SNI TLS handshake failed: {error}"))?;
    let certificate = tls
        .peer_certificate()
        .map_err(|error| format!("cannot inspect default certificate: {error}"))?
        .ok_or_else(|| "backend did not present a default certificate".to_string())?;
    let der = certificate
        .to_der()
        .map_err(|error| format!("cannot encode default certificate: {error}"))?;
    dns_names_from_certificate(&der)
}

fn dns_names_from_certificate(der: &[u8]) -> Result<Vec<String>, String> {
    let (_, certificate) = X509Certificate::from_der(der)
        .map_err(|error| format!("cannot parse default certificate: {error}"))?;
    let san = certificate
        .subject_alternative_name()
        .map_err(|error| format!("cannot parse certificate SANs: {error}"))?
        .ok_or_else(|| "default certificate has no Subject Alternative Name".to_string())?;

    let mut names: Vec<String> = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) if !name.starts_with("*.") => {
                tls_client_hello::normalize_hostname(name).ok()
            }
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

fn reconcile_routes(state: &ProxyState) {
    if state.hosting_profile.is_public() {
        return;
    }
    let routes: Vec<(String, ActiveRoute)> = match state.routes.read() {
        Ok(routes) => routes
            .iter()
            .map(|(hostname, route)| (hostname.clone(), route.clone()))
            .collect(),
        Err(_) => return,
    };

    for (hostname, route) in routes {
        if !registration_matches(&state.config, &route.backend) {
            deactivate_route(state, &hostname, true, "registration was removed");
            continue;
        }

        if !is_port_open(i64::from(route.backend.port)) {
            record_tcp_failure(state, &hostname);
            continue;
        }

        let recovered = route.tcp_failures > 0;
        let tls_due = route.last_tls_check.elapsed() >= TLS_REVALIDATION_INTERVAL;
        if recovered || tls_due {
            revalidate_hostname(state, &hostname, &route);
        } else if let Ok(mut routes) = state.routes.write()
            && let Some(active) = routes.get_mut(&hostname)
        {
            active.tcp_failures = 0;
        }
    }
}

fn revalidate_hostname(state: &ProxyState, hostname: &str, incumbent: &ActiveRoute) {
    if let Some(_permit) = state.probes.acquire(Instant::now() + DISCOVERY_TIMEOUT)
        && let Ok(certificate_fingerprint) = probe_backend(hostname, &incumbent.backend)
    {
        clear_conflict(state, hostname);
        if certificate_fingerprint != incumbent.certificate_fingerprint {
            eprintln!(
                "Observed certificate rotation for {hostname} at 127.0.0.1:{}",
                incumbent.backend.port
            );
        }
        install_active_route(
            state,
            hostname,
            ProbeMatch {
                backend: incumbent.backend.clone(),
                certificate_fingerprint,
            },
        );
        return;
    }

    let cached = route_cache::load(&state.config, hostname);
    let candidates = candidate_backends(&state.config, cached.as_ref())
        .into_iter()
        .filter(|backend| backend != &incumbent.backend)
        .collect();
    let mut matches = probe_candidates(hostname, candidates, state);

    match matches.len() {
        0 => {
            clear_conflict(state, hostname);
            deactivate_route(state, hostname, false, "TLS revalidation failed");
        }
        1 => {
            clear_conflict(state, hostname);
            let replacement = matches.pop().unwrap();
            eprintln!(
                "Moving TLS route {hostname} from {} {}:{} to {} {}:{} after revalidation",
                incumbent.backend.project,
                incumbent.backend.role,
                incumbent.backend.port,
                replacement.backend.project,
                replacement.backend.role,
                replacement.backend.port
            );
            install_active_route(state, hostname, replacement);
        }
        _ => {
            record_conflict(
                state,
                hostname,
                matches.into_iter().map(|matched| matched.backend).collect(),
            );
            deactivate_route(
                state,
                hostname,
                false,
                "incumbent is invalid and multiple contenders remain",
            );
        }
    }
}

fn install_active_route(state: &ProxyState, hostname: &str, matched: ProbeMatch) {
    if let Ok(mut routes) = state.routes.write() {
        routes.insert(
            hostname.to_string(),
            ActiveRoute {
                backend: matched.backend.clone(),
                certificate_fingerprint: matched.certificate_fingerprint.clone(),
                last_tls_check: Instant::now(),
                tcp_failures: 0,
            },
        );
    }
    route_cache::store(
        &state.config,
        hostname,
        &matched.backend.project,
        &matched.backend.role,
        &matched.certificate_fingerprint,
    );
}

fn registration_matches(config: &Path, backend: &Backend) -> bool {
    let document = read_config(config);
    document
        .get("ports")
        .and_then(|item| item.as_table())
        .and_then(|projects| projects.get(&backend.project))
        .and_then(|item| item.as_table())
        .and_then(|roles| roles.get(&backend.role))
        .and_then(|item| item.as_integer())
        .and_then(|port| u16::try_from(port).ok())
        == Some(backend.port)
}

fn record_tcp_failure(state: &ProxyState, hostname: &str) {
    let failures = if let Ok(mut routes) = state.routes.write() {
        routes.get_mut(hostname).map(|route| {
            route.tcp_failures = route.tcp_failures.saturating_add(1);
            route.tcp_failures
        })
    } else {
        None
    };

    if failures.is_some_and(|failures| failures >= TCP_FAILURE_THRESHOLD) {
        deactivate_route(
            state,
            hostname,
            false,
            "backend failed three consecutive TCP checks",
        );
    }
}

fn deactivate_route(state: &ProxyState, hostname: &str, remove_cached: bool, reason: &str) {
    let removed = state
        .routes
        .write()
        .ok()
        .and_then(|mut routes| routes.remove(hostname))
        .is_some();
    if removed {
        eprintln!("Deactivated TLS route {hostname}: {reason}");
    }
    if remove_cached {
        route_cache::remove(&state.config, hostname);
    }
}

fn candidate_backends(config: &Path, cached: Option<&route_cache::CachedRoute>) -> Vec<Backend> {
    let document = read_config(config);
    let mut candidates = Vec::new();

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
                candidates.push(candidate);
            }
        }
    }

    candidates.sort_by(|left, right| {
        left.project
            .cmp(&right.project)
            .then_with(|| (left.role != "https").cmp(&(right.role != "https")))
            .then_with(|| left.port.cmp(&right.port))
    });
    if let Some(cached) = cached
        && let Some(index) = candidates
            .iter()
            .position(|backend| backend.project == cached.project && backend.role == cached.role)
    {
        candidates.swap(0, index);
    }
    candidates.into_iter().take(MAX_PROBES).collect()
}

fn probe_candidates(
    hostname: &str,
    candidates: Vec<Backend>,
    state: &ProxyState,
) -> Vec<ProbeMatch> {
    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    let deadline = started + DISCOVERY_TIMEOUT;
    let launch_deadline = started + DISCOVERY_TIMEOUT.saturating_sub(PROBE_TIMEOUT);

    for backend in candidates {
        let sender = sender.clone();
        let hostname = hostname.to_string();
        let probes = Arc::clone(&state.probes);
        let Some(permit) = probes.acquire(launch_deadline) else {
            break;
        };
        if let Err(error) = thread::Builder::new()
            .name("phx-port-probe".to_string())
            .spawn(move || {
                let _permit = permit;
                match probe_backend(&hostname, &backend) {
                    Ok(certificate_fingerprint) => {
                        let _ = sender.send(ProbeMatch {
                            backend,
                            certificate_fingerprint,
                        });
                    }
                    Err(error) => {
                        eprintln!(
                            "Probe rejected {hostname} at 127.0.0.1:{} ({} {}): {error}",
                            backend.port, backend.project, backend.role
                        );
                    }
                }
            })
        {
            eprintln!("Cannot start bounded certificate probe: {error}");
            break;
        }
    }
    drop(sender);

    prefer_https_per_project(collect_probe_matches(receiver, deadline))
}

fn collect_probe_matches(
    receiver: mpsc::Receiver<ProbeMatch>,
    deadline: Instant,
) -> Vec<ProbeMatch> {
    let mut matches = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(backend) => matches.push(backend),
            Err(mpsc::RecvTimeoutError::Disconnected | mpsc::RecvTimeoutError::Timeout) => break,
        }
    }
    matches
}

fn prefer_https_per_project(matches: Vec<ProbeMatch>) -> Vec<ProbeMatch> {
    let mut by_project = HashMap::<String, ProbeMatch>::new();
    for matched in matches {
        by_project
            .entry(matched.backend.project.clone())
            .and_modify(|current| {
                if matched.backend.role == "https" && current.backend.role != "https" {
                    *current = ProbeMatch {
                        backend: matched.backend.clone(),
                        certificate_fingerprint: matched.certificate_fingerprint.clone(),
                    };
                }
            })
            .or_insert(matched);
    }
    let mut preferred: Vec<_> = by_project.into_values().collect();
    preferred.sort_by(|left, right| left.backend.cmp(&right.backend));
    preferred
}

fn probe_backend(hostname: &str, backend: &Backend) -> Result<String, String> {
    let stream = connect_backend_with_timeout(backend, PROBE_TIMEOUT)
        .map_err(|error| format!("TCP connection failed: {error}"))?;
    let connector =
        TlsConnector::new().map_err(|error| format!("cannot create TLS connector: {error}"))?;
    let tls = connector
        .connect(hostname, stream)
        .map_err(|error| format!("TLS validation failed: {error}"))?;
    let certificate = tls
        .peer_certificate()
        .map_err(|error| format!("cannot inspect peer certificate: {error}"))?
        .ok_or_else(|| "backend did not present a certificate".to_string())?;
    let digest = Sha256::digest(
        certificate
            .to_der()
            .map_err(|error| format!("cannot encode peer certificate: {error}"))?,
    );
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
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

#[cfg(test)]
mod tests {
    use super::{
        ActiveRoute, Backend, MAX_PROBES, MAX_WAITING_CLIENTS, OVERLOAD_EVENT_INTERVAL,
        ProbeLimiter, ProbeMatch, ProxyState, WaitingClient, bind_listener, cache_negative,
        clear_conflict, collect_probe_matches, observe_workloads, prefer_https_per_project,
        reconcile_routes, reconcile_workloads, record_conflict, render_control_response,
        resolve_backend, supports_eager_discovery,
    };
    use crate::{
        admission::AdmissionRejection, ingress_config::HostingProfile, route_cache, update_config,
    };
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;
    use toml_edit::value;

    fn backend() -> Backend {
        Backend {
            project: "/project".to_string(),
            role: "https".to_string(),
            port: 4401,
        }
    }

    fn active_route(backend: Backend) -> ActiveRoute {
        ActiveRoute {
            backend,
            certificate_fingerprint: "AA:BB".to_string(),
            last_tls_check: Instant::now(),
            tcp_failures: 0,
        }
    }

    #[test]
    fn concurrent_requests_share_one_hostname_discovery() {
        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let barrier = Arc::new(Barrier::new(10));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut clients = Vec::new();

        for _ in 0..10 {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            let calls = Arc::clone(&calls);
            clients.push(thread::spawn(move || {
                barrier.wait();
                state
                    .discover_once("www.example.com", || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(30));
                        Ok(backend())
                    })
                    .unwrap()
            }));
        }

        for client in clients {
            assert_eq!(client.join().unwrap(), backend());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn waiting_client_limit_fails_closed() {
        let count = AtomicUsize::new(MAX_WAITING_CLIENTS);
        assert!(WaitingClient::acquire(&count).is_err());
        assert_eq!(count.load(Ordering::SeqCst), MAX_WAITING_CLIENTS);
    }

    #[test]
    fn probe_limiter_releases_capacity() {
        let limiter = Arc::new(ProbeLimiter::new());
        let deadline = Instant::now() + Duration::from_secs(1);
        let permits: Vec<_> = (0..MAX_PROBES)
            .map(|_| limiter.acquire(deadline).unwrap())
            .collect();
        assert!(
            limiter
                .acquire(Instant::now() + Duration::from_millis(1))
                .is_none()
        );
        drop(permits);
        assert!(limiter.acquire(deadline).is_some());
    }

    #[test]
    fn completed_probe_is_retained_after_the_collection_deadline() {
        let (sender, receiver) = std::sync::mpsc::channel();
        sender
            .send(ProbeMatch {
                backend: backend(),
                certificate_fingerprint: "AA:BB".to_string(),
            })
            .unwrap();
        drop(sender);
        let deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();

        let matches = collect_probe_matches(receiver, deadline);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].backend, backend());
    }

    #[test]
    fn workload_change_invalidates_negative_routes() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        cache_negative(&state, "www.example.com");
        assert!(!state.negative.lock().unwrap().is_empty());

        observe_workloads(&state, &[backend()]);

        assert!(state.negative.lock().unwrap().is_empty());
    }

    #[test]
    fn conflicts_are_recorded_deterministically_and_can_be_cleared() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        let mut contender = backend();
        contender.project = "/contender".to_string();
        contender.port = 4402;

        record_conflict(
            &state,
            "www.example.com",
            vec![contender.clone(), backend(), contender],
        );

        let conflicts = state.conflicts.read().unwrap();
        let mut expected = vec![backend(), {
            let mut contender = backend();
            contender.project = "/contender".to_string();
            contender.port = 4402;
            contender
        }];
        expected.sort();
        assert_eq!(conflicts["www.example.com"], expected);
        drop(conflicts);

        clear_conflict(&state, "www.example.com");
        assert!(state.conflicts.read().unwrap().is_empty());
    }

    #[test]
    fn ipv6_listener_is_v6_only_so_ipv4_can_share_its_port() {
        let Ok(ipv6) = bind_listener("[::]:0") else {
            return;
        };
        let port = ipv6.local_addr().unwrap().port();
        let ipv4 = bind_listener(&format!("0.0.0.0:{port}")).unwrap();

        assert!(ipv6.local_addr().unwrap().is_ipv6());
        assert!(ipv4.local_addr().unwrap().is_ipv4());
    }

    #[test]
    fn control_status_reports_state_and_stop_sets_shutdown() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        state
            .routes
            .write()
            .unwrap()
            .insert("www.example.com".to_string(), active_route(backend()));
        state.accepted_connections.store(7, Ordering::Relaxed);
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let routing = state
            .admission
            .try_admit(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .unwrap();
        let handoff = state.admission.try_acquire_handoff().unwrap();

        let status = render_control_response(&state, &shutdown, "STATUS");
        assert!(status.contains("hosting_profile=development"));
        assert!(status.contains("active_routes=1"));
        assert!(status.contains("accepted_connections=7"));
        assert!(status.contains("active_connections=1"));
        assert!(status.contains("active_connection_limit=256"));
        assert!(status.contains("pre_routing_connections=1"));
        assert!(status.contains("pre_routing_connection_limit=128"));
        assert!(status.contains("active_relays=0"));
        assert!(status.contains("relay_connection_limit=128"));
        assert!(status.contains("handoff_negotiations=1"));
        assert!(status.contains("handoff_negotiation_limit=64"));
        assert!(status.contains("accepts_per_second_limit=200"));
        assert!(status.contains("accept_burst_limit=400"));
        assert!(status.contains("source_entries=1"));
        assert!(status.contains("source_entry_limit=4096"));
        assert!(status.contains("source_accepts_per_second_limit=20"));
        assert!(status.contains("source_accept_burst_limit=40"));
        assert!(status.contains("source_pre_routing_limit=16"));
        assert!(status.contains("source_ipv6_prefix=64"));
        assert!(status.contains("source_entry_ttl_seconds=300"));
        assert!(status.contains("source_policy_overrides=0"));
        assert!(status.contains("connection_queue_limit=1"));
        assert!(status.contains("connection_workers=256"));

        drop(handoff);
        let relay = state.admission.try_acquire_relay().unwrap();
        let relay = routing.into_relay(relay);
        let status = render_control_response(&state, &shutdown, "STATUS");
        assert!(status.contains("active_connections=1"));
        assert!(status.contains("pre_routing_connections=0"));
        assert!(status.contains("active_relays=1"));
        assert!(status.contains("handoff_negotiations=0"));
        drop(relay);
        assert!(
            render_control_response(&state, &shutdown, "STATUS").contains("active_connections=0")
        );

        assert_eq!(
            render_control_response(&state, &shutdown, "STOP"),
            "stopping\n"
        );
        assert!(shutdown.load(Ordering::Acquire));
    }

    #[test]
    fn public_profile_is_observable_and_disables_dynamic_registry_discovery() {
        let directory = tempdir().unwrap();
        let registry = directory.path().join("ports.toml");
        update_config(&registry, |document| {
            document["ports"]["contoso-web"]["https"] = value(4401);
        });
        let state = ProxyState::new_with_profile(
            registry,
            HostingProfile::Public {
                ingress_config: directory.path().join("ingress.toml"),
            },
        );

        reconcile_workloads(&state);
        assert!(state.workloads.lock().unwrap().is_empty());
        let error = resolve_backend("www.example.com", &state).unwrap_err();
        assert_eq!(
            error,
            "public ingress has no verified Route Declaration for www.example.com"
        );
        assert_eq!(state.successful_discoveries.load(Ordering::Relaxed), 0);

        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let status = render_control_response(&state, &shutdown, "STATUS");
        assert!(status.contains("hosting_profile=public"));
        assert!(status.contains("active_routes=0"));
    }

    #[test]
    fn every_overload_reason_is_counted_and_rate_limited_with_fixed_labels() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        let now = Instant::now();
        let status_counters = [
            "rejected_accept_rate",
            "rejected_global_capacity",
            "rejected_source_rate",
            "rejected_source_concurrency",
            "rejected_source_state_capacity",
            "rejected_pre_routing_capacity",
            "rejected_relay_capacity",
            "handoff_capacity_skips",
            "rejected_worker_queue",
        ];

        for reason in AdmissionRejection::ALL {
            let event = state.record_admission_rejection_at(reason, now).unwrap();
            assert_eq!(
                event.to_string(),
                format!(
                    "event=ingress_overload reason={} rejected=1 suppressed=0",
                    reason.event_reason()
                )
            );
            assert!(
                state
                    .record_admission_rejection_at(reason, now + Duration::from_millis(1))
                    .is_none()
            );
        }

        let status =
            render_control_response(&state, &std::sync::atomic::AtomicBool::new(false), "STATUS");
        for counter in status_counters {
            assert!(
                status.lines().any(|line| line == format!("{counter}=2")),
                "missing counter {counter} in status:\n{status}"
            );
        }

        for reason in AdmissionRejection::ALL {
            let event = state
                .record_admission_rejection_at(reason, now + OVERLOAD_EVENT_INTERVAL)
                .unwrap();
            assert_eq!(
                event.to_string(),
                format!(
                    "event=ingress_overload reason={} rejected=2 suppressed=1",
                    reason.event_reason()
                )
            );
        }
    }

    #[test]
    fn eager_discovery_extracts_exact_dns_sans_but_not_wildcards() {
        let certificate = rcgen::generate_simple_self_signed(vec![
            "www.example.com".to_string(),
            "api.example.com".to_string(),
            "*.example.com".to_string(),
        ])
        .unwrap();

        assert_eq!(
            super::dns_names_from_certificate(certificate.cert.der()).unwrap(),
            ["api.example.com", "www.example.com"]
        );
    }

    #[test]
    fn eager_discovery_never_probes_compatibility_main_ports() {
        let mut main = backend();
        main.role = "main".to_string();

        assert!(!supports_eager_discovery(&main));
        assert!(supports_eager_discovery(&backend()));
    }

    #[test]
    fn https_is_preferred_only_after_both_project_roles_validate() {
        let mut main_backend = backend();
        main_backend.role = "main".to_string();
        let main = ProbeMatch {
            backend: main_backend,
            certificate_fingerprint: "MAIN".to_string(),
        };
        let mut https_backend = backend();
        https_backend.role = "https".to_string();
        https_backend.port = 4402;
        let https = ProbeMatch {
            backend: https_backend.clone(),
            certificate_fingerprint: "HTTPS".to_string(),
        };
        let mut other_backend = backend();
        other_backend.project = "/other".to_string();
        other_backend.port = 4403;
        let other = ProbeMatch {
            backend: other_backend.clone(),
            certificate_fingerprint: "OTHER".to_string(),
        };

        let preferred = prefer_https_per_project(vec![main, other, https]);

        assert_eq!(preferred.len(), 2);
        assert!(preferred.iter().any(|matched| {
            matched.backend == https_backend && matched.certificate_fingerprint == "HTTPS"
        }));
        assert!(
            preferred
                .iter()
                .any(|matched| matched.backend == other_backend)
        );
    }

    #[test]
    fn removed_registration_deactivates_and_forgets_the_route() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        let state = ProxyState::new(path.clone());
        state
            .routes
            .write()
            .unwrap()
            .insert("www.example.com".to_string(), active_route(backend()));
        route_cache::store(&path, "www.example.com", "/project", "https", "AA:BB");

        reconcile_routes(&state);

        assert!(state.routes.read().unwrap().is_empty());
        assert!(route_cache::load(&path, "www.example.com").is_none());
    }

    #[test]
    fn three_tcp_failures_deactivate_but_retain_the_cached_route() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        update_config(&path, |document| {
            document["ports"]["/project"] = toml_edit::table();
            document["ports"]["/project"]["https"] = value(i64::from(port));
        });
        route_cache::store(&path, "www.example.com", "/project", "https", "AA:BB");

        let state = ProxyState::new(path.clone());
        let mut backend = backend();
        backend.port = port;
        state
            .routes
            .write()
            .unwrap()
            .insert("www.example.com".to_string(), active_route(backend));

        reconcile_routes(&state);
        reconcile_routes(&state);
        assert!(!state.routes.read().unwrap().is_empty());
        reconcile_routes(&state);

        assert!(state.routes.read().unwrap().is_empty());
        assert!(route_cache::load(&path, "www.example.com").is_some());
    }
}
