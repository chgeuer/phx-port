use crate::{config_path, is_port_open, read_config, route_cache, tls_client_hello};
use native_tls::TlsConnector;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);
const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_PROBES: usize = 32;
const MAX_WAITING_CLIENTS: usize = 64;
const MAX_NEGATIVE_ROUTES: usize = 1024;
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const LIVENESS_INTERVAL: Duration = Duration::from_secs(1);
const TLS_REVALIDATION_INTERVAL: Duration = Duration::from_secs(30);
const TCP_FAILURE_THRESHOLD: u8 = 3;

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

    fn acquire(&self, deadline: Instant) -> Option<ProbePermit<'_>> {
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
        Some(ProbePermit { limiter: self })
    }
}

struct ProbePermit<'a> {
    limiter: &'a ProbeLimiter,
}

impl Drop for ProbePermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut in_use) = self.limiter.in_use.lock() {
            *in_use = in_use.saturating_sub(1);
            self.limiter.available.notify_one();
        }
    }
}

struct ProxyState {
    config: PathBuf,
    routes: RwLock<HashMap<String, ActiveRoute>>,
    flights: Mutex<HashMap<String, Arc<DiscoveryFlight>>>,
    negative: Mutex<HashMap<String, Instant>>,
    workloads: Mutex<Vec<Backend>>,
    waiting_clients: AtomicUsize,
    probes: Arc<ProbeLimiter>,
}

impl ProxyState {
    fn new(config: PathBuf) -> Self {
        Self {
            config,
            routes: RwLock::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
            workloads: Mutex::new(Vec::new()),
            waiting_clients: AtomicUsize::new(0),
            probes: Arc::new(ProbeLimiter::new()),
        }
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

pub fn run(listen_addresses: &[String]) -> Result<(), String> {
    let state = Arc::new(ProxyState::new(config_path()));
    let mut listeners = Vec::new();

    for address in listen_addresses {
        let listener = TcpListener::bind(address)
            .map_err(|error| format!("cannot listen on {address}: {error}"))?;
        eprintln!("TLS proxy listening on {}", listener.local_addr().unwrap());
        listeners.push(listener);
    }

    for listener in listeners {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            for accepted in listener.incoming() {
                match accepted {
                    Ok(stream) => {
                        let state = Arc::clone(&state);
                        thread::spawn(move || {
                            if let Err(error) = handle_connection(stream, state) {
                                eprintln!("TLS proxy connection rejected: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("TLS proxy accept failed: {error}"),
                }
            }
        });
    }

    {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            loop {
                thread::sleep(LIVENESS_INTERVAL);
                reconcile_routes(&state);
            }
        });
    }

    loop {
        thread::park();
    }
}

fn handle_connection(mut client: TcpStream, state: Arc<ProxyState>) -> Result<(), String> {
    client
        .set_read_timeout(Some(CLIENT_HELLO_TIMEOUT))
        .map_err(|error| format!("cannot set ClientHello timeout: {error}"))?;
    let (hostname, buffered) =
        tls_client_hello::read_sni(&mut client).map_err(|error| error.to_string())?;
    client.set_read_timeout(None).ok();

    let cached = state
        .routes
        .read()
        .map_err(|_| "route table lock poisoned".to_string())?
        .get(&hostname)
        .map(|route| route.backend.clone());

    let (backend, upstream) = if let Some(backend) = cached {
        match connect_backend(&backend) {
            Ok(stream) => (backend, stream),
            Err(_) => {
                state
                    .routes
                    .write()
                    .map_err(|_| "route table lock poisoned".to_string())?
                    .remove(&hostname);
                let backend = resolve_backend(&hostname, &state)?;
                let upstream = connect_backend(&backend)
                    .map_err(|error| format!("verified backend disappeared: {error}"))?;
                (backend, upstream)
            }
        }
    } else {
        let backend = resolve_backend(&hostname, &state)?;
        let upstream = connect_backend(&backend)
            .map_err(|error| format!("verified backend disappeared: {error}"))?;
        (backend, upstream)
    };

    eprintln!(
        "Routing {hostname} to 127.0.0.1:{} ({} {})",
        backend.port, backend.project, backend.role
    );
    relay(client, upstream, &buffered).map_err(|error| format!("relay failed: {error}"))
}

fn resolve_backend(hostname: &str, state: &ProxyState) -> Result<Backend, String> {
    let cached = route_cache::load(&state.config, hostname);
    let candidates = candidate_backends(&state.config, cached.as_ref());
    invalidate_negative_cache_if_workloads_changed(state, &candidates);

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

    state.discover_once(hostname, || {
        discover_backend(hostname, state, candidates, &state.config)
    })
}

fn discover_backend(
    hostname: &str,
    state: &ProxyState,
    candidates: Vec<Backend>,
    config: &Path,
) -> Result<Backend, String> {
    let matches = probe_candidates(hostname, candidates, state);

    if matches.len() != 1 {
        let error = match matches.len() {
            0 => format!("no active backend presents a trusted certificate for {hostname}"),
            count => format!("{count} active backends present trusted certificates for {hostname}"),
        };
        cache_negative(state, hostname);
        return Err(error);
    }

    let matched = matches.into_iter().next().unwrap();
    let backend = matched.backend;
    state
        .routes
        .write()
        .map_err(|_| "route table lock poisoned".to_string())?
        .insert(
            hostname.to_string(),
            ActiveRoute {
                backend: backend.clone(),
                certificate_fingerprint: matched.certificate_fingerprint.clone(),
                last_tls_check: Instant::now(),
                tcp_failures: 0,
            },
        );
    route_cache::store(
        config,
        hostname,
        &backend.project,
        &backend.role,
        &matched.certificate_fingerprint,
    );
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

fn invalidate_negative_cache_if_workloads_changed(state: &ProxyState, candidates: &[Backend]) {
    let mut snapshot = candidates.to_vec();
    snapshot.sort();
    if let Ok(mut workloads) = state.workloads.lock()
        && *workloads != snapshot
    {
        *workloads = snapshot;
        if let Ok(mut negative) = state.negative.lock() {
            negative.clear();
        }
    }
}

fn reconcile_routes(state: &ProxyState) {
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
            let Some(_permit) = state.probes.acquire(Instant::now() + DISCOVERY_TIMEOUT) else {
                continue;
            };
            match probe_backend(&hostname, &route.backend) {
                Ok(fingerprint) => {
                    if fingerprint != route.certificate_fingerprint {
                        eprintln!(
                            "Observed certificate rotation for {hostname} at 127.0.0.1:{}",
                            route.backend.port
                        );
                    }
                    if let Ok(mut routes) = state.routes.write()
                        && let Some(active) = routes.get_mut(&hostname)
                    {
                        active.tcp_failures = 0;
                        active.last_tls_check = Instant::now();
                        active.certificate_fingerprint = fingerprint.clone();
                    }
                    route_cache::store(
                        &state.config,
                        &hostname,
                        &route.backend.project,
                        &route.backend.role,
                        &fingerprint,
                    );
                }
                Err(error) => {
                    eprintln!(
                        "Deactivating TLS route {hostname} after certificate revalidation failed: {error}"
                    );
                    deactivate_route(state, &hostname, false, "TLS revalidation failed");
                }
            }
        } else if let Ok(mut routes) = state.routes.write()
            && let Some(active) = routes.get_mut(&hostname)
        {
            active.tcp_failures = 0;
        }
    }
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

    let mut candidates: Vec<_> = by_project.into_values().collect();
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
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;

    for backend in candidates {
        let sender = sender.clone();
        let hostname = hostname.to_string();
        let probes = Arc::clone(&state.probes);
        thread::spawn(move || {
            let Some(_permit) = probes.acquire(deadline) else {
                return;
            };
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
        ActiveRoute, Backend, MAX_PROBES, MAX_WAITING_CLIENTS, ProbeLimiter, ProxyState,
        WaitingClient, cache_negative, invalidate_negative_cache_if_workloads_changed,
        reconcile_routes,
    };
    use crate::{route_cache, update_config};
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
        let limiter = ProbeLimiter::new();
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
    fn workload_change_invalidates_negative_routes() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        cache_negative(&state, "www.example.com");
        assert!(!state.negative.lock().unwrap().is_empty());

        invalidate_negative_cache_if_workloads_changed(&state, &[backend()]);

        assert!(state.negative.lock().unwrap().is_empty());
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
