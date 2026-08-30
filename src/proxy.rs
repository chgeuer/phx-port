use crate::{config_path, is_port_open, read_config, route_cache, tls_client_hello};
use native_tls::TlsConnector;
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

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
    conflicts: RwLock<HashMap<String, Vec<Backend>>>,
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
            conflicts: RwLock::new(HashMap::new()),
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
        let listener = bind_listener(address)
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
                reconcile_workloads(&state);
                reconcile_routes(&state);
            }
        });
    }

    loop {
        thread::park();
    }
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
    let candidates = candidate_backends(&state.config, None);
    let added = observe_workloads(state, &candidates);

    for backend in added {
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
    let cached = route_cache::load(&state.config, hostname);
    let candidates = candidate_backends(&state.config, cached.as_ref());
    let mut matches = probe_candidates(hostname, candidates, state);

    if let Some(index) = matches
        .iter()
        .position(|matched| matched.backend == incumbent.backend)
    {
        let matched = matches.swap_remove(index);
        if matches.is_empty() {
            clear_conflict(state, hostname);
        } else {
            let mut owners = vec![matched.backend.clone()];
            owners.extend(matches.into_iter().map(|contender| contender.backend));
            record_conflict(state, hostname, owners);
        }
        if matched.certificate_fingerprint != incumbent.certificate_fingerprint {
            eprintln!(
                "Observed certificate rotation for {hostname} at 127.0.0.1:{}",
                incumbent.backend.port
            );
        }
        install_active_route(state, hostname, matched);
        return;
    }

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
    prefer_https_per_project(matches)
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
        ActiveRoute, Backend, MAX_PROBES, MAX_WAITING_CLIENTS, ProbeLimiter, ProbeMatch,
        ProxyState, WaitingClient, bind_listener, cache_negative, clear_conflict,
        observe_workloads, prefer_https_per_project, reconcile_routes, record_conflict,
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
